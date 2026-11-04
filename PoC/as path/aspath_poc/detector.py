"""Candidate filter for AS-PATH anomalies (the counterpart of unexpectedOrigin_poc/detector.py).

Same idea as there: cheap deterministic rules decide WHAT reaches the model; the model + evidence then give a second opinion.
Here the rules look at the AS path of an announcement for a watched prefix (or a more-specific of it) / watched ASN, and each
rule is tied to a sentence in the ROUTE LLM paper or the proposal (RULES below, printed by `python aspath.py rules`).

Scope: the paper's two PATH categories. Prefix hijacks (unexpected origin / more-specific from a foreign origin) are the
unexpectedOrigin PoC's job; announcements whose origin is not an authorised origin are counted as `deferred_origin`
and skipped (--origin-policy any would run the path rules on them as well).
"""
import ipaddress, itertools, json, os, statistics, time
from collections import Counter, defaultdict

# ----------------------------------------------------------------------------------------------------------------------
# Rule catalogue: id -> (anomaly type it indicates, role, what it checks, where the logic comes from)
# role: "primary" rules make an announcement a candidate; "supporting" rules only add evidence to a candidate.
# ----------------------------------------------------------------------------------------------------------------------
RULES = {
    "new_origin_upstream": dict(
        type="path_hijack", role="primary",
        check="The AS next to the (authorised) origin on the path was never (or rarely) seen next to that origin for this watched prefix/ASN.",
        paper="Path hijack = an AS manipulates or fabricates the AS path while the origin can still look legitimate (App. B.1, Fig. 10); forged-origin hijacks are the topic of DFOH [38], "
              "cited by the paper; Fig. 4 flags the link next to the origin (AS7219-AS10990) as rarely seen before the event; Fig. 14 shows fabricated paths.",
        proposal="5b baseline: 'preferred peer for reaching key destinations'; 5c path-shift: compare the selected path with the expected preferred peer; FR1/FR4 origin/path changes."),
    "new_as_link": dict(
        type="path_hijack", role="primary",
        check="Some adjacent AS pair on the path was never (or rarely) observed in the baseline learned before the event.",
        paper="Fig. 4 evidence marks each AS-path link as seen before or never/rarely seen before the event time; the Random-Forest baseline (Sec. VII) uses newly observed AS-path edges as a feature; "
              "the retriever's knowledge base (App. E.4) stores the adjacent AS pairs of historical windows; BEAM (Sec. IV-A) is built on abnormal AS-path changes.",
        proposal="5b baseline: 'typical AS-path characteristics'; 5c 'AS-path deviation'; FR1 'AS-path anomalies'; FR2 'significant AS-PATH changes'; FR5 baseline."),
    "valley_violation": dict(
        type="route_leak", role="primary",
        check="Using CAIDA AS relationships, the path is not valley-free (up*, at most one peer link, down*). Reports the leaker, where it learned the route and where it sent it.",
        paper="Route leak = a route propagated against export policy such as valley-free (App. B.1, Fig. 10); App. E.6 says deterministic rules can catch valley-free violations but incomplete "
              "AS-relationship data can hide a leak; BEAM (Sec. IV-A) builds on AS routing roles.",
        proposal="FR6 unintended transit-to-transit / transit-to-peer / peer-to-peer propagation shown as incident evidence; RFC 7908 [10]; 5c path-shift."),
    "path_length_deviation": dict(
        type="path_hijack", role="supporting",
        check="Path length differs from the baseline median for this prefix/ASN by at least --len-delta hops (supporting evidence only).",
        paper="AS-path length is one of the Random-Forest baseline's features (Sec. VII).",
        proposal="5b baseline: 'typical AS-path characteristics'; FR2 'significant AS-PATH changes'."),
}
LEAK_KINDS = {("provider", "provider"): "transit-to-transit", ("provider", "peer"): "transit-to-peer",
              ("peer", "provider"): "peer-to-transit", ("peer", "peer"): "peer-to-peer"}
PRECEDENCE = ("new_origin_upstream", "valley_violation", "new_as_link")   # which primary rule names the candidate when several fire (our choice)


def anomaly_type(subtype):
    """Type comes from the rule that fired, as in unexpectedOrigin (pipeline.anomaly_type). The model label is advisory."""
    return RULES[subtype]["type"]


def norm(prefix):
    try:
        return str(ipaddress.ip_network(prefix, strict=False))
    except ValueError:
        return prefix


def flat(path):
    """RIS path -> list of ints, prepending removed, AS-set hops skipped."""
    return [a for a, _ in itertools.groupby(int(h) for h in path or [] if not isinstance(h, list))]


def origin_ok(path):
    return bool(path) and not isinstance(path[-1], list)       # AS_SET origin (aggregate) is skipped, as in unexpectedOrigin


def edge(a, b):
    return (a, b) if a <= b else (b, a)                          # AS adjacency is undirected


def valley(path, asrel):
    """First valley-free violation, or None. The route travelled origin -> collector, so walk the path backwards.
    Link steps: up (customer->provider), peer, down (provider->customer). Valid: up* peer? down*.
    Returns dict(leaker, learned_from, learned_role, exported_to, exported_role, kind). Links without a known relationship are skipped
    (the paper: with incomplete relationship data a leak may violate no deterministic rule -> that is what the model is for)."""
    rp, phase, last = path[::-1], "up", None            # last = (step, sender, receiver) of the previous known link
    for x, y in zip(rp, rp[1:]):
        step = {"provider": "up", "customer": "down", "peer": "peer"}.get(asrel.role(x, y))
        if step is None:
            continue
        if step != "down" and phase != "up":
            src = last[1] if last and last[2] == x else None
            lrole = {"down": "provider", "peer": "peer"}[last[0]]
            erole = "provider" if step == "up" else "peer"
            return dict(leaker=x, learned_from=src, learned_role=lrole, exported_to=y, exported_role=erole, kind=LEAK_KINDS[(lrole, erole)])
        if step != "up":
            phase = "down"
        last = (step, x, y)


class Baseline:
    """What was normal BEFORE the event (time-consistent evidence, paper R3): AS links seen, the ASes next to each watched
    object's origin, path lengths and paths per watched object. Built from a learning window or a historical file."""

    def __init__(self):
        self.edges = Counter()                      # undirected AS link -> times seen (all watched objects together, like the paper's knowledge base)
        self.upstreams = defaultdict(Counter)       # watch key -> {AS next to the origin: times seen}
        self.lengths = defaultdict(list)            # watch key -> path lengths seen
        self.paths = defaultdict(Counter)           # watch key -> {"AS AS AS": times seen}
        self.nobs = Counter()                       # watch key -> announcements learned

    def learn(self, key, path):
        for a, b in zip(path, path[1:]):
            self.edges[edge(a, b)] += 1
        if len(path) > 1:
            self.upstreams[key][path[-2]] += 1
        self.lengths[key].append(len(path)); self.paths[key][" ".join(map(str, path))] += 1; self.nobs[key] += 1

    def support(self, a, b):
        return self.edges.get(edge(a, b), 0)

    def typical_path(self, key):
        c = self.paths.get(key)
        return c.most_common(1)[0][0] if c else ""

    def median_length(self, key):
        return statistics.median(self.lengths[key]) if self.lengths.get(key) else None

    def save(self, path):
        json.dump(dict(edges=[[a, b, n] for (a, b), n in self.edges.items()], upstreams={k: dict(v) for k, v in self.upstreams.items()},
                       lengths=self.lengths, paths={k: dict(v) for k, v in self.paths.items()}, nobs=dict(self.nobs)), open(path, "w"))

    def load(self, path):
        if not os.path.exists(path):
            return False
        d = json.load(open(path))
        for a, b, n in d["edges"]:
            self.edges[edge(a, b)] += n
        for k, v in d["upstreams"].items():
            self.upstreams[k].update({int(a): n for a, n in v.items()})
        for k, v in d["lengths"].items():
            self.lengths[k].extend(v)
        for k, v in d["paths"].items():
            self.paths[k].update(v)
        self.nobs.update(d["nobs"])
        return sum(self.nobs.values()) > 0

    def stats(self):
        return dict(links=len(self.edges), watched=len(self.nobs), announcements=sum(self.nobs.values()))


class PathCandidates:
    """Announcement for a watched prefix / ASN whose path trips a primary rule -> candidate dict (same keys as unexpectedOrigin's, plus rule details)."""

    def __init__(self, whitelist, asrel, baseline, asns=(), min_support=1, len_delta=3, origin_policy="authorized", enabled=None):
        self.rel, self.base, self.min_support, self.len_delta, self.origin_policy = asrel, baseline, min_support, len_delta, origin_policy
        self.enabled = set(enabled) if enabled else set(RULES)         # for ablation (evaluate.py); default: all rules
        self.watch = {}
        self.counts = Counter()                     # updates / covered / deferred_origin / no_baseline / candidates
        self.set_watch(whitelist, asns)

    def set_watch(self, whitelist, asns=()):
        """whitelist.json: prefix -> [expected origin ASNs] (same file as the other PoCs); asns: watch ASNs (all prefixes they originate)."""
        w = {}
        for p, o in whitelist.items():
            net = ipaddress.ip_network(p, strict=False); w[str(net)] = (net, {int(x) for x in o})
        for a in asns:
            w[f"AS{int(a)}"] = (None, {int(a)})
        self.watch = w

    def cover(self, net, origin):
        for k, (n, _) in self.watch.items():
            if n is not None and n.version == net.version and net.subnet_of(n):
                return k
        return f"AS{origin}" if f"AS{origin}" in self.watch else None

    def covered(self, msg):
        """[(watch key, prefix, path, announcement)] for every announcement of this UPDATE that falls under the watch list."""
        if msg.get("type") != "UPDATE" or not origin_ok(msg.get("path")):
            return []
        path, out = flat(msg["path"]), []
        for ann in msg.get("announcements") or []:
            for p in ann.get("prefixes", []):
                prefix = norm(p)
                try:
                    net = ipaddress.ip_network(prefix)
                except ValueError:
                    continue
                key = self.cover(net, path[-1])
                if key:
                    out.append((key, prefix, path, ann))
        return out

    def check(self, key, prefix, path):
        """-> ('deferred'|'nobaseline'|'clean'|'candidate', hits). hits: list of dict(rule, detail, **data)."""
        net, exp = self.watch[key]
        if path[-1] not in exp and self.origin_policy == "authorized":
            return "deferred", []
        hits = []
        v = valley(path, self.rel) if "valley_violation" in self.enabled else None
        if v:
            who = f"AS{v['learned_from']}" if v["learned_from"] else "a neighbour"
            hits.append(dict(rule="valley_violation", cause=(v["leaker"], v["exported_to"]), data=v,
                             detail=f"AS{v['leaker']} learned the route from its {v['learned_role']} {who} and announced it to its {v['exported_role']} AS{v['exported_to']} "
                                    f"({v['kind']}): breaks valley-free policy"))
        if self.base.nobs[key] == 0:                            # nothing learned for this object yet: cannot judge links (NFR3: no false alerts without a baseline)
            return ("candidate" if hits else "nobaseline"), hits
        bad = [(a, b, self.base.support(a, b)) for a, b in zip(path, path[1:]) if self.base.support(a, b) < self.min_support]
        if bad and "new_as_link" in self.enabled:
            hits.append(dict(rule="new_as_link", cause=tuple(sorted(edge(a, b) for a, b, _ in bad)), data=bad,
                             detail="; ".join(f"AS{a}-AS{b} " + ("never" if n == 0 else "rarely") + " observed in the baseline" for a, b, n in bad)))
        if len(path) > 1 and "new_origin_upstream" in self.enabled:
            up = path[-2]
            if self.base.upstreams[key].get(up, 0) < self.min_support:
                hits.append(dict(rule="new_origin_upstream", cause=(up, path[-1]), data=up,
                                 detail=f"AS{up} was not seen next to origin AS{path[-1]} for {key} (baseline upstreams: "
                                        + (", ".join(f"AS{a}" for a, _ in self.base.upstreams[key].most_common(4)) or "none") + ")"))
        if not hits:
            return "clean", []
        med = self.base.median_length(key)
        if med is not None and self.base.nobs[key] >= 3 and abs(len(path) - med) >= self.len_delta:
            hits.append(dict(rule="path_length_deviation", cause=(), data=(len(path), med),
                             detail=f"path has {len(path)} ASes, baseline median is {med:g}"))
        return "candidate", hits

    def candidate(self, msg, ann, key, prefix, path, hits):
        net, exp = self.watch[key]
        primary = [h["rule"] for h in hits if RULES[h["rule"]]["role"] == "primary"]
        sub = next(r for r in PRECEDENCE if r in primary)
        main = next(h for h in hits if h["rule"] == sub)
        return dict(ts=float(msg["timestamp"]) if msg.get("timestamp") is not None else time.time(), prefix=prefix,
                    watched=str(net) if net is not None else prefix, key=key, subtype=sub, anomaly_type=anomaly_type(sub), origin=path[-1],
                    expected=sorted(exp), path=path, collector=msg.get("host", ""), peer_asn=str(msg.get("peer_asn", "")), peer_ip=msg.get("peer", ""),
                    next_hop=ann.get("next_hop", ""), origin_attr=msg.get("origin", ""), med=msg.get("med"), community=msg.get("community"),
                    hits=[{k: h[k] for k in ("rule", "detail")} for h in hits], cause=main["cause"],
                    leak=next((h["data"] for h in hits if h["rule"] == "valley_violation"), None))

    def candidates(self, msg):
        """unexpectedOrigin-style API: UPDATE -> list of candidate dicts (stateless, no cooldown; the pipeline caches model calls)."""
        out = []
        if msg.get("type") != "UPDATE":
            return out
        self.counts["updates"] += 1
        for key, prefix, path, ann in self.covered(msg):
            self.counts["covered"] += 1
            state, hits = self.check(key, prefix, path)
            self.counts["deferred_origin" if state == "deferred" else "no_baseline" if state == "nobaseline" else "candidates" if state == "candidate" else "clean"] += 1
            if state == "candidate":
                out.append(self.candidate(msg, ann, key, prefix, path, hits))
        return out
