"""candidate -> evidence -> model -> verdict -> correlated incident -> SQLite   (same shape as unexpectedOrigin_poc/pipeline.py)

classify() mirrors unexpectedOrigin's classify(): ownership lines + CAIDA evidence + the same prompt + the same label parser.
Differences, all on purpose: (a) one extra evidence block with baseline facts in the paper's Fig. 4 wording (--no-history-evidence turns it off,
like --no-ownership-evidence there); (b) the type comes from the rule that fired (path_hijack / route_leak), the model label stays advisory;
(c) correlation + recovery, because the proposal asks for one incident per cause (FR11) and for timing/recovery.
"""
import json, sqlite3, threading, time
from prompt import build_messages, flagged, parse_label

COLS = [("first_ts", "REAL"), ("last_ts", "REAL"), ("recovered_ts", "REAL"), ("status", "TEXT"), ("count", "INTEGER"), ("peers_seen", "INTEGER"),
        ("collectors_seen", "INTEGER"), ("paths_seen", "TEXT"), ("affected", "INTEGER"), ("affected_prefixes", "TEXT"), ("occurrence", "INTEGER"),
        ("watched", "TEXT"), ("prefix", "TEXT"), ("origin", "TEXT"), ("expected_origin", "TEXT"), ("peer_asn", "TEXT"), ("collector", "TEXT"),
        ("as_path", "TEXT"), ("expected_path", "TEXT"), ("subtype", "TEXT"), ("anomaly_type", "TEXT"), ("signals", "TEXT"), ("llm_label", "TEXT"),
        ("llm_agrees", "TEXT"), ("llm_ms", "INTEGER"), ("raw_output", "TEXT"), ("model", "TEXT"), ("prompt_style", "TEXT"), ("severity", "TEXT"),
        ("evidence", "TEXT"), ("source", "TEXT")]
UPD = ("last_ts", "recovered_ts", "status", "count", "peers_seen", "collectors_seen", "paths_seen", "affected", "affected_prefixes", "llm_label", "llm_agrees")


class Store:
    def __init__(self, db="aspath.db"):
        self.con, self.lock = sqlite3.connect(db, check_same_thread=False), threading.Lock()
        self.con.execute("CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, " + ", ".join(f"{n} {t}" for n, t in COLS) + ")")
        have = {r[1] for r in self.con.execute("PRAGMA table_info(incidents)")}
        for n, t in COLS:                                      # migrate databases made by older versions
            if n not in have:
                self.con.execute(f"ALTER TABLE incidents ADD COLUMN {n} {t}")
        self.con.commit()

    def add(self, a):
        with self.lock:
            cur = self.con.execute(f"INSERT INTO incidents({','.join(n for n, _ in COLS)}) VALUES({','.join('?' * len(COLS))})", [a.get(n) for n, _ in COLS])
            self.con.commit()
            return cur.lastrowid

    def save(self, i, a):
        with self.lock:
            self.con.execute(f"UPDATE incidents SET {','.join(k + '=?' for k in UPD)} WHERE id=?", [a.get(k) for k in UPD] + [i])
            self.con.commit()


# ---------------------------------------------------------------------------------------------------- evidence
def severity(label, llm_used=True):
    """unexpectedOrigin's rule: the rule candidate IS the alert; the model only says how strongly it is corroborated.
    any anomaly label -> high; none (model disagrees) or unreadable/unknown -> medium. Without a model (rules only) -> medium."""
    if not llm_used:
        return "medium"
    return "medium" if label in ("none", "unparsed", "unknown") else "high"


def agreement(label, atype):
    """Does the model's label match the type the rule assigned? (for the dashboard and RQ-style analysis; it never changes the alert)"""
    if label is None:
        return "no model"
    if label in ("none",):
        return "model: none"
    if not flagged(label):
        return "model: unclear"
    return "yes" if label.replace(" ", "_") == atype else f"type differs ({label})"


def ownership_lines(c):
    """Operator-whitelist statements (NOT RPKI/IRR), worded as in unexpectedOrigin; for a path anomaly the origin is authorised."""
    exp = ", ".join(f"AS{e}" for e in c["expected"])
    out = [f"{c['watched']} is originated by {exp} (the expected origin configured by the network operator)."]
    if c["origin"] in c["expected"]:
        out.append(f"AS{c['origin']} is an authorized origin for {c['watched']}.")
    elif c["prefix"] != c["watched"]:
        out.append(f"AS{c['origin']} announced {c['prefix']}, a more-specific prefix of {c['watched']}, but AS{c['origin']} is not an authorized origin for {c['watched']}.")
    else:
        out.append(f"AS{c['origin']} is not an authorized origin for {c['watched']}.")
    return out


def history_lines(c, base, k=6):
    """Baseline facts in the wording of the paper's Fig. 4 time-aware evidence block ('observed before' / 'never observed before event time')."""
    key, out = c["key"], []
    out.append(f"AS{c['origin']} was observed as an origin of {c['watched']} before the event time.")
    if base.nobs[key]:
        out.append(f"The usual path for {c['watched']} before the event time was: {base.typical_path(key)}.")
        links = []
        for a, b in zip(c["path"], c["path"][1:]):
            n = base.support(a, b)
            links.append((n >= 2, f"AS{a}-AS{b} " + ("was never observed before event time." if n == 0 else "was rarely observed before event time." if n == 1 else "was observed before.")))
        out += [s for _, s in sorted(links, key=lambda t: t[0])][:k]                # unusual links first
    if c.get("leak"):
        v = c["leak"]
        out.append(f"AS{v['leaker']} announced a route learned from its {v['learned_role']} to its {v['exported_role']} AS{v['exported_to']}, which violates valley-free routing ({v['kind']}).")
    return out


def facts_for(c, asrel, base, k=8):
    """Structured facts for the optional 'paper' / 'infer' prompt styles."""
    links = [(a, b, base.support(a, b)) for a, b in zip(c["path"], c["path"][1:])][:k]
    rels, seen = [], set()
    for a, b in [(c["origin"], e) for e in c["expected"] if e != c["origin"]] + list(zip(c["path"], c["path"][1:])):
        t = asrel.code(a, b)
        if t and frozenset((a, b)) not in seen:
            rels.append(t); seen.add(frozenset((a, b)))
    return dict(watched=c["watched"], expected=c["expected"], origin=c["origin"], links=links, rels=rels[:k])


def evidence_lines(c, asrel, base, top_k=8, ownership=True, history=True):
    ev = asrel.evidence(c["path"], c["origin"], c["expected"], top_k)
    if history:
        ev = history_lines(c, base) + ev
    if ownership:
        ev = ownership_lines(c) + ev
    return ev


def classify(cand, asrel, llm, base, top_k=8, ownership=True, history=True, style="repo", use_evidence=True):
    ev = evidence_lines(cand, asrel, base, top_k, ownership, history)
    t = time.time()
    try:
        raw = llm.generate(build_messages(cand, ev if use_evidence else None, style, facts_for(cand, asrel, base, top_k)))
    except Exception as e:                                        # a model failure must not stop the monitor (NFR3)
        raw = f"ERROR: {type(e).__name__}: {e}"
    label = parse_label(raw)
    return dict(label=label, raw_output=raw, severity=severity(label), evidence=ev, ms=int((time.time() - t) * 1000), model=getattr(llm, "name", None),
                agrees=agreement(label, cand["anomaly_type"]))


def rules_only(cand, asrel, base, top_k=8, ownership=True, history=True):
    return dict(label=None, raw_output=None, severity=severity(None, False), evidence=evidence_lines(cand, asrel, base, top_k, ownership, history), ms=None,
                model=None, agrees="no model")


# ---------------------------------------------------------------------------------------------------- correlation
class Correlator:
    """One incident per cause (FR11). Cause = rule + the offending links / leaker. A prefix watch groups per prefix; an ASN watch consolidates
    every prefix of that ASN with the same cause. An incident recovers when every (peer, prefix) that showed it announces a normal route or withdraws it."""

    def __init__(self, store=None, source="online", style="repo"):
        self.store, self.source, self.style = store, source, style
        self.open, self.seen, self.recovered = {}, {}, []

    def ik(self, c):
        return (c["key"], "*" if c["key"].startswith("AS") else c["prefix"], c["subtype"], tuple(map(str, c["cause"])))

    def is_open(self, c):
        return self.ik(c) in self.open

    def add(self, c, res, now, expected_path=""):
        k, peer, host, p = self.ik(c), c["peer_asn"], c["collector"], " ".join(map(str, c["path"]))
        if k in self.open:
            i, inc = self.open[k]
            inc["count"] += 1; inc["last_ts"] = now
            inc["_open"].add((peer, c["prefix"])); inc["_peers"].add(peer); inc["_cols"].add(host); inc["_paths"].add(p); inc["_aff"].add(c["prefix"])
            inc.update(peers_seen=len(inc["_peers"]), collectors_seen=len(inc["_cols"]), paths_seen=" ; ".join(sorted(inc["_paths"])[:10]),
                       affected=len(inc["_aff"]), affected_prefixes=", ".join(sorted(inc["_aff"])[:20]))
            if self.store:
                self.store.save(i, inc)
            return inc
        self.seen[k] = self.seen.get(k, 0) + 1
        inc = dict(first_ts=now, last_ts=now, recovered_ts=None, status="active", count=1, peers_seen=1, collectors_seen=1, paths_seen=p, affected=1,
                   affected_prefixes=c["prefix"], occurrence=self.seen[k], watched=c["watched"], prefix=c["prefix"], origin=str(c["origin"]),
                   expected_origin=",".join(f"AS{o}" for o in c["expected"]), peer_asn=peer, collector=host, as_path=p, expected_path=expected_path,
                   subtype=c["subtype"], anomaly_type=c["anomaly_type"], signals="; ".join(f"{h['rule']}: {h['detail']}" for h in c["hits"]),
                   llm_label=res["label"], llm_agrees=res["agrees"], llm_ms=res["ms"], raw_output=res["raw_output"], model=res["model"],
                   prompt_style=self.style if res["model"] else None, severity=res["severity"], evidence=" | ".join(res["evidence"]), source=self.source,
                   _open={(peer, c["prefix"])}, _peers={peer}, _cols={host}, _paths={p}, _aff={c["prefix"]})
        self.open[k] = (self.store.add(inc) if self.store else 0, inc)
        return inc

    def recover(self, prefix, peer, now):
        for k, (i, inc) in list(self.open.items()):
            if (peer, prefix) in inc["_open"]:
                inc["_open"].discard((peer, prefix))
                if not inc["_open"]:
                    inc.update(status="recovered", recovered_ts=now)
                    if self.store:
                        self.store.save(i, inc)
                    self.recovered.append(inc); del self.open[k]

    def drain(self):
        r, self.recovered = self.recovered, []
        return r
