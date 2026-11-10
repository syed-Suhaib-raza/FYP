"""Baseline from routing HISTORY (RIPEstat bgp-state snapshots) instead of a live learning window.

Why: a learning window learns whatever happens in its first minutes, attack included. History is sampled from the past, so an attacker
active NOW cannot write into it.  Remaining weakness (cannot be removed by any baseline): an attack that was live in the past is in the history.
Defence = persistence rules.  A link is ESTABLISHED only if it was seen in >= min_snapshots snapshots, from >= min_peers different RIS peers,
and those snapshots span >= min_span_days.  A hijack of minutes/hours cannot do that; one that lasted weeks and was seen by many peers can.
Anything seen but not established stays in the baseline with count 1 ("rarely observed"), so the model still gets that evidence.

Data call: https://stat.ripe.net/data/bgp-state/data.json?resource=<prefix|ASn>&timestamp=<unix|ISO>
  data.bgp_state = [{target_prefix, path:[peer ... origin], community, source_id:"<rrc>-<peer ip>"}]
Mapping into detector.Baseline (so detector.py needs almost no change; run with --min-support 2):
  established link/upstream -> count = number of snapshots (>=2);  seen but not established -> 1;  never seen -> 0 (absent).
"""
import ipaddress, json, os, time, urllib.parse, urllib.request
from collections import Counter, defaultdict

from detector import edge, flat

API = "https://stat.ripe.net/data/bgp-state/data.json"
DIR = os.path.join("data", "history")


def sample_times(now, days=60, n=12, embargo_days=3):
    """n unix times spread evenly over [now-days, now-embargo]. The embargo keeps the most recent days out, so a fresh attack is not in the baseline."""
    now = now - now % 86400                                  # snap to midnight UTC: same timestamps all day, so the disk cache is reused between runs
    start, end = now - days * 86400, now - embargo_days * 86400
    return [int(end)] if n <= 1 else [int(start + i * (end - start) / (n - 1)) for i in range(n)]


RRCS = None                  # optional "0,1,3": ask only these RIS collectors (much smaller answers for an ASN watch); set by aspath.py --history-rrcs
TIMEOUT = 120                # seconds per request; an ASN answer can be big
LAST_ERROR = ""


def _http(resource, ts, retries=1):
    global LAST_ERROR
    q = {"resource": resource, "timestamp": ts}
    if RRCS:
        q["rrcs"] = RRCS
    url = f"{API}?{urllib.parse.urlencode(q)}"
    for i in range(retries + 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "fyp-aspath-poc"}), timeout=TIMEOUT) as r:
                d = json.load(r)
            if d.get("status") == "ok":
                return d["data"]
            LAST_ERROR = f"status={d.get('status')} messages={d.get('messages')}"
        except Exception as e:
            LAST_ERROR = f"{type(e).__name__}: {e}"
        time.sleep(1.5 * (i + 1))
    return None


def fetch(resource, ts, folder=DIR, get=None, pause=0.3):
    """One snapshot, cached on disk (re-runs do not hit the API again). None if the API could not be reached."""
    os.makedirs(folder, exist_ok=True)
    f = os.path.join(folder, f"{resource.replace('/', '_').replace(':', '-')}{'_rrc' + RRCS.replace(',', '-') if RRCS else ''}_{ts}.json")
    if os.path.exists(f):
        try:
            return json.load(open(f))
        except ValueError:
            pass
    data = (get or _http)(resource, ts)
    if data is None:
        return None
    for r in data.get("bgp_state") or []:
        r.pop("community", None)                              # not used; keeps cache files about 40% smaller
    json.dump(data, open(f, "w"))
    if get is None:
        time.sleep(pause)                                    # be polite to the public API
    return data


class _Stat:
    def __init__(self):
        self.snaps, self.peers, self.first_only = set(), set(), True

    def add(self, ts, peer, first=False):
        self.snaps.add(ts); self.peers.add(peer); self.first_only &= first

    def established(self, k, m, span_s):
        # the link between a RIS peer and its neighbour (first hop) can only ever be seen by that one peer, so it needs 1 peer, not m
        return len(self.snaps) >= k and len(self.peers) >= (1 if self.first_only else m) and (max(self.snaps) - min(self.snaps)) >= span_s


def fill(base, watch, now=None, days=60, n=12, embargo_days=3, min_snapshots=3, min_peers=3, min_span_days=10, folder=DIR, get=None, log=print):
    """Fill `base` (detector.Baseline) from history for every object in `watch` ({key: (net|None, {expected origins})}).
    Returns the number of snapshot answers used (0 = API unreachable / nothing usable: caller should fall back to a live learning window)."""
    now = now or time.time()
    times, span_s = sample_times(now, days, n, embargo_days), min_span_days * 86400
    links, ups, routes, used = defaultdict(_Stat), defaultdict(_Stat), {}, 0
    fails, step, total = 0, 0, len(times) * len(watch)
    for key, (net, exp) in watch.items():
        resource, rfails, rused, ops = (str(net) if net is not None else key), 0, 0, []
        for ts in times:
            step += 1
            if rfails >= 3:                                  # 3 failures in a row for this resource: skip its remaining snapshots instead of waiting for each
                continue
            data = fetch(resource, ts, folder, get)
            if data is None:
                rfails += 1; fails += 1
                log(f"history [{step}/{total}] {resource} {time.strftime('%Y-%m-%d', time.gmtime(ts))}: no answer ({LAST_ERROR or 'unknown'})")
                if rfails == 3:
                    log(f"history: giving up on {resource}. If it is an ASN, try --history-rrcs 0,1,3 (fewer collectors, smaller answer) or watch its prefixes instead.")
                continue
            rfails = 0; rused += 1
            log(f"history [{step}/{total}] {resource} {time.strftime('%Y-%m-%d', time.gmtime(ts))}: {len(data.get('bgp_state') or [])} routes")
            for r in data.get("bgp_state") or []:
                try:
                    path, peer = flat(r.get("path")), r.get("source_id", "")
                    if not path or path[-1] not in exp:     # authorised origin only: foreign-origin routes are the unexpectedOrigin PoC's topic
                        continue
                    if net is not None and not ipaddress.ip_network(r["target_prefix"], strict=False).subnet_of(net):
                        continue
                except (ValueError, TypeError, KeyError):
                    continue
                ops.append((key, ts, peer, path))
        if rused and rused < min_snapshots:                  # too little history for this object: judging its links from 1-2 snapshots would make normal links look rare
            log(f"history: {resource} has only {rused} usable snapshot(s) (< {min_snapshots}); ignoring it, so no link alerts for it (the leak rule still works)")
            continue
        used += rused
        for key, ts, peer, path in ops:
            for i, (a, b) in enumerate(zip(path, path[1:])):
                links[edge(a, b)].add(ts, peer, i == 0)
            if len(path) > 1:
                ups[(key, path[-2])].add(ts, peer)
            routes[(key, ts, peer, tuple(path))] = None
    if not used:
        log("history: RIPEstat gave no usable snapshots (offline or blocked?)")
        return 0
    ok = {e for e, s in links.items() if s.established(min_snapshots, min_peers, span_s)}
    for e, s in links.items():
        base.edges[e] += max(len(s.snaps), 2) if e in ok else 1
    for (key, up), s in ups.items():
        base.upstreams[key][up] += max(len(s.snaps), 2) if s.established(min_snapshots, min_peers, span_s) else 1
    for (key, ts, peer, path) in routes:                      # typical path / median length only from routes whose every link is established
        if all(edge(a, b) in ok for a, b in zip(path, path[1:])):
            base.lengths[key].append(len(path)); base.paths[key][" ".join(map(str, path))] += 1; base.nobs[key] += 1
    base.meta = dict(source="history", built=int(time.time()), window_from=times[0], window_to=times[-1], snapshots=used, planned=len(times) * len(watch),
                     watch=sorted(watch), links_seen=len(links), links_established=len(ok), min_snapshots=min_snapshots, min_peers=min_peers, min_span_days=min_span_days)
    log(f"history baseline: {used}/{len(times) * len(watch)} snapshots, {len(links)} links seen, {len(ok)} established "
        f"(>= {min_snapshots} snapshots, >= {min_peers} peers, >= {min_span_days} days apart)")
    return used


def rarest(base, k=15):
    """Links seen in history but NOT established: the ones to look at first (they are exactly where a past attack would sit)."""
    return sorted(((a, b, n) for (a, b), n in base.edges.items() if n < 2), key=lambda t: t[2])[:k]