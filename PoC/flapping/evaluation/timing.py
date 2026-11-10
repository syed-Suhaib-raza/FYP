"""Shared pieces for the accuracy / latency tests (eval.py, live_eval.py). Does NOT modify flap.py.

TimedDetector  = your FlapDetector + two extra numbers on every alert (added after the alert is stored, so your
                 alerts table / flap.db schema is untouched):
                   first_ts          when the first withdrawal / path change of this flap run happened (stream time)
                   events_to_detect  how many withdrawals + path changes it took before the alert fired
oracle()       = the GROUND-TRUTH rule used to score the detector. It is deliberately NOT the penalty model, so the
                 detector is not marked against itself:
                   a route is FLAPPING if it has >= 4 changes within 15 minutes, or >= 5 changes within 90 minutes
                   (change = withdrawal of a route we saw announced, or its AS path replaced while it is up)
                   changes caused by a peer-session reset (from state=down until 60 s after state=up) are not counted
                 This definition is OUR assumption (operators have no single standard); see README_EVAL.md.
"""
from collections import defaultdict
from flap import FlapDetector, norm

WIN_SHORT, N_SHORT = 900, 4          # >= 4 changes in 15 min
WIN_LONG, N_LONG = 5400, 5           # >= 5 changes in 90 min
RESET_GRACE = 60                     # seconds after a session comes back that still count as the reset


class TimedDetector(FlapDetector):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.first, self.nch = {}, {}

    def _charge(self, key, peer_asn, now, amount):
        r = self.routes[key]
        self._decay(r, now)
        if key not in self.first or (r.penalty < self.reuse / 2 and key not in self.active):   # a new flap run starts
            self.first[key], self.nch[key] = now, 0
        self.nch[key] += 1
        return super()._charge(key, peer_asn, now, amount)

    def _emit(self, event, key, r, ts, reason=""):
        a = super()._emit(event, key, r, ts, reason)
        a["first_ts"], a["events_to_detect"], a["key"] = self.first.get(key), self.nch.get(key), key
        return a


def changes(updates):
    """-> {(prefix, host, peer): [change timestamps]} using the same notion of 'change' as the detector,
    but ignoring everything a peer-session reset causes."""
    known, up, path = {}, {}, {}
    reset_until = {}                  # (host, peer) -> time until which updates are reset noise (inf while down)
    out = defaultdict(list)
    for m in sorted(updates, key=lambda m: m.get("timestamp", 0)):
        host, peer = m.get("host", ""), str(m.get("peer") or m.get("peer_asn", ""))
        t = float(m.get("timestamp", 0))
        sess = (host, peer)
        if m.get("type") == "RIS_PEER_STATE":
            if m.get("state") == "down":
                reset_until[sess] = float("inf")
                for k in [k for k in known if k[1:] == sess]:
                    del known[k]
            else:
                reset_until[sess] = t + RESET_GRACE
            continue
        if m.get("type") != "UPDATE":
            continue
        resetting = t <= reset_until.get(sess, -1)
        for p in map(norm, m.get("withdrawals") or []):
            k = (p, host, peer)
            if k in known and up.get(k) and not resetting:
                up[k] = False
                out[k].append(t)
        pt = tuple(tuple(h) if isinstance(h, list) else h for h in m.get("path") or [])
        for a in m.get("announcements") or []:
            for p in map(norm, a.get("prefixes", [])):
                k = (p, host, peer)
                if k not in known:
                    known[k], up[k], path[k] = True, True, pt
                    continue
                was_up, changed = up.get(k), path.get(k) != pt
                up[k], path[k] = True, pt
                if was_up and changed and not resetting:
                    out[k].append(t)
    return out


def qualifies(ts):
    """-> time at which the ground-truth rule is first satisfied, or None."""
    ts = sorted(ts)
    best = None
    for i in range(len(ts)):
        if i + N_SHORT - 1 < len(ts) and ts[i + N_SHORT - 1] - ts[i] <= WIN_SHORT:
            best = ts[i + N_SHORT - 1] if best is None else min(best, ts[i + N_SHORT - 1])
        if i + N_LONG - 1 < len(ts) and ts[i + N_LONG - 1] - ts[i] <= WIN_LONG:
            best = ts[i + N_LONG - 1] if best is None else min(best, ts[i + N_LONG - 1])
    return best


def oracle(updates):
    """-> {key: time the ground-truth rule is first satisfied} for every flapping route."""
    return {k: q for k, ts in changes(updates).items() if (q := qualifies(ts)) is not None}


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    i = (len(xs) - 1) * p / 100
    lo, hi = int(i), min(int(i) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (i - lo)
