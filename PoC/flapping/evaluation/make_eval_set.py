"""Build the labelled SIMULATED test set: 250 cases (125 flapping, 125 normal), seeded and reproducible.
   python make_eval_set.py                      # writes eval_set.jsonl (seed 42)
   python make_eval_set.py --seed 7 --out other_set.jsonl

Each line = one case: {"id","kind","difficulty","label": "flap"|"normal","t0","updates":[RIS-Live-shaped dicts]}
  t0 = time of the first withdrawal / path change of the flapping episode (None for normal cases); detection
       latency is measured from t0.
The label follows the independent ground-truth rule in timing.py (>=4 changes in 15 min or >=5 in 90 min,
session-reset noise excluded). test_eval.py checks that every case's label agrees with that rule.
Kinds (count):
 FLAPPING 125  classic 35 | path_flap 18 | mixed 12 | fast_burst 10 | multi_peer 15 | slow 15 (hard) |
               borderline_flap 10 (hard) | path_four 10 (hard: 4 path changes in <=13 min)
 NORMAL   125  stable 20 | single_flap 20 | beacon 15 | maintenance 10 | session_reset 15 | isolated_changes 10 |
               spaced_flaps 10 (hard) | double_flap 10 (hard) | three_changes 5 (hard) | three_withdrawals 10 (hard: 3 fast withdrawals)
"hard" includes the DEFINITION-BOUNDARY cases (path_four, three_withdrawals, three_changes): the ground-truth rule and the
detector's penalty model legitimately disagree there, so errors on them say "different definitions", not "bug".
Every case also carries 2-5 unrelated background routes with ordinary churn.
"""
import argparse, json, random

BASE = 1760000000
HOST = "rrc00"


class Builder:
    def __init__(self, rng, idx):
        self.rng, self.idx, self.msgs, self.n_prefix = rng, idx, [], 0

    def prefix(self):
        self.n_prefix += 1
        return f"10.{self.idx // 250 + 1}.{(self.idx * 3 + self.n_prefix) % 250}.0/24"

    @staticmethod
    def peer(k):
        return 64500 + k, f"192.0.2.{10 + k}"

    def ann(self, t, k, prefix, path):
        asn, ip = self.peer(k)
        self.msgs.append({"timestamp": round(t, 3), "peer": ip, "peer_asn": str(asn), "host": HOST, "type": "UPDATE",
                          "path": path, "announcements": [{"prefixes": [prefix]}]})

    def wd(self, t, k, prefix):
        asn, ip = self.peer(k)
        self.msgs.append({"timestamp": round(t, 3), "peer": ip, "peer_asn": str(asn), "host": HOST, "type": "UPDATE",
                          "withdrawals": [prefix]})

    def state(self, t, k, st):
        asn, ip = self.peer(k)
        self.msgs.append({"timestamp": round(t, 3), "peer": ip, "peer_asn": str(asn), "host": HOST,
                          "type": "RIS_PEER_STATE", "state": st})

    def paths(self, k):
        asn, _ = self.peer(k)
        o = 65000 + self.idx % 90
        return [asn, 3356, o], [asn, 1299, o], [asn, 174, o]          # base, alt A, alt B


def cycle_flaps(b, k, prefix, n, period, t, down=(0.25, 0.6)):
    """n withdraw/restore cycles; returns time of first withdrawal."""
    base = b.paths(k)[0]
    first = t
    for _ in range(n):
        b.wd(t, k, prefix)
        b.ann(t + period * b.rng.uniform(*down), k, prefix, base)
        t += period * b.rng.uniform(0.9, 1.1)
    return first


def make_case(kind, idx, rng):
    b = Builder(rng, idx)
    p, base0 = b.prefix(), None
    k = 0
    start = rng.uniform(60, 300)
    path0 = b.paths(0)[0]
    b.ann(0, 0, p, path0)                                   # baseline: the route exists before anything happens
    label, t0, diff = "normal", None, "easy"
    if kind == "classic":
        t0 = cycle_flaps(b, 0, p, rng.randint(4, 8), rng.uniform(30, 150), start); label = "flap"
    elif kind == "fast_burst":
        t0 = cycle_flaps(b, 0, p, rng.randint(4, 5), rng.uniform(20, 30), start); label = "flap"
    elif kind == "slow":
        t0 = cycle_flaps(b, 0, p, rng.randint(5, 8), rng.uniform(360, 600), start, down=(0.1, 0.3)); label = "flap"; diff = "hard"
    elif kind == "borderline_flap":
        t0 = cycle_flaps(b, 0, p, 4, rng.uniform(240, 270), start); label = "flap"; diff = "hard"
    elif kind == "path_flap":
        _, a, c = b.paths(0)
        t, t0 = start, start
        for i in range(rng.randint(6, 12)):
            b.ann(t, 0, p, [a, c][i % 2]); t += rng.uniform(10, 60)
        label = "flap"
    elif kind == "mixed":
        base, a, c = b.paths(0)
        t, t0, cur = start, start, base
        for i in range(rng.randint(5, 8)):
            if i % 2 == 0:
                b.wd(t, 0, p); b.ann(t + rng.uniform(15, 40), 0, p, cur)
            else:
                cur = a if cur != a else c
                b.ann(t, 0, p, cur)
            t += rng.uniform(40, 90)
        label = "flap"
    elif kind == "multi_peer":
        t0 = None
        for pk in range(1, rng.randint(2, 3) + 1):
            if pk > 0:
                b.ann(0, pk, p, b.paths(pk)[0])
            f = cycle_flaps(b, pk, p, rng.randint(4, 6), rng.uniform(40, 120), start + rng.uniform(0, 60))
            t0 = f if t0 is None else min(t0, f)
        label = "flap"
    elif kind == "path_four":                               # 4 path changes in <=13 min: flap by count; a path change only
        _, a, c = b.paths(0)                                # costs 500 in the penalty model, so decay can keep it below 2000
        t, t0 = start, start
        for i in range(4):
            b.ann(t, 0, p, [a, c][i % 2]); t += rng.uniform(150, 260)
        label = "flap"; diff = "hard"
    elif kind == "three_withdrawals":                       # 3 fast withdrawals: 3 changes (< 4) by count, but the penalty
        t = start                                           # model adds 1000 each and fires on the 3rd
        for i in range(3):
            b.wd(t, 0, p); b.ann(t + rng.uniform(30, 60), 0, p, path0); t += rng.uniform(120, 200)
        diff = "hard"
    elif kind == "stable":
        t = rng.uniform(300, 1800)
        for _ in range(rng.randint(0, 3)):
            b.ann(t, 0, p, path0); t += rng.uniform(300, 1800)
    elif kind == "single_flap":
        b.wd(start, 0, p); b.ann(start + rng.uniform(60, 1800), 0, p, path0)
    elif kind == "double_flap":
        t = start
        b.wd(t, 0, p); b.ann(t + rng.uniform(30, 90), 0, p, path0)
        t += rng.uniform(150, 300)
        b.wd(t, 0, p); b.ann(t + rng.uniform(30, 90), 0, p, path0); diff = "hard"
    elif kind == "three_changes":                           # 3 changes in <10 min: under the ground-truth rule (needs 4)
        base, a, c = b.paths(0)
        t = start
        b.wd(t, 0, p); b.ann(t + 60, 0, p, base)
        t += rng.uniform(120, 200); b.ann(t, 0, p, a)
        t += rng.uniform(90, 180); b.ann(t, 0, p, c); diff = "hard"
    elif kind == "isolated_changes":
        _, a, c = b.paths(0)
        t, cur = start, 0
        for i in range(rng.randint(3, 5)):
            b.ann(t, 0, p, [a, c][i % 2]); t += rng.uniform(2700, 5400)
    elif kind == "beacon":                                  # RIPE-beacon style: scheduled withdraw / announce
        period, t = rng.uniform(7200, 14400), start
        for _ in range(rng.randint(3, 6)):
            b.wd(t, 0, p); b.ann(t + period / 2, 0, p, path0); t += period
    elif kind == "maintenance":
        b.wd(start, 0, p); b.ann(start + rng.uniform(1800, 7200), 0, p, path0)
    elif kind == "spaced_flaps":
        t = start
        for _ in range(rng.randint(4, 5)):
            b.wd(t, 0, p); b.ann(t + rng.uniform(120, 300), 0, p, path0); t += rng.uniform(2400, 4200)
        diff = "hard"
    elif kind == "session_reset":                           # the peer session bounces; some collectors then report
        prefixes = [p] + [b.prefix() for _ in range(rng.randint(3, 7))]   # the withdrawals: NOT route flaps
        for q in prefixes[1:]:
            b.ann(0, 0, q, path0)
        t = start
        for _ in range(3):
            b.state(t, 0, "down")
            for j, q in enumerate(prefixes):
                b.wd(t + 1 + 0.2 * j, 0, q)
            b.state(t + 20, 0, "up")
            for j, q in enumerate(prefixes):
                b.ann(t + 25 + 0.2 * j, 0, q, path0)
            t += rng.uniform(120, 240)
    else:
        raise ValueError(kind)
    for _ in range(rng.randint(2, 5)):                      # unrelated background routes with ordinary churn
        q = b.prefix()
        b.ann(0, 0, q, path0)
        if rng.random() < 0.5:
            tq = rng.uniform(100, 3000); b.wd(tq, 0, q); b.ann(tq + rng.uniform(30, 600), 0, q, path0)
    b.msgs.sort(key=lambda m: m["timestamp"])
    return {"kind": kind, "difficulty": diff, "label": label, "t0": None if t0 is None else round(t0, 3),
            "updates": b.msgs}


PLAN = [("classic", 35), ("path_flap", 18), ("mixed", 12), ("fast_burst", 10), ("multi_peer", 15), ("slow", 15),
        ("borderline_flap", 10), ("path_four", 10), ("stable", 20), ("single_flap", 20), ("beacon", 15),
        ("maintenance", 10), ("session_reset", 15), ("isolated_changes", 10), ("spaced_flaps", 10),
        ("double_flap", 10), ("three_changes", 5), ("three_withdrawals", 10)]


def build(seed=42):
    rng = random.Random(seed)
    cases, i = [], 0
    for kind, n in PLAN:
        for _ in range(n):
            i += 1
            c = make_case(kind, i, rng)
            cases.append({"id": f"case-{i:03d}", **c})
    rng.shuffle(cases)                                      # no order effects; ids stay with their case
    return cases


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--seed", type=int, default=42); ap.add_argument("--out", default="eval_set.jsonl")
    a = ap.parse_args()
    cases = build(a.seed)
    with open(a.out, "w") as f:
        for c in cases:
            f.write(json.dumps(c) + "\n")
    from collections import Counter
    print(f"{len(cases)} cases -> {a.out}  labels {dict(Counter(c['label'] for c in cases))}")
    print(dict(Counter(c['kind'] for c in cases)))
