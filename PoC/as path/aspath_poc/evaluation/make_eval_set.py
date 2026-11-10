"""Build the labelled SIMULATED test set for the AS-path PoC: 250 cases of path hijacks, route leaks and normal traffic.
Counterpart of flapping/make_eval_set.py (TEST 1; TEST 2 is live_eval.py).

   python make_eval_set.py                      # writes eval_set.jsonl + eval_as_rel.txt, seed 42
   python make_eval_set.py --seed 7 --out other.jsonl --rel-out other_as_rel.txt

Every case gets its OWN block of ASNs and its own /24, so cases never interact and a FRESH Monitor per case is enough
(no shared state, no ordering effects). eval_as_rel.txt is the CAIDA-format relationship file that all cases' synthetic
AS links are written into (safe because the ASN blocks never overlap).

One line of eval_set.jsonl = one case:
  {"id","kind","label": "path hijack"|"route leak"|"normal","prefix","origin","learn","note","updates":[RIS-Live-shaped dicts]}
learn = learning-window length in seconds. Every update except the LAST is baseline (must be learned, must never raise
an alert); the last one is the message under test (t=65 > learn=50).

THE 250 CASES (70 hijack + 80 leak + 100 normal = 150 anomalous / 100 normal)
  PATH HIJACK (70)
    new_origin_upstream 35   the AS right before the origin is replaced by an attacker
    new_as_link         35   a new link further up the path (attacker prepended / inserted), origin's upstream unchanged
  ROUTE LEAK (80)           RFC 7908 / CAIDA kinds, relationships known
    transit-to-transit 17 | transit-to-peer 17 | peer-to-peer 17 | peer-to-transit 17
    leak_unknown_rel   12    "hard": a leak whose relationships are NOT in the relationship file. The valley rule cannot see
                             it (the paper, App. E.6: incomplete relationship data hides leaks); the new links still make
                             the rules fire, but with the WRONG type (path hijack) -> shows up in type agreement
  NORMAL (100)
    normal_repeat          30   the learned path again
    normal_prepend         15   the learned path with AS-path prepending (must be flattened, not flagged)
    normal_alt_path        15   a second, legitimate, already-learned path (multi-homed) -> clean
    normal_new_peer        25   "hard": a brand-new peering AS prepended to a known path. Legit in real life, but a
                             rules-only detector cannot tell it from new_as_link -> quantifies the honest false-positive rate
    normal_foreign_origin  15   origin outside the whitelist -> deferred to the unexpectedOrigin PoC, correctly not flagged

The seed changes the per-case topology (chain length, which hop is replaced/inserted, prepend counts, collectors), so the
detection counts per kind are the same on every seed but the individual cases differ.
"""
import argparse, json, random
from collections import Counter

LEAK_RELATION = {"transit-to-transit": ("provider", "provider"), "transit-to-peer": ("provider", "peer"),
                 "peer-to-peer": ("peer", "peer"), "peer-to-transit": ("peer", "provider")}
LEARN = 50           # learning window (s): baseline messages at t=0,15,30 (< 50); test message at t=65 (> 50)
HOSTS = ("rrc00", "rrc01", "rrc03", "rrc04")

PLAN = [("new_origin_upstream", 35), ("new_as_link", 35),
        ("transit-to-transit", 17), ("transit-to-peer", 17), ("peer-to-peer", 17), ("peer-to-transit", 17), ("leak_unknown_rel", 12),
        ("normal_repeat", 30), ("normal_prepend", 15), ("normal_alt_path", 15), ("normal_new_peer", 25), ("normal_foreign_origin", 15)]
LABEL = {"new_origin_upstream": "path hijack", "new_as_link": "path hijack", "leak_unknown_rel": "route leak",
         **{k: "route leak" for k in LEAK_RELATION}}


def label_of(kind):
    return LABEL.get(kind, "normal")


def prefix(i):
    return f"10.{60 + i // 250}.{i % 250}.0/24"


def bg_prefix(i):
    return f"172.{16 + i // 250}.{i % 250}.0/24"             # never in the watch list: must be ignored


def msg(t, peer_asn, host, path, pfx):
    return dict(type="ris_message", data=dict(timestamp=round(t, 3), peer=f"192.0.2.{(peer_asn % 250) + 1}", peer_asn=str(peer_asn),
                                               host=host, type="UPDATE", path=path, origin="igp", announcements=[dict(prefixes=[pfx])]))


def make_case(kind, i, rng):
    b = 80000 + i * 16                                         # 16 ASNs per case, blocks never overlap
    O, ATK, EXP, FOREIGN, ALT, NEWPEER = b, b + 1, b + 2, b + 3, b + 4, b + 5
    k = rng.choice((2, 3, 4))                                  # transit chain length between origin and collector peer
    chain = [b + 8 + j for j in range(k)]                      # chain[0] is next to the origin, chain[-1] is the collector's peer
    p, host = prefix(i), rng.choice(HOSTS)
    rel = [f"{chain[0]}|{O}|-1"] + [f"{chain[j + 1]}|{chain[j]}|-1" for j in range(k - 1)]       # each hop is the provider of the one below
    base = list(reversed(chain)) + [O]                         # [peer ... chain[0], origin]
    peer = chain[-1]
    learn_paths = [base, base, base]
    test_path, test_peer, note = base, peer, ""

    if kind == "new_origin_upstream":
        test_path = base[:-2] + [ATK, O]; note = f"AS{ATK} replaces AS{chain[0]} next to the origin"
    elif kind == "new_as_link":
        if k >= 3 and rng.random() < 0.5:                      # inserted in the middle of the chain
            pos = rng.randrange(1, len(base) - 2)
            test_path = base[:pos] + [ATK] + base[pos:]; note = f"AS{ATK} inserted mid-path"
        else:                                                  # prepended: attacker becomes the collector's peer
            test_path, test_peer = [ATK] + base, ATK; note = f"AS{ATK} prepended, new link AS{ATK}-AS{peer}"
    elif kind in LEAK_RELATION:
        learned, exported = LEAK_RELATION[kind]
        U1 = chain[0]
        rel.append(f"{U1}|{ATK}|-1" if learned == "provider" else f"{U1}|{ATK}|0")        # ATK learned the route from U1 as customer->provider / peer
        rel.append(f"{EXP}|{ATK}|-1" if exported == "provider" else f"{ATK}|{EXP}|0")     # ... and exported it to EXP
        test_path, test_peer = [EXP, ATK, U1, O], EXP; note = f"AS{ATK} learned from its {learned}, exported to its {exported}"
    elif kind == "leak_unknown_rel":
        U1 = chain[0]                                          # same shape as a leak, but NO relationship lines for ATK/EXP
        test_path, test_peer = [EXP, ATK, U1, O], EXP; note = "leak shape, relationships missing from the file"
    elif kind == "normal_repeat":
        note = "learned path again"
    elif kind == "normal_prepend":
        test_path = [x for h in base for x in [h] * rng.choice((1, 2, 3))]; note = "AS-path prepending"
    elif kind == "normal_alt_path":
        alt = chain[:]; alt[0] = ALT                           # second upstream of the origin, also learned in the baseline
        rel += [f"{ALT}|{O}|-1"] + ([f"{chain[1]}|{ALT}|-1"] if k > 1 else [])
        alt_path = list(reversed(alt)) + [O]
        learn_paths = [base, alt_path, base]; test_path = alt_path; note = "second learned (multi-homed) path"
    elif kind == "normal_new_peer":
        test_path, test_peer = [NEWPEER] + base, NEWPEER; note = "new peering AS prepended to a known path (hard)"
    elif kind == "normal_foreign_origin":
        test_path = base[:-1] + [FOREIGN]; note = "foreign origin: deferred to unexpectedOrigin"

    updates = [msg(t, peer, host, lp, p) for t, lp in zip((0, 15, 30), learn_paths)]
    updates.append(msg(45, FOREIGN, host, [FOREIGN, ALT], bg_prefix(i)))   # unwatched background route: must be ignored
    updates.append(msg(65, test_peer, host, test_path, p))
    return dict(id=f"case-{i:03d}", kind=kind, label=label_of(kind), prefix=p, origin=O, learn=LEARN, note=note, updates=updates), rel


def build(seed=42):
    rng = random.Random(seed)
    cases, rels, i = [], [], 0
    for kind, n in PLAN:
        for _ in range(n):
            i += 1
            c, rel = make_case(kind, i, rng)
            cases.append(c); rels += rel
    rng.shuffle(cases)                                         # ids stay attached to their ASN blocks; only the order is shuffled
    return cases, rels


def write(cases, rels, out, rel_out):
    with open(out, "w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c) + "\n")
    with open(rel_out, "w", encoding="utf-8") as f:
        f.write("# SYNTHETIC relationships for the simulated AS-path test, CAIDA format as1|as2|rel (-1: as1 is provider of as2, 0: peers)\n")
        for r in sorted(set(rels)):
            f.write(r + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42); ap.add_argument("--out", default="eval_set.jsonl"); ap.add_argument("--rel-out", default="eval_as_rel.txt")
    a = ap.parse_args()
    cases, rels = build(a.seed)
    write(cases, rels, a.out, a.rel_out)
    print(f"{len(cases)} cases -> {a.out}  labels {dict(Counter(c['label'] for c in cases))}")
    print(dict(Counter(c['kind'] for c in cases)))
    print(f"{len(set(rels))} relationship lines -> {a.rel_out}")
