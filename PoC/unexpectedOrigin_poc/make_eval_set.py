"""Build a labelled evaluation set (SYNTHETIC, labels by construction) from the whitelist + a CAIDA as-rel file.
   python make_eval_set.py --asrel <caida file> --n 12 --out eval_set.jsonl
Case kinds (label = what a human would say about an announcement of the watched prefix by `origin`):
  legit_customer   legit  easy  origin is a direct customer/sibling of the expected origin
  legit_cone2      legit  hard  origin is a customer-of-customer (no direct link; a naive relationship rule flags it)
  hijack_random    hijack easy  origin has no relationship to the expected origin
  hijack_related   hijack hard  origin is a peer/provider of the expected origin (a relationship exists; a naive rule misses it)
Each case is announced either as the exact prefix (Unexpected Origin) or as a more-specific (Unexpected Deaggregation); eval.py reports both separately.
Real incidents: append your own lines in the same format (see README), with "source": "incident"."""
import argparse, ipaddress, json, random
from asrel import ASRel

p = argparse.ArgumentParser()
p.add_argument("--whitelist", default="whitelist.json"); p.add_argument("--asrel", required=True)
p.add_argument("--n", type=int, default=12, help="cases per kind per (prefix, expected origin)")
p.add_argument("--seed", type=int, default=7); p.add_argument("--out", default="eval_set.jsonl")
a = p.parse_args()
rnd = random.Random(a.seed)
wl, ar = json.load(open(a.whitelist, encoding="utf-8")), ASRel(a.asrel)
all_asns = sorted(ar.nbr)
T = 1760000000
rows = []


def msg(ts, path, prefix):
    return {"type": "UPDATE", "timestamp": ts, "host": "rrc00", "peer_asn": str(path[0]),
            "path": path, "announcements": [{"next_hop": "10.0.0.1", "prefixes": [prefix]}]}


def add(kind, label, diff, prefix, exp, origin, mid):
    if origin is None:
        return
    vantage = rnd.choice(all_asns)
    path = [vantage] + ([mid] if mid and mid not in (vantage, origin) else []) + [origin]
    net = ipaddress.ip_network(prefix)
    if rnd.random() < 0.5:
        pfx = prefix                                        # exact prefix -> Unexpected Origin
    else:                                                   # strictly more-specific -> Unexpected Deaggregation
        k = rnd.choice([1, 2])
        pfx = str(rnd.choice(list(net.subnets(prefixlen_diff=min(k, net.max_prefixlen - net.prefixlen)))))
    rows.append({"id": f"{kind}-{len(rows)}", "kind": kind, "label": label, "difficulty": diff, "source": "synthetic",
                 "data": msg(T + len(rows) * 700, path, pfx)})


for prefix, expected in wl.items():
    for e in expected:
        direct = sorted(ar.related(e, {"customer", "sibling"})); cone = sorted(ar.cone2(e))
        peers_prov = sorted(ar.related(e, {"peer", "provider"}))
        unrelated = [x for x in all_asns if x != e and x not in ar.related(e) and x not in cone]
        for _ in range(a.n):
            add("legit_customer", "legit", "easy", prefix, e, rnd.choice(direct) if direct else None, e)
            add("legit_cone2", "legit", "hard", prefix, e, rnd.choice(cone) if cone else None,
                rnd.choice(sorted(ar.related(rnd.choice(cone), {"provider"}))) if cone else None)
            add("hijack_random", "hijack", "easy", prefix, e, rnd.choice(unrelated) if unrelated else None, rnd.choice(all_asns))
            add("hijack_related", "hijack", "hard", prefix, e, rnd.choice(peers_prov) if peers_prov else None, rnd.choice(all_asns))
rnd.shuffle(rows)
with open(a.out, "w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
from collections import Counter
print(len(rows), "cases ->", a.out, dict(Counter(r["kind"] for r in rows)))
