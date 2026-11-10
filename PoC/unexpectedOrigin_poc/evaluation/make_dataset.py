"""Build the labelled Unexpected-Origin evaluation stream (SYNTHETIC; labels are true by construction).

    python evaluation/make_dataset.py        # -> evaluation/labelled_updates.jsonl (~200), eval_whitelist.json, eval_asrel.txt

Every line is a RIS-Live message plus a `truth` block the PoC never sees:
    {"type": "ris_message", "data": {...UPDATE...},
     "truth": {"label": "benign"|"anomalous", "type": "none"|"unexpected_origin"|"unexpected_deaggregation"|"path_hijack"|"route_leak",
               "scenario": "...", "category": "...", "difficulty": "easy"|"hard", "in_scope": true|false, "note": "..."}}

`label` is about the announcement itself: is this update an illegitimate origination of (part of) a watched prefix?
`type` is what the PoC should call it: exact watched prefix -> unexpected_origin, strictly more-specific ->
unexpected_deaggregation. `in_scope=false` marks anomalies an origin check cannot see by design (forged-origin path
hijack, route leak with the correct origin); they are reported separately, not in the headline metrics.

Legitimacy follows the convention of make_eval_set.py: a direct customer or sibling of the expected origin, or a
customer-of-customer, may originate the space (hard case for the last one); a peer/provider or an unrelated AS may not.
The AS relationships that make those labels true are written to evaluation/eval_asrel.txt (CAIDA format) and the model
gets its evidence from that file. ASNs/prefixes are placeholders; the roles given to them are fictional.
"""
import argparse, ipaddress, json, os, random

HERE = os.path.dirname(os.path.abspath(__file__))
T0 = 1762000000
SPAN = 3 * 3600                         # BGP-time span of the stream
PEERS = [3333, 2914, 6939, 1299, 174, 3356, 6453, 6762, 7018, 37100]
HOSTS = [f"rrc{i:02d}" for i in (0, 1, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 19, 20, 21, 22, 23, 24, 25, 26)]

WHITELIST = {"1.1.1.0/24": [13335], "8.8.8.0/24": [15169], "66.167.90.0/24": [3257],
             "104.16.0.0/22": [13335, 209242], "45.223.8.0/22": [9541]}

# provider|customer|-1, peer|peer|0, sibling|sibling|1  (synthetic world used for the labels)
ASREL = """# SYNTHETIC CAIDA-format relationships for the evaluation stream (evaluation/make_dataset.py)
13335|23001|-1
13335|23002|-1
13335|209242|1
23001|23101|-1
174|13335|0
1299|13335|0
3356|13335|-1
15169|26910|-1
15169|36040|1
26910|26911|-1
3356|15169|0
6939|15169|0
3257|31042|-1
3257|29226|-1
31042|31500|-1
1299|3257|0
174|3257|-1
3491|9541|-1
6453|9541|-1
9541|135520|-1
9541|136525|-1
135520|138000|-1
9541|17557|0
3333|1299|-1
2914|1299|0
6939|1299|0
174|2914|0
3356|174|0
6453|3356|0
6762|3356|0
7018|174|0
37100|6453|-1
"""

LEGIT = {  # watched prefix -> [(origin, path tail before origin, category, difficulty, more_specific?)]
    "1.1.1.0/24": [(23001, [13335], "legit_customer", "easy"), (209242, [], "legit_sibling", "easy"),
                   (23101, [13335, 23001], "legit_customer_of_customer", "hard")],
    "8.8.8.0/24": [(36040, [], "legit_sibling", "easy"), (26910, [15169], "legit_customer", "easy"),
                   (26911, [15169, 26910], "legit_customer_of_customer", "hard")],
    "66.167.90.0/24": [(31042, [3257], "legit_customer", "easy"), (31500, [3257, 31042], "legit_customer_of_customer", "hard")],
    "104.16.0.0/22": [(23002, [13335], "legit_customer", "easy")],
    "45.223.8.0/22": [(135520, [9541], "legit_customer", "easy"), (136525, [9541], "legit_customer", "easy"),
                      (138000, [9541, 135520], "legit_customer_of_customer", "hard")],
}
RELATED_BAD = {"1.1.1.0/24": [174, 1299, 3356], "8.8.8.0/24": [3356, 6939], "66.167.90.0/24": [1299, 174],
               "104.16.0.0/22": [174, 1299], "45.223.8.0/22": [3491, 6453, 17557]}
UNRELATED = [47065, 140224, 328608, 199524, 263702, 211398, 51088, 58224, 9009, 136907, 207656, 45090]
PRIVATE = [64666, 65010, 64512, 65530]
BACKGROUND = [("102.67.200.0/24", 37662), ("41.188.128.0/24", 36974), ("31.13.64.0/24", 32934), ("23.235.32.0/24", 54113),
              ("140.82.112.0/24", 36459), ("157.240.1.0/24", 32934), ("151.101.0.0/24", 54113), ("39.32.0.0/24", 45595),
              ("58.65.128.0/24", 38547), ("119.160.96.0/24", 24499), ("202.59.80.0/24", 9541), ("110.93.192.0/24", 17557),
              ("1.0.0.0/24", 13335), ("8.8.4.0/24", 15169), ("45.223.16.0/24", 47065)]


def build(seed):
    rnd = random.Random(seed)
    rows = []

    def path_to(*tail):
        p = [rnd.choice(PEERS)]
        if rnd.random() < 0.5:
            p.append(rnd.choice([x for x in (1299, 174, 3356, 2914, 6453) if x != p[0] and x not in tail]))
        return p + [x for x in tail if x != p[-1]]

    def sub(prefix):
        net = ipaddress.ip_network(prefix)
        k = rnd.choice([1, 2]) if net.prefixlen < 24 else 1
        return str(rnd.choice(list(net.subnets(prefixlen_diff=k))))

    def add(ts, path, prefix, label, typ, scen, cat, diff="easy", in_scope=True, note=""):
        data = {"timestamp": T0 + ts, "host": rnd.choice(HOSTS), "peer_asn": str(path[0]), "type": "UPDATE",
                "path": path, "announcements": [{"next_hop": f"192.0.2.{rnd.randint(1, 254)}", "prefixes": [prefix]}]}
        rows.append({"type": "ris_message", "data": data,
                     "truth": {"label": label, "type": typ, "scenario": scen, "category": cat, "difficulty": diff,
                               "in_scope": in_scope, "note": note}})
        return rows[-1]

    t = lambda: rnd.randint(0, SPAN)
    W = list(WHITELIST)
    n = [0]

    def sid(prefix):
        n[0] += 1
        return f"{prefix}{n[0]:03d}"

    # ---------------- benign: no candidate expected -----------------------------------------------------------
    for _ in range(50):
        w = rnd.choice(W)
        add(t(), path_to(rnd.choice(WHITELIST[w])), w, "benign", "none", sid("B"), "expected_origin_exact")
    for _ in range(15):
        w = rnd.choice(W)
        add(t(), path_to(rnd.choice(WHITELIST[w])), sub(w), "benign", "none", sid("B"), "expected_origin_more_specific",
            note="traffic engineering by the authorised origin")
    for k in range(25):
        pfx, o = BACKGROUND[k % len(BACKGROUND)]
        add(t(), path_to(o), pfx, "benign", "none", sid("B"), "unwatched_prefix")
    for _ in range(4):
        w = rnd.choice(["1.1.1.0/24", "8.8.8.0/24"])
        add(t(), path_to(3356) + [[WHITELIST[w][0], 64496]], w, "benign", "none", sid("B"), "as_set_origin",
            note="aggregate with AS_SET origin (skipped by the detector)")

    # ---------------- benign: candidate, legitimately authorised by relationship -----------------------------
    def legit(cat_filter, count, more_specific, diff_override=None, cat_name=None):
        out = []
        pool = [(w, o, tail, c, d) for w, l in LEGIT.items() for (o, tail, c, d) in l if c == cat_filter]
        for _ in range(count):
            w, o, tail, c, d = rnd.choice(pool)
            pfx = sub(w) if more_specific else w
            cat = cat_name or (c + ("_more_specific" if more_specific else "_exact"))
            out.append(add(t(), path_to(*tail, o), pfx, "benign", "none", sid("L"), cat, diff_override or d))
        return out
    legit("legit_customer", 6, False)
    cust_ms = legit("legit_customer", 10, True)
    legit("legit_sibling", 4, False)
    legit("legit_customer_of_customer", 6, rnd.random() < 0.5)
    for _ in range(5):
        add(t(), path_to(32787), sub("45.223.8.0/22"), "benign", "none", sid("L"), "ddos_scrubbing_diversion", "hard",
            note="planned scrubbing: scrubber originates a /24 of the customer block; no relationship in the data")
    for base in rnd.sample(cust_ms, 7):    # same (prefix, origin) again from other vantage points inside the cooldown
        d = base["data"]
        add(d["timestamp"] - T0 + rnd.randint(15, 400), [rnd.choice(PEERS)] + d["path"][1:], d["announcements"][0]["prefixes"][0],
            "benign", "none", base["truth"]["scenario"], "legit_customer_repeat_in_cooldown")

    # ---------------- anomalous, in scope ----------------------------------------------------------------------
    hijacks = []
    for _ in range(15):
        w = rnd.choice(W)
        hijacks.append(add(t(), path_to(rnd.choice(UNRELATED)), w, "anomalous", "unexpected_origin", sid("H"),
                           "exact_hijack_unrelated"))
    for _ in range(18):
        w = rnd.choice(W)
        hijacks.append(add(t(), path_to(rnd.choice(UNRELATED)), sub(w), "anomalous", "unexpected_deaggregation", sid("H"),
                           "subprefix_hijack_unrelated"))
    for _ in range(10):
        w = rnd.choice(W)
        ms = rnd.random() < 0.5
        hijacks.append(add(t(), path_to(rnd.choice(RELATED_BAD[w])), sub(w) if ms else w, "anomalous",
                           "unexpected_deaggregation" if ms else "unexpected_origin", sid("H"), "hijack_by_related_as", "hard",
                           note="origin is a peer/provider of the victim: a relationship exists but does not authorise it"))
    for _ in range(5):
        w = rnd.choice(W)
        ms = rnd.random() < 0.5
        hijacks.append(add(t(), path_to(rnd.choice(UNRELATED[:4]), rnd.choice(PRIVATE)), sub(w) if ms else w, "anomalous",
                           "unexpected_deaggregation" if ms else "unexpected_origin", sid("H"), "private_asn_origin"))
    for base in rnd.sample(hijacks, 12):
        d = base["data"]
        add(d["timestamp"] - T0 + rnd.randint(10, 500), [rnd.choice(PEERS)] + d["path"][1:], d["announcements"][0]["prefixes"][0],
            "anomalous", base["truth"]["type"], base["truth"]["scenario"], "hijack_repeat_in_cooldown", base["truth"]["difficulty"])

    # ---------------- anomalous, out of scope (origin is correct) ----------------------------------------------
    for _ in range(5):
        w = rnd.choice(W)
        add(t(), [rnd.choice(PEERS), rnd.choice(UNRELATED), WHITELIST[w][0]], w, "anomalous", "path_hijack", sid("X"),
            "forged_origin_path_hijack", "hard", in_scope=False, note="attacker prepends the victim ASN")
    for _ in range(3):
        add(t(), [rnd.choice([3333, 7018]), 3491, 135520, 9541], "45.223.8.0/22", "anomalous", "route_leak", sid("X"),
            "route_leak_valid_origin", "hard", in_scope=False, note="customer re-announces its provider's route upstream")

    rows.sort(key=lambda r: (r["data"]["timestamp"], r["truth"]["scenario"]))
    return rows


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--out", default=os.path.join(HERE, "labelled_updates.jsonl"))
    a = p.parse_args()
    rows = build(a.seed)
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    json.dump(WHITELIST, open(os.path.join(HERE, "eval_whitelist.json"), "w", encoding="utf-8"), indent=2)
    open(os.path.join(HERE, "eval_asrel.txt"), "w", encoding="utf-8").write(ASREL)
    from collections import Counter
    c = Counter((r["truth"]["label"], r["truth"]["in_scope"]) for r in rows)
    print(f"{len(rows)} updates -> {a.out}")
    print("  benign:", c[("benign", True)], " anomalous in-scope:", c[("anomalous", True)], " anomalous out-of-scope:", c[("anomalous", False)])
    print("  by category:", dict(Counter(r["truth"]["category"] for r in rows)))
