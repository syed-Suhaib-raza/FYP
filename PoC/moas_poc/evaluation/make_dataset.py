"""Build the labelled MOAS evaluation stream (SYNTHETIC; labels are true by construction).

    python evaluation/make_dataset.py                      # -> evaluation/labelled_updates.jsonl (~200 updates)

Every line is a RIS-Live message plus a `truth` block that the PoC never sees:
    {"type": "ris_message", "data": {...UPDATE...},
     "truth": {"label": "benign"|"anomalous", "scenario": "A01", "category": "...", "difficulty": "easy"|"hard",
               "in_scope": true|false, "note": "..."}}

Meaning of `label` (state semantics): the decision the monitor SHOULD hold for this update's prefix right after the
update has been processed, i.e. "is this prefix currently in an anomalous multi-origin state?". For example the
legitimate origin re-announcing while a hijack is still active is labelled anomalous (the prefix is still hijacked),
and the first update after the hijacker has aged out of the window is labelled benign again.

`in_scope=false` marks anomalies that an exact-prefix MOAS detector cannot see by design (forged-origin path hijack,
sub-prefix hijack, a bogon announced by a single origin). They are reported separately, not in the headline metrics.

ASNs and prefixes are placeholders chosen to look realistic; the roles given to them here (hijacker, scrubber, ...)
are fictional. The watched prefixes and their authorised origins live in evaluation/eval_whitelist.json.
"""
import argparse, json, os, random

HERE = os.path.dirname(os.path.abspath(__file__))
T0 = 1762000000                       # 2025-11-01 12:26:40 UTC, start of the synthetic stream
WINDOW = 3600                         # must match --window of the catalog (moas.py default)
PEERS = [3333, 2914, 6939, 1299, 174, 3356, 6453, 6762, 7018, 37100]
HOSTS = [f"rrc{i:02d}" for i in (0, 1, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 19, 20, 21, 22, 23, 24, 25, 26)]

WHITELIST = {
    "1.1.1.0/24": [13335],
    "8.8.8.0/24": [15169],
    "66.167.15.0/24": [3257, 2828],        # origin migration 3257 -> 2828, both authorised
    "66.167.90.0/24": [3257],
    "104.16.0.0/24": [13335, 209242],      # planned multi-origin (anycast)
    "45.223.10.0/24": [9541],              # operator customer block (synthetic)
    "45.223.11.0/24": [9541],
    "45.223.12.0/24": [9541],
}


class Scenario:
    def __init__(self, rnd, sid, prefix, start, difficulty="easy", note=""):
        self.rnd, self.sid, self.prefix, self.start, self.difficulty, self.note = rnd, sid, prefix, start, difficulty, note
        self.rows = []

    def upd(self, dt, path, label, category, in_scope=True, peer=None, host=None, prefix=None):
        peer = peer if peer is not None else (path[0] if len(path) > 1 else self.rnd.choice(PEERS))
        if path[0] != peer:
            path = [peer] + path
        data = {"timestamp": T0 + self.start + dt, "host": host or self.rnd.choice(HOSTS), "peer_asn": str(peer),
                "type": "UPDATE", "path": path,
                "announcements": [{"next_hop": f"192.0.2.{self.rnd.randint(1, 254)}", "prefixes": [prefix or self.prefix]}]}
        truth = {"label": label, "scenario": self.sid, "category": category, "difficulty": self.difficulty,
                 "in_scope": in_scope, "note": self.note}
        self.rows.append({"type": "ris_message", "data": data, "truth": truth})


def via(rnd, *tail):
    """random vantage path ending in `tail` (tail = [... , origin])"""
    p = [rnd.choice(PEERS)]
    if rnd.random() < 0.6:
        mid = rnd.choice([x for x in (1299, 174, 3356, 2914, 6453, 3257) if x not in tail and x != p[0]])
        p.append(mid)
    return p + [x for x in tail if x != p[-1]]


def build(seed):
    rnd = random.Random(seed)
    S = []

    def sc(*a, **k):
        s = Scenario(rnd, *a, **k); S.append(s); return s

    B, A = "benign", "anomalous"

    # --- A01: 1.1.1.0/24 steady, exact-prefix hijack by an unrelated public AS, hijack ages out ---------------
    s = sc("A01", "1.1.1.0/24", 0, "easy", "watched prefix, unrelated public AS originates it, then disappears")
    for i in range(10):
        s.upd(i * 90, via(rnd, 13335), B, "steady_single_origin")
    for i, dt in enumerate((1000, 1004, 1011, 1030, 1047, 1060)):
        s.upd(dt, via(rnd, 47065), A, "exact_hijack_watched")
    s.upd(1100, via(rnd, 13335), A, "legit_origin_during_hijack")
    s.upd(1060 + WINDOW + 400, via(rnd, 13335), B, "after_hijack_aged_out")
    s.upd(1060 + WINDOW + 700, via(rnd, 13335), B, "steady_single_origin")

    # --- A02: 8.8.8.0/24 steady then private-ASN origin ---------------------------------------------------------
    s = sc("A02", "8.8.8.0/24", 300, "easy", "watched prefix, private ASN appears as second origin")
    for i in range(8):
        s.upd(i * 120, via(rnd, 15169), B, "steady_single_origin")
    for dt in (1500, 1520, 1533, 1590):
        s.upd(dt, via(rnd, 64666), A, "exact_hijack_watched_private_asn")

    # --- A03: 66.167.90.0/24 (from the original sample): 4637 vs authorised 3257 -------------------------------
    s = sc("A03", "66.167.90.0/24", 900, "easy", "watched prefix, unauthorised public AS")
    for i in range(3):
        s.upd(i * 40, via(rnd, 3257), B, "steady_single_origin")
    for dt in (200, 205, 260):
        s.upd(dt, via(rnd, 1299, 4637), A, "exact_hijack_watched")

    # --- A04: hijacks of UNWATCHED prefixes by unrelated public ASes (no prior knowledge -> hard) ---------------
    for k, (pfx, legit, bad) in enumerate([("102.130.48.0/24", 37100, 328608), ("41.75.112.0/24", 36924, 199524),
                                           ("196.49.4.0/24", 37271, 263702)]):
        s = sc(f"A04{'abc'[k]}", pfx, 2000 + k * 1700, "hard", "unwatched prefix, unrelated origin (no whitelist knowledge)")
        s.upd(0, via(rnd, legit), B, "steady_single_origin")
        s.upd(55, via(rnd, legit), B, "steady_single_origin")
        for dt in (300, 312, 340, 395):
            s.upd(dt, via(rnd, bad), A, "exact_hijack_unwatched")

    # --- A05: fat-finger / leaked private ASN as origin on unwatched prefixes ----------------------------------
    for k, (pfx, legit, bad) in enumerate([("103.21.244.0/24", 38001, 65010), ("180.92.160.0/24", 45595, 64512)]):
        s = sc(f"A05{'ab'[k]}", pfx, 2500 + k * 2600, "easy", "private ASN leaked as origin")
        s.upd(0, via(rnd, legit), B, "steady_single_origin")
        s.upd(70, via(rnd, legit), B, "steady_single_origin")
        for dt in (400, 420, 470):
            s.upd(dt, via(rnd, legit, bad), A, "private_asn_origin")

    # --- A06: AS_TRANS (23456) as origin: broken 4-byte ASN handling ------------------------------------------
    s = sc("A06", "202.69.160.0/24", 3100, "easy", "AS_TRANS appears as an origin (misconfiguration)")
    s.upd(0, via(rnd, 38547), B, "steady_single_origin")
    s.upd(90, via(rnd, 38547), B, "steady_single_origin")
    s.upd(600, via(rnd, 23456), A, "as_trans_origin")
    s.upd(640, via(rnd, 23456), A, "as_trans_origin")

    # --- A07: bogon (shared address space 100.64/10) announced, then announced by a second origin --------------
    s = sc("A07", "100.64.12.0/24", 4200, "easy", "non-routable space; first announcement is a single-origin bogon")
    s.upd(0, via(rnd, 38193), A, "bogon_single_origin", in_scope=False)
    s.upd(150, via(rnd, 17557), A, "bogon_moas")
    s.upd(170, via(rnd, 38193), A, "bogon_moas")
    s.upd(210, via(rnd, 17557), A, "bogon_moas")

    # --- A08: forged-origin (Type-1) path hijack: origin stays legit, so no MOAS exists ------------------------
    s = sc("A08", "45.223.11.0/24", 5000, "hard", "attacker prepends the victim's ASN; origin looks correct")
    s.upd(0, via(rnd, 9541), B, "steady_single_origin")
    s.upd(60, via(rnd, 9541), B, "steady_single_origin")
    for dt in (500, 506, 530, 580):
        s.upd(dt, [rnd.choice(PEERS), 51088, 9541], A, "forged_origin_path_hijack", in_scope=False)

    # --- A09: sub-prefix hijack (more-specific): different prefix key, so no exact-prefix MOAS -----------------
    s = sc("A09", "1.1.1.0/25", 1200, "hard", "more-specific of a watched prefix by an unrelated AS")
    for dt in (0, 9, 30, 75):
        s.upd(dt, via(rnd, 47065), A, "subprefix_hijack", in_scope=False)

    # --- A10: planned multi-origin prefix, then an unauthorised third origin joins -----------------------------
    s = sc("A10", "104.16.0.0/24", 600, "easy", "authorised anycast pair, then an unauthorised origin joins")
    for i in range(8):
        s.upd(i * 100, via(rnd, (13335, 209242)[i % 2]), B, "planned_multi_origin")
    for dt in (1400, 1410, 1460):
        s.upd(dt, via(rnd, 50673), A, "origin_added_to_planned_moas")
    s.upd(1500, via(rnd, 13335), A, "legit_origin_during_hijack")

    # --- A11: hijacker forges adjacency to the victim (victim appears as its upstream) -> looks like a customer --
    s = sc("A11", "46.19.36.0/24", 6000, "hard", "hijacker path contains the victim ASN as upstream (forged adjacency)")
    s.upd(0, via(rnd, 39351), B, "steady_single_origin")
    s.upd(80, via(rnd, 39351), B, "steady_single_origin")
    for dt in (700, 715, 760, 790):
        s.upd(dt, [rnd.choice(PEERS), 39351, 211398], A, "hijack_forged_adjacency")

    # --- A13: operator customer block hijacked -----------------------------------------------------------------
    s = sc("A13", "45.223.12.0/24", 7000, "easy", "watched operator prefix, unrelated public AS")
    s.upd(0, via(rnd, 9541), B, "steady_single_origin")
    s.upd(45, via(rnd, 9541), B, "steady_single_origin")
    for dt in (800, 803, 845, 900):
        s.upd(dt, via(rnd, 140224), A, "exact_hijack_watched")

    # ======================================== benign ==========================================================
    # B03: unwatched, single-origin background traffic (the bulk of a real feed)
    bg = [("102.67.200.0/24", 37662), ("41.188.128.0/24", 36974), ("31.13.64.0/24", 32934), ("23.235.32.0/24", 54113),
          ("140.82.112.0/24", 36459), ("157.240.1.0/24", 32934), ("151.101.0.0/24", 54113), ("185.60.216.0/24", 32934),
          ("39.32.0.0/24", 45595), ("58.65.128.0/24", 38547), ("119.160.96.0/24", 24499), ("202.59.80.0/24", 9541),
          ("110.93.192.0/24", 17557), ("182.176.0.0/24", 17557), ("203.99.48.0/24", 23674)]
    for k, (pfx, o) in enumerate(bg):
        s = sc(f"B03{k:02d}", pfx, rnd.randint(0, 9000), "easy", "unwatched, single origin")
        for i in range(3):
            s.upd(i * rnd.randint(60, 400), via(rnd, o), B, "steady_single_origin_unwatched")

    # B05/B06/B13: provider aggregation - the customer origin's path goes through the other origin (upstream relation)
    for sid, pfx, up, cust, start in (("B05", "77.77.77.0/24", 3320, 6830, 400), ("B06", "185.40.4.0/24", 6762, 202134, 3300)):
        s = sc(sid, pfx, start, "easy", "upstream also originates the customer prefix (aggregation)")
        s.upd(0, via(rnd, up), B, "provider_aggregation")
        for dt in (10, 20, 35, 70, 120):
            s.upd(dt, [rnd.choice(PEERS), up, cust] if rnd.random() < .5 else via(rnd, up, cust), B, "provider_aggregation")
    s = sc("B13", "37.156.40.0/24", 5200, "easy", "benign aggregation MOAS that ends when the customer withdraws")
    s.upd(0, via(rnd, 12880), B, "provider_aggregation")
    s.upd(30, via(rnd, 12880, 49100), B, "provider_aggregation")
    s.upd(60, via(rnd, 12880, 49100), B, "provider_aggregation")
    s.upd(900, via(rnd, 12880), B, "provider_aggregation")
    s.upd(60 + WINDOW + 300, via(rnd, 12880), B, "moas_ended")
    s.upd(60 + WINDOW + 400, via(rnd, 12880), B, "steady_single_origin")

    # B07: aggregate announced with an AS_SET origin (one origin key -> no MOAS)
    s = sc("B07", "151.101.64.0/22", 2600, "easy", "aggregate with AS_SET origin")
    for dt in (0, 50, 110, 300):
        s.upd(dt, via(rnd, 3356) + [[54113, 30081]], B, "as_set_aggregate")

    # B08: planned origin migration, both origins authorised
    s = sc("B08", "66.167.15.0/24", 1800, "easy", "migration 3257 -> 2828, both whitelisted")
    for dt in (0, 60, 120):
        s.upd(dt, via(rnd, 3257), B, "planned_origin_migration")
    for dt in (300, 330, 400):
        s.upd(dt, via(rnd, 2828), B, "planned_origin_migration")

    # B09: DDoS-scrubbing diversion: scrubbing provider originates the customer prefix during an attack
    s = sc("B09", "45.223.10.0/24", 4500, "hard", "planned scrubbing diversion; scrubber not in the whitelist")
    s.upd(0, via(rnd, 9541), B, "steady_single_origin")
    s.upd(40, via(rnd, 9541), B, "steady_single_origin")
    for dt in (600, 612, 650, 700):
        s.upd(dt, via(rnd, 32787), B, "ddos_scrubbing_diversion")

    # B10/B11: unwatched benign multi-origin without any upstream relation (anycast, sibling ASes)
    for sid, pfx, o1, o2, start, cat in (("B10", "199.83.128.0/24", 19551, 62571, 1500, "anycast_unwatched"),
                                         ("B11", "23.192.0.0/24", 20940, 16625, 6500, "sibling_origins_unwatched")):
        s = sc(sid, pfx, start, "hard", "benign multi-origin, nothing in the data says so")
        for i, dt in enumerate((0, 20, 45, 90, 140, 200)):
            s.upd(dt, via(rnd, (o1, o2)[i % 2]), B, cat)

    # B12: origin change after a gap longer than the window: never two active origins
    s = sc("B12", "91.198.174.0/24", 1000, "easy", "origin change after a long gap, no overlap")
    s.upd(0, via(rnd, 43821), B, "origin_change_no_overlap")
    s.upd(60, via(rnd, 43821), B, "origin_change_no_overlap")
    s.upd(60 + WINDOW + 200, via(rnd, 14907), B, "origin_change_no_overlap")
    s.upd(60 + WINDOW + 260, via(rnd, 14907), B, "origin_change_no_overlap")

    rows = []
    for s in S:
        rows += s.rows
    rows.sort(key=lambda r: (r["data"]["timestamp"], r["truth"]["scenario"]))
    return rows


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--out", default=os.path.join(HERE, "labelled_updates.jsonl"))
    p.add_argument("--whitelist-out", default=os.path.join(HERE, "eval_whitelist.json"))
    a = p.parse_args()
    rows = build(a.seed)
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    json.dump(WHITELIST, open(a.whitelist_out, "w", encoding="utf-8"), indent=2)
    from collections import Counter
    lab = Counter((r["truth"]["label"], r["truth"]["in_scope"]) for r in rows)
    print(f"{len(rows)} updates -> {a.out}")
    print("  benign:", lab[("benign", True)], " anomalous in-scope:", lab[("anomalous", True)],
          " anomalous out-of-scope:", lab[("anomalous", False)])
    print("  scenarios:", len({r['truth']['scenario'] for r in rows}))
