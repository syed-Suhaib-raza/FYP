"""Build the labelled RPKI evaluation stream (SYNTHETIC; labels are true by construction).

    python evaluation/make_dataset.py        # -> evaluation/labelled_updates.jsonl + eval_vrps_v1/v2/v3.json,
                                             #    eval_whitelist.json, eval_customers.json

Every line is a RIS-Live-shaped message plus a `truth` block that the PoC never sees:
    {"type": "ris_message", "data": {...UPDATE | RIS_PEER_STATE | VRP_RELOAD...},
     "truth": {"scenario": "S03", "category": "...", "difficulty": "easy"|"hard", "in_scope": true|false,
               "checks": [{"prefix", "origin", "label", "state", "severity"}, ...]}}

`checks` = what the monitor SHOULD hold right after this line, for the listed (prefix, origin):
    label     "anomalous" if an ACTIVE NOC alert must exist for it, else "benign"
    state     its RFC 6811 state under the VRPs in force (VALID, NOT_FOUND, INVALID_AS, INVALID_ML, INVALID_AS_AND_ML)
    severity  the severity from the doc's table when anomalous (CRITICAL / HIGH / LOW), else null
A normal update has one check (its own prefix and origin). A VRP_RELOAD or a peer going down has one check per
(prefix, origin) it changes. VRP_RELOAD lines are not RIS messages: they stand for "Routinator now serves this
VRP file" and let the stream contain ROA changes at known points.

The labels follow the alert policy of the chosen approach (RPKI_Invalid doc, Our Solution), written here by hand
per scenario and NOT computed with the PoC's code:
  - alert on Invalid routes that touch Cybernet and on NotFound inside Cybernet space;
  - severity: foreign origin first time CRITICAL, foreign origin seen in an earlier episode HIGH, customer HIGH,
    Cybernet's own mistakes HIGH, NotFound LOW;
  - an alert is ACTIVE once 2 RIS peers carry the route (MIN_PEERS = 2) and stays ACTIVE until none does;
  - a ROA change re-validates routes that are already held (no BGP update needed).
`in_scope=false`: a forged-origin path hijack (the real origin kept at the end of a fake path). It is RPKI Valid by
definition, so no RPKI monitor can see it; reported separately, not in the headline metrics.
Prefixes: Cybernet's real 72.255.0.0/18 plus documentation ranges. ROAs, customers and attackers are invented.
"""
import json, os, random

HERE = os.path.dirname(os.path.abspath(__file__))
T0 = 1762000000
PEERS = [("rrc00", "193.0.0.56", 3333), ("rrc01", "195.66.224.175", 2914), ("rrc03", "80.249.208.34", 6939),
         ("rrc12", "80.81.192.85", 1299), ("rrc21", "37.49.237.1", 174), ("rrc04", "192.65.185.3", 3356),
         ("rrc05", "193.203.0.7", 6453), ("rrc06", "202.249.2.169", 2497), ("rrc07", "194.68.123.136", 1257),
         ("rrc10", "217.29.66.1", 12779)]
UPSTREAMS = [3491, 1299, 6762, 4637, 7473]          # transits in front of Cybernet in normal paths

V1 = [("AS9541", "72.255.0.0/18", 20), ("AS24440", "203.0.113.0/24", 24), ("AS64496", "198.51.100.0/24", 24),
      ("AS0", "192.0.2.0/24", 24), ("AS9541", "2001:db8:100::/40", 48), ("AS15169", "8.8.8.0/24", 24),
      ("AS13335", "1.1.1.0/24", 24)]
V2 = [("AS9541", "72.255.0.0/18", 18)] + [r for r in V1 if r[1] not in ("72.255.0.0/18", "203.0.113.0/24")]
WHITELIST = {"72.255.0.0/18": [9541], "72.255.128.0/18": [9541], "203.0.113.0/24": [24440],
             "198.51.100.0/24": [9541], "192.0.2.0/24": [9541], "2001:db8:100::/40": [9541]}
CUSTOMERS = [64510]
MIN_PEERS = 2

# (prefix, origin) -> scenario facts. "v": per VRP version, (alertable, state, severity); v3 == v1.
SPEC = {}


def spec(prefix, origin, scenario, category, difficulty, v1, v2=None):
    SPEC[(prefix, origin)] = dict(scenario=scenario, category=category, difficulty=difficulty, v={"v1": v1, "v2": v2 or v1})


class Stream:
    def __init__(self):
        self.t, self.ver, self.rows = T0, "v1", []
        self.rib = {}                                   # (prefix, peer index) -> origin
        self.active = set()                             # (prefix, origin) with an ACTIVE alert (truth)

    def _peers(self, prefix, origin):
        return sum(1 for (p, _), o in self.rib.items() if p == prefix and o == origin)

    def _update_truth(self, key):
        alertable, _, _ = SPEC[key]["v"]["v2" if self.ver == "v2" else "v1"]
        n = self._peers(*key)
        if not alertable or n == 0:
            self.active.discard(key)
        elif n >= MIN_PEERS:
            self.active.add(key)

    def check(self, prefix, origin):
        key = (prefix, origin)
        self._update_truth(key)
        _, state, sev = SPEC[key]["v"]["v2" if self.ver == "v2" else "v1"]
        anomalous = key in self.active
        return dict(prefix=prefix, origin=origin, label="anomalous" if anomalous else "benign", state=state,
                    severity=sev if anomalous else None, scenario=SPEC[key]["scenario"],
                    category=SPEC[key]["category"], difficulty=SPEC[key]["difficulty"], in_scope=True)

    def _emit(self, data, key, checks, in_scope=True):
        self.t += random.choice((2, 3, 5, 8))
        data["timestamp"] = self.t
        s = SPEC[key]
        self.rows.append({"type": "ris_message", "data": data,
                          "truth": dict(scenario=s["scenario"], category=s["category"], difficulty=s["difficulty"],
                                        in_scope=in_scope, checks=checks)})

    def ann(self, prefix, origin, peers, via=None, forged=False):
        for i in peers:
            h, ip, asn = PEERS[i]
            path = [asn] + (via or [random.choice(UPSTREAMS)]) + [origin]     # an AS_SET stays one (list) hop
            old = self.rib.get((prefix, i))
            self.rib[(prefix, i)] = None if isinstance(origin, list) else origin
            key = (prefix, self.rib[(prefix, i)])
            data = {"type": "UPDATE", "host": h, "peer": ip, "peer_asn": asn, "path": path, "origin": "IGP",
                    "announcements": [{"next_hop": ip, "prefixes": [prefix]}]}
            if forged:                                  # truth: anomalous but invisible to RPKI (out of scope)
                c = self.check(*key)
                c.update(label="anomalous", severity=None, scenario="S15", category="forged_origin_path_hijack",
                         difficulty="hard", in_scope=False)
                self._emit(data, ("FORGED", 0), [c], in_scope=False)
                continue
            checks = [self.check(*key)]
            if old is not None and old != key[1]:        # the peer replaced another origin's route
                checks.append(self.check(prefix, old))
            self._emit(data, key, checks)

    def wd(self, prefix, peers):
        for i in peers:
            h, ip, asn = PEERS[i]
            origin = self.rib.pop((prefix, i))
            self._emit({"type": "UPDATE", "host": h, "peer": ip, "peer_asn": asn, "path": [], "withdrawals": [prefix]},
                       (prefix, origin), [self.check(prefix, origin)])

    def peer_down(self, i, scenario_key):
        h, ip, asn = PEERS[i]
        gone = [(p, o) for (p, j), o in self.rib.items() if j == i]
        for p, _ in gone:
            del self.rib[(p, i)]
        self._emit({"type": "RIS_PEER_STATE", "host": h, "peer": ip, "peer_asn": asn, "state": "down"},
                   scenario_key, [self.check(p, o) for p, o in sorted(set(gone), key=str)])

    def reload(self, ver, file, scenario_key):
        self.ver = ver
        held = sorted({(p, o) for (p, _), o in self.rib.items()}, key=str)
        self._emit({"type": "VRP_RELOAD", "file": file}, scenario_key, [self.check(p, o) for p, o in held])


def vrp_file(name, roas):
    json.dump({"metadata": {"generated": T0, "generatedTime": "2025-11-01T12:26:40Z"},
               "roas": [{"asn": a, "prefix": p, "maxLength": m, "ta": "apnic"} for a, p, m in roas]},
              open(os.path.join(HERE, name), "w"), indent=1)


def build(seed=7):
    random.seed(seed)
    V, NF, IA, IM, IAM = "VALID", "NOT_FOUND", "INVALID_AS", "INVALID_ML", "INVALID_AS_AND_ML"
    spec("72.255.0.0/18", 9541, "S01", "own_valid", "easy", (False, V, None))
    spec("72.255.32.0/20", 9541, "S02", "roa_tightened", "hard", (False, V, None), (True, IM, "HIGH"))
    spec("203.0.113.0/24", 24440, "S17", "roa_expired", "hard", (False, V, None), (True, NF, "LOW"))
    spec("72.255.16.0/20", 64520, "S19", "foreign_first_time", "easy", (True, IA, "CRITICAL"))
    spec("72.255.40.0/24", 9541, "S03", "own_maxlength", "easy", (True, IM, "HIGH"))
    spec("72.255.0.0/18", 64666, "S04", "exact_prefix_hijack", "easy", (True, IA, "CRITICAL"))
    spec("72.255.8.0/24", 64667, "S05", "subprefix_hijack", "easy", (True, IAM, "CRITICAL"), (True, IAM, "CRITICAL"))
    spec("72.255.48.0/20", 64510, "S06", "customer_not_in_roa", "easy", (True, IA, "HIGH"))
    spec("198.51.100.0/24", 9541, "S07", "own_not_authorised", "easy", (True, IA, "HIGH"))
    spec("192.0.2.0/24", 64668, "S08", "as0_roa", "easy", (True, IA, "CRITICAL"))
    spec("72.255.12.0/22", None, "S09", "as_set_origin", "hard", (True, IAM, "CRITICAL"))
    spec("72.255.128.0/18", 9541, "S10", "own_no_roa", "easy", (True, NF, "LOW"))
    spec("2001:db8:100::/40", 9541, "S11", "own_valid_ipv6", "easy", (False, V, None))
    spec("2001:db8:100:ff00::/56", 9541, "S11b", "own_maxlength_ipv6", "easy", (True, IM, "HIGH"))
    spec("72.255.60.0/24", 9541, "S12", "single_peer_noise", "hard", (False, IM, None))
    spec("8.8.8.0/24", 64669, "S13", "invalid_not_cybernet", "easy", (False, IA, None))
    spec("8.8.8.0/24", 15169, "S14", "valid_not_cybernet", "easy", (False, V, None))
    spec("1.1.1.0/24", 13335, "S14", "valid_not_cybernet", "easy", (False, V, None))
    spec("72.255.160.0/20", 64670, "S16", "foreign_in_space_no_roa", "hard", (True, NF, "LOW"))
    spec("72.255.0.0/19", 9541, "S02", "roa_tightened", "hard", (False, V, None), (True, IM, "HIGH"))
    SPEC[("FORGED", 0)] = dict(scenario="S15", category="forged_origin_path_hijack", difficulty="hard", v={})

    s = Stream()
    # ---- phase A (VRPs v1) ---------------------------------------------------------------------------------
    s.ann("72.255.0.0/18", 9541, [0, 1, 2, 3])
    s.ann("72.255.32.0/20", 9541, [0, 1, 2])
    s.ann("203.0.113.0/24", 24440, [0, 1])
    s.ann("72.255.0.0/19", 9541, [2, 3])
    for _ in range(3):
        s.ann("72.255.0.0/18", 9541, [0, 1, 2, 3])                   # path changes: still valid
    s.ann("72.255.16.0/20", 64520, [4, 5], via=[6453])                # partner, first episode -> CRITICAL
    s.wd("72.255.16.0/20", [4, 5])
    # ---- phase B: ROA tightened + expired, then fixed --------------------------------------------------------
    s.reload("v2", "eval_vrps_v2.json", ("72.255.32.0/20", 9541))
    s.ann("72.255.0.0/18", 9541, [0, 1])                              # still valid under /18 max
    s.ann("72.255.32.0/20", 9541, [0])                                # duplicate while Invalid
    s.reload("v1", "eval_vrps_v3.json", ("72.255.32.0/20", 9541))
    # ---- phase C (VRPs v1 again) -----------------------------------------------------------------------------
    s.ann("72.255.40.0/24", 9541, [0, 1, 2, 3])                       # own too specific
    s.wd("72.255.40.0/24", [0, 1, 2, 3])
    s.ann("72.255.40.0/24", 9541, [4, 5])                             # reopened
    s.ann("8.8.8.0/24", 15169, [3, 4, 5]); s.ann("1.1.1.0/24", 13335, [0, 1, 2, 3])
    s.ann("72.255.0.0/18", 64666, [5, 6, 7], via=[174])     # exact-prefix hijack
    s.wd("72.255.0.0/18", [5, 6, 7])
    s.ann("72.255.8.0/24", 64667, [6, 7, 8], via=[3356])              # sub-prefix hijack
    s.wd("72.255.8.0/24", [6, 7, 8])
    s.ann("72.255.48.0/20", 64510, [0, 1, 2], via=[3491, 9541])       # customer behind Cybernet
    s.ann("198.51.100.0/24", 9541, [2, 3, 4])                         # leased block, ROA names AS64496
    s.ann("192.0.2.0/24", 64668, [1, 2], via=[6939])                  # AS0 ROA
    s.wd("192.0.2.0/24", [1, 2])
    s.ann("72.255.12.0/22", [64700, 64701], [3, 4], via=[2914])       # AS_SET origin
    s.ann("72.255.128.0/18", 9541, [0, 1, 2])                         # Cybernet prefix with no ROA
    s.ann("72.255.160.0/20", 64670, [6, 7], via=[6453])               # foreign origin in Cybernet space, no ROA
    s.ann("8.8.8.0/24", 64669, [0, 1, 2], via=[6939])                 # invalid, not Cybernet
    s.ann("2001:db8:100::/40", 9541, [0, 1, 2])
    s.ann("2001:db8:100:ff00::/56", 9541, [8, 9])                     # IPv6 too specific
    s.ann("72.255.60.0/24", 9541, [6])                                # one RIS peer only
    s.peer_down(8, ("2001:db8:100:ff00::/56", 9541))
    s.peer_down(9, ("2001:db8:100:ff00::/56", 9541))
    SPEC[("72.255.16.0/20", 64520)]["v"] = {"v1": (True, "INVALID_AS", "HIGH"), "v2": (True, "INVALID_AS", "HIGH")}
    s.ann("72.255.16.0/20", 64520, [6, 7], via=[6453])                # partner returns: seen before -> HIGH
    s.ann("72.255.0.0/18", 9541, [5, 6], via=[64666], forged=True)    # forged-origin path hijack (out of scope)
    s.ann("72.255.60.0/24", 9541, [6])                                # the single peer again
    for _ in range(20):                                               # steady background traffic
        s.ann("72.255.0.0/18", 9541, random.sample(range(4), 2))
        s.ann("2001:db8:100::/40", 9541, random.sample(range(3), 1))
        s.ann("1.1.1.0/24", 13335, random.sample(range(4), 1))
        s.ann("72.255.0.0/19", 9541, random.sample([2, 3], 1))
    s.wd("72.255.48.0/20", [0, 1, 2])
    s.wd("72.255.128.0/18", [0, 1, 2])
    return s.rows


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=7)
    a = p.parse_args()
    rows = build(a.seed)
    vrp_file("eval_vrps_v1.json", V1); vrp_file("eval_vrps_v2.json", V2); vrp_file("eval_vrps_v3.json", V1)
    json.dump(WHITELIST, open(os.path.join(HERE, "eval_whitelist.json"), "w"), indent=1)
    json.dump(CUSTOMERS, open(os.path.join(HERE, "eval_customers.json"), "w"))
    with open(os.path.join(HERE, "labelled_updates.jsonl"), "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    checks = [c for r in rows for c in r["truth"]["checks"]]
    ins = [c for r in rows for c in r["truth"]["checks"] if r["truth"]["in_scope"]]
    print(f"{len(rows)} lines, {len(checks)} checks ({sum(c['label'] == 'anomalous' for c in ins)} anomalous in scope, "
          f"{sum(c['label'] == 'benign' for c in ins)} benign, {len(checks) - len(ins)} out of scope), "
          f"{len({r['truth']['scenario'] for r in rows})} scenarios")
