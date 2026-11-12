"""Builds the offline demo (SYNTHETIC): VRP files, whitelist, customers and a replay that shows every alert type.

    python demo_data/make_demo.py          # rewrites the files in demo_data/

The story (one line per step in demo_updates.jsonl, timestamps 10 s apart):
  1. Cybernet's /18 and a /20 are Valid; AS24440's 203.0.113.0/24 is Valid.
  2. A scrubbing partner AS64520 announces 72.255.16.0/20 (not in the ROA): CRITICAL (first time), then withdraws.
  3. ROA change: 72.255.0.0/18 maxLength /20 -> /18 and the 203.0.113.0/24 ROA expires. No BGP update happens,
     yet the /20 turns INVALID_ML (HIGH) and 203.0.113.0/24 turns NotFound (LOW): re-validation on VRP change.
  4. ROAs fixed: both alerts resolve.
  5. Own too-specific /24 (HIGH), exact-prefix hijack (CRITICAL), customer not in ROA (HIGH), leased block whose
     ROA names another AS (HIGH), AS0 ROA hijack (CRITICAL), Cybernet prefix with no ROA (LOW), IPv6 too specific (HIGH).
  6. A single RIS peer carrying an Invalid route: stays PENDING (MIN_PEERS = 2), no NOC alert.
  7. The partner returns: HIGH this time (it has history). Peer sessions go down and hijacks are withdrawn: RESOLVED.
Prefixes are Cybernet's real 72.255.0.0/18 plus documentation ranges; ROAs and roles are invented for the demo.
"""
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
T0 = 1762000000
PEERS = [("rrc00", "193.0.0.56", 3333), ("rrc01", "195.66.224.175", 2914), ("rrc03", "80.249.208.34", 6939),
         ("rrc12", "80.81.192.85", 1299), ("rrc21", "37.49.237.1", 174)]

VRPS = [("AS9541", "72.255.0.0/18", 20), ("AS24440", "203.0.113.0/24", 24), ("AS64496", "198.51.100.0/24", 24),
        ("AS0", "192.0.2.0/24", 24), ("AS9541", "2001:db8:100::/40", 48)]
TIGHT = [("AS9541", "72.255.0.0/18", 18), ("AS64496", "198.51.100.0/24", 24), ("AS0", "192.0.2.0/24", 24),
         ("AS9541", "2001:db8:100::/40", 48)]
WHITELIST = {"72.255.0.0/18": [9541], "72.255.128.0/18": [9541], "203.0.113.0/24": [24440],
             "198.51.100.0/24": [9541], "192.0.2.0/24": [9541], "2001:db8:100::/40": [9541]}
CUSTOMERS = [64510]


def vrp_file(name, roas):
    data = {"metadata": {"generated": T0, "generatedTime": "2025-11-01T12:26:40Z"},
            "roas": [{"asn": a, "prefix": p, "maxLength": m, "ta": "apnic"} for a, p, m in roas]}
    json.dump(data, open(os.path.join(HERE, name), "w"), indent=1)


lines, t = [], [T0]


def msg(data):
    t[0] += 10
    data["timestamp"] = t[0]
    lines.append({"type": "ris_message", "data": data})


def ann(prefix, path, peers):
    for i in peers:
        h, ip, asn = PEERS[i]
        msg({"type": "UPDATE", "host": h, "peer": ip, "peer_asn": asn, "path": [asn] + path,
             "announcements": [{"next_hop": ip, "prefixes": [prefix]}]})


def wd(prefix, peers):
    for i in peers:
        h, ip, asn = PEERS[i]
        msg({"type": "UPDATE", "host": h, "peer": ip, "peer_asn": asn, "path": [], "withdrawals": [prefix]})


def reload(name):
    msg({"type": "VRP_RELOAD", "file": name})


def peer_down(i):
    h, ip, asn = PEERS[i]
    msg({"type": "RIS_PEER_STATE", "host": h, "peer": ip, "peer_asn": asn, "state": "down"})


if __name__ == "__main__":
    vrp_file("demo_vrps.json", VRPS)
    vrp_file("demo_vrps_roa_tightened.json", TIGHT)
    vrp_file("demo_vrps_fixed.json", VRPS)
    json.dump(WHITELIST, open(os.path.join(HERE, "demo_whitelist.json"), "w"), indent=1)
    json.dump(CUSTOMERS, open(os.path.join(HERE, "demo_customers.json"), "w"))

    ann("72.255.0.0/18", [3491, 9541], [0, 1, 2])              # 1. valid
    ann("72.255.32.0/20", [3491, 9541], [0, 1])
    ann("203.0.113.0/24", [1299, 24440], [3, 4])
    ann("72.255.16.0/20", [6453, 64520], [3, 4])               # 2. partner, first time -> CRITICAL
    wd("72.255.16.0/20", [3, 4])
    reload("demo_vrps_roa_tightened.json")                     # 3. ROA change -> HIGH + LOW without BGP updates
    reload("demo_vrps_fixed.json")                             # 4. fixed -> resolved
    ann("72.255.40.0/24", [3491, 9541], [0, 1])                # 5. own too specific -> HIGH
    ann("72.255.0.0/18", [174, 64666], [3, 4])                 #    hijack of the /18 -> CRITICAL
    ann("72.255.48.0/20", [3491, 9541, 64510], [0, 2])         #    customer not in ROA -> HIGH
    ann("198.51.100.0/24", [3491, 9541], [1, 2])               #    leased block, ROA names AS64496 -> HIGH
    ann("192.0.2.0/24", [6939, 64668], [0, 1])                 #    AS0 ROA -> CRITICAL
    ann("72.255.128.0/18", [3491, 9541], [1, 2])               #    no ROA -> LOW
    ann("2001:db8:100:ff00::/56", [3491, 9541], [3, 4])        #    IPv6 too specific -> HIGH
    ann("72.255.60.0/24", [3491, 9541], [2])                   # 6. one peer only -> stays PENDING
    ann("72.255.16.0/20", [6453, 64520], [0, 1])               # 7. partner returns -> HIGH (seen before)
    peer_down(3); peer_down(4)                                 #    sessions down: IPv6 alert + hijack lose peers
    wd("72.255.0.0/18", [3, 4])                                #    (already gone with the sessions)
    wd("192.0.2.0/24", [0, 1])                                 #    AS0 hijack withdrawn -> RESOLVED
    with open(os.path.join(HERE, "demo_updates.jsonl"), "w") as fh:
        fh.write("# offline demo for main.py --demo (built by make_demo.py; synthetic)\n")
        for l in lines:
            fh.write(json.dumps(l) + "\n")
    print(f"wrote {len(lines)} lines")
