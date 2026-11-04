"""Writes sample_updates.jsonl: SYNTHETIC labelled RIS-Live-style updates (gt = normal | path hijack | route leak) for demo / tests / evaluate.py.
Learning window (t < 1760000600) = normal routes only; detection part has normal routes, path hijacks, one of each route-leak kind, a benign
topology change (rules will flag it: an honest false positive), an unlabelled foreign-origin announcement (left to the unexpectedOrigin PoC) and a withdrawal."""
import json
rows = []
def m(ts, peer, host, path, prefix, gt=None, kind="ris_message", wd=None):
    d = dict(timestamp=ts, peer="192.0.2.%d" % (peer % 250), peer_asn=str(peer), host=host, type="UPDATE", path=path, origin="igp")
    d["announcements"] = [dict(prefixes=[prefix])] if prefix else []
    if wd: d["withdrawals"] = wd
    rows.append(dict(type=kind, data=d, **({"gt": gt} if gt else {})))
P, G, V6 = "72.255.0.0/18", "8.8.8.0/24", "2001:db8:100::/40"
base = [(3356, [3356, 17557, 9541], P), (1299, [1299, 3356, 17557, 9541], P), (6762, [6762, 17557, 9541], P), (2914, [2914, 3356, 17557, 9541], P),
        (2914, [2914, 3356, 15169], G), (1299, [1299, 15169], G), (3356, [3356, 17557, 9541], V6), (6939, [6939, 3356, 17557, 9541], P)]
t = 1760000010
for rep in range(3):                                           # learning window: each route 3 times
    for peer, path, pfx in base:
        m(t, peer, "rrc00", path, pfx); t += 20
t = 1760001000
def n(peer, path, pfx, gt="normal", host="rrc00"):
    global t
    m(t, peer, host, path, pfx, gt); t += 30
n(3356, [3356, 17557, 9541], P)                                                  # normal
n(1299, [1299, 3356, 17557, 9541], P)                                            # normal
n(2914, [2914, 3356, 15169], G, host="rrc01")                                    # normal
n(1299, [1299, 64510, 9541], P, "path hijack")                                   # forged-origin style: unseen AS next to the legitimate origin (paper Fig. 1 pattern)
n(2914, [2914, 3356, 64510, 9541], P, "path hijack")                             # same cause seen by another peer (correlated into one incident)
n(2914, [2914, 64511, 3356, 15169], G, "path hijack", host="rrc01")              # fabricated link in the middle of the path, origin legitimate
n(1299, [1299, 64500, 3356, 17557, 9541], P, "route leak")                       # transit-to-transit: 64500 took 3356's route and gave it to its other provider 1299
n(6939, [6939, 64501, 3356, 17557, 9541], P, "route leak")                       # transit-to-peer
n(2914, [2914, 64502, 17557, 9541], P, "route leak")                             # peer-to-peer
n(1299, [1299, 64504, 17557, 9541], P, "route leak")                             # peer-to-transit
n(174, [174, 3356, 17557, 9541], P, "normal")                                    # benign: new collector peer 174 (new link 174-3356, legitimate peering) -> a rules false positive
n(3356, [3356, 17557, 9541], P)                                                  # normal again (recovers the open incidents seen via peer 3356)
n(1299, [1299, 3356, 17557, 9541], P)
n(2914, [2914, 3356, 17557, 9541], P)
m(t, 2914, "rrc00", [], None, wd=[P], gt=None); t += 30                          # withdrawal (recovery)
n(6939, [6939, 3356, 17557, 9541], P)
n(1299, [1299, 64500, 3356, 17557, 9541], P, "route leak")                       # the leak again after it recovered -> a new incident, occurrence #2
rows.append(dict(type="ris_message", data=dict(timestamp=t, peer="192.0.2.77", peer_asn="1299", host="rrc00", type="UPDATE", path=[1299, 65000],
                 origin="igp", announcements=[dict(prefixes=["72.255.4.0/24"])]))); t += 30   # foreign origin: not a path anomaly (unexpectedOrigin PoC), deferred
with open("sample_updates.jsonl", "w") as f:
    for r in rows: f.write(json.dumps(r) + "\n")
print(len(rows), "lines")
