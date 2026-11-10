import json, sys, csv, time, statistics as st
from collections import defaultdict

alerts_file = sys.argv[1]
out_csv = sys.argv[2] if len(sys.argv) > 2 else "events.csv"
GAP = 60  # seconds: same peer, alerts closer than this = one event

rows = [json.loads(l) for l in open(alerts_file)]
rows.sort(key=lambda r: r["trigger_ts"])
by_peer = defaultdict(list)
for r in rows:
    by_peer[r["peer_asn"]].append(r)

events = []
for peer, rs in by_peer.items():
    cur = [rs[0]]
    for r in rs[1:]:
        if r["trigger_ts"] - cur[-1]["trigger_ts"] <= GAP:
            cur.append(r)
        else:
            events.append(cur); cur = [r]
    events.append(cur)
events.sort(key=lambda e: e[0]["trigger_ts"])

print(f"alerts: {len(rows)}")
print(f"events (peer bursts): {len(events)}")
print(f"distinct prefixes: {len({r['prefix'] for r in rows})}, distinct peers: {len(by_peer)}")
print("largest bursts (prefixes in one event):", sorted((len(e) for e in events), reverse=True)[:5])
print("median detection delay per event (s):",
      round(st.median(min(r['detection_delay_s'] for r in e) for e in events), 1))
print("median total time per event (s):",
      round(st.median(min(r['total_time_s'] for r in e) for e in events), 1))

with open(out_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["event_id", "peer_asn", "alerts_in_event", "example_prefix",
                "first_alert_utc", "detection_delay_s", "total_time_s", "verdict"])
    for i, e in enumerate(events, 1):
        w.writerow([i, e[0]["peer_asn"], len(e), e[0]["prefix"],
                    time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(e[0]["trigger_ts"])),
                    e[0]["detection_delay_s"], e[0]["total_time_s"], ""])
print("wrote", out_csv, "- fill the verdict column for a sample of events")