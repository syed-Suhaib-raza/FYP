"""Group raw alerts from a live_eval.py run (xxx_alerts.jsonl) into events, so a burst of alerts for one cause is counted
and manually verified ONCE. Counterpart of flapping/cluster_events.py.

   python cluster_events.py full_alerts.jsonl full_events.csv
   python cluster_events.py pfx_alerts.jsonl pfx_events.csv
   python cluster_events.py live_alerts.jsonl                  # -> events.csv
   python cluster_events.py live_alerts.jsonl ev.csv --gap 600 # change the gap (seconds)

Event = the same (prefix, collector) alerting again within GAP seconds (default 300; hijacks/leaks are rarer and slower-moving
than flaps). The summary also counts DISTINCT CAUSES (same rule + same AS link / same leaker, prefix numbers removed), because one
misconfigured AS leaking 500 prefixes is 500 events but ONE cause. Fill the `verdict` column (TRUE/FALSE) for a sample of events and
pass the CSV to:  python live_eval.py analyze <capture> --alerts <alerts> --out <report> --labels <events csv>
"""
import argparse, csv, json, re, statistics, time
from collections import Counter, defaultdict

import llm_eval

GAP = 300


def cause_key(r):
    s = re.sub(r"\(baseline upstreams:[^)]*\)", "", r.get("signals") or "")
    s = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d+\b|[0-9a-fA-F:]+:[0-9a-fA-F:]*/\d+", "<prefix>", s)
    return (r.get("anomaly_type"), r.get("subtype"), s.strip())


def cluster(rows, gap=GAP):
    rows = sorted(rows, key=lambda r: r.get("msg_ts") or 0)
    by_key = defaultdict(list)
    for r in rows:
        by_key[(r["prefix"], r["collector"])].append(r)
    events = []
    for rs in by_key.values():
        cur = [rs[0]]
        for r in rs[1:]:
            if (r.get("msg_ts") or 0) - (cur[-1].get("msg_ts") or 0) <= gap:
                cur.append(r)
            else:
                events.append(cur); cur = [r]
        events.append(cur)
    events.sort(key=lambda e: e[0].get("msg_ts") or 0)
    return events, by_key


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("alerts"); ap.add_argument("out", nargs="?", default="events.csv"); ap.add_argument("--gap", type=int, default=GAP)
    a = ap.parse_args(argv)
    rows = [json.loads(l) for l in open(a.alerts, encoding="utf-8") if l.strip()]
    events, by_key = cluster(rows, a.gap)

    print(f"alerts: {len(rows)}")
    print(f"events (prefix/collector bursts, gap {a.gap}s): {len(events)}")
    print(f"distinct prefixes: {len({r['prefix'] for r in rows})}, distinct (prefix, collector) pairs: {len(by_key)}")
    print(f"distinct causes (same rule + same link/leaker): {len({cause_key(r) for r in rows})}")
    print("largest bursts (alerts in one event):", sorted((len(e) for e in events), reverse=True)[:5])
    print("by anomaly type:", dict(Counter(r["anomaly_type"] for r in rows)))
    print("by rule:", dict(Counter(r["subtype"] for r in rows)))
    print("by severity:", dict(Counter(r["severity"] for r in rows)))
    fd = sorted(e[0]["feed_delay_s"] for e in events if e[0].get("feed_delay_s") is not None)
    if fd:
        print("feed delay (s) of first alert in each event, median:", round(statistics.median(fd), 3))
    mv = Counter(llm_eval.vr(r) for r in rows)
    if any(k != "unscored" for k in mv):
        print("model verdict on the alerts:", dict(mv), "(unscored = model off, rate-capped or failed)")
    top = Counter(cause_key(r) for r in rows).most_common(5)
    if top:
        print("most frequent causes:")
        for (t, rule, s), n in top:
            print(f"   {n:5d} x {t}/{rule}: {s[:110]}")

    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["event_id", "prefix", "collector", "alerts_in_event", "types_in_event", "anomaly_type", "rule", "severity", "as_path", "signals",
                    "first_alert_utc", "feed_delay_s", "compute_ms", "llm_label", "llm_agrees", "llm_view", "verdict"])
        for i, e in enumerate(events, 1):
            x = e[0]
            w.writerow([i, x["prefix"], x["collector"], len(e), "+".join(sorted({y["anomaly_type"] for y in e})), x["anomaly_type"], x["subtype"], x["severity"], x["as_path"], x.get("signals", ""),
                        time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(x["msg_ts"])) if x.get("msg_ts") else "",
                        x.get("feed_delay_s"), x.get("compute_ms"), x.get("llm_label"), x.get("llm_agrees"), llm_eval.vr(x), ""])
    print("wrote", a.out, "- fill the verdict column (TRUE/FALSE) for a sample of events" if events else "- no events (no alerts fired)")


if __name__ == "__main__":
    main()
