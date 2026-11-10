"""TEST 2 - LIVE data (RIPE RIS Live): latency measured in real time + accuracy against an independent rule.

  python live_eval.py record --minutes 60 --prefix 193.0.0.0/8 --prefix 194.0.0.0/8     # needs internet
  python live_eval.py record --minutes 60 --host rrc00 --prefix 193.0.0.0/8             # one collector only
  python live_eval.py record --from-file sample_updates.jsonl                           # dry run, no internet
  python live_eval.py analyze live_capture.jsonl --alerts live_alerts.jsonl             # re-analyse a saved run
  python live_eval.py analyze live_capture.jsonl --alerts live_alerts.jsonl --labels live_report_alerts.csv

record  runs the SAME detector as ris_live.py (default thresholds) on the live stream, saves every message
        (live_capture.jsonl), logs every alert with its timings (live_alerts.jsonl), then runs `analyze`.
analyze writes live_report.md / live_report.json / live_report_alerts.csv

Latency per alert (all in seconds; RIS timestamps are the collector's clock, so keep your PC clock synced):
  detection delay  = trigger message time - first withdrawal/path change of that flap      (how long the flap needed to look like a flap)
  feed delay       = time our PC received the trigger message - its RIS timestamp         (collector -> internet -> us)
  compute time     = time the detector spent processing the trigger message
  total time       = alert wall-clock time - first change of the flap  (~ detection delay + feed delay + compute)
Network latency (added): during `record` we also measure, and store in the capture file as {"net": ...} lines:
  DNS / TCP connect / TLS / WebSocket-upgrade time to ris-live.ripe.net (set-up), the WebSocket ping round trip every 10 s,
  and this PC's clock offset from NTP every 5 min. analyze then splits the feed delay into
  network one-way (~RTT/2) + RIS-side/other, and reports feed delay and total time corrected for the PC clock offset.
  Use --no-net to skip the probes (e.g. when UDP 123 is blocked).
Accuracy: live data has NO ground truth. Two honest substitutes:
  (a) agreement with the independent count rule in timing.py applied to the recorded stream (precision / recall vs that rule)
  (b) MANUAL verification: fill the `verdict` column (TRUE/FALSE) of live_report_alerts.csv after checking each alert
      (e.g. RIPEstat / bgp.tools for that prefix and time), then re-run analyze with --labels.
"""
import argparse, asyncio, csv, json, statistics, time
from timing import TimedDetector, changes, qualifies, pct
import netlat

URL = "wss://ris-live.ripe.net/v1/ws/?client=fyp-flap-eval"


def stat(xs, nd=3):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return dict(n=len(xs), median=round(statistics.median(xs), nd), mean=round(statistics.mean(xs), nd),
                p95=round(pct(xs, 95), nd), min=round(min(xs), nd), max=round(max(xs), nd))


class Recorder:
    """Feeds messages to the detector and writes the capture + per-alert timing log."""

    def __init__(self, cap_path, alert_path, header, cfg):
        self.det = TimedDetector(source="online", **cfg)
        self.cap, self.al = open(cap_path, "w", encoding="utf-8"), open(alert_path, "w", encoding="utf-8")
        self.cap.write(json.dumps({"header": {**header, "config": cfg}}) + "\n")
        self.n = self.alerts = 0
        self.t_start = time.time()

    def handle(self, d, recv=None):
        recv = time.time() if recv is None else recv
        if d.get("type") not in ("UPDATE", "RIS_PEER_STATE"):
            return []
        self.cap.write(json.dumps({"recv": recv, "data": d}) + "\n")
        self.n += 1
        t = time.perf_counter()
        out = self.det.process(d)
        proc = time.perf_counter() - t
        for a in out:
            if a["event"] != "onset":
                continue
            wall = time.time() if self._live else recv + proc
            rec = dict(prefix=a["prefix"], peer=a["key"][2], peer_asn=a["peer_asn"], collector=a["collector"],
                       first_ts=a["first_ts"], trigger_ts=a["ts"], recv_wall=recv, alert_wall=wall,
                       compute_ms=round(proc * 1000, 4), events_to_detect=a["events_to_detect"], penalty=a["penalty"],
                       withdrawals=a["withdrawals"], path_changes=a["path_changes"], severity=a["severity"],
                       as_path=a["as_path"], detection_delay_s=round(a["ts"] - a["first_ts"], 3),
                       feed_delay_s=round(recv - a["ts"], 3), total_time_s=round(wall - a["first_ts"], 3))
            self.al.write(json.dumps(rec) + "\n"); self.al.flush()
            self.alerts += 1
            print(f"[{time.strftime('%H:%M:%S')}] FLAP {a['prefix']} peer AS{a['peer_asn']} via {a['collector']}: "
                  f"detected {rec['detection_delay_s']}s after the first change, total {rec['total_time_s']}s", flush=True)
        return out

    _live = True

    def net(self, d):
        self.cap.write(json.dumps({"net": d}) + "\n")

    def close(self):
        self.cap.close(); self.al.close()


async def probe(ws, rec, every=10, ntp_every=300):
    """runs beside the reader: WebSocket ping round trip every `every` s, NTP clock offset every `ntp_every` s."""
    loop, last_ntp = asyncio.get_running_loop(), 0.0
    while True:
        await asyncio.sleep(every)
        try:
            t = time.perf_counter(); waiter = await ws.ping(); await asyncio.wait_for(waiter, 15)
            rec.net(dict(kind="ws_rtt", t=time.time(), rtt_ms=round((time.perf_counter() - t) * 1000, 2)))
        except Exception:
            pass
        if time.time() - last_ntp > ntp_every:
            last_ntp = time.time()
            o = await loop.run_in_executor(None, netlat.sntp_offset)
            rec.net(dict(kind="ntp", t=time.time(), **(o or dict(offset_s=None))))


async def live(rec, a):
    import websockets
    loop = asyncio.get_running_loop()
    net_on = getattr(a, "net", False)
    if net_on:                                        # set-up cost to the RIS Live server: DNS / TCP / TLS
        rec.net(dict(kind="setup", **((await loop.run_in_executor(None, netlat.connect_times)) or {})))
    subs = [{"type": "UPDATE", "moreSpecific": a.more_specific, "socketOptions": {"includeRaw": False},
             **({"prefix": p} if p else {}), **({"host": a.host} if a.host else {})} for p in (a.prefix or [None])]
    subs.append({"type": "RIS_PEER_STATE", "socketOptions": {"includeRaw": False}, **({"host": a.host} if a.host else {})})
    end = time.time() + a.minutes * 60
    last_tick = last_status = time.time()
    while time.time() < end:
        ptask = None
        try:
            t_open = time.perf_counter()
            async with websockets.connect(URL, ping_interval=30) as ws:
                rec.net(dict(kind="ws_open", ms=round((time.perf_counter() - t_open) * 1000, 2)))
                if net_on:
                    ptask = asyncio.create_task(probe(ws, rec))
                for s in subs:
                    await ws.send(json.dumps({"type": "ris_subscribe", "data": s}))
                print(f"connected; recording {a.minutes} min; watching {a.prefix or 'host ' + str(a.host)}", flush=True)
                while time.time() < end:
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=5)
                    except asyncio.TimeoutError:
                        raw = None
                    now = time.time()
                    if raw:
                        m = json.loads(raw)
                        if m.get("type") == "ris_error":
                            print("RIS error:", m.get("data")); continue
                        if m.get("type") == "ris_message":
                            rec.handle(m["data"], now)
                    if now - last_tick > 10:
                        rec.det.tick(); last_tick = now
                    if now - last_status > 30:
                        last_status = now
                        print(f"[{time.strftime('%H:%M:%S')}] {rec.n} messages, {len(rec.det.routes)} routes, "
                              f"{rec.alerts} alerts, {int(end - now)}s left", flush=True)
        except Exception as e:
            print("connection lost:", e, "- retrying in 5s", flush=True)
            await asyncio.sleep(5)
        finally:
            if ptask:
                ptask.cancel()


def analyze(cap_path, alert_path=None, out="live_report", labels=None):
    lines = [json.loads(l) for l in open(cap_path, encoding="utf-8")]
    header, msgs = lines[0].get("header", {}), [l for l in lines[1:] if "data" in l]
    cfg = header.get("config", {})
    data = [l["data"] for l in msgs]
    net = [l["net"] for l in lines[1:] if "net" in l]
    md = [f"# Route flapping: LIVE test", f"Capture: {cap_path}; {len(msgs)} messages; watching {header.get('watching', '?')}; "
          f"detector settings {cfg}.", ""]
    # ---- feed + pipeline latency (every message, even with zero flaps)
    recv_t = [l["recv"] for l in msgs]
    dur = (max(recv_t) - min(recv_t)) if len(recv_t) > 1 else 0
    feed = [l["recv"] - l["data"]["timestamp"] for l in msgs if l["data"].get("timestamp") is not None]
    det = TimedDetector(source="live-replay", **cfg)
    comp, alerts = [], []
    for d in data:
        t = time.perf_counter(); evs = det.process(d); comp.append((time.perf_counter() - t) * 1000)
        alerts += [a for a in evs if a["event"] == "onset"]
    md += ["## Feed and pipeline latency (all messages)", f"- recorded for {dur / 60:.1f} min = {len(msgs) / max(dur, 1):.1f} messages/s; "
           f"{det.stats['withdrawals']} withdrawals, {det.stats['announcements']} announcements, {det.stats['peer_resets']} peer resets",
           f"- feed delay (our receive time - RIS timestamp), s: {stat(feed)}",
           f"- detector compute per message, ms (replay on this machine): {stat(comp, 4)}", ""]
    # ---- network latency + clock correction
    setup = next((n for n in net if n.get("kind") == "setup" and n.get("tcp_ms") is not None), None)
    wso = [n["ms"] for n in net if n.get("kind") == "ws_open"]
    rtt = [n["rtt_ms"] for n in net if n.get("kind") == "ws_rtt"]
    ntp = [n for n in net if n.get("kind") == "ntp" and n.get("offset_s") is not None]
    offset = statistics.median(n["offset_s"] for n in ntp) if ntp else None
    netinfo = dict(setup=setup, ws_open_ms=wso, ws_rtt_ms=stat(rtt, 2), ntp_offset_s=offset,
                   ntp_offsets=[n["offset_s"] for n in ntp])
    if net:
        md += ["## Network latency (live probes)"]
        md += [f"- set-up to ris-live.ripe.net: DNS {setup['dns_ms']} ms, TCP connect {setup['tcp_ms']} ms (= 1 round trip), "
               f"TLS {setup['tls_ms']} ms, WebSocket upgrade {wso[0] if wso else '?'} ms (server {setup['addr']})" if setup else
               "- set-up probe (DNS/TCP/TLS) not available"]
        md += [f"- WebSocket ping round trip, ms: {stat(rtt, 2)}" if rtt else "- no WebSocket ping samples (run shorter than 10 s?)"]
        if rtt:
            md += [f"- network one-way delay estimate = RTT/2 = {statistics.median(rtt) / 2:.1f} ms median (assumes a symmetric path)"]
        if offset is not None:
            offs = [n["offset_s"] for n in ntp]
            md += [f"- PC clock vs NTP ({ntp[0]['server']}): offset {offset:+.3f} s median over {len(offs)} samples "
                   f"(range {min(offs):+.3f} .. {max(offs):+.3f}; positive = PC clock is behind). Added to every PC timestamp below."]
            fc = [f + offset for f in feed]
            md += [f"- feed delay corrected for the clock offset, s: {stat(fc)}"]
            if rtt and fc:
                one = statistics.median(rtt) / 2000
                md += [f"- split of the median corrected feed delay {statistics.median(fc):.3f} s: network one-way ~{one:.3f} s "
                       f"+ RIS-side / other ~{statistics.median(fc) - one:.3f} s (collector -> RIS Live server -> send, queueing, our read)"]
        else:
            md += ["- clock offset NOT measured (UDP 123 blocked?): feed delay and total time below include any PC-vs-RIS clock error"]
        md += [""]
    # ---- alert latency (measured live)
    live_alerts = [json.loads(l) for l in open(alert_path, encoding="utf-8")] if alert_path else []
    md += [f"## Flap alerts: {len(alerts)} raised in replay, {len(live_alerts)} logged live",
           "(if these differ, the live run and the replay saw a different clock for `tick`; the replay uses stream time)"]
    if live_alerts:
        md += ["", "| Latency (live) | n | median | mean | p95 | min | max |", "|---|---|---|---|---|---|---|"]
        for lab, key in (("Detection delay (s)", "detection_delay_s"), ("Feed delay (s)", "feed_delay_s"),
                         ("Compute (ms)", "compute_ms"), ("TOTAL time to detect (s)", "total_time_s"),
                         ("Changes needed before alert", "events_to_detect")):
            s = stat([x[key] for x in live_alerts]); md.append(f"| {lab} | {s['n']} | {s['median']} | {s['mean']} | {s['p95']} | {s['min']} | {s['max']} |")
        if offset is not None:
            for lab, key in (("Feed delay, clock-corrected (s)", "feed_delay_s"), ("TOTAL time to detect, clock-corrected (s)", "total_time_s")):
                s = stat([x[key] + offset for x in live_alerts]); md.append(f"| {lab} | {s['n']} | {s['median']} | {s['mean']} | {s['p95']} | {s['min']} | {s['max']} |")
            if rtt:
                tot = statistics.median(x["total_time_s"] + offset for x in live_alerts)
                md += ["", f"Network share: one-way ~{statistics.median(rtt) / 2000:.3f} s of a median {tot:.1f} s total = "
                           f"{100 * statistics.median(rtt) / 2000 / tot:.2f}%. The rest is the flap itself unfolding (detection delay)."]
    elif alerts:
        s = stat([a["ts"] - a["first_ts"] for a in alerts]); md += ["", f"Detection delay from replay (s): {s}"]
    else:
        md += ["", "No flap alert fired: flaps are rare. Record longer or watch more address space; the feed latency above is still valid."]
    # ---- accuracy vs the independent rule
    ch = changes(data); truth = {k: q for k, ts in ch.items() if (q := qualifies(ts)) is not None}
    fk = {a["key"]: a for a in alerts}                 # detector key = (prefix, collector, peer): same as changes()
    F, T, P = set(fk), set(truth), set(ch)
    tp, fp, fn = F & T, F - T, T - F
    tn = P - F - T
    pr = len(tp) / len(F) if F else None; rc = len(tp) / len(T) if T else None
    f1 = 2 * pr * rc / (pr + rc) if pr and rc else None
    md += ["", "## Accuracy against the independent count rule (>=4 changes/15 min or >=5/90 min, resets excluded)",
           f"- routes with at least one change (population): {len(P)}; flapping by the rule: {len(T)}; alerted by the detector: {len(F)}",
           f"- TP {len(tp)} | FP {len(fp)} | FN {len(fn)} | TN {len(tn)}",
           f"- precision {pr if pr is None else round(pr, 3)} | recall {rc if rc is None else round(rc, 3)} | F1 {f1 if f1 is None else round(f1, 3)} | "
           f"accuracy {round((len(tp) + len(tn)) / len(P), 4) if P else None} (dominated by TN: most routes change once)"]
    if not T:
        md.append("- NOTE: no route met the rule in this window, so recall is undefined and 'accuracy' is not meaningful "
                  "(any alert counts as a false positive only relative to our rule); do not quote it as detector accuracy. Report precision of any alerts (manual verdicts) and the false-alarm count instead.")
    lead = [truth[k] - fk[k]["ts"] for k in tp]
    if lead:
        md.append(f"- for TPs, rule satisfied minus detector alert time, s (positive = detector fired first): {stat(lead, 1)}")
    if fp:
        md += ["", "False-positive candidates (alerted, rule not satisfied):"] + [f"- {k[0]} via {k[1]}: {len(ch.get(k, []))} changes" for k in sorted(fp)[:20]]
    if fn:
        md += ["", "Missed by the detector (rule satisfied):"] + [f"- {k[0]} via {k[1]}: {len(ch[k])} changes" for k in sorted(fn)[:20]]
    # ---- manual verification sheet / score
    rows = []
    for i, a in enumerate(alerts, 1):
        k = a["key"]
        rows.append(dict(id=i, prefix=a["prefix"], collector=a["collector"], peer_asn=a["peer_asn"],
                         first_change_utc=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(a["first_ts"])),
                         alert_utc=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(a["ts"])), withdrawals=a["withdrawals"],
                         path_changes=a["path_changes"], penalty=a["penalty"], rule_agrees=k in T, verdict=""))
    csv_path = out + "_alerts.csv"
    manual = None
    if labels:
        done = [r for r in csv.DictReader(open(labels, encoding="utf-8")) if r.get("verdict", "").strip().upper() in ("TRUE", "FALSE")]
        if done:
            t = sum(r["verdict"].strip().upper() == "TRUE" for r in done)
            manual = dict(labelled=len(done), true=t, precision=round(t / len(done), 3))
            md += ["", f"## Manual verification: {manual['true']} of {manual['labelled']} alerts confirmed as real flapping "
                   f"= precision {manual['precision']}"]
        else:
            md += ["", f"## Manual verification: {labels} has no filled `verdict` column (needs TRUE or FALSE per alert)"]
    else:
        md += ["", f"## Manual verification: open {csv_path}, fill `verdict` (TRUE/FALSE) per alert, then re-run analyze with --labels {csv_path}"]
    if rows:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    md += ["", "## Limits of this live test", "- no ground truth: precision/recall are relative to our own counting rule, not to confirmed incidents",
           "- recall is only meaningful for routes whose announcement we saw (RIS Live sends no initial table; withdrawals of unseen routes are ignored)",
           "- flaps are rare: a short run may contain few or none; results are for this window, this prefix set and these collectors only"]
    open(out + ".md", "w", encoding="utf-8").write("\n".join(md) + "\n")
    json.dump(dict(messages=len(msgs), duration_s=dur, feed_delay_s=stat(feed), compute_ms=stat(comp, 4),
                   alerts_live=live_alerts, alerts_replay=len(alerts), network=netinfo,
                   accuracy=dict(population=len(P), truth=len(T), flagged=len(F), tp=len(tp), fp=len(fp), fn=len(fn), tn=len(tn),
                                 precision=pr, recall=rc, f1=f1), manual=manual), open(out + ".json", "w", encoding="utf-8"), indent=1)
    print("\n".join(md))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record"); r.add_argument("--minutes", type=float, default=60)
    r.add_argument("--prefix", action="append"); r.add_argument("--host", help="one RIS collector, e.g. rrc00")
    r.add_argument("--no-more-specific", dest="more_specific", action="store_false")
    r.add_argument("--from-file", help="dry run: replay a JSONL instead of connecting")
    r.add_argument("--capture", default="live_capture.jsonl"); r.add_argument("--alerts", default="live_alerts.jsonl")
    r.add_argument("--out", default="live_report")
    r.add_argument("--no-net", dest="net", action="store_false", help="skip the network/NTP probes")
    r.add_argument("--half-life", type=int, default=900); r.add_argument("--suppress", type=int, default=2000)
    r.add_argument("--reuse", type=int, default=750); r.add_argument("--min-peers", type=int, default=1)
    an = sub.add_parser("analyze"); an.add_argument("capture"); an.add_argument("--alerts"); an.add_argument("--out", default="live_report")
    an.add_argument("--labels")
    a = ap.parse_args()
    if a.cmd == "analyze":
        analyze(a.capture, a.alerts, a.out, a.labels)
    else:
        if not (a.from_file or a.prefix or a.host):
            ap.error("give --prefix and/or --host (the whole table is too much)")
        cfg = dict(half_life=a.half_life, suppress=a.suppress, reuse=a.reuse, min_peers=a.min_peers)
        rec = Recorder(a.capture, a.alerts, {"watching": a.from_file or a.prefix or a.host, "minutes": a.minutes}, cfg)
        try:
            if a.from_file:
                Recorder._live = False
                for line in open(a.from_file, encoding="utf-8"):
                    d = json.loads(line)["data"]
                    rec.handle(d, d.get("timestamp"))
            else:
                asyncio.run(live(rec, a))
        except KeyboardInterrupt:
            print("\nstopped early; analysing what was recorded")
        rec.close()
        analyze(a.capture, a.alerts, a.out)
