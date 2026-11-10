"""TEST 2 - LIVE data (RIPE RIS Live) for the AS-path PoC: latency measured in real time + a manual verification sheet.
Counterpart of flapping/live_eval.py; TEST 1 (simulated, labelled) is eval.py.

  # Run A - the WHOLE collector rrc00, route-leak (valley-free) rule only (no baseline needed)
  python live_eval.py record --minutes 45 --host rrc00 --capture full_capture.jsonl --alerts full_alerts.jsonl --out full_report
  # Run B - three /8 blocks on rrc00, ALL rules (leak + new-link + new-origin-upstream) against a baseline learnt first
  python live_eval.py record --minutes 45 --host rrc00 --prefix 193.0.0.0/8 --prefix 194.0.0.0/8 --prefix 195.0.0.0/8 \\
                             --capture pfx_capture.jsonl --alerts pfx_alerts.jsonl --out pfx_report
  python cluster_events.py full_alerts.jsonl full_events.csv
  python cluster_events.py pfx_alerts.jsonl pfx_events.csv

  python live_eval.py record --minutes 5 --host rrc00 --capture trial.jsonl --alerts trial_alerts.jsonl --out trial_report   # 5-min trial first
  python live_eval.py record --from-file sample_updates.jsonl --out dry_report            # dry run, no internet (tests this script itself)
  python live_eval.py analyze full_capture.jsonl --alerts full_alerts.jsonl --out full_report --labels full_events.csv      # after manual verdicts

How the flags map (the AS-path PoC has no --host of its own, this script adds it):
  --host rrc00           = RIS collector filter (same as aspath.py --collector rrc00)
  --host only            = --scope all : every UPDATE of that collector, valley rule only (no per-prefix baseline exists for a firehose)
  --prefix ... (+ host)  = --scope watch on those prefixes (and their more-specifics): all rules. These prefixes have no expected-origin list
                           (a /8 has thousands of origins), so ANY origin is accepted and learnt (origin hijacks stay the
                           unexpectedOrigin PoC's job) and the baseline is learnt LIVE during the first --learn seconds (default 600) into
                           <out>_baseline.json (fresh each run, your baseline.json is never touched). Attacks inside the learning window are
                           learnt as normal -- stated limit. Add --baseline-source history to use RIPEstat history instead (slow for a /8).
  --scope / --whitelist / --baseline-source / --baseline given explicitly always win.

record  runs the SAME Monitor as `aspath.py live` (rules + the model when --llm hf/llamacpp/mock is given; the run scripts pass --llm hf), saves every UPDATE (capture) and every NEW incident
        with its timing (alerts), then calls analyze.
analyze streams the capture (constant memory), writes <out>.md / <out>.json / <out>_alerts.csv.

Latency per alert (s; RIS timestamps are the collector's clock, so keep your PC clock synced: Windows `w32tm /resync`):
  feed delay   = our receive time - RIS timestamp   (collector -> internet -> us)
  compute time = time the detector spent on that message
An AS-path alert fires on a SINGLE announcement (no penalty build-up like flapping), so feed delay + compute time IS the latency budget.
Backlog check: if the detector cannot keep up, feed delay grows during the run; the report compares the first and last 10% of the run.

Accuracy: live BGP has NO ground truth for path hijacks / route leaks. Two honest substitutes: (a) internal consistency (rule type counts,
model agreement if --llm), (b) MANUAL verification: fill `verdict` (TRUE/FALSE) per alert/event (RIPEstat / bgp.tools / CAIDA AS-rank), re-run analyze with --labels.
"""
import argparse, asyncio, csv, json, os, re, statistics, sys, time
from array import array
from collections import Counter

from aspath import ASRel, Monitor, common, history_baseline, load_watch, subscriptions, use_real_asrel
from llm import make_llm
import llm_eval

URL = "wss://ris-live.ripe.net/v1/ws/?client=fyp-aspath-eval"


class AnyOrigin(set):
    """Expected-origin list of a broad prefix scope (e.g. a /8): every origin is accepted (and learnt in the learning window)."""
    def __contains__(self, x):
        return True


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    i = (len(xs) - 1) * p / 100
    lo, hi = int(i), min(int(i) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (i - lo)


def stat(xs, nd=3):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return dict(n=len(xs), median=round(statistics.median(xs), nd), mean=round(statistics.mean(xs), nd),
                p95=round(pct(xs, 95), nd), min=round(min(xs), nd), max=round(max(xs), nd))


def given(flag, argv=None):
    return any(x == flag or x.startswith(flag + "=") for x in (sys.argv[1:] if argv is None else argv))


def resolve(a, argv=None):
    """Turn the flapping-style command line into the AS-path PoC's settings (see module docstring). Mutates and returns a."""
    a.collector = a.collector or a.host
    a.host = a.collector
    if not given("--scope", argv):
        a.scope = "all" if (a.collector and not a.prefix and not a.from_file) else "watch"
    a.auto_baseline = False
    if a.scope != "all" and (a.prefix or a.from_file):
        if not given("--baseline-source", argv):
            a.baseline_source = "learn"
        if not given("--baseline", argv):
            a.baseline, a.auto_baseline = a.out + "_baseline.json", True
    return a


_LLM = {}


def get_llm(a):
    """Load the model ONCE per process (a Hugging Face model can take a minute and gigabytes), reuse it for the self-test and the run."""
    key = getattr(a, "llm", "none")
    if key not in _LLM:
        _LLM[key] = make_llm(a)
    return _LLM[key]


SELFTEST_PREFIX, SELFTEST_ORIGIN = "198.51.100.0/24", 64500


def _msg(ts, path, prefix):
    return {"timestamp": ts, "peer": "192.0.2.1", "peer_asn": str(path[0]), "host": "rrc00", "type": "UPDATE", "path": path, "origin": "igp",
            "announcements": [{"prefixes": [prefix]}]}


def llm_selftest(a):
    """Before a 45-minute run: prove the model is really loaded and answers. A tiny throwaway Monitor learns one path for a documentation
    prefix, then sees a replaced upstream (a path hijack shape); the alert it raises must carry a usable model verdict.
    Returns (ok, detail). Without this, a mis-loaded model would silently give 45 minutes of 'rules only' data."""
    llm = get_llm(a)
    if llm is None:
        return False, "make_llm returned no model"
    try:
        mon = Monitor(None, {SELFTEST_PREFIX: [SELFTEST_ORIGIN]}, ASRel(None), llm, (), 50, "eval", "repo", 8, 0,
                      a.min_support, a.len_delta, a.origin_policy, True, True)
        path = [64511, 64501, SELFTEST_ORIGIN]
        for ts in (0, 15, 30):
            mon.process(_msg(ts, path, SELFTEST_PREFIX))
        mon.process(_msg(45, [64599, 64598], "203.0.113.0/24"))
        t = time.perf_counter()
        out = mon.process(_msg(65, [64511, 64502, SELFTEST_ORIGIN], SELFTEST_PREFIX))
        dt = time.perf_counter() - t
    except Exception as e:
        return False, f"model call raised {type(e).__name__}: {e}"
    if not out:
        return False, "the self-test hijack raised no alert, so the model was not reached (PoC rules changed?)"
    v = llm_eval.vr(out[0])
    if v in ("unscored", "other"):
        return False, f"alert raised but the model verdict is unusable (llm_label={out[0].get('llm_label')!r})"
    return True, f"model {out[0].get('model')!r} answered {out[0].get('llm_label')!r} ({v}) in {dt:.2f} s"


def setup_monitor(a):
    """Same construction as aspath.py's live mode: real CAIDA relationships (also for --scope all: the valley rule needs them), watch list, baseline."""
    if not a.from_file:
        use_real_asrel(a)
    wl, asns = load_watch(a.whitelist, a.asns)
    if a.prefix:
        wl = {p: wl.get(p, []) for p in a.prefix}
    if a.scope != "all" and a.from_file is None and not (a.prefix or wl or asns):
        raise SystemExit("nothing to watch: give --prefix, --host (whole collector), or fill whitelist.json / watch_asns.json")
    mon = Monitor(None, wl, ASRel(a.as_rel if os.path.exists(a.as_rel) else None), get_llm(a), asns, a.learn, "online",
                  a.prompt, a.top_k, a.cooldown, a.min_support, a.len_delta, a.origin_policy, a.ownership_evidence, a.history_evidence)
    mon.max_llm_per_min = a.max_llm_per_min or 0       # 0 = NO cap: the model judges every alert in both runs (pass --max-llm-per-min N to cap it)
    if getattr(a, "llm", "none") not in (None, "none") and get_llm(a) is None:
        raise SystemExit(f"--llm {a.llm}: no model could be loaded. Fix that first (a run without the model would not be the full PoC).")
    if a.scope == "all":
        mon.det.watch = {"GLOBAL": (None, set())}; mon.learn = 0; mon.ownership = False; wl, asns = {}, []
    else:
        for k, (net, exp) in list(mon.det.watch.items()):
            if net is not None and not exp:                      # broad prefix with no expected origins: accept and learn any origin
                mon.det.watch[k] = (net, AnyOrigin())
        if a.auto_baseline:
            pass                                                 # fresh baseline: learnt live in the first --learn seconds
        elif not (a.baseline_source == "history" and history_baseline(a, mon)):
            mon.load_baseline(a.baseline)
    return mon, wl, asns


class Recorder:
    """Feeds UPDATEs to the Monitor and writes the capture + per-alert timing log + per-message compute time for ALL messages."""

    def __init__(self, mon, cap_path, alert_path, header, quiet_after=200):
        self.mon, self.header, self.quiet_after = mon, header, quiet_after
        self.cap, self.al = open(cap_path, "w", encoding="utf-8"), open(alert_path, "w", encoding="utf-8")
        self.cap.write(json.dumps({"header": header}) + "\n")
        self.n = self.alerts = 0
        self.proc = array("d")                                   # seconds spent in Monitor.process per UPDATE (all messages)
        self._live = True

    def handle(self, d, recv=None):
        recv = time.time() if recv is None else recv
        if d.get("type") != "UPDATE":
            return []
        self.cap.write(json.dumps({"recv": recv, "data": d}) + "\n")
        self.n += 1
        t = time.perf_counter()
        out = self.mon.process(d)
        proc = time.perf_counter() - t
        self.proc.append(proc)
        for inc in out:
            if inc["count"] != 1:          # same cause seen again / by another peer: merged into the open incident, not a new alert
                continue
            wall = time.time() if self._live else recv
            msg_ts = d.get("timestamp")
            feed_delay = (recv - msg_ts) if msg_ts is not None else None
            rec = dict(prefix=inc["prefix"], watched=inc["watched"], peer_asn=inc["peer_asn"], collector=inc["collector"],
                       anomaly_type=inc["anomaly_type"], subtype=inc["subtype"], severity=inc["severity"], as_path=inc["as_path"],
                       origin=inc["origin"], expected_origin=inc["expected_origin"], signals=inc["signals"],
                       llm_label=inc["llm_label"], llm_agrees=inc["llm_agrees"], model=inc["model"],
                       msg_ts=msg_ts, recv_wall=recv, alert_wall=wall,
                       feed_delay_s=round(feed_delay, 3) if feed_delay is not None else None, compute_ms=round(proc * 1000, 4))
            self.al.write(json.dumps(rec) + "\n"); self.al.flush()
            self.alerts += 1
            if self.alerts <= self.quiet_after or self.alerts % 50 == 0:      # a firehose run can raise thousands: do not drown the console
                print(f"[{time.strftime('%H:%M:%S')}] #{self.alerts} {inc['severity'].upper()} {inc['anomaly_type']} {inc['prefix']} "
                      f"path {inc['as_path']} | {inc['signals']}", flush=True)
        self.mon.drain_recovered()
        return out

    def close(self, runstats_path=None):
        self.cap.close(); self.al.close()
        if runstats_path:
            json.dump(dict(header=self.header, messages=self.n, alerts=self.alerts, compute_ms_all_messages=stat([x * 1000 for x in self.proc], 4),
                           monitor_stats=self.mon.stats), open(runstats_path, "w", encoding="utf-8"), indent=1)


async def live(rec, a, subs):
    import websockets
    end = time.time() + a.minutes * 60
    last_status = time.time()
    while time.time() < end:
        try:
            async with websockets.connect(URL, ping_interval=30, max_size=None) as ws:
                for s in subs:
                    await ws.send(json.dumps({"type": "ris_subscribe", "data": s}))
                print(f"connected; recording {a.minutes} min", flush=True)
                while time.time() < end:
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=5)
                    except asyncio.TimeoutError:
                        raw = None
                    now = time.time()
                    if raw:
                        m = json.loads(raw)
                        if m.get("type") == "ris_message":
                            rec.handle(m["data"], now)
                    if now - last_status > 30:
                        last_status = now
                        print(f"[{time.strftime('%H:%M:%S')}] {rec.n} messages, {rec.alerts} alerts, "
                              f"{int(end - now)}s left, stats {rec.mon.stats}", flush=True)
        except Exception as e:
            print("connection lost:", e, "- retrying in 5s", flush=True)
            await asyncio.sleep(5)


def build_subs(a, wl, asns):
    if a.scope == "all":
        return [{"type": "UPDATE", "socketOptions": {"includeRaw": False}, **({"host": a.collector} if a.collector else {})}]
    subs = subscriptions(wl, asns)
    if a.collector:
        subs = [dict(s, host=a.collector) for s in subs]
    return subs


# ---------------------------------------------------------------------------------------------------------------- analyze
def analyze(cap_path, alert_path=None, out="live_report", labels=None):
    n, header = 0, {}
    recv_t, feed = array("d"), array("d")
    hosts, kinds_msg = Counter(), Counter()
    with open(cap_path, encoding="utf-8") as f:                    # streamed: a 45-minute full-collector capture is far too big to hold in memory
        for line in f:
            l = json.loads(line)
            if "header" in l:
                header = l["header"]; continue
            d = l["data"]; n += 1
            recv_t.append(l["recv"]); hosts[d.get("host", "?")] += 1
            kinds_msg["announce" if d.get("announcements") else "withdraw-only" if d.get("withdrawals") else "other"] += 1
            if d.get("timestamp") is not None:
                feed.append(l["recv"] - d["timestamp"])
    md = ["# AS-path anomaly PoC: LIVE test", f"Capture: {cap_path}; {n} messages; header {header}.", ""]

    dur = (max(recv_t) - min(recv_t)) if n > 1 else 0
    md += ["## Feed latency (all messages)", f"- recorded for {dur / 60:.1f} min = {n / max(dur, 1):.1f} messages/s; {dict(kinds_msg)}; by collector {dict(hosts.most_common(5))}",
           f"- feed delay (our receive time - RIS timestamp), s: {stat(list(feed))}"]
    k = max(len(feed) // 10, 1)
    if len(feed) >= 20:
        md += [f"- backlog check: median feed delay first 10% of messages {statistics.median(feed[:k]):.3f} s, last 10% {statistics.median(feed[-k:]):.3f} s "
               "(a clear rise means the detector or network cannot keep up)"]
    rs_path = out + "_runstats.json"
    if os.path.exists(rs_path):
        rs = json.load(open(rs_path, encoding="utf-8"))
        md += [f"- detector compute per message (ALL {rs['messages']} messages), ms: {rs['compute_ms_all_messages']}", f"- monitor counters: {rs['monitor_stats']}"]
    md += [""]

    live_alerts = [json.loads(l) for l in open(alert_path, encoding="utf-8")] if alert_path and os.path.exists(alert_path) else []
    md += [f"## AS-path alerts: {len(live_alerts)} logged live", ""]
    if live_alerts:
        md += ["| Latency (live, per alert) | n | median | mean | p95 | min | max |", "|---|---|---|---|---|---|---|"]
        for lab, key in (("Feed delay (s)", "feed_delay_s"), ("Compute (ms)", "compute_ms")):
            s = stat([x[key] for x in live_alerts], 4)
            if s:
                md.append(f"| {lab} | {s['n']} | {s['median']} | {s['mean']} | {s['p95']} | {s['min']} | {s['max']} |")
        by_type, by_sev, by_rule = (Counter(x[k2] for x in live_alerts) for k2 in ("anomaly_type", "severity", "subtype"))
        leak_kinds = Counter(m.group(1) for x in live_alerts for m in [re.search(r"\((transit-to-transit|transit-to-peer|peer-to-peer|peer-to-transit)\)", x.get("signals") or "")] if m)
        md += ["", f"- by anomaly type: {dict(by_type)}", f"- by rule that fired: {dict(by_rule)}", f"- by severity: {dict(by_sev)}"]
        if leak_kinds:
            md += [f"- route-leak kinds: {dict(leak_kinds)}"]
        md += [f"- distinct prefixes: {len({x['prefix'] for x in live_alerts})}, distinct collectors: {len({x['collector'] for x in live_alerts})}"]
    else:
        md += ["No alert fired: hijacks/leaks are rare on a real feed. Record longer, widen the scope, or check that the real CAIDA file was used (header above / console start)."]

    lsum = llm_eval.live_summary(live_alerts) if live_alerts else None
    model_on = bool(header.get("llm") and header.get("llm") != "none")
    if lsum and (model_on or lsum["scored"]):
        md += llm_eval.live_markdown(lsum, stat)
    elif model_on:
        md += ["", "## Model (LLM)", f"- model {header.get('llm')} was on ({header.get('llm_check')}), but no alert fired, so it was never asked. "
               "Nothing to evaluate for the model in this run."]
    elif live_alerts:
        md += ["", "## Model (LLM)", "- **the model was OFF in this run**: only the rule engine is evaluated."]
    if lsum and model_on and lsum["coverage"] < 0.5:
        md += [f"- **WARNING: the model scored only {lsum['coverage']:.0%} of the alerts.** On a full-collector run this is the rate cap "
               f"(header: max_llm_per_min {header.get('max_llm_per_min')}); raise it with --max-llm-per-min if the model is fast enough to keep up."]

    md += ["", "## Accuracy", "No automatic ground truth exists for live BGP path hijacks / route leaks.",
           "Internal consistency only (not a substitute for verification): rule-type counts and rule-vs-model agreement above.", "",
           f"## Manual verification: fill `verdict` (TRUE/FALSE) in {out}_alerts.csv (per alert) or in the events CSV from cluster_events.py (per event; far fewer rows) "
           f"after checking RIPEstat / bgp.tools / CAIDA AS-rank for that prefix, origin and path, then re-run: "
           f"python live_eval.py analyze {cap_path} --alerts {alert_path or 'ALERTS.jsonl'} --out {out} --labels <that csv>"]
    manual = None
    if labels and os.path.exists(labels):
        rows_l = list(csv.DictReader(open(labels, encoding="utf-8")))
        unit = "events" if rows_l and "event_id" in rows_l[0] else "alerts"
        done = [r for r in rows_l if r.get("verdict", "").strip().upper() in ("TRUE", "FALSE")]
        if done:
            t = sum(r["verdict"].strip().upper() == "TRUE" for r in done)
            manual = dict(unit=unit, labelled=len(done), total=len(rows_l), true=t, precision=round(t / len(done), 3))
            md += ["", f"## Manual verification result: {t} of {len(done)} labelled {unit} confirmed real = precision {manual['precision']} "
                       f"(sample: {len(done)} of {len(rows_l)} {unit})"]
            for r in rows_l:
                r["llm_view"] = r.get("llm_view") or llm_eval.vr(r)
            mv = llm_eval.model_vs_verdict(rows_l)
            if mv:
                manual["model_vs_verdict"] = mv
                md += [f"- model vs your verdicts ({mv['labelled']} labelled and model-scored): of {mv['real']} real, the model kept {mv['model_kept_real']}; "
                       f"of {mv['false']} false, the model rejected {mv['model_rejected_false']} (model agrees with you on {mv['model_accuracy']:.0%})"]

    rows = [dict(id=i, prefix=x["prefix"], watched=x["watched"], anomaly_type=x["anomaly_type"], rule=x["subtype"], severity=x["severity"],
                 collector=x["collector"], peer_asn=x["peer_asn"], as_path=x["as_path"], signals=x["signals"],
                 msg_utc=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(x["msg_ts"])) if x.get("msg_ts") else "",
                 feed_delay_s=x["feed_delay_s"], compute_ms=x["compute_ms"], llm_label=x.get("llm_label"),
                 llm_agrees=x.get("llm_agrees"), llm_view=x.get("llm_view") or llm_eval.vr(x), model=x.get("model"), verdict="")
            for i, x in enumerate(live_alerts, 1)]
    if rows:
        with open(out + "_alerts.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

    md += ["", "## Limits of this live test",
           "- no ground truth: 'accuracy' above is internal consistency / a manual sample, not confirmed incidents; recall against real incidents cannot be measured",
           "- RIS Live shows routes as seen by RIS collector peers, not Cybernet's network; one run, one window, one collector selection: not generalisable",
           "- RIS Live sends no initial table: a learnt baseline only knows paths announced after the run starts, so legitimate-but-unseen links look 'new' (false positives)",
           "- an attack inside the learning window is learnt as normal (Run B); the full-collector run (Run A) has no baseline, so only valley_violation (route leak) can fire",
           "- valley-free checking depends on CAIDA relationship coverage: unknown links are skipped, so leaks can be missed and some alerts are wrong when relationships are wrong",
           "- timestamps are RIS collector time; feed delay depends on your PC clock; time queued before our code reads a message is only visible through the backlog check"]
    open(out + ".md", "w", encoding="utf-8").write("\n".join(md) + "\n")
    json.dump(dict(messages=n, duration_s=dur, header=header, feed_delay_s=stat(list(feed)), alerts_live=live_alerts, manual=manual,
                   llm={k: v for k, v in (lsum or {}).items() if not k.startswith("compute_ms")}),
              open(out + ".json", "w", encoding="utf-8"), indent=1)
    print("\n".join(md))


def main(argv=None):
    c = common()
    ap = argparse.ArgumentParser(description="AS-path PoC live test (TEST 2)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record", parents=[c])
    r.set_defaults(llm="hf")                      # the model is part of the full PoC test: ON by default; --llm none = rules only, on purpose
    r.add_argument("--minutes", type=float, default=60)
    r.add_argument("--host", help="RIS collector, e.g. rrc00 (alias of --collector). Alone = whole collector (--scope all)")
    r.add_argument("--prefix", action="append", help="watch scope: explicit prefixes (+ their more-specifics) instead of whitelist.json")
    r.add_argument("--from-file", help="dry run: replay a JSONL (RIS-Live-shaped, like sample_updates.jsonl) instead of connecting")
    r.add_argument("--capture", default="live_capture.jsonl"); r.add_argument("--alerts", default="live_alerts.jsonl")
    r.add_argument("--out", default="live_report")
    r.add_argument("--skip-llm-check", action="store_true", help="do not run the model self-test before recording")
    r.add_argument("--quiet-after", type=int, default=200, help="print every alert for the first N, then every 50th (console only; the file has all)")
    an = sub.add_parser("analyze"); an.add_argument("capture"); an.add_argument("--alerts"); an.add_argument("--out", default="live_report")
    an.add_argument("--labels", help="CSV with a verdict column (live_report_alerts.csv or the events CSV from cluster_events.py)")
    a = ap.parse_args(argv)
    if a.cmd == "analyze":
        return analyze(a.capture, a.alerts, a.out, a.labels)
    resolve(a, argv)
    llm_check = "model off (--llm none): this is NOT the full PoC"
    if a.llm not in (None, "none"):
        if a.skip_llm_check:
            llm_check = "model self-test skipped"
        else:
            print(f"model self-test ({a.llm}) ...", flush=True)
            ok, detail = llm_selftest(a)
            print(("OK: " if ok else "FAILED: ") + detail, flush=True)
            if not ok:
                raise SystemExit("The model does not work, so the run was not started. Fix it, or use --skip-llm-check / --llm none on purpose.")
            llm_check = detail
    else:
        print("WARNING: --llm none: the model is NOT part of this run (the full PoC test uses --llm hf).", flush=True)
    mon, wl, asns = setup_monitor(a)
    header = dict(watching=a.from_file or (f"ALL of {a.collector or 'all collectors'}" if a.scope == "all" else (a.prefix or list(wl) + [f"AS{x}" for x in asns])),
                  host=a.collector, minutes=a.minutes, scope=a.scope, llm=a.llm, baseline_source=("none" if a.scope == "all" else a.baseline_source),
                  learn_s=0 if a.scope == "all" else mon.learn, min_support=a.min_support, origin_policy=a.origin_policy, as_rel=a.as_rel,
                  llm_check=llm_check, max_llm_per_min=mon.max_llm_per_min)
    print("settings:", header, flush=True)
    rec = Recorder(mon, a.capture, a.alerts, header, a.quiet_after)
    try:
        if a.from_file:
            rec._live = False
            for line in open(a.from_file, encoding="utf-8"):
                d = json.loads(line)["data"]
                rec.handle(d, d.get("timestamp"))
        else:
            asyncio.run(live(rec, a, build_subs(a, wl, asns)))
    except KeyboardInterrupt:
        print("\nstopped early; analysing what was recorded")
    rec.close(a.out + "_runstats.json")
    if a.scope != "all":
        mon.save_baseline(a.baseline)
    analyze(a.capture, a.alerts, a.out)


if __name__ == "__main__":
    main()
