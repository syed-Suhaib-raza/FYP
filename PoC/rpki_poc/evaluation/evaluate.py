"""Correctness + latency evaluation of the RPKI Invalid PoC (deterministic) on a labelled stream.

Run from the rpki_poc folder:
    python evaluation/evaluate.py --mode offline                  # in-process replay: all three configs
    python evaluation/evaluate.py --mode online                   # over a websocket with RIS Live feed delays

The PoC is deterministic, so the questions differ from the AI PoCs:
  - Is it CORRECT? Accuracy should be 100% on in-scope checks; any miss is a bug, not a weak model.
  - Does it give the right RFC 6811 state and the doc's severity? (state confusion matrix, severity accuracy)
  - How FAST is it? (decision latency offline; end-to-end with real RIS Live delays online)
  - What do the design choices buy? Ablations: `no-revalidation` (do not re-check routes when the VRPs change)
    and `min-peers-1` (alert on the first RIS peer) against the chosen `full` config.

For every line the evaluator feeds the PoC, then reads, for each (prefix, origin) in the line's `checks`, whether an
ACTIVE alert exists (anomalous / benign), the RPKI state and the severity, and compares them with the truth.
Timing per line: decision_ms = processing incl. SQLite writes. Online adds network_ms (feed delay), queue_ms and e2e_ms.
Outputs: evaluation/results/<mode>_<config>.{md,json,csv} and evaluation/results/summary.md
"""
import argparse, glob, json, os, platform, sys, tempfile, time
from collections import Counter
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [HERE, ROOT]

from bgp_feed import parse_data                                    # noqa: E402  (PoC)
from engine import RpkiDetector                                    # noqa: E402
from store import Store                                            # noqa: E402
from vrp_store import VrpStore                                     # noqa: E402
import netfeed                                                     # noqa: E402
from evalcore import (classification, confusion, lat, lat_table, metric_table, group_table, LoopThread,  # noqa: E402
                      write_outputs, _fmt_ms)

netfeed.ORDER = "global"          # ROA changes / peer-down affect several prefixes: keep the global order online

CONFIGS = {"full": dict(min_peers=2, revalidate=True),
           "no-revalidation": dict(min_peers=2, revalidate=False),
           "min-peers-1": dict(min_peers=1, revalidate=True)}
STATES = ["VALID", "NOT_FOUND", "INVALID_AS", "INVALID_ML", "INVALID_AS_AND_ML"]
CSV_COLS = ["seq", "check", "timestamp", "kind", "prefix", "origin", "scenario", "category", "difficulty", "in_scope",
            "truth", "pred", "truth_state", "pred_state", "truth_severity", "pred_severity", "triggered",
            "decision_ms", "network_ms", "queue_ms", "e2e_ms"]


# ------------------------------------------------------------------------------------------------------------
class Pipeline:
    """The PoC exactly as main.py runs it (detector + SQLite store), fed line by line."""

    def __init__(self, db, cfg, whitelist, customers):
        for s in ("", "-wal", "-shm"):
            if os.path.exists(db + s):
                os.remove(db + s)
        vrps = VrpStore.from_file(os.path.join(HERE, "eval_vrps_v1.json"))
        self.det = RpkiDetector(vrps, Store(db), whitelist, customers, {9541, 24440}, cfg["min_peers"],
                                revalidate=cfg["revalidate"], source="eval")
        self.roa_events = []

    def decide(self, data, checks):
        t0 = time.perf_counter()
        outs = []
        for ev in parse_data(data):
            if ev.kind == "vrp_reload":
                o, _ = self.det.reload_vrps(VrpStore.from_file(os.path.join(HERE, ev.file)), ev.timestamp)
                outs += o
            else:
                outs += self.det.process(ev)
        t1 = time.perf_counter()
        self.roa_events += [o["change"] for o in outs if o["kind"] == "roa"]
        res = []
        for c in checks:
            a = self.det.active_alert(c["prefix"], c["origin"])
            res.append(dict(pred="anomalous" if a else "benign", pred_state=self.det.result(c["prefix"], c["origin"]).state,
                            pred_severity=a["severity"] if a else None))
        return res, dict(triggered=any(o["kind"] == "alert" for o in outs), decision_s=t1 - t0)


def records_for(i, row, res, d, timing=None):
    out = []
    for k, (c, r) in enumerate(zip(row["truth"]["checks"], res)):
        rec = dict(seq=i, check=k, timestamp=row["data"]["timestamp"], kind=row["data"]["type"], prefix=c["prefix"],
                   origin=c["origin"], scenario=c["scenario"], category=c["category"], difficulty=c["difficulty"],
                   in_scope=c["in_scope"], truth=c["label"], pred=r["pred"], truth_state=c["state"],
                   pred_state=r["pred_state"], truth_severity=c["severity"], pred_severity=r["pred_severity"],
                   triggered=d["triggered"], decision_s=d["decision_s"])
        rec.update(timing or {})
        for f in ("decision", "network", "queue", "e2e"):
            v = rec.get(f + "_s")
            rec[f + "_ms"] = round(v * 1000, 4) if v is not None else None
        out.append(rec)
    return out


def run_offline(rows, pipe):
    recs = []
    for i, row in enumerate(rows):
        t_in = time.time()
        res, d = pipe.decide(row["data"], row["truth"]["checks"])
        recs += records_for(i, row, res, d, dict(t_ingest=t_in, t_decided=t_in + d["decision_s"]))
    return recs


def run_online(rows, pipe, url, idle_timeout=180):
    recs, seen = [], []

    def on_message(data, tm):
        i = tm["seq"]
        res, d = pipe.decide(data, rows[i]["truth"]["checks"])
        seen.append(i)
        if len(seen) % 25 == 0 or len(seen) == len(rows):
            print(f"\r  received {len(seen)}/{len(rows)}", end="" if len(seen) < len(rows) else "\n", flush=True)
        emit = tm["emit"] if tm["emit"] is not None else tm["recv"]
        sent = tm["sent"] if tm["sent"] is not None else tm["recv"]
        recs.extend(records_for(i, rows[i], res, d, dict(network_s=sent - emit, queue_s=tm["recv"] - sent,
                                                         e2e_s=(tm["recv"] - emit) + d["decision_s"],
                                                         t_ingest=emit, t_decided=tm["recv"] + d["decision_s"])))

    import asyncio
    asyncio.run(netfeed.stream_client(url, on_message, max_wait=idle_timeout))
    if seen != sorted(seen):
        print("WARNING: messages arrived out of order; labels that depend on order may not apply")
    return recs


def time_real_feed(msgs, pipe):
    return [pipe.decide(m, [])[1] for m in msgs]


# ------------------------------------------------------------------------------------------------------------
def detection(recs):
    by = {}
    for r in recs:
        by.setdefault(r["scenario"], []).append(r)
    out = []
    for sid, rs in sorted(by.items()):
        rs.sort(key=lambda r: (r["seq"], r["check"]))
        first = next((k for k, r in enumerate(rs) if r["truth"] == "anomalous" and r["in_scope"]), None)
        if first is None:
            continue
        hit = next((k for k in range(first, len(rs)) if rs[k]["pred"] == "anomalous"), None)
        a = rs[first]
        row = dict(scenario=sid, prefix=a["prefix"], category=a["category"], difficulty=a["difficulty"], detected=hit is not None)
        if hit is not None:
            h = rs[hit]
            row.update(lines_to_detect=h["seq"] - a["seq"] + 1, bgp_time_to_detect_s=h["timestamp"] - a["timestamp"],
                       wall_time_to_detect_ms=round((h["t_decided"] - a["t_ingest"]) * 1000, 3))
        out.append(row)
    return out


def state_table(recs):
    used = [s for s in STATES if any(r["truth_state"] == s or r["pred_state"] == s for r in recs)]
    md = ["| truth \\ PoC state | " + " | ".join(used) + " |", "|---|" + "---|" * len(used)]
    for t in used:
        md.append(f"| {t} | " + " | ".join(str(sum(r['truth_state'] == t and r['pred_state'] == p for r in recs)) for p in used) + " |")
    return "\n".join(md)


def report(a, mode, cfg_name, rows, recs, meta, roa_events):
    ins = [r for r in recs if r["in_scope"]]
    oos = [r for r in recs if not r["in_scope"]]
    pairs = [(r["truth"], r["pred"]) for r in ins]
    m = classification(pairs)
    state_ok = sum(r["truth_state"] == r["pred_state"] for r in ins)
    sev = [r for r in ins if r["truth"] == "anomalous" and r["pred"] == "anomalous"]
    sev_ok = sum(r["truth_severity"] == r["pred_severity"] for r in sev)
    lines_ = {}
    for r in recs:
        lines_.setdefault(r["seq"], r)
    line_recs = list(lines_.values())
    trig = [r for r in line_recs if r["triggered"]]
    det = detection(recs)
    roa_med = [c for c in roa_events if c["severity"] == "MEDIUM"]
    cfg = CONFIGS[cfg_name]
    md = [f"# RPKI Invalid PoC evaluation: {mode} (config: {cfg_name})", "",
          f"- run: {meta['started']} on {platform.node()} ({platform.system()} {platform.machine()}, Python {platform.python_version()})",
          f"- dataset: `{os.path.relpath(a.dataset, ROOT)}`: {len(rows)} lines, {len(recs)} checks, "
          f"{len({r['scenario'] for r in recs})} scenarios ({sum(r['truth'] == 'anomalous' for r in ins)} anomalous in scope, "
          f"{sum(r['truth'] == 'benign' for r in ins)} benign, {len(oos)} out of scope); synthetic, labels by construction",
          f"- config `{cfg_name}`: MIN_PEERS={cfg['min_peers']}, re-validate on VRP change={cfg['revalidate']}. "
          "The labels assume the chosen design (`full`); ablation runs show what changes without it.",
          f"- wall time for the whole stream: {meta['wall_s']:.2f} s"]
    if mode == "online":
        md += [f"- transport: websocket, RIS Live protocol, {meta['feed']}; send rate {a.rate} msg/s; global order kept",
               f"- feed delay model: {meta['delay_desc']}"]
        if meta.get("probe"):
            md.append("- real RIS Live probe: " + netfeed.probe_text(meta["probe"]))
    md += ["", "## 1. Alert decision (in-scope checks)", "",
           "anomalous = an ACTIVE NOC alert exists for the (prefix, origin). A deterministic engine should score 1.0.", "",
           metric_table(m), "", confusion(pairs), "",
           "### By category", "", group_table(ins, "category"), "",
           "## 2. RFC 6811 state and severity", "",
           f"- state correct: **{state_ok}/{len(ins)}** in-scope checks",
           f"- severity correct (doc table) when an alert is raised: **{sev_ok}/{len(sev)}**",
           f"- ROA changes reported as MEDIUM: **{len(roa_med)}** (expected 2: maxLength reduced on 72.255.0.0/18, "
           "ROA for 203.0.113.0/24 removed)", "", state_table(ins), "",
           "## 3. Time to decision", "", "Processing per line, including SQLite writes. Triggering lines opened, "
           "re-opened or resolved an alert.", "", "All values in milliseconds.", ""]
    rows_lat = [("decision, all lines", lat([r["decision_s"] for r in line_recs])),
                ("decision, triggering lines", lat([r["decision_s"] for r in trig])),
                ("decision, other lines", lat([r["decision_s"] for r in line_recs if not r["triggered"]]))]
    if mode == "online":
        rows_lat += [("feed delay (emit -> sent)", lat([r["network_s"] for r in line_recs])),
                     ("socket + queueing (sent -> read)", lat([r["queue_s"] for r in line_recs])),
                     ("end-to-end (emit -> decision), all", lat([r["e2e_s"] for r in line_recs])),
                     ("end-to-end (emit -> decision), triggering", lat([r["e2e_s"] for r in trig]))]
    md += [lat_table(rows_lat), "", "## 4. Detection of anomalous episodes", "",
           "From the first check where an alert should be active to the first check where the PoC has it.", "",
           "| scenario | prefix | category | difficulty | detected | lines until detection | BGP time (s) | wall time (ms) |",
           "|---|---|---|---|---|---|---|---|"]
    for d in det:
        md.append(f"| {d['scenario']} | {d['prefix']} | {d['category']} | {d['difficulty']} | {'yes' if d['detected'] else 'NO'} | "
                  f"{d.get('lines_to_detect', '-')} | {d.get('bgp_time_to_detect_s', '-')} | {_fmt_ms(d.get('wall_time_to_detect_ms'))} |")
    nd = sum(d["detected"] for d in det)
    md += ["", f"Detected {nd}/{len(det)} anomalous episodes.", "",
           "## 5. Out of scope (RPKI Valid by definition)", "",
           "| category | n | PoC alerted |", "|---|---|---|"]
    cats = Counter(r["category"] for r in oos)
    for c, n in sorted(cats.items()):
        md.append(f"| {c} | {n} | {sum(r['pred'] == 'anomalous' for r in oos if r['category'] == c)} |")
    wrong = [r for r in ins if r["truth"] != r["pred"] or r["truth_state"] != r["pred_state"]
             or (r["truth"] == r["pred"] == "anomalous" and r["truth_severity"] != r["pred_severity"])]
    md += ["", "## 6. Wrong checks", "", "| seq | scenario | prefix | origin | truth | PoC | truth state | PoC state | truth sev | PoC sev |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for r in wrong:
        md.append(f"| {r['seq']} | {r['scenario']} | {r['prefix']} | {r['origin']} | {r['truth']} | {r['pred']} | "
                  f"{r['truth_state']} | {r['pred_state']} | {r['truth_severity']} | {r['pred_severity']} |")
    if not wrong:
        md.append("| - | none | | | | | | | | |")
    md += ["", "## Notes", "",
           "- The PoC is deterministic: the same stream always gives the same result. Latency varies with the machine.",
           "- The forged-origin path hijack keeps the real origin, so it is RPKI Valid: covered by the AS-Path module.",
           "- Agreement with Routinator is measured on live runs: `python evaluation/routinator_agreement.py --db rpki.db`."]
    if meta.get("realfeed"):
        rf = meta["realfeed"]
        md += ["", "## 7. Real RIS Live traffic (unlabelled, timing only)", "",
               f"{rf['n']} real messages ({rf['rate']:.1f} msg/s); processing used {rf['busy_pct']:.2f}% of the wall time.", "",
               lat_table([("RIS Live feed delay (arrival - collector timestamp)", rf["delay"]),
                          ("websocket round trip to RIS Live", rf["rtt"]), ("decision, real updates", rf["decision"])]), ""]
    summary = dict(mode=mode, config=cfg_name, metrics=m, n_lines=len(rows), n_checks=len(recs),
                   state_acc=f"{state_ok}/{len(ins)}", severity_acc=f"{sev_ok}/{len(sev)}", roa_medium=len(roa_med),
                   decision=lat([r["decision_s"] for r in line_recs]), decision_trig=lat([r["decision_s"] for r in trig]),
                   e2e=lat([r.get("e2e_s") for r in line_recs]) if mode == "online" else None,
                   network=lat([r.get("network_s") for r in line_recs]) if mode == "online" else None,
                   detected=f"{nd}/{len(det)}", delay_model=meta.get("delay_desc"), started=meta["started"])
    return md, summary, det


def write_summary(out_dir):
    runs = []
    for f in sorted(glob.glob(os.path.join(out_dir, "*.json"))):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except ValueError:
            continue
        if isinstance(d, dict) and "summary" in d:
            runs.append(d["summary"])
    if not runs:
        return
    ms = lambda d, k: _fmt_ms(d.get(k)) if d and d.get("n") else "-"
    md = ["# RPKI Invalid PoC: evaluation summary", "",
          "Deterministic PoC: `full` is the chosen design and should be exact; the other configs are ablations. "
          "Latency in milliseconds.", "",
          "| run | config | lines | checks | accuracy | precision | recall | F1 | FPR | state correct | severity correct | "
          "ROA changes (medium) | episodes detected | decision p50 | decision p95 | network p50 | end-to-end p50 | end-to-end p95 |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    order = list(CONFIGS)
    for s in sorted(runs, key=lambda s: (s["mode"] != "offline", order.index(s["config"]))):
        m = s["metrics"]
        md.append(f"| {s['mode']} | {s['config']} | {s['n_lines']} | {s['n_checks']} | {m['accuracy']} | {m['precision']} | "
                  f"{m['recall']} | {m['f1']} | {m['fpr']} | {s['state_acc']} | {s['severity_acc']} | {s['roa_medium']} | "
                  f"{s['detected']} | {ms(s['decision'], 'p50')} | {ms(s['decision'], 'p95')} | {ms(s.get('network'), 'p50')} | "
                  f"{ms(s.get('e2e'), 'p50')} | {ms(s.get('e2e'), 'p95')} |")
    dm = [f"{s['mode']}/{s['config']}: {s['delay_model']}" for s in runs if s.get("delay_model")]
    if dm:
        md += ["", "Online feed delay model: " + "; ".join(dm)]
    open(os.path.join(out_dir, "summary.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")


# ------------------------------------------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["offline", "online"], required=True)
    p.add_argument("--config", choices=list(CONFIGS) + ["all"], default=None,
                   help="offline default: all three; online default: full")
    p.add_argument("--dataset", default=os.path.join(HERE, "labelled_updates.jsonl"))
    p.add_argument("--whitelist", default=os.path.join(HERE, "eval_whitelist.json"))
    p.add_argument("--customers", default=os.path.join(HERE, "eval_customers.json"))
    p.add_argument("--out-dir", default=os.path.join(HERE, "results"))
    p.add_argument("--db-dir", default=os.path.join(tempfile.gettempdir(), "rpki_eval"))
    g = p.add_argument_group("online")
    g.add_argument("--delay-model", default="auto",
                   help="auto (probe RIS Live, fall back to none) | ris | none | trace:FILE | fixed:S | uniform:A,B")
    g.add_argument("--probe-seconds", type=float, default=60)
    g.add_argument("--probe-host", default="rrc00")
    g.add_argument("--probe-url", default=netfeed.RIS_URL)
    g.add_argument("--rate", type=float, default=20.0)
    g.add_argument("--feed-url")
    g.add_argument("--idle-timeout", type=float, default=180)
    g.add_argument("--feed-host", default="127.0.0.1")
    g.add_argument("--feed-port", type=int, default=0)
    a = p.parse_args()

    rows = [json.loads(l) for l in open(a.dataset, encoding="utf-8") if l.strip()]
    wl = json.load(open(a.whitelist, encoding="utf-8"))
    customers = set(json.load(open(a.customers, encoding="utf-8")))
    os.makedirs(a.out_dir, exist_ok=True)
    os.makedirs(a.db_dir, exist_ok=True)
    cfg_names = list(CONFIGS) if (a.config in (None, "all") and a.mode == "offline") else [a.config or "full"]
    if a.mode == "online" and cfg_names == list(CONFIGS):
        cfg_names = ["full"]

    meta = dict(started=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    probe, delay = None, None
    if a.mode == "online" and not a.feed_url:
        if a.delay_model in ("auto", "ris"):
            sub = {"type": "UPDATE", "socketOptions": {"includeRaw": False}, **({"host": a.probe_host} if a.probe_host else {})}
            print(f"probing RIS Live for {a.probe_seconds:.0f} s ...", flush=True)
            probe = netfeed.probe_ris_live(a.probe_seconds, sub, url=a.probe_url)
            print("  ->", netfeed.probe_text(probe), flush=True)
            if a.delay_model == "ris" and not probe["delays"]:
                raise SystemExit(f"RIS Live probe failed: {probe['error']}")
            json.dump({k: v for k, v in probe.items() if k != "messages"},
                      open(os.path.join(a.out_dir, "ris_probe_trace.json"), "w"), indent=1)
            meta["probe"] = {k: v for k, v in probe.items() if k != "messages"}
        delay = netfeed.DelayModel.parse(a.delay_model, probe["delays"] if probe else None)
        meta["delay_desc"] = delay.describe() + (" from the RIS Live probe" if probe and probe["delays"] else "")
    elif a.mode == "online":
        meta["delay_desc"] = "applied by the external feed server"

    for name in cfg_names:
        pipe = Pipeline(os.path.join(a.db_dir, f"rpki_{a.mode}_{name}.db"), CONFIGS[name], wl, customers)
        t = time.time()
        if a.mode == "offline":
            recs = run_offline(rows, pipe)
        else:
            lt = None
            if a.feed_url:
                url, meta["feed"] = a.feed_url, f"external feed server {a.feed_url}"
            else:
                lt = LoopThread()
                server, url = lt.run(netfeed.serve_feed(rows, a.feed_host, a.feed_port, a.rate, delay))
                meta["feed"] = f"built-in feed server {url}"
            print(f"streaming {len(rows)} labelled lines from {url} ...", flush=True)
            recs = run_online(rows, pipe, url, a.idle_timeout)
            if lt:
                lt.run(netfeed.close_server(server))
                lt.stop()
        meta["wall_s"] = time.time() - t
        recs.sort(key=lambda r: (r["seq"], r["check"]))
        if a.mode == "online" and probe and probe.get("messages"):
            rp = Pipeline(os.path.join(a.db_dir, "rpki_realfeed.db"), CONFIGS[name], wl, customers)
            ds = time_real_feed(probe["messages"], rp)
            dur = max(a.probe_seconds, 1e-9)
            meta["realfeed"] = dict(n=len(ds), rate=len(ds) / dur, busy_pct=100 * sum(d["decision_s"] for d in ds) / dur,
                                    delay=lat(probe["delays"]), rtt=lat(probe["rtts"]), decision=lat([d["decision_s"] for d in ds]))
        md, summary, det = report(a, a.mode, name, rows, recs, meta, pipe.roa_events)
        base = os.path.join(a.out_dir, f"{a.mode}_{name}")
        write_outputs(base, md, recs, CSV_COLS, extra=dict(summary=summary, detection=det,
                                                           meta={k: v for k, v in meta.items() if k != "probe"}))
        m = summary["metrics"]
        print(f"[{a.mode}/{name}] accuracy {m['accuracy']}  precision {m['precision']}  recall {m['recall']}  F1 {m['f1']}  "
              f"FPR {m['fpr']}  state {summary['state_acc']}  severity {summary['severity_acc']}  episodes {summary['detected']}  "
              f"decision p50 {summary['decision'].get('p50')} ms" + (f"  e2e p50 {summary['e2e'].get('p50')} ms" if summary.get("e2e") else ""))
        print(f"  -> {base}.md / .json / .csv")
        meta.pop("realfeed", None)
    write_summary(a.out_dir)
    print(f"  -> {os.path.join(a.out_dir, 'summary.md')}")


if __name__ == "__main__":
    main()
