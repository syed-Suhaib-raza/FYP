"""Latency + accuracy evaluation of the MOAS PoC (catalog layer -> AI layer) on a labelled update stream.

Run from the moas_poc folder:
    python evaluation/evaluate.py --mode offline                     # in-process replay, processing latency only
    python evaluation/evaluate.py --mode online                      # over a websocket, adds network/feed latency
    python evaluation/evaluate.py --mode offline --backend llm --llm-model <name> [--llm-url http://host:11434/v1]

For every update the evaluator records the decision the PoC holds for that update's prefix right after processing it
(anomalous / benign / uncertain; "benign" when there is no active multi-origin conflict) and compares it with the
ground truth in labelled_updates.jsonl (see make_dataset.py for the label semantics). Timing per update:
    catalog_ms   moas.MoasCatalog.process()  (layer 1)
    ai_ms        ai_layer.run_once() for the event(s) that update opened/changed/closed (layer 2, incl. SQLite I/O)
    decision_ms  catalog + AI = time from the update entering the PoC to its decision
online only:
    network_ms   emit -> sent: feed delay applied by the delay model (measured RIS Live delays when reachable)
    queue_ms     sent -> read by the PoC: socket transport + waiting behind earlier, slower decisions
    e2e_ms       emit -> decision: what an operator experiences
Outputs: evaluation/results/<mode>_<backend>.{md,json,csv} and evaluation/results/summary.md
"""
import argparse, glob, json, os, platform, sqlite3, sys, tempfile, time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [HERE, ROOT]

from moas import MoasCatalog, Store                               # noqa: E402  (PoC layer 1)
from ai_layer import BaselineBackend, LLMBackend, run_once        # noqa: E402  (PoC layer 2)
import netfeed                                                    # noqa: E402
from evalcore import (classification, confusion, lat, lat_table, metric_table, group_table, LoopThread,  # noqa: E402
                      write_outputs, _fmt_ms)

CSV_COLS = ["seq", "timestamp", "prefix", "origin", "scenario", "category", "difficulty", "in_scope", "truth", "pred",
            "score", "triggered", "event_id", "revision", "catalog_ms", "ai_ms", "decision_ms", "network_ms", "queue_ms",
            "e2e_ms", "reason"]


# ------------------------------------------------------------------------------------------------------------
class Pipeline:
    """The PoC exactly as deployed (catalog writes SQLite, AI layer reads it on its own connection), except that the
    AI layer is run immediately after each catalog change instead of on its --interval poll."""

    def __init__(self, db, window, whitelist, backend):
        for s in ("", "-wal", "-shm"):
            if os.path.exists(db + s):
                os.remove(db + s)
        self.store = Store(db)
        self.cat = MoasCatalog(self.store, window=window)
        self.ai_con = sqlite3.connect(db, timeout=30)
        self.backend, self.wl = backend, whitelist
        self.verdicts = {}            # event id -> (revision, Verdict): latest verdict per event
        self.retry = False

    def decide(self, data):
        pfx = next((p for a in data.get("announcements", []) for p in a.get("prefixes", [])), None)
        t0 = time.perf_counter()
        changed = self.cat.process(data)
        t1 = time.perf_counter()
        err, n_scored = None, 0
        if changed or self.retry:
            logs = []
            for ev, _, v in run_once(self.ai_con, [self.backend], self.wl, log=logs.append):
                self.verdicts[ev["id"]] = (ev["revision"], v)
                n_scored += 1
            self.retry, err = bool(logs), (logs[-1].strip() if logs else None)
        t2 = time.perf_counter()
        ev = self.cat.open.get(pfx)
        if ev is None:
            pred, score, reason, eid, rev = "benign", None, "no active multi-origin conflict", None, None
        else:
            eid, rev = ev.id, ev.revision
            rv = self.verdicts.get(ev.id)
            pred, score, reason = (rv[1].label, rv[1].score, rv[1].reason) if rv else ("no_decision", None, err or "not scored")
        return dict(prefix=pfx, pred=pred, score=score, reason=reason, event_id=eid, revision=rev,
                    triggered=bool(changed), n_scored=n_scored, catalog_s=t1 - t0,
                    ai_s=(t2 - t1) if (changed or n_scored) else None, decision_s=t2 - t0, error=err)


def origin_of(data):
    p = data.get("path") or []
    if not p:
        return None
    return "{" + ",".join(map(str, p[-1])) + "}" if isinstance(p[-1], list) else str(p[-1])


def record(i, row, d, timing=None):
    t, data = row["truth"], row["data"]
    r = dict(seq=i, timestamp=data["timestamp"], prefix=d["prefix"], origin=origin_of(data), scenario=t["scenario"],
             category=t["category"], difficulty=t["difficulty"], in_scope=t["in_scope"], truth=t["label"], pred=d["pred"],
             score=d["score"], triggered=d["triggered"], event_id=d["event_id"], revision=d["revision"],
             catalog_s=d["catalog_s"], ai_s=d["ai_s"], decision_s=d["decision_s"], reason=d["reason"], error=d["error"])
    r.update(timing or {})
    for k in ("catalog", "ai", "decision", "network", "queue", "e2e"):
        v = r.get(k + "_s")
        r[k + "_ms"] = round(v * 1000, 4) if v is not None else None
    return r


# ------------------------------------------------------------------------------------------------------------
def run_offline(rows, pipe):
    recs = []
    for i, row in enumerate(rows):
        t_in = time.time()
        d = pipe.decide(row["data"])
        recs.append(record(i, row, d, dict(t_ingest=t_in, t_decided=t_in + d["decision_s"])))
    return recs


def run_online(rows, pipe, url, idle_timeout=180):
    recs, seen = [], []

    def on_message(data, tm):
        d = pipe.decide(data)
        i = tm["seq"]
        seen.append(i)
        if len(seen) % 25 == 0 or len(seen) == len(rows):
            print(f"\r  received {len(seen)}/{len(rows)}", end="" if len(seen) < len(rows) else "\n", flush=True)
        emit = tm["emit"] if tm["emit"] is not None else tm["recv"]
        sent = tm["sent"] if tm["sent"] is not None else tm["recv"]
        recs.append(record(i, rows[i], d, dict(network_s=sent - emit, queue_s=tm["recv"] - sent,
                                               e2e_s=(tm["recv"] - emit) + d["decision_s"],
                                               t_ingest=emit, t_decided=tm["recv"] + d["decision_s"])))

    import asyncio
    try:
        asyncio.run(netfeed.stream_client(url, on_message, max_wait=idle_timeout))
    except TimeoutError as e:
        raise SystemExit(f"\nstream stalled: {e} after {len(seen)}/{len(rows)} updates (raise --idle-timeout if the "
                         f"model or the feed delay is legitimately slower)")
    if sorted(seen) != list(range(len(rows))):
        print(f"WARNING: received {len(set(seen))}/{len(rows)} labelled messages")
    order = {}
    for i in seen:
        order.setdefault(rows[i]["data"]["announcements"][0]["prefixes"][0], []).append(i)
    if any(v != sorted(v) for v in order.values()):
        print("WARNING: updates of the same prefix arrived out of order; per-prefix labels may not apply")
    return recs


def time_real_feed(msgs, pipe):
    out = []
    for m in msgs:
        d = pipe.decide(m)
        out.append(d)
    return out


# ------------------------------------------------------------------------------------------------------------
def detection(recs):
    """Per anomalous episode: first in-scope anomalous update -> first update for which the PoC says anomalous."""
    by = {}
    for r in recs:
        by.setdefault(r["scenario"], []).append(r)
    out = []
    for sid, rs in sorted(by.items()):
        rs.sort(key=lambda r: r["seq"])
        first = next((k for k, r in enumerate(rs) if r["truth"] == "anomalous" and r["in_scope"]), None)
        if first is None:
            continue
        hit = next((k for k in range(first, len(rs)) if rs[k]["pred"] == "anomalous"), None)
        rev = next((k for k in range(first, len(rs)) if rs[k]["pred"] in ("anomalous", "uncertain")), None)
        a = rs[first]
        row = dict(scenario=sid, prefix=a["prefix"], category=a["category"], difficulty=a["difficulty"],
                   detected=hit is not None, flagged_for_review=rev is not None)
        if hit is not None:
            h = rs[hit]
            row.update(updates_to_detect=hit - first + 1, bgp_time_to_detect_s=h["timestamp"] - a["timestamp"],
                       wall_time_to_detect_ms=round((h["t_decided"] - a["t_ingest"]) * 1000, 3))
        out.append(row)
    return out


def report(args, mode, backend_name, rows, recs, meta):
    ins = [r for r in recs if r["in_scope"]]
    oos = [r for r in recs if not r["in_scope"]]
    pairs = [(r["truth"], r["pred"]) for r in ins]
    m = classification(pairs)
    trig = [r for r in recs if r["triggered"]]
    det = detection(recs)
    md = [f"# MOAS PoC evaluation: {mode} (backend: {backend_name})", "",
          f"- run: {meta['started']} on {platform.node()} ({platform.system()} {platform.machine()}, Python {platform.python_version()})",
          f"- dataset: `{os.path.relpath(args.dataset, ROOT)}`: {len(rows)} updates, {len({r['truth']['scenario'] for r in rows})} scenarios "
          f"({sum(r['truth']['label'] == 'benign' for r in rows)} benign, {sum(r['truth']['label'] == 'anomalous' and r['truth']['in_scope'] for r in rows)} anomalous in scope, "
          f"{sum(not r['truth']['in_scope'] for r in rows)} anomalous out of scope); synthetic, labels by construction",
          f"- whitelist: `{os.path.relpath(args.whitelist, ROOT)}`, catalog window {args.window} s",
          f"- wall time for the whole stream: {meta['wall_s']:.2f} s"]
    if mode == "online":
        md += [f"- transport: websocket, RIS Live protocol, {meta['feed']}; send rate {args.rate} msg/s",
               f"- feed delay model: {meta['delay_desc']}"]
        if meta.get("probe"):
            pr = meta["probe"]
            md.append("- real RIS Live probe: " + netfeed.probe_text(pr))
    if backend_name == "baseline":
        md.append("- backend `baseline` is the PoC's untuned additive rule set, not a model")
    md += ["", "## 1. Classification (in-scope updates)", "", metric_table(m), "", confusion(pairs), "",
           "### By category", "", group_table(ins, "category"), "",
           "## 2. Time to decision", "",
           "Processing per update (catalog + AI layer). *Triggering* updates are those that opened, changed or closed a "
           "MOAS event and therefore caused an AI-layer verdict; every other update is decided by the catalog alone.", ""]
    rows_lat = [("catalog (layer 1), all updates", lat([r["catalog_s"] for r in recs])),
                ("AI layer (layer 2), triggering updates", lat([r["ai_s"] for r in trig])),
                ("decision, all updates", lat([r["decision_s"] for r in recs])),
                ("decision, triggering updates", lat([r["decision_s"] for r in trig])),
                ("decision, non-triggering updates", lat([r["decision_s"] for r in recs if not r["triggered"]]))]
    if mode == "online":
        rows_lat += [("feed delay incl. sender scheduling (emit -> sent)", lat([r["network_s"] for r in recs])),
                     ("socket + queueing (sent -> read)", lat([r["queue_s"] for r in recs])),
                     ("end-to-end (emit -> decision), all", lat([r["e2e_s"] for r in recs])),
                     ("end-to-end (emit -> decision), triggering", lat([r["e2e_s"] for r in trig]))]
    md += ["All values in milliseconds.", "", lat_table(rows_lat), ""]
    md += ["## 3. Detection of anomalous episodes", "",
           "From the first anomalous update of a scenario to the first update whose decision is `anomalous`. "
           "BGP time is measured on the update timestamps (0 = caught on the first anomalous update); "
           "wall time is ingest of that first update to the decision" + (" (online: from its emit time)." if mode == "online" else "."), "",
           "| scenario | prefix | category | difficulty | detected | flagged (anomalous or uncertain) | updates until detection | BGP time (s) | wall time (ms) |",
           "|---|---|---|---|---|---|---|---|---|"]
    for d in det:
        md.append(f"| {d['scenario']} | {d['prefix']} | {d['category']} | {d['difficulty']} | {'yes' if d['detected'] else 'NO'} | "
                  f"{'yes' if d['flagged_for_review'] else 'no'} | {d.get('updates_to_detect', '-')} | {d.get('bgp_time_to_detect_s', '-')} | "
                  f"{_fmt_ms(d.get('wall_time_to_detect_ms'))} |")
    nd = sum(d["detected"] for d in det)
    md += ["", f"Detected {nd}/{len(det)} anomalous episodes; flagged for review {sum(d['flagged_for_review'] for d in det)}/{len(det)}.", ""]
    md += ["## 4. Out-of-scope anomalies (not visible to an exact-prefix MOAS detector)", "",
           "| category | n | PoC said anomalous |", "|---|---|---|"]
    cats = {}
    for r in oos:
        cats.setdefault(r["category"], []).append(r)
    for c, rs in sorted(cats.items()):
        md.append(f"| {c} | {len(rs)} | {sum(r['pred'] == 'anomalous' for r in rs)} |")
    wrong = [r for r in ins if r["truth"] != r["pred"]]
    md += ["", "## 5. Misclassified in-scope updates", "", "| seq | scenario | prefix | origin | category | truth | predicted | score | reason |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in wrong:
        md.append(f"| {r['seq']} | {r['scenario']} | {r['prefix']} | AS{r['origin']} | {r['category']} | {r['truth']} | {r['pred']} | "
                  f"{r['score'] if r['score'] is not None else '-'} | {(r['reason'] or '')[:110]} |")
    md += ["", "## Notes", "",
           "- Label semantics: the decision the monitor should hold for the update's prefix right after the update "
           "(see `evaluation/make_dataset.py`). Accuracy counts `uncertain` as wrong; precision/recall count it as an alert.",
           "- The AI layer is called right after each catalog change. In deployment `ai_layer.py --watch` polls every "
           "`--interval` seconds (default 5), which adds up to that interval to every triggering decision.",
           "- Offline replays the file as fast as possible in one process, so its latency is pure processing time.",
           ]
    if mode == "online":
        md.append("- Online streams the same updates through a websocket in RIS Live format, with the feed server on its own "
                  "thread so it keeps sending on schedule while the PoC is busy (queueing shows up in `sent -> read`).")
    if meta.get("realfeed"):
        rf = meta["realfeed"]
        md += ["", "## 6. Real RIS Live traffic (unlabelled, timing only)", "",
               f"{rf['n']} real messages ({rf['rate']:.1f} msg/s observed); {rf['triggered']} triggered an AI verdict; "
               f"processing used {rf['busy_pct']:.2f}% of the wall time, i.e. the PoC keeps up with this feed: {'yes' if rf['busy_pct'] < 100 else 'NO'}.", "",
               lat_table([("RIS Live feed delay (arrival - collector timestamp)", rf["delay"]),
                          ("websocket round trip to RIS Live", rf["rtt"]),
                          ("decision, all real updates", rf["decision"]),
                          ("decision, triggering real updates", rf["decision_trig"])]), ""]
    summary = dict(mode=mode, backend=backend_name, metrics=m, n_updates=len(recs),
                   decision=lat([r["decision_s"] for r in recs]), decision_trig=lat([r["decision_s"] for r in trig]),
                   e2e=lat([r.get("e2e_s") for r in recs]) if mode == "online" else None,
                   e2e_trig=lat([r.get("e2e_s") for r in trig]) if mode == "online" else None,
                   network=lat([r.get("network_s") for r in recs]) if mode == "online" else None,
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
    md = ["# MOAS PoC: evaluation summary", "", "Latency in milliseconds. Accuracy counts `uncertain` as wrong; precision/recall count it as an alert.", "",
          "| run | backend | updates | accuracy | precision | recall | F1 | FPR | uncertain | episodes detected | decision p50 | decision p95 | decision p95 (triggering) | network p50 | end-to-end p50 | end-to-end p95 |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in sorted(runs, key=lambda s: (s["backend"], s["mode"] != "offline")):
        m = s["metrics"]
        md.append(f"| {s['mode']} | {s['backend']} | {s['n_updates']} | {m['accuracy']} | {m['precision']} | {m['recall']} | {m['f1']} | {m['fpr']} | "
                  f"{m['uncertain']} | {s['detected']} | {ms(s['decision'], 'p50')} | {ms(s['decision'], 'p95')} | {ms(s['decision_trig'], 'p95')} | "
                  f"{ms(s.get('network'), 'p50')} | {ms(s.get('e2e'), 'p50')} | {ms(s.get('e2e'), 'p95')} |")
    md += ["", "Online feed delay model per run: " + "; ".join(f"{s['mode']}/{s['backend']}: {s['delay_model']}" for s in runs if s.get("delay_model")), ""]
    open(os.path.join(out_dir, "summary.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")


# ------------------------------------------------------------------------------------------------------------
def make_backends(a):
    out = []
    if a.backend in ("baseline", "both"):
        out.append(BaselineBackend())
    if a.backend in ("llm", "both"):
        if not a.llm_model:
            raise SystemExit("--llm-model is required for the llm backend")
        out.append(LLMBackend(a.llm_model, a.llm_url, a.llm_api_key or os.environ.get("LLM_API_KEY")))
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["offline", "online"], required=True)
    p.add_argument("--dataset", default=os.path.join(HERE, "labelled_updates.jsonl"))
    p.add_argument("--whitelist", default=os.path.join(HERE, "eval_whitelist.json"))
    p.add_argument("--window", type=int, default=3600)
    p.add_argument("--backend", choices=["baseline", "llm", "both"], default="baseline")
    p.add_argument("--llm-url", default="http://localhost:11434/v1")
    p.add_argument("--llm-model")
    p.add_argument("--llm-api-key")
    p.add_argument("--out-dir", default=os.path.join(HERE, "results"))
    p.add_argument("--db-dir", default=os.path.join(tempfile.gettempdir(), "poc_eval"),
                   help="where the PoC's scratch SQLite files go (default: system temp dir)")
    g = p.add_argument_group("online")
    g.add_argument("--delay-model", default="auto",
                   help="auto (probe RIS Live, fall back to none) | ris | none | trace:FILE | fixed:S | uniform:A,B")
    g.add_argument("--probe-seconds", type=float, default=60, help="how long to listen to real RIS Live")
    g.add_argument("--probe-host", default="rrc00", help="RIS collector to sample for the probe ('' = all collectors)")
    g.add_argument("--probe-url", default=netfeed.RIS_URL)
    g.add_argument("--rate", type=float, default=20.0, help="labelled messages sent per second")
    g.add_argument("--feed-url", help="use an external evaluation/feed_server.py at this ws:// URL instead of the built-in one")
    g.add_argument("--idle-timeout", type=float, default=180, help="give up if no message arrives for this many seconds")
    g.add_argument("--feed-host", default="127.0.0.1")
    g.add_argument("--feed-port", type=int, default=0)
    a = p.parse_args()

    rows = [json.loads(l) for l in open(a.dataset, encoding="utf-8") if l.strip()]
    wl = json.load(open(a.whitelist, encoding="utf-8"))
    os.makedirs(a.out_dir, exist_ok=True)
    os.makedirs(a.db_dir, exist_ok=True)
    backends = make_backends(a)
    if a.mode == "online" and len(backends) > 1:
        raise SystemExit("online mode evaluates one backend per run (use --backend baseline or --backend llm)")

    meta = dict(started=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    probe = None
    if a.mode == "online":
        if a.feed_url:
            delay, meta["delay_desc"] = None, "applied by the external feed server"
        else:
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

    for b in backends:
        slug = b.name.replace(":", "-").replace("/", "-")
        db = os.path.join(a.db_dir, f"moas_{a.mode}_{slug}.db")
        pipe = Pipeline(db, a.window, wl, b)
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
            est = len(rows) / a.rate + (max(delay(k) for k in range(len(rows))) if delay else 0)
            print(f"streaming {len(rows)} labelled updates from {url} (expected about {est:.0f} s) ...", flush=True)
            recs = run_online(rows, pipe, url, a.idle_timeout)
            if lt:
                lt.run(netfeed.close_server(server))
                lt.stop()
        meta["wall_s"] = time.time() - t
        recs.sort(key=lambda r: r["seq"])
        if a.mode == "online" and probe and probe["messages"]:
            rp = Pipeline(os.path.join(a.db_dir, f"moas_realfeed_{slug}.db"), a.window, wl, b)
            ds = time_real_feed(probe["messages"], rp)
            dur = max(a.probe_seconds, 1e-9)
            meta["realfeed"] = dict(n=len(ds), rate=len(ds) / dur, triggered=sum(d["triggered"] for d in ds),
                                    busy_pct=100 * sum(d["decision_s"] for d in ds) / dur,
                                    delay=lat(probe["delays"]), rtt=lat(probe["rtts"]),
                                    decision=lat([d["decision_s"] for d in ds]),
                                    decision_trig=lat([d["decision_s"] for d in ds if d["triggered"]]))
        md, summary, det = report(a, a.mode, b.name, rows, recs, meta)
        base = os.path.join(a.out_dir, f"{a.mode}_{slug}")
        write_outputs(base, md, recs, CSV_COLS, extra=dict(summary=summary, detection=det,
                                                           meta={k: v for k, v in meta.items() if k != "probe"}))
        m = summary["metrics"]
        print(f"[{a.mode}/{b.name}] accuracy {m['accuracy']}  precision {m['precision']}  recall {m['recall']}  "
              f"F1 {m['f1']}  uncertain {m['uncertain']}  episodes detected {summary['detected']}  "
              f"decision p50 {summary['decision'].get('p50')} ms  p95 {summary['decision'].get('p95')} ms"
              + (f"  end-to-end p50 {summary['e2e'].get('p50')} ms" if summary.get("e2e") else ""))
        print(f"  -> {base}.md / .json / .csv")
    write_summary(a.out_dir)
    print(f"  -> {os.path.join(a.out_dir, 'summary.md')}")


if __name__ == "__main__":
    main()
