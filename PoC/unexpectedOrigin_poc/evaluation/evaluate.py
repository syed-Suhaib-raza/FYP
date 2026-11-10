"""Latency + accuracy evaluation of the Unexpected-Origin PoC (candidate filter -> AS-relationship evidence -> RouteLLM).

Run from the unexpectedOrigin_poc folder:
    python evaluation/evaluate.py --mode offline --mock          # no GPU: tests the evaluation + pipeline only
    python evaluation/evaluate.py --mode online  --mock
    python evaluation/evaluate.py --mode offline                 # real RouteLLM (CUDA machine), 4-bit by default
    python evaluation/evaluate.py --mode online --asrel <caida file>    # NOTE: labels assume evaluation/eval_asrel.txt

Per update the evaluator records what the PoC decides and compares it with the ground truth (make_dataset.py):
  rule      every candidate (watched prefix, origin not whitelisted) is an alert           -> anomalous / benign
  B2        candidate AND origin has no direct relationship with an expected origin        -> anomalous / benign
  pipeline  what the PoC reports: model label is an anomaly -> anomalous (severity high);
            model says none -> benign (kept at severity medium); unparsed/unknown -> uncertain
plus the anomaly type (unexpected_origin / unexpected_deaggregation / none). A repeat that the detector suppresses
(same prefix+origin inside --cooldown) keeps the decision of the earlier alert, as the deployed system does.
Timing per update:
  detector_ms  OriginCandidates.candidates()
  model_ms     pipeline.classify() for each candidate (evidence + model + parse) + SQLite write
  decision_ms  detector + model
online only: network_ms (emit -> sent), queue_ms (sent -> read, incl. waiting behind slow model calls), e2e_ms.
Outputs: evaluation/results/<mode>_<model>.{md,json,csv} and evaluation/results/summary.md
"""
import argparse, glob, json, os, platform, sys, tempfile, time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [HERE, ROOT]

from asrel import ASRel                                           # noqa: E402  (PoC modules)
from detector import OriginCandidates, origin_of                  # noqa: E402
from pipeline import Store, classify                              # noqa: E402
from prompt import build_messages                                 # noqa: E402
import netfeed                                                    # noqa: E402
from evalcore import (classification, confusion, lat, lat_table, metric_table, group_table, LoopThread,  # noqa: E402
                      write_outputs, _fmt_ms)

CSV_COLS = ["seq", "timestamp", "prefix", "origin", "scenario", "category", "difficulty", "in_scope", "truth", "truth_type",
            "pred", "pred_type", "rule_pred", "b2_pred", "model_label", "suppressed", "triggered", "detector_ms", "model_ms",
            "llm_ms", "decision_ms", "network_ms", "queue_ms", "e2e_ms", "raw_output"]
NOT_ANOMALY = ("none", "unparsed", "unknown")


class Pipeline:
    def __init__(self, db, whitelist, asrel, llm, a):
        for s in ("", "-wal", "-shm"):
            if os.path.exists(db + s):
                os.remove(db + s)
        self.det = OriginCandidates(whitelist, a.only_exact, a.cooldown)
        self.store, self.asrel, self.llm, self.a = Store(db), asrel, llm, a
        self.last = {}                 # (prefix, origin) -> decision of the latest alert, for suppressed repeats

    def decide(self, data):
        pfx = next((p for x in data.get("announcements", []) for p in x.get("prefixes", [])), None)
        org = origin_of(data.get("path") or [])
        before = self.det.suppressed
        t0 = time.perf_counter()
        cands = self.det.candidates(data)
        t1 = time.perf_counter()
        res = []
        for c in cands:
            r = classify(c, self.asrel, self.llm, self.a.top_k, self.a.ownership_evidence)
            self.store.add(r)
            res.append(r)
        t2 = time.perf_counter()
        d = dict(prefix=pfx, origin=org, triggered=bool(res), suppressed=False, detector_s=t1 - t0,
                 model_s=(t2 - t1) if res else None, llm_s=res[0]["latency"] if res else None, decision_s=t2 - t0)
        if res:
            r = res[0]
            label = r["label"]
            dec = dict(rule_pred="anomalous", pred_type_rule=r["anomaly_type"], model_label=label, raw_output=r["raw_output"],
                       b2_pred="benign" if any(self.asrel.pair(r["origin"], e) for e in r["expected"]) else "anomalous",
                       pred="benign" if label == "none" else "uncertain" if label in NOT_ANOMALY else "anomalous")
            dec["pred_type"] = r["anomaly_type"] if dec["pred"] == "anomalous" else "none"
            self.last[(r["prefix"], r["origin"])] = dec
            d.update(dec)
        elif self.det.suppressed > before and (pfx, org) in self.last:
            d.update(self.last[(pfx, org)], suppressed=True)
        else:
            d.update(rule_pred="benign", b2_pred="benign", pred="benign", pred_type="none", pred_type_rule="none",
                     model_label=None, raw_output=None)
        return d


def record(i, row, d, timing=None):
    t, data = row["truth"], row["data"]
    r = dict(seq=i, timestamp=data["timestamp"], scenario=t["scenario"], category=t["category"], difficulty=t["difficulty"],
             in_scope=t["in_scope"], truth=t["label"], truth_type=t["type"], **d)
    r.update(timing or {})
    for k in ("detector", "model", "llm", "decision", "network", "queue", "e2e"):
        v = r.get(k + "_s")
        r[k + "_ms"] = round(v * 1000, 4) if v is not None else None
    return r


def run_offline(rows, pipe):
    out = []
    for i, row in enumerate(rows):
        t_in = time.time()
        d = pipe.decide(row["data"])
        out.append(record(i, row, d, dict(t_ingest=t_in, t_decided=t_in + d["decision_s"])))
    return out


def run_online(rows, pipe, url, idle_timeout=180):
    import asyncio
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

    try:
        asyncio.run(netfeed.stream_client(url, on_message, max_wait=idle_timeout))
    except TimeoutError as e:
        raise SystemExit(f"\nstream stalled: {e} after {len(seen)}/{len(rows)} updates (raise --idle-timeout if the "
                         f"model or the feed delay is legitimately slower)")
    if sorted(seen) != list(range(len(rows))):
        print(f"WARNING: received {len(set(seen))}/{len(rows)} labelled messages")
    return recs


# ------------------------------------------------------------------------------------------------------------
def type_confusion(recs, key):
    types = ("unexpected_origin", "unexpected_deaggregation", "none")
    rows = ["| truth type \\ predicted | " + " | ".join(types) + " |", "|---|---|---|---|"]
    for t in types:
        rows.append(f"| {t} | " + " | ".join(str(sum(r["truth_type"] == t and r[key] == p for r in recs)) for p in types) + " |")
    ok = sum(r["truth_type"] == r[key] for r in recs)
    return "\n".join(rows) + f"\n\nType accuracy (benign = none): {ok}/{len(recs)} = {ok / len(recs):.3f}" if recs else ""


def detection(recs):
    by = {}
    for r in recs:
        if r["truth"] == "anomalous" and r["in_scope"]:
            by.setdefault(r["scenario"], []).append(r)
    out = []
    for sid, rs in sorted(by.items()):
        rs.sort(key=lambda r: r["seq"])
        hit = next((k for k, r in enumerate(rs) if r["pred"] == "anomalous"), None)
        a = rs[0]
        row = dict(scenario=sid, prefix=a["prefix"], origin=a["origin"], category=a["category"], difficulty=a["difficulty"],
                   detected=hit is not None, rule_detected=any(r["rule_pred"] == "anomalous" for r in rs))
        if hit is not None:
            row.update(updates_to_detect=hit + 1, wall_time_to_detect_ms=round((rs[hit]["t_decided"] - a["t_ingest"]) * 1000, 3))
        out.append(row)
    return out


def report(a, mode, model_name, rows, recs, meta):
    ins = [r for r in recs if r["in_scope"]]
    oos = [r for r in recs if not r["in_scope"]]
    m_pipe = classification([(r["truth"], r["pred"]) for r in ins])
    m_rule = classification([(r["truth"], r["rule_pred"]) for r in ins])
    m_b2 = classification([(r["truth"], r["b2_pred"]) for r in ins])
    trig = [r for r in recs if r["triggered"]]
    det = detection(recs)
    md = [f"# Unexpected Origin PoC evaluation: {mode} (model: {model_name})", ""]
    if model_name == "MOCK":
        md += ["> **MOCK model.** `llm.MockLLM` is a string-matching stand-in, not RouteLLM. The *pipeline* numbers below test the "
               "evaluation and the plumbing only; model accuracy and model latency must come from a run without `--mock` on the GPU machine.", ""]
    md += [f"- run: {meta['started']} on {platform.node()} ({platform.system()} {platform.machine()}, Python {platform.python_version()})",
           f"- dataset: `{os.path.relpath(a.dataset, ROOT)}`: {len(rows)} updates ({sum(r['truth']['label'] == 'benign' for r in rows)} benign, "
           f"{sum(r['truth']['label'] == 'anomalous' and r['truth']['in_scope'] for r in rows)} anomalous in scope, "
           f"{sum(not r['truth']['in_scope'] for r in rows)} anomalous out of scope); synthetic, labels by construction",
           f"- whitelist `{os.path.relpath(a.whitelist, ROOT)}`, AS relationships `{os.path.relpath(a.asrel, ROOT) if a.asrel else None}`, "
           f"cooldown {a.cooldown} s, ownership evidence {'on' if a.ownership_evidence else 'off'}, top-k {a.top_k}"
           + (f", quantisation {a.quant}" if model_name != "MOCK" else ""),
           f"- model load time (excluded from latency): {meta['load_s']:.2f} s; warm-up calls: {a.warmup}",
           f"- wall time for the whole stream: {meta['wall_s']:.2f} s"]
    if mode == "online":
        md += [f"- transport: websocket, RIS Live protocol, {meta['feed']}; send rate {a.rate} msg/s",
               f"- feed delay model: {meta['delay_desc']}"]
        if meta.get("probe"):
            pr = meta["probe"]
            md.append("- real RIS Live probe: " + netfeed.probe_text(pr))
    md += ["", "## 1. Classification (in-scope updates)", "",
           "| metric | rule only (candidate = alert) | rule + B2 (no CAIDA relationship) | **PoC pipeline (rule + model)** |", "|---|---|---|---|"]
    for k, lbl in [("n", "updates"), ("accuracy", "accuracy (uncertain = wrong)"), ("uncertain", "uncertain"),
                   ("precision", "precision"), ("recall", "recall"), ("f1", "F1"), ("fpr", "false-positive rate"),
                   ("tp", "TP"), ("fp", "FP"), ("fn", "FN"), ("tn", "TN")]:
        md.append(f"| {lbl} | {m_rule[k]} | {m_b2[k]} | **{m_pipe[k]}** |")
    md += ["", "PoC pipeline confusion:", "", confusion([(r["truth"], r["pred"]) for r in ins]), "",
           "### Anomaly type (PoC pipeline)", "", type_confusion(ins, "pred_type"), "",
           "### By category (PoC pipeline)", "", group_table(ins, "category"), "",
           "## 2. Time to decision", "",
           "*Triggering* updates are candidates that went to the model; every other update is decided by the candidate filter "
           "alone (including repeats suppressed by the cooldown).", "", "All values in milliseconds.", ""]
    rows_lat = [("candidate filter, all updates", lat([r["detector_s"] for r in recs])),
                ("model generate (rounded to 10 ms by classify), triggering", lat([r["llm_s"] for r in trig])),
                ("classify + store, triggering", lat([r["model_s"] for r in trig])),
                ("decision, all updates", lat([r["decision_s"] for r in recs])),
                ("decision, triggering updates", lat([r["decision_s"] for r in trig])),
                ("decision, non-triggering updates", lat([r["decision_s"] for r in recs if not r["triggered"]]))]
    if mode == "online":
        rows_lat += [("feed delay incl. sender scheduling (emit -> sent)", lat([r["network_s"] for r in recs])),
                     ("socket + queueing (sent -> read)", lat([r["queue_s"] for r in recs])),
                     ("end-to-end (emit -> decision), all", lat([r["e2e_s"] for r in recs])),
                     ("end-to-end (emit -> decision), triggering", lat([r["e2e_s"] for r in trig]))]
    md += [lat_table(rows_lat), "",
           "## 3. Detection of hijack episodes", "",
           "An episode is one hijack announcement plus its repeats from other vantage points. Wall time runs from the first "
           "anomalous update's " + ("emit" if mode == "online" else "ingest") + " to the first `anomalous` decision.", "",
           "| episode | prefix | origin | category | difficulty | rule alerted | pipeline detected | updates until detection | wall time (ms) |",
           "|---|---|---|---|---|---|---|---|---|"]
    for d in det:
        md.append(f"| {d['scenario']} | {d['prefix']} | AS{d['origin']} | {d['category']} | {d['difficulty']} | {'yes' if d['rule_detected'] else 'NO'} | "
                  f"{'yes' if d['detected'] else 'NO'} | {d.get('updates_to_detect', '-')} | {_fmt_ms(d.get('wall_time_to_detect_ms'))} |")
    nd = sum(d["detected"] for d in det)
    md += ["", f"Pipeline detected {nd}/{len(det)} episodes; the rule layer alerted on {sum(d['rule_detected'] for d in det)}/{len(det)}.", "",
           "## 4. Out-of-scope anomalies (origin is the expected one, so no candidate)", "", "| category | n | PoC said anomalous |", "|---|---|---|"]
    cats = {}
    for r in oos:
        cats.setdefault(r["category"], []).append(r)
    for c, rs in sorted(cats.items()):
        md.append(f"| {c} | {len(rs)} | {sum(r['pred'] == 'anomalous' for r in rs)} |")
    md += ["", "## 5. Misclassified in-scope updates (PoC pipeline)", "",
           "| seq | episode | prefix | origin | category | truth | predicted | model label | raw output |", "|---|---|---|---|---|---|---|---|---|"]
    for r in ins:
        if r["truth"] != r["pred"]:
            raw = (r.get("raw_output") or "").replace("|", "/").replace("\n", " ")[:60]
            md.append(f"| {r['seq']} | {r['scenario']} | {r['prefix']} | AS{r['origin']} | {r['category']} | {r['truth']} | {r['pred']} | "
                      f"{r.get('model_label') or '-'} | {raw} |")
    md += ["", "Model label counts: " + json.dumps({l: sum(r.get('model_label') == l for r in trig) for l in sorted({r.get('model_label') for r in trig})}), "",
           "## Notes", "",
           "- Labels are synthetic and true by construction for the relationships in `evaluation/eval_asrel.txt`; with a real CAIDA "
           "file the evidence changes but the labels do not, so keep the evaluation file for scoring.",
           "- Accuracy counts `uncertain` as wrong; precision/recall count `uncertain` as an alert (it goes to an operator).",
           "- Offline replays the stream as fast as possible in one process: latency = processing only. Model load time is excluded."]
    if mode == "online":
        md.append("- Online streams the same updates over a websocket in RIS Live format. The feed server runs on its own thread, so "
                  "while a slow model call blocks the PoC, later updates queue up (visible in `sent -> read` and end-to-end).")
    if meta.get("realfeed"):
        rf = meta["realfeed"]
        md += ["", "## 6. Real RIS Live traffic (unlabelled, timing only)", "",
               f"{rf['n']} real messages ({rf['rate']:.1f} msg/s); {rf['triggered']} were candidates for the watched prefixes; "
               f"processing used {rf['busy_pct']:.2f}% of the wall time.", "",
               lat_table([("RIS Live feed delay (arrival - collector timestamp)", rf["delay"]),
                          ("websocket round trip to RIS Live", rf["rtt"]),
                          ("decision, all real updates", rf["decision"]),
                          ("decision, triggering real updates", rf["decision_trig"])]), ""]
    summary = dict(mode=mode, backend=model_name, metrics=m_pipe, rule_metrics=m_rule, b2_metrics=m_b2, n_updates=len(recs),
                   type_accuracy=round(sum(r["truth_type"] == r["pred_type"] for r in ins) / len(ins), 3),
                   decision=lat([r["decision_s"] for r in recs]), decision_trig=lat([r["decision_s"] for r in trig]),
                   e2e=lat([r.get("e2e_s") for r in recs]) if mode == "online" else None,
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
    md = ["# Unexpected Origin PoC: evaluation summary", "", "PoC pipeline decisions (rule + model). Latency in milliseconds. "
          "MOCK rows test the plumbing only, not RouteLLM.", "",
          "| run | model | updates | accuracy | precision | recall | F1 | FPR | uncertain | type accuracy | episodes detected | decision p50 | decision p95 (triggering) | network p50 | end-to-end p50 | end-to-end p95 |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in sorted(runs, key=lambda s: (s["backend"], s["mode"] != "offline")):
        m = s["metrics"]
        md.append(f"| {s['mode']} | {s['backend']} | {s['n_updates']} | {m['accuracy']} | {m['precision']} | {m['recall']} | {m['f1']} | {m['fpr']} | "
                  f"{m['uncertain']} | {s['type_accuracy']} | {s['detected']} | {ms(s['decision'], 'p50')} | {ms(s['decision_trig'], 'p95')} | "
                  f"{ms(s.get('network'), 'p50')} | {ms(s.get('e2e'), 'p50')} | {ms(s.get('e2e'), 'p95')} |")
    r0 = runs[0]
    md += ["", f"Reference (same updates, no model): rule only accuracy {r0['rule_metrics']['accuracy']}, precision {r0['rule_metrics']['precision']}, "
           f"recall {r0['rule_metrics']['recall']}; rule + B2 accuracy {r0['b2_metrics']['accuracy']}, precision {r0['b2_metrics']['precision']}, "
           f"recall {r0['b2_metrics']['recall']}.", "",
           "Online feed delay model per run: " + "; ".join(f"{s['mode']}/{s['backend']}: {s['delay_model']}" for s in runs if s.get("delay_model")), ""]
    open(os.path.join(out_dir, "summary.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")


# ------------------------------------------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--mode", choices=["offline", "online"], required=True)
    p.add_argument("--dataset", default=os.path.join(HERE, "labelled_updates.jsonl"))
    p.add_argument("--whitelist", default=os.path.join(HERE, "eval_whitelist.json"))
    p.add_argument("--asrel", default=os.path.join(HERE, "eval_asrel.txt"))
    p.add_argument("--base-model", default=os.environ.get("ROUTE_LLM_BASE_MODEL", "meta-llama/Meta-Llama-3.1-8B-Instruct"))
    p.add_argument("--adapter", default=os.environ.get("ROUTE_LLM_ADAPTER", os.path.join(ROOT, "models", "route-llm-llama3.1-8b-instruct-lora")))
    p.add_argument("--quant", choices=["4bit", "8bit", "bf16"], default="4bit")
    p.add_argument("--mock", action="store_true", help="MockLLM (no GPU): tests the pipeline/evaluation only")
    p.add_argument("--only-exact", action="store_true")
    p.add_argument("--cooldown", type=int, default=600)
    p.add_argument("--top-k", type=int, default=8)
    p.add_argument("--ownership-evidence", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--warmup", type=int, default=1, help="untimed model calls before the stream (CUDA warm-up)")
    p.add_argument("--out-dir", default=os.path.join(HERE, "results"))
    p.add_argument("--db-dir", default=os.path.join(tempfile.gettempdir(), "poc_eval"),
                   help="where the PoC's scratch SQLite files go (default: system temp dir)")
    g = p.add_argument_group("online")
    g.add_argument("--delay-model", default="auto", help="auto (probe RIS Live, fall back to none) | ris | none | trace:FILE | fixed:S | uniform:A,B")
    g.add_argument("--probe-seconds", type=float, default=60)
    g.add_argument("--probe-host", default="rrc00", help="RIS collector to sample for the probe ('' = all)")
    g.add_argument("--probe-url", default=netfeed.RIS_URL)
    g.add_argument("--rate", type=float, default=20.0, help="labelled messages sent per second")
    g.add_argument("--feed-url", help="use an external evaluation/feed_server.py at this ws:// URL")
    g.add_argument("--idle-timeout", type=float, default=180, help="give up if no message arrives for this many seconds")
    g.add_argument("--feed-host", default="127.0.0.1")
    g.add_argument("--feed-port", type=int, default=0)
    a = p.parse_args()

    rows = [json.loads(l) for l in open(a.dataset, encoding="utf-8") if l.strip()]
    wl = json.load(open(a.whitelist, encoding="utf-8"))
    os.makedirs(a.out_dir, exist_ok=True)
    os.makedirs(a.db_dir, exist_ok=True)
    meta = dict(started=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))

    t = time.time()
    asrel = ASRel(a.asrel)
    if a.mock:
        from llm import MockLLM
        llm = MockLLM()
    else:
        from llm import RouteLLM
        llm = RouteLLM(a.base_model, a.adapter, a.quant)
    for _ in range(a.warmup):
        llm.generate(build_messages("TIME: 0, TYPE: A, PREFIX: 192.0.2.0/24, ASPATH: 64500 64501", ["AS64500 and AS64501 are peers."]))
    meta["load_s"] = time.time() - t

    probe, delay = None, None
    if a.mode == "online":
        if a.feed_url:
            meta["delay_desc"] = "applied by the external feed server"
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

    slug = llm.name.replace(":", "-").replace("/", "-")
    pipe = Pipeline(os.path.join(a.db_dir, f"uo_{a.mode}_{slug}.db"), wl, asrel, llm, a)
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
        rp = Pipeline(os.path.join(a.db_dir, f"uo_realfeed_{slug}.db"), wl, asrel, llm, a)
        ds = [rp.decide(m) for m in probe["messages"]]
        dur = max(a.probe_seconds, 1e-9)
        meta["realfeed"] = dict(n=len(ds), rate=len(ds) / dur, triggered=sum(d["triggered"] for d in ds),
                                busy_pct=100 * sum(d["decision_s"] for d in ds) / dur, delay=lat(probe["delays"]), rtt=lat(probe["rtts"]),
                                decision=lat([d["decision_s"] for d in ds]), decision_trig=lat([d["decision_s"] for d in ds if d["triggered"]]))

    md, summary, det = report(a, a.mode, llm.name, rows, recs, meta)
    base = os.path.join(a.out_dir, f"{a.mode}_{slug}")
    write_outputs(base, md, recs, CSV_COLS, extra=dict(summary=summary, detection=det, meta={k: v for k, v in meta.items() if k != "probe"}))
    write_summary(a.out_dir)
    m = summary["metrics"]
    print(f"[{a.mode}/{llm.name}] accuracy {m['accuracy']}  precision {m['precision']}  recall {m['recall']}  F1 {m['f1']}  "
          f"uncertain {m['uncertain']}  type accuracy {summary['type_accuracy']}  episodes detected {summary['detected']}  "
          f"decision p50 {summary['decision'].get('p50')} ms  p95 {summary['decision'].get('p95')} ms"
          + (f"  end-to-end p50 {summary['e2e'].get('p50')} ms" if summary.get("e2e") else ""))
    print(f"  -> {base}.md / .json / .csv\n  -> {os.path.join(a.out_dir, 'summary.md')}")


if __name__ == "__main__":
    main()
