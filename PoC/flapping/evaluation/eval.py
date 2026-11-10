"""TEST 1 - SIMULATED data: accuracy + detection latency of the flap detector on a labelled set (default 250 cases).
   python make_eval_set.py                               # once: writes eval_set.jsonl
   python eval.py eval_set.jsonl                         # default thresholds -> results_sim.md/.json/.csv
   python eval.py eval_set.jsonl --sweep                 # also: accuracy/latency for several alert thresholds
   python eval.py eval_set.jsonl --suppress 1000         # one custom setting

Each case is run through a FRESH detector (no state carried between cases). A case is predicted FLAP if the detector
raises at least one onset alert. Latency is measured from t0 (first withdrawal / path change of the flapping
episode) to the first alert:
   detection delay  = alert time - t0                 (stream time: how long the flap had to run before it was detectable)
   compute time     = CPU time the detector spent on the case's messages up to that alert
   total time       = detection delay + compute time
Compared against two naive baselines on the same cases:
   B1 any-withdrawal : a single withdrawal = flap                       (what you get with no flap logic)
   B2 count>=3/10min : 3 withdrawals/path changes of one route in 10 min (a simple stateless counter)
"""
import argparse, csv, json, statistics, time
import timing
from timing import TimedDetector, pct, changes


# ---------------------------------------------------------------- one case through each method
def run_detector(case, cfg):
    det = TimedDetector(source="eval", **cfg)
    spent, hit = 0.0, None
    for m in case["updates"]:
        t = time.perf_counter()
        out = det.process(m)
        spent += time.perf_counter() - t
        on = [a for a in out if a["event"] == "onset"]
        if on and hit is None:
            hit = (min(a["ts"] for a in on), spent, min(a["events_to_detect"] or 0 for a in on))
    return hit, spent, len(case["updates"])


def run_b1(case):
    """naive: first withdrawal of anything."""
    ts = [m["timestamp"] for m in case["updates"] if m.get("type") == "UPDATE" and m.get("withdrawals")]
    return (min(ts), 0.0, 1) if ts else None


def run_b2(case, n=3, win=600):
    """stateless counter: n withdrawals/path changes of one route within `win` s (no reset handling, no decay)."""
    ev, last = {}, {}
    for m in sorted(case["updates"], key=lambda m: m["timestamp"]):
        if m.get("type") != "UPDATE":
            continue
        host, peer, t = m.get("host", ""), str(m.get("peer") or m.get("peer_asn", "")), m["timestamp"]
        for p in m.get("withdrawals") or []:
            ev.setdefault((p, host, peer), []).append(t)
            if sum(1 for x in ev[(p, host, peer)] if t - x <= win) >= n:
                return t, 0.0, n
        pt = tuple(map(lambda h: tuple(h) if isinstance(h, list) else h, m.get("path") or []))
        for a in m.get("announcements") or []:
            for p in a.get("prefixes", []):
                k = (p, host, peer)
                if k in last and last[k] != pt:
                    ev.setdefault(k, []).append(t)
                    if sum(1 for x in ev[k] if t - x <= win) >= n:
                        return t, 0.0, n
                last[k] = pt
    return None


# ---------------------------------------------------------------- scoring
def metrics(rows):
    tp = sum(r["truth"] and r["pred"] for r in rows); fp = sum((not r["truth"]) and r["pred"] for r in rows)
    fn = sum(r["truth"] and (not r["pred"]) for r in rows); tn = sum((not r["truth"]) and (not r["pred"]) for r in rows)
    pr = tp / (tp + fp) if tp + fp else 0.0; rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    d = [r["delay"] for r in rows if r["truth"] and r["pred"] and r["delay"] is not None]
    tot = [r["total"] for r in rows if r["truth"] and r["pred"] and r["total"] is not None]
    ev = [r["events"] for r in rows if r["truth"] and r["pred"] and r["events"]]
    n = len(rows)
    return dict(n=n, tp=tp, fp=fp, fn=fn, tn=tn, accuracy=round((tp + tn) / n, 3) if n else 0.0, precision=round(pr, 3),
                recall=round(rc, 3), f1=round(f1, 3), fpr=round(fp / (fp + tn), 3) if fp + tn else 0.0,
                delay_mean_s=round(statistics.mean(d), 1) if d else None, delay_median_s=round(statistics.median(d), 1) if d else None,
                delay_p95_s=round(pct(d, 95), 1) if d else None, delay_min_s=round(min(d), 1) if d else None,
                delay_max_s=round(max(d), 1) if d else None,
                total_median_s=round(statistics.median(tot), 3) if tot else None,
                events_median=statistics.median(ev) if ev else None)


def evaluate(cases, cfg):
    rows, spent_all, msgs_all = [], 0.0, 0
    for c in cases:
        truth, t0 = c["label"] == "flap", c.get("t0")
        for name, fn in (("detector", lambda: run_detector(c, cfg)), ("B1", lambda: (run_b1(c), 0, 0)),
                         ("B2", lambda: (run_b2(c), 0, 0))):
            res = fn()
            hit, spent, nmsg = (res if name == "detector" else (res[0], 0.0, 0))
            if name == "detector":
                spent_all += spent; msgs_all += nmsg
            pred = hit is not None
            delay = (hit[0] - t0) if (pred and truth and t0 is not None) else None
            rows.append(dict(id=c["id"], kind=c["kind"], difficulty=c["difficulty"], method=name, truth=truth, pred=pred,
                             delay=delay, compute_s=hit[1] if hit else None,
                             total=(delay + hit[1]) if delay is not None else None, events=hit[2] if hit else None))
    return rows, spent_all, msgs_all


def table(rows_by_name):
    out = ["| Method | n | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 | FPR | Delay median (s) | Delay mean (s) | Delay p95 (s) |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for k, m in rows_by_name.items():
        out.append(f"| {k} | {m['n']} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {m['accuracy']} | {m['precision']} | {m['recall']} | "
                   f"{m['f1']} | {m['fpr']} | {m['delay_median_s']} | {m['delay_mean_s']} | {m['delay_p95_s']} |")
    return "\n".join(out)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file"); ap.add_argument("--out", default="results_sim"); ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--half-life", type=int, default=900); ap.add_argument("--suppress", type=int, default=2000)
    ap.add_argument("--reuse", type=int, default=750); ap.add_argument("--min-peers", type=int, default=1)
    a = ap.parse_args()
    cases = [json.loads(l) for l in open(a.file)]
    cfg = dict(half_life=a.half_life, suppress=a.suppress, reuse=a.reuse, min_peers=a.min_peers)
    rows, spent, nmsg = evaluate(cases, cfg)
    by = lambda meth, f=lambda r: True: [r for r in rows if r["method"] == meth and f(r)]
    names = {"detector": f"Flap detector (suppress={a.suppress})", "B1": "B1 any-withdrawal", "B2": "B2 count>=3 in 10 min"}
    md = [f"# Route flapping: SIMULATED test ({len(cases)} cases)",
          f"Detector settings: half-life {a.half_life}s, suppress {a.suppress}, reuse {a.reuse}, min-peers {a.min_peers}. "
          f"Positives: {sum(c['label'] == 'flap' for c in cases)}, negatives: {sum(c['label'] == 'normal' for c in cases)}.",
          "Ground truth = independent count rule (>=4 changes in 15 min or >=5 in 90 min, session resets excluded); see timing.py.", ""]
    for title, flt in (("All cases", lambda r: True), ("Easy cases", lambda r: r["difficulty"] == "easy"),
                       ("Hard cases (slow / borderline / near-threshold normals)", lambda r: r["difficulty"] == "hard")):
        sub = {names[m]: metrics(by(m, flt)) for m in names}
        md += [f"## {title}", table(sub), ""]
    # latency block (detector, true positives only)
    tp = [r for r in by("detector") if r["truth"] and r["pred"]]
    md += ["## Latency (detector, correctly detected flaps)",
           "| Measure | median | mean | p95 | min | max |", "|---|---|---|---|---|---|"]
    def row(label, xs, f=lambda v: round(v, 2)):
        xs = [x for x in xs if x is not None]
        return (f"| {label} | {f(statistics.median(xs))} | {f(statistics.mean(xs))} | {f(pct(xs, 95))} | {f(min(xs))} | {f(max(xs))} |" if xs else f"| {label} | - | - | - | - | - |")
    md += [row("Detection delay (s): alert time - first change", [r["delay"] for r in tp]),
           row("Compute time to alert (ms)", [r["compute_s"] * 1000 for r in tp], lambda v: round(v, 3)),
           row("Total time to detect (s) = delay + compute", [r["total"] for r in tp], lambda v: round(v, 3)),
           row("Withdrawals/path changes needed before the alert", [r["events"] for r in tp], lambda v: round(v, 1)), ""]
    md += [f"Detector throughput: {nmsg} messages in {spent * 1000:.1f} ms = {nmsg / max(spent, 1e-9):,.0f} msg/s "
           f"({spent / max(nmsg, 1) * 1e6:.1f} us per message, this machine).", ""]
    # per-kind
    md += ["## Per kind (detector)", "| Kind | Truth | Difficulty | Cases | Correct | Missed / false alarms | Median delay (s) |", "|---|---|---|---|---|---|---|"]
    kinds = sorted({(r["kind"], r["truth"], r["difficulty"]) for r in by("detector")})
    for kd, truth, diff in kinds:
        sub = by("detector", lambda r: r["kind"] == kd)
        ok = sum(r["pred"] == truth for r in sub)
        d = [r["delay"] for r in sub if r["delay"] is not None]
        md.append(f"| {kd} | {'flap' if truth else 'normal'} | {diff} | {len(sub)} | {ok} | {len(sub) - ok} | {round(statistics.median(d), 1) if d else '-'} |")
    wrong = [r for r in by("detector") if r["pred"] != r["truth"]]
    md += ["", f"## Detector errors ({len(wrong)})"] + [f"- {r['id']} ({r['kind']}): {'MISSED a flap' if r['truth'] else 'FALSE ALARM'}" for r in wrong]
    sweep = []
    if a.sweep:
        md += ["", "## Threshold sweep (accuracy vs latency trade-off)", "| suppress | Accuracy | Precision | Recall | F1 | FPR | Delay median (s) | Delay p95 (s) |", "|---|---|---|---|---|---|---|---|"]
        for s in (1000, 1500, 2000, 2500, 3000, 4000, 6000):
            r2, _, _ = evaluate(cases, {**cfg, "suppress": s})
            m = metrics([r for r in r2 if r["method"] == "detector"]); sweep.append({"suppress": s, **m})
            md.append(f"| {s} | {m['accuracy']} | {m['precision']} | {m['recall']} | {m['f1']} | {m['fpr']} | {m['delay_median_s']} | {m['delay_p95_s']} |")
    # how much does the headline depend on OUR definition of "flapping"? relabel every case with other count thresholds
    md += ["", "## Sensitivity to the ground-truth definition (accuracy only)",
           "The labels come from our own rule (>=N changes in 15 min or >=N+1 in 90 min). Re-labelling with other N shows how much the score depends on that choice.",
           "| N | positives | Accuracy | Precision | Recall | F1 | FP | FN |", "|---|---|---|---|---|---|---|---|"]
    pred = {r["id"]: r["pred"] for r in by("detector")}
    keep = (timing.N_SHORT, timing.N_LONG)
    for n in (3, 4, 5, 6):
        timing.N_SHORT, timing.N_LONG = n, n + 1
        rl = [dict(truth=bool(timing.oracle(c["updates"])), pred=pred[c["id"]], delay=None, total=None, events=None) for c in cases]
        m = metrics(rl)
        md.append(f"| {n} | {sum(r['truth'] for r in rl)} | {m['accuracy']} | {m['precision']} | {m['recall']} | {m['f1']} | {m['fp']} | {m['fn']} |")
    timing.N_SHORT, timing.N_LONG = keep
    open(a.out + ".md", "w", encoding="utf-8").write("\n".join(md) + "\n")
    json.dump({"config": cfg, "overall": {names[m]: metrics(by(m)) for m in names}, "sweep": sweep, "rows": rows},
              open(a.out + ".json", "w", encoding="utf-8"), indent=1)
    with open(a.out + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["id", "kind", "difficulty", "method", "truth_flap", "predicted_flap", "delay_s", "compute_ms", "total_s", "events_to_detect"])
        for r in rows:
            w.writerow([r["id"], r["kind"], r["difficulty"], r["method"], r["truth"], r["pred"],
                        "" if r["delay"] is None else round(r["delay"], 3), "" if r["compute_s"] is None else round(r["compute_s"] * 1000, 4),
                        "" if r["total"] is None else round(r["total"], 4), r["events"] or ""])
    print("\n".join(md))
