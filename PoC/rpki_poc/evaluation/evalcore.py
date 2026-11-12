"""Metric and report helpers shared by evaluate.py (same file as moas_poc and unexpectedOrigin_poc)."""
import json, os, statistics, threading, asyncio

from netfeed import pctl


def classification(pairs):
    """pairs = [(truth, pred)], truth in {anomalous, benign}, pred in {anomalous, benign, uncertain, no_decision}.
    accuracy       : uncertain / no_decision count as wrong
    TP/FP/FN/TN    : uncertain counts as an alert (it would be sent to an operator for review)
    decided_acc    : accuracy over updates that got a definite anomalous/benign decision"""
    n = len(pairs)
    alert = lambda p: p in ("anomalous", "uncertain", "no_decision")
    tp = sum(t == "anomalous" and alert(p) for t, p in pairs)
    fn = sum(t == "anomalous" and not alert(p) for t, p in pairs)
    fp = sum(t == "benign" and alert(p) for t, p in pairs)
    tn = sum(t == "benign" and not alert(p) for t, p in pairs)
    unc = sum(p in ("uncertain", "no_decision") for _, p in pairs)
    correct = sum(t == p for t, p in pairs)
    dec = [(t, p) for t, p in pairs if p in ("anomalous", "benign")]
    pr = tp / (tp + fp) if tp + fp else float("nan")
    rc = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * pr * rc / (pr + rc) if tp and (pr + rc) else 0.0
    return dict(n=n, correct=correct, accuracy=_r(correct / n) if n else None, uncertain=unc,
                decided=len(dec), decided_accuracy=_r(sum(t == p for t, p in dec) / len(dec)) if dec else None,
                tp=tp, fp=fp, fn=fn, tn=tn, precision=_r(pr), recall=_r(rc), f1=_r(f1),
                fpr=_r(fp / (fp + tn)) if fp + tn else None)


def confusion(pairs, truths=("anomalous", "benign"), preds=("anomalous", "benign", "uncertain", "no_decision")):
    used = [p for p in preds if any(q == p for _, q in pairs)] or list(preds[:2])
    rows = ["| truth \\ predicted | " + " | ".join(used) + " |", "|---|" + "---|" * len(used)]
    for t in truths:
        rows.append(f"| {t} | " + " | ".join(str(sum(a == t and b == p for a, b in pairs)) for p in used) + " |")
    return "\n".join(rows)


def lat(values_s):
    v = [x for x in values_s if x is not None]
    if not v:
        return dict(n=0)
    ms = [x * 1000 for x in v]
    return dict(n=len(ms), mean=_r(statistics.mean(ms), 3), p50=_r(pctl(ms, 50), 3), p90=_r(pctl(ms, 90), 3),
                p95=_r(pctl(ms, 95), 3), p99=_r(pctl(ms, 99), 3), max=_r(max(ms), 3))


def lat_table(rows):
    """rows = [(name, lat_dict)] -> markdown, milliseconds"""
    out = ["| stage | n | mean | p50 | p90 | p95 | p99 | max |", "|---|---|---|---|---|---|---|---|"]
    for name, d in rows:
        if d.get("n"):
            out.append(f"| {name} | {d['n']} | " + " | ".join(_fmt_ms(d[k]) for k in ("mean", "p50", "p90", "p95", "p99", "max")) + " |")
        else:
            out.append(f"| {name} | 0 | - | - | - | - | - | - |")
    return "\n".join(out)


def metric_table(m):
    keys = [("n", "updates"), ("accuracy", "accuracy (uncertain = wrong)"), ("uncertain", "uncertain / no decision"),
            ("decided_accuracy", "accuracy on decided updates"), ("precision", "precision (alert = anomalous or uncertain)"),
            ("recall", "recall"), ("f1", "F1"), ("fpr", "false-positive rate"),
            ("tp", "TP"), ("fp", "FP"), ("fn", "FN"), ("tn", "TN")]
    return "\n".join(["| metric | value |", "|---|---|"] + [f"| {lbl} | {m.get(k)} |" for k, lbl in keys])


def group_table(recs, key, pred_key="pred"):
    groups = {}
    for r in recs:
        groups.setdefault(r[key], []).append(r)
    out = ["| " + key + " | truth | n | correct | accuracy | predicted | mean decision latency (ms) |", "|---|---|---|---|---|---|---|"]
    for g, rs in sorted(groups.items(), key=lambda kv: (kv[1][0]["truth"], kv[0])):
        c = sum(r["truth"] == r[pred_key] for r in rs)
        preds = {}
        for r in rs:
            preds[r[pred_key]] = preds.get(r[pred_key], 0) + 1
        ml = statistics.mean(r["decision_s"] for r in rs) * 1000
        out.append(f"| {g} | {rs[0]['truth']} | {len(rs)} | {c} | {c / len(rs):.2f} | {json.dumps(preds)} | {_fmt_ms(ml)} |")
    return "\n".join(out)


def _r(x, d=3):
    return None if x is None or x != x else round(x, d)


def _fmt_ms(x):
    if x is None:
        return "-"
    return f"{x:.3f}" if x < 10 else f"{x:.1f}"


class LoopThread:
    """An asyncio loop in a background thread, so the feed server keeps sending on schedule even while the
    PoC blocks its own thread on a slow decision (as a real network would)."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.t = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.t.start()

    def run(self, coro, timeout=None):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)


def write_outputs(base, md_lines, recs, csv_cols, extra=None):
    import csv
    os.makedirs(os.path.dirname(base) or ".", exist_ok=True)
    open(base + ".md", "w", encoding="utf-8").write("\n".join(md_lines) + "\n")
    json.dump(dict(extra or {}, records=recs), open(base + ".json", "w", encoding="utf-8"), indent=1, default=str)
    with open(base + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(csv_cols)
        for r in recs:
            w.writerow([r.get(c) for c in csv_cols])
