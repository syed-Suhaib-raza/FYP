"""Evaluate the model vs. baselines on a labelled set.
   python eval.py eval_set.jsonl --asrel <caida file> [--mock] [--out results]
Baselines (all see exactly the same candidates the model sees):
  B1 whitelist-only : every candidate (origin not in whitelist) is called a hijack
  B2 whitelist+rel  : hijack iff the origin has NO direct CAIDA relationship with any expected origin
Model: "strict" = positive only when label == prefix hijack; "any" = positive for any non-none anomaly label."""
import argparse, json, statistics, csv
from common import add_args, build
from detector import OriginCandidates
from pipeline import classify


def metrics(pairs):
    """pairs = [(truth_is_hijack, predicted_is_hijack)]"""
    tp = sum(t and p for t, p in pairs); fp = sum((not t) and p for t, p in pairs)
    fn = sum(t and (not p) for t, p in pairs); tn = sum((not t) and (not p) for t, p in pairs)
    pr = tp / (tp + fp) if tp + fp else 0.0; rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return dict(n=len(pairs), tp=tp, fp=fp, fn=fn, tn=tn, precision=round(pr, 3), recall=round(rc, 3), f1=round(f1, 3),
                accuracy=round((tp + tn) / len(pairs), 3) if pairs else 0.0)


def table(rows_by_method):
    out = ["| Method | n | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |", "|---|---|---|---|---|---|---|---|---|---|"]
    for name, m in rows_by_method.items():
        out.append(f"| {name} | {m['n']} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {m['precision']} | {m['recall']} | {m['f1']} | {m['accuracy']} |")
    return "\n".join(out)


if __name__ == "__main__":
    p = argparse.ArgumentParser(); p.add_argument("file"); p.add_argument("--out", default="results"); add_args(p)
    a = p.parse_args()
    wl, asrel, llm = build(a)
    recs, skipped = [], 0
    for line in open(a.file, encoding="utf-8"):
        case = json.loads(line)
        cands = OriginCandidates(wl, a.only_exact, cooldown=0).candidates(case["data"])   # fresh detector: no cross-case cooldown
        if not cands:
            skipped += 1; continue
        r = classify(cands[0], asrel, llm, a.top_k, a.ownership_evidence)
        truth = case["label"] == "hijack"
        related = any(asrel.pair(r["origin"], e) for e in r["expected"])
        recs.append(dict(id=case["id"], subtype=r["subtype"], pred_type=r["anomaly_type"], kind=case.get("kind", ""), difficulty=case.get("difficulty", "?"), source=case.get("source", "?"),
                         truth=case["label"], model_label=r["label"], raw=r["raw_output"], latency=r["latency"],
                         b1=True, b2=not related, strict=r["label"] == "prefix hijack", any=r["label"] not in ("none", "unparsed"),
                         unparsed=r["label"] == "unparsed", prefix=r["prefix"], origin=r["origin"], evidence=r["evidence"]))
    def run(subset):
        T = lambda k: [(x["truth"] == "hijack", x[k]) for x in subset]
        return {"B1 whitelist-only": metrics(T("b1")), "B2 whitelist+relationship": metrics(T("b2")),
                f"Model ({llm.name}) strict": metrics(T("strict")), f"Model ({llm.name}) any-anomaly": metrics(T("any"))}
    md = [f"# Unexpected Origin evaluation ({llm.name})", f"{len(recs)} cases evaluated, {skipped} skipped (not candidates). "
          f"Unparsed model outputs: {sum(x['unparsed'] for x in recs)}. Mean latency {statistics.mean(x['latency'] for x in recs):.2f}s.", ""]
    if llm.name == "MOCK":
        md.append("**WARNING: MOCK model: these numbers only test the pipeline.**\n")
    for title, flt in [("All cases", lambda x: True), ("Easy", lambda x: x["difficulty"] == "easy"), ("Hard", lambda x: x["difficulty"] == "hard"),
                       ("Unexpected Origin cases (exact prefix)", lambda x: x["subtype"] == "origin"),
                       ("Unexpected Deaggregation cases (more-specific prefix)", lambda x: x["subtype"] == "deaggregation"),
                       ("Real incidents only", lambda x: x["source"] == "incident")]:
        sub = [x for x in recs if flt(x)]
        if sub:
            md += [f"## {title}", table(run(sub)), ""]
    md.append("## Predicted anomaly type vs. truth (hijack cases only; type = prefix geometry x model verdict)")
    for st in ("origin", "deaggregation"):
        h = [x for x in recs if x["subtype"] == st and x["truth"] == "hijack"]
        if h:
            cnt = {}
            for x in h:
                cnt[x["pred_type"]] = cnt.get(x["pred_type"], 0) + 1
            md.append(f"- true Unexpected {'Origin' if st == 'origin' else 'Deaggregation'} ({len(h)}): predicted {json.dumps(cnt)}")
    md.append("")
    md.append("Model label counts: " + json.dumps({l: sum(x["model_label"] == l for x in recs) for l in sorted({x["model_label"] for x in recs})}))
    open(a.out + ".md", "w", encoding="utf-8").write("\n".join(md) + "\n")
    json.dump(recs, open(a.out + ".json", "w", encoding="utf-8"), indent=1)
    with open(a.out + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["id", "kind", "difficulty", "source", "subtype", "truth", "pred_type", "model_label", "raw", "baseline_B2", "latency"])
        for x in recs:
            w.writerow([x["id"], x["kind"], x["difficulty"], x["source"], x["subtype"], x["truth"], x["pred_type"], x["model_label"], x["raw"], x["b2"], x["latency"]])
    print("\n".join(md))
