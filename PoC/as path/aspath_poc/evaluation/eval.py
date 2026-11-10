"""TEST 1 - SIMULATED data: accuracy + compute time of the AS-path detector on the labelled 250-case set.
Counterpart of flapping/eval.py; TEST 2 (live) is live_eval.py.

   python make_eval_set.py                          # once: writes eval_set.jsonl + eval_as_rel.txt (already included)
   python eval.py eval_set.jsonl                    # -> results_sim.md / results_sim.json / results_sim.csv
   python eval.py eval_set.jsonl --sweep            # + sensitivity table (min-support 1/2/3 x origin-policy authorized/any)
   python eval.py eval_set.jsonl --llm mock         # harness check with the FAKE model (numbers say nothing about the real model)
   python eval.py eval_set.jsonl --llm hf           # the REAL model (same backend names as aspath.py: hf / llamacpp), full model report
   python eval.py eval_set.jsonl --llm hf --llm-runs 2   # run the model twice: repeatability check
   (any other aspath.py model flag, e.g. a model path, is passed through to the model loader)
   python eval.py eval_set.jsonl --min-support 2    # one custom setting (also --len-delta, --origin-policy)

Each case is run through a FRESH Monitor (own prefix, own ASNs, own tiny baseline learnt first -- see make_eval_set.py).
A case is predicted ANOMALOUS if the detector raises an alert for its ONE test message. The baseline messages must never
raise one (NFR3: no false alerts from the learning window itself) -- counted in `false_learn`.

Compared against one naive baseline on the same cases:
   B1 any-new-edge : flag if ANY adjacent AS pair of the test path was not seen in the learning window
                     (no origin / valley-free / prepending logic, just "a link I haven't seen before")
Also reported: rule ablation (which rule catches what), type agreement (does the firing rule name hijack vs leak correctly),
per-kind table with the rule that fired, detector errors, compute time per case.
"""
import argparse, csv, json, statistics, time
from collections import Counter

from aspath import ASRel, Monitor, common
from detector import edge, flat
from llm import make_llm
import llm_eval

LINKS = ("new_as_link", "new_origin_upstream")
LABELS = ("path hijack", "route leak", "normal")


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    i = (len(xs) - 1) * p / 100
    lo, hi = int(i), min(int(i) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (i - lo)


# ---------------------------------------------------------------- one case through each method
def run_detector(case, rel, llm, min_support, len_delta, origin_policy, enabled=None):
    mon = Monitor(None, {case["prefix"]: [case["origin"]]}, rel, llm, (), case["learn"], "eval", "repo", 8, 0,
                  min_support, len_delta, origin_policy, True, True, enabled=enabled)
    spent, false_in_learning, hit = 0.0, False, None
    last = len(case["updates"]) - 1
    for i, u in enumerate(case["updates"]):
        t = time.perf_counter()
        out = mon.process(u["data"])
        spent += time.perf_counter() - t
        if i < last and out:                                   # a baseline / background message must never itself raise an alert
            false_in_learning = True
        if i == last and out:
            hit = out[0]
    return hit, spent, false_in_learning


def run_b1(case):
    """naive: flag the test message if any adjacent AS pair is new relative to the learning-window messages."""
    *base, test = case["updates"]
    seen = set()
    for u in base:
        if u["data"]["announcements"][0]["prefixes"][0] != case["prefix"]:
            continue
        path = flat(u["data"]["path"])
        seen.update(edge(a, b) for a, b in zip(path, path[1:]))
    path = flat(test["data"]["path"])
    return any(edge(a, b) not in seen for a, b in zip(path, path[1:]))


# ---------------------------------------------------------------- scoring
def metrics(rows, pred_key="pred"):
    tp = sum(r["truth"] and r[pred_key] for r in rows); fp = sum((not r["truth"]) and r[pred_key] for r in rows)
    fn = sum(r["truth"] and (not r[pred_key]) for r in rows); tn = sum((not r["truth"]) and (not r[pred_key]) for r in rows)
    pr = tp / (tp + fp) if tp + fp else 0.0; rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    n = len(rows)
    return dict(n=n, tp=tp, fp=fp, fn=fn, tn=tn, accuracy=round((tp + tn) / n, 3) if n else 0.0, precision=round(pr, 3),
                recall=round(rc, 3), f1=round(f1, 3), fpr=round(fp / (fp + tn), 3) if fp + tn else 0.0)


def table(rows_by_name):
    out = ["| Method | n | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 | FPR |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for k, m in rows_by_name.items():
        out.append(f"| {k} | {m['n']} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {m['accuracy']} | {m['precision']} | "
                   f"{m['recall']} | {m['f1']} | {m['fpr']} |")
    return "\n".join(out)


def evaluate(cases, rel, llm, min_support, len_delta, origin_policy, enabled=None):
    rows, spent_all, false_learn = [], 0.0, 0
    for c in cases:
        truth = c["label"] != "normal"
        hit, spent, bad_learn = run_detector(c, rel, llm, min_support, len_delta, origin_policy, enabled)
        spent_all += spent; false_learn += bad_learn
        pred = hit is not None
        rtype = hit["anomaly_type"].replace("_", " ") if hit else None
        rows.append(dict(id=c["id"], kind=c["kind"], label=c["label"], truth=truth, pred=pred, pred_b1=run_b1(c),
                         rtype=rtype, rule=hit["subtype"] if hit else None, type_ok=(rtype == c["label"]) if hit else None,
                         llm_label=hit.get("llm_label") if hit else None, llm_agrees=hit.get("llm_agrees") if hit else None,
                         llm_model=hit.get("model") if hit else None, compute_ms=spent * 1000, bad_learn=bad_learn))
    return rows, spent_all, false_learn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file"); ap.add_argument("--out", default="results_sim")
    ap.add_argument("--as-rel", default="eval_as_rel.txt"); ap.add_argument("--min-support", type=int, default=1)
    ap.add_argument("--len-delta", type=int, default=3); ap.add_argument("--origin-policy", choices=["authorized", "any"], default="authorized")
    ap.add_argument("--llm", choices=["none", "mock", "hf", "llamacpp"], default="hf",
                    help="model backend (default hf = the real model, so the full PoC is tested). --llm none = rules only, on purpose")
    ap.add_argument("--llm-runs", type=int, default=1, help="run the model this many times on the detections (2 = repeatability check)")
    ap.add_argument("--sweep", action="store_true", help="add the sensitivity table (min-support x origin-policy)")
    a, rest = ap.parse_known_args()
    cases = [json.loads(l) for l in open(a.file, encoding="utf-8")]
    rel = ASRel(a.as_rel)
    llm = None
    if a.llm == "none":
        print("WARNING: --llm none: RULES ONLY. The model is NOT tested in this run (omit --llm, or use --llm hf, for the full PoC).", flush=True)
    else:
        try:                                                    # other aspath.py model flags (model path, ...) are passed through
            cargs = common().parse_known_args(rest)[0]
        except SystemExit:
            cargs = argparse.Namespace()
        cargs.llm = a.llm
        llm = make_llm(cargs)
        if llm is None:
            raise SystemExit(f"--llm {a.llm}: make_llm returned no model (check the model files / flags of aspath.py). Not running a model test without a model.")
    # rules-only pass is ALWAYS the main result (so numbers stay comparable with and without a model); the model pass is added on top
    rows, spent, false_learn = evaluate(cases, rel, None, a.min_support, a.len_delta, a.origin_policy)
    model_rows = model_runs = None
    if llm:
        model_runs = [evaluate(cases, rel, llm, a.min_support, a.len_delta, a.origin_policy)[0] for _ in range(max(a.llm_runs, 1))]
        model_rows = model_runs[0]
        if not any(llm_eval.vr(y) != "unscored" for y in model_rows if y["pred"]):
            raise SystemExit("The model was loaded but gave NO usable verdict on any detection (all llm_label empty / 'no model'). "
                             "Not writing a rules-only report as a model test. Check how aspath.py passes the model to Monitor (mode / flags).")
        changed = [x["id"] for x, y in zip(rows, model_rows) if x["pred"] != y["pred"]]
        for x, y in zip(rows, model_rows):
            x.update(llm_label=y["llm_label"], llm_agrees=y["llm_agrees"], llm_model=y["llm_model"], compute_model_ms=y["compute_ms"])

    md = [f"# AS-path anomaly PoC: SIMULATED test ({len(cases)} cases)",
          f"**Model (LLM): {'ON, backend ' + a.llm if llm else 'OFF: RULES ONLY, the model is not tested in this report'}.**",
          f"Detector settings: min-support {a.min_support}, len-delta {a.len_delta}, origin-policy {a.origin_policy}. "
          f"Positives (anomalous): {sum(c['label'] != 'normal' for c in cases)}, negatives (normal): {sum(c['label'] == 'normal' for c in cases)}.",
          f"False alerts raised by a LEARNING-window / background message itself (should be 0, NFR3): {false_learn}", ""]
    md += ["## All cases", table({"Rule engine (all rules)": metrics(rows, "pred"), "B1 any-new-edge": metrics(rows, "pred_b1")}), ""]
    for lab in LABELS:
        sub = [r for r in rows if r["label"] == lab]
        md += [f"## Label = {lab} ({len(sub)} cases)", table({"Rule engine": metrics(sub, "pred"), "B1 any-new-edge": metrics(sub, "pred_b1")}), ""]

    anom = [r for r in rows if r["truth"]]
    det = [r for r in anom if r["pred"]]
    md += ["## Type agreement (anomalous cases): does the FIRING rule's anomaly_type match the ground-truth label?",
           f"- {sum(r['type_ok'] for r in det)}/{len(det)} detected anomalous cases named correctly (path hijack vs route leak)"]
    wrong_type = [r for r in det if not r["type_ok"]]
    if wrong_type:
        md += [f"- mis-typed: {dict(Counter(r['kind'] for r in wrong_type))}"]
    md += [""]

    md += ["## Per kind (rule engine)", "| Kind | Truth | Cases | Correct | Missed / false alarms | Rules that fired |", "|---|---|---|---|---|---|"]
    for kind in sorted({r["kind"] for r in rows}):
        sub = [r for r in rows if r["kind"] == kind]
        ok = sum(r["pred"] == r["truth"] for r in sub)
        fired = dict(Counter(r["rule"] for r in sub if r["rule"])) or "-"
        md.append(f"| {kind} | {sub[0]['label'] if sub[0]['truth'] else 'normal'} | {len(sub)} | {ok} | {len(sub) - ok} | {fired} |")

    wrong = [r for r in rows if r["pred"] != r["truth"]]
    md += ["", f"## Detector errors ({len(wrong)}: missed or false alarm)",
           "Expected by design: normal_new_peer = false alarms (a rules-only detector cannot tell a new legitimate peer from a hijack link). "
           "Any other kind listed here would be a real defect. (leak_unknown_rel is NOT an error here: it is detected, only mis-typed, see type agreement.)", ""]
    md += [f"- {r['id']} ({r['kind']}): {'MISSED' if r['truth'] else 'FALSE ALARM'}" for r in wrong]
    md += ["", "Errors per kind: " + str(dict(Counter(r["kind"] for r in wrong))), ""]

    md += ["## Rule ablation (rules only, no model): which rule catches what", ""]
    abl = {}
    for name, en in (("valley_violation only", ("valley_violation",)), ("new_origin_upstream only", ("new_origin_upstream",)),
                     ("new_as_link only", ("new_as_link",)), ("both link rules", LINKS)):
        r2, _, _ = evaluate(cases, rel, None, a.min_support, a.len_delta, a.origin_policy, en)
        abl[name] = metrics(r2, "pred")
        abl[name + " :: recall by label"] = None
        by = {lab: round(sum(x["pred"] for x in r2 if x["label"] == lab) / max(sum(x["label"] == lab for x in r2), 1), 3) for lab in ("path hijack", "route leak")}
        abl[name + " :: recall by label"] = by
    md += [table({k: v for k, v in abl.items() if "::" not in k}), ""]
    md += [f"- {k.replace(' :: recall by label', '')}: recall on path hijack {v['path hijack']}, on route leak {v['route leak']}" for k, v in abl.items() if "::" in k]
    md += [""]

    sweep = None
    if a.sweep:
        md += ["## Sensitivity: min-support x origin-policy", "(min-support: a link seen fewer times than this in the baseline is 'new'. "
               "The 3-message learning window sees each learned link 2-3 times, 1 time on the alternate path.)", ""]
        sweep = {}
        for pol in ("authorized", "any"):
            for ms in (1, 2, 3):
                r2, _, fl = evaluate(cases, rel, None, ms, a.len_delta, pol)
                m = metrics(r2, "pred"); m["false_learn"] = fl; sweep[f"min-support {ms}, origin-policy {pol}"] = m
        md += [table({k: v for k, v in sweep.items()}), ""]

    comp = [r["compute_ms"] for r in rows]
    nmsg = sum(len(c["updates"]) for c in cases)
    md += ["## Compute time", f"- {len(cases)} cases ({nmsg} messages) in {sum(comp):.1f} ms total; per case (all its messages) median {statistics.median(comp):.3f} ms, "
           f"p95 {pct(comp, 95):.3f} ms, max {max(comp):.3f} ms; about {nmsg / max(sum(comp) / 1000, 1e-9):,.0f} messages/s (single thread, rules only).",
           "- depends on your machine; no network or feed delay exists in this test.", ""]

    llm_sum = veto = stab = None
    if llm:
        name = getattr(llm, "name", None) or a.llm
        llm_sum = llm_eval.sim_summary(rows)
        veto = llm_eval.veto_metrics(rows, metrics)
        stab = llm_eval.stability(model_runs[0], model_runs[1]) if len(model_runs) > 1 else None
        comp_m = [r["compute_model_ms"] for r in rows]
        md += llm_eval.sim_markdown(llm_sum, name, table(veto), stab,
                                    dict(median=statistics.median(comp), p95=pct(comp, 95)),
                                    dict(median=statistics.median(comp_m), p95=pct(comp_m, 95), max=max(comp_m)))
        if changed:
            md += [f"- NOTE: the model run changed the rules' decision on {len(changed)} cases ({changed[:5]}...): in this PoC the model can alter which alerts fire.", ""]
        else:
            md += ["- the model never changed which cases the rules flagged (it only adds a label); detector accuracy above is therefore the rules' accuracy.", ""]

    md += ["## Limits of this simulated test",
           "- the 250 cases are generated by us: they show the code behaves as designed on stated scenarios, not on real BGP",
           "- labels come from construction (we know which message is the attack); accuracy is mostly fixed by the NUMBER of deliberate hard cases "
           "(normal_new_peer, leak_unknown_rel) in the set, not general accuracy",
           "- 60% anomalous is not a realistic base rate: on real traffic attacks are rare, so precision there would be lower for the same FPR",
           "- each case = one fresh detector, one prefix, a 3-message baseline: no table-scale interference, no long-running state, no real CAIDA coverage gaps",
           "- the origin-hijack category (unexpected origin) is the unexpectedOrigin PoC's job and is only checked as 'deferred, not flagged'"]

    open(a.out + ".md", "w", encoding="utf-8").write("\n".join(md) + "\n")
    json.dump(dict(config=dict(min_support=a.min_support, len_delta=a.len_delta, origin_policy=a.origin_policy, llm=a.llm),
                   overall=metrics(rows, "pred"), b1=metrics(rows, "pred_b1"), false_learn=false_learn,
                   ablation={k: v for k, v in abl.items() if "::" not in k}, sweep=sweep, llm=llm_sum,
                   llm_veto={k: v for k, v in veto.items()} if veto else None, llm_stability=stab, rows=rows),
              open(a.out + ".json", "w", encoding="utf-8"), indent=1)
    with open(a.out + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["id", "kind", "label", "truth_anomalous", "predicted_anomalous", "rule_type", "type_correct", "llm_label", "llm_agrees", "llm_view", "compute_ms"])
        for r in rows:
            w.writerow([r["id"], r["kind"], r["label"], r["truth"], r["pred"], r["rtype"], r["type_ok"], r.get("llm_label"), r.get("llm_agrees"),
                        r.get("llm_view"), round(r["compute_ms"], 4)])
    print("\n".join(md))


if __name__ == "__main__":
    main()
