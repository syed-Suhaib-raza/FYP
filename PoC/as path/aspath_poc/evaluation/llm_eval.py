"""LLM scoring helpers shared by eval.py (TEST 1, simulated) and live_eval.py (TEST 2, live) for the AS-path PoC.

The PoC's Monitor attaches three fields to every alert it raises: `llm_label` (what the model said), `llm_agrees` (did the model
agree with the firing rule) and `model` (which backend). This module turns those fields into numbers. It only reads those fields,
so it does not depend on how llm.py is written inside.

Model vocabulary: the label strings are normalised by `view()` into
   hijack | leak | normal | unscored | other
`unscored` = no model, model skipped (rate limit / off) or empty label. `other` = a label this file does not recognise: the report
prints every raw label it saw and warns when `other` is not zero, so a different vocabulary is never silently counted wrong.
Edit the three sets below if your model uses other words.
"""
from collections import Counter

HIJACK_WORDS = ("hijack",)
LEAK_WORDS = ("leak",)
NORMAL_EXACT = {"normal", "benign", "legit", "legitimate", "none", "no anomaly", "not anomalous", "false positive", "expected", "ok"}
NORMAL_WORDS = ("normal", "benign", "legitimate", "no anomaly")
# NOT a verdict: no model ran / it was skipped. Note: the label "none" IS a verdict (the model saw no anomaly); the PoC marks "no model ran" with llm_agrees == "no model".
UNSCORED = {"", "no model", "no_model", "n/a", "na", "skipped", "rate limited", "rate-limited", "off", "null"}


def view(label, agrees=None):
    """Normalise a raw llm_label (and llm_agrees) into hijack / leak / normal / unscored / other."""
    if label is None or str(agrees).strip().lower() == "no model":
        return "unscored"
    s = str(label).strip().lower().replace("_", " ")
    if s in UNSCORED:
        return "unscored"
    if any(w in s for w in LEAK_WORDS):
        return "leak"
    if any(w in s for w in HIJACK_WORDS):
        return "hijack"
    if s in NORMAL_EXACT or any(w in s for w in NORMAL_WORDS):
        return "normal"
    return "other"


def vr(rec):
    """view() of a row / alert dict."""
    return view(rec.get("llm_label"), rec.get("llm_agrees"))


def agreed(v):
    return v is True or str(v).strip().lower() == "true"


def to_label(v):
    """model view -> the harness label names used in the simulated set."""
    return {"hijack": "path hijack", "leak": "route leak", "normal": "normal"}.get(v)


def pct(a, b):
    return round(a / b, 3) if b else 0.0


# ------------------------------------------------------------------------------------------------ simulated (TEST 1)
def sim_summary(rows):
    """rows = eval.py rows from the run WITH the model. Returns a dict of model metrics over the detections (cases the rules flagged).

    The model sees only what the rules flagged, so model recall/precision are defined on that set:
      veto detector = rule fired AND model did not say 'normal'.
    """
    det = [r for r in rows if r["pred"]]
    for r in det:
        r["llm_view"] = vr(r)
    scored = [r for r in det if r["llm_view"] not in ("unscored",)]
    tp = [r for r in det if r["truth"]]
    fp = [r for r in det if not r["truth"]]
    out = dict(detections=len(det), scored=len(scored), coverage=pct(len(scored), len(det)),
               raw_labels=dict(Counter(str(r.get("llm_label")) for r in det)),
               other=sum(r["llm_view"] == "other" for r in det))
    out["agrees_with_rule"] = sum(agreed(r.get("llm_agrees")) for r in scored)
    out["agree_rate"] = pct(out["agrees_with_rule"], len(scored))
    # on real anomalies (TP): does the model keep them (not 'normal') and name the type right?
    tps = [r for r in tp if r["llm_view"] != "unscored"]
    out["tp_scored"] = len(tps)
    out["tp_kept"] = sum(r["llm_view"] != "normal" for r in tps)
    out["tp_vetoed"] = sum(r["llm_view"] == "normal" for r in tps)
    out["tp_type_right"] = sum(to_label(r["llm_view"]) == r["label"] for r in tps)
    # on rule false alarms (FP): does the model reject them?
    fps = [r for r in fp if r["llm_view"] != "unscored"]
    out["fp_scored"] = len(fps)
    out["fp_rejected"] = sum(r["llm_view"] == "normal" for r in fps)
    out["fp_kept"] = len(fps) - out["fp_rejected"]
    # confusion: truth label x model view
    conf = {}
    for r in scored:
        conf.setdefault(r["label"], Counter())[r["llm_view"]] += 1
    out["confusion"] = {k: dict(v) for k, v in conf.items()}
    # per kind: how the model judged each kind of detection
    kinds = {}
    for r in scored:
        kinds.setdefault(r["kind"], Counter())[r["llm_view"]] += 1
    out["per_kind"] = {k: dict(v) for k, v in sorted(kinds.items())}
    return out


def veto_metrics(rows, metrics):
    """Rule engine vs rule + model-veto, scored against ground truth on ALL cases (undetected cases stay undetected)."""
    for r in rows:
        v = r.get("llm_view") or vr(r)
        r["pred_veto"] = bool(r["pred"] and v != "normal")
        r["pred_strict"] = bool(r["pred"] and v in ("hijack", "leak"))
    return {"Rules only": metrics(rows, "pred"), "Rules + model veto (drop alert if model says normal)": metrics(rows, "pred_veto"),
            "Rules + model strict (keep only if model names hijack/leak)": metrics(rows, "pred_strict")}


def stability(rows_a, rows_b):
    """Same cases run twice with the model: how often does the model answer the same? (nondeterminism check)"""
    both = [(a, b) for a, b in zip(rows_a, rows_b) if a["pred"] and b["pred"]]
    same = sum(vr(a) == vr(b) for a, b in both)
    return dict(compared=len(both), same=same, rate=pct(same, len(both)))


def sim_markdown(s, name, veto_table, stab=None, comp_rules=None, comp_model=None):
    mock = "mock" in str(name).lower()
    md = [f"## Model (LLM) test: {name}", ""]
    if mock:
        md += ["**The model used here is the MOCK (fake) model: this section only proves the harness works. It says nothing about the real model.** "
               "Re-run with `--llm hf` (or `llamacpp`) for the real numbers.", ""]
    md += [f"The model is only asked about cases the rules flagged ({s['detections']} detections); a case the rules miss never reaches it.",
           f"- model gave a usable verdict on {s['scored']}/{s['detections']} detections (coverage {s['coverage']})",
           f"- model agreed with the firing rule on {s['agrees_with_rule']}/{s['scored']} (agree rate {s['agree_rate']})",
           f"- raw labels the model returned: {s['raw_labels']}"]
    if s["other"]:
        md += [f"- **WARNING: {s['other']} labels were not recognised** (counted neither as hijack/leak/normal). Edit the word lists at the top of llm_eval.py."]
    md += ["", "### On real anomalies the rules caught (true positives)",
           f"- model kept {s['tp_kept']}/{s['tp_scored']}, wrongly called {s['tp_vetoed']} of them 'normal' (those would be lost if the model could veto)",
           f"- model named the anomaly type correctly (path hijack vs route leak) on {s['tp_type_right']}/{s['tp_scored']}",
           "", "### On the rules' false alarms (normal traffic the rules flagged)",
           f"- model rejected {s['fp_rejected']}/{s['fp_scored']} as 'normal'; kept (still false alarms) {s['fp_kept']}",
           "", "### Model verdict by ground-truth label (rows = truth, columns = model)"]
    cols = ["hijack", "leak", "normal", "other"]
    md += ["| truth | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
    for lab, c in sorted(s["confusion"].items()):
        md.append(f"| {lab} | " + " | ".join(str(c.get(k, 0)) for k in cols) + " |")
    md += ["", "### Model verdict by case kind", "| kind | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
    for kind, c in s["per_kind"].items():
        md.append(f"| {kind} | " + " | ".join(str(c.get(k, 0)) for k in cols) + " |")
    md += ["", "### Does the model improve the detector? (all 250 cases vs ground truth)", veto_table, ""]
    if stab:
        md += [f"### Repeatability: the model answered the same on {stab['same']}/{stab['compared']} detections in two runs (rate {stab['rate']})", ""]
    if comp_rules is not None and comp_model is not None:
        md += ["### Compute time with and without the model (per case, ms)",
               f"- rules only: median {comp_rules['median']:.3f}, p95 {comp_rules['p95']:.3f}", f"- with model: median {comp_model['median']:.3f}, p95 {comp_model['p95']:.3f}, max {comp_model['max']:.3f}",
               "- the difference is the model's cost; it is paid only on cases the rules flag", ""]
    return md


# ------------------------------------------------------------------------------------------------ live (TEST 2)
def live_summary(alerts):
    """alerts = list of dicts from <run>_alerts.jsonl."""
    for x in alerts:
        x["llm_view"] = vr(x)
    scored = [x for x in alerts if x["llm_view"] != "unscored"]
    out = dict(alerts=len(alerts), scored=len(scored), coverage=pct(len(scored), len(alerts)),
               raw_labels=dict(Counter(str(x.get("llm_label")) for x in alerts)),
               views=dict(Counter(x["llm_view"] for x in scored)),
               models=dict(Counter(str(x.get("model")) for x in alerts)),
               other=sum(x["llm_view"] == "other" for x in alerts))
    out["agrees_with_rule"] = sum(agreed(x.get("llm_agrees")) for x in scored)
    out["agree_rate"] = pct(out["agrees_with_rule"], len(scored))
    out["says_normal"] = sum(x["llm_view"] == "normal" for x in scored)
    # model type vs the type the rule gave
    out["type_same_as_rule"] = sum(to_label(x["llm_view"]) == str(x.get("anomaly_type", "")).replace("_", " ") for x in scored)
    by_rule = {}
    for x in scored:
        by_rule.setdefault(x.get("subtype"), Counter())[x["llm_view"]] += 1
    out["by_rule"] = {k: dict(v) for k, v in by_rule.items()}
    ms = [x["compute_ms"] for x in scored if x.get("compute_ms") is not None]
    ms0 = [x["compute_ms"] for x in alerts if x["llm_view"] == "unscored" and x.get("compute_ms") is not None]
    out["compute_ms_scored"], out["compute_ms_unscored"] = ms, ms0
    return out


def live_markdown(s, stat):
    md = ["", "## Model (LLM) on the live alerts", f"- model(s) used: {s['models']}",
          f"- the model gave a verdict on {s['scored']}/{s['alerts']} alerts (coverage {s['coverage']}); the rest were not scored "
          "(rate cap on a full-collector run, model error or model off)",
          f"- model agreed with the firing rule on {s['agrees_with_rule']}/{s['scored']} (agree rate {s['agree_rate']}); said 'normal' on {s['says_normal']}",
          f"- model's verdicts: {s['views']}; raw labels: {s['raw_labels']}"]
    if s["other"]:
        md += [f"- **WARNING: {s['other']} labels not recognised**: edit the word lists in llm_eval.py"]
    if s["by_rule"]:
        md += [f"- verdict by rule that fired: {s['by_rule']}"]
    a, b = stat(s["compute_ms_scored"], 3), stat(s["compute_ms_unscored"], 3)
    if a:
        md += [f"- alert compute time WITH model (ms): {a}"]
    if b:
        md += [f"- alert compute time WITHOUT model (ms): {b}"]
    md += ["- feed delay + that compute time is the whole latency of a model-checked alert; a slow model blocks the feed loop, see the backlog check above",
           "- the model has no ground truth live either: its verdicts are judged by the manual `verdict` column (the model-vs-your-verdicts line appears after you fill the verdict column and re-run analyze --labels)"]
    return md


def model_vs_verdict(alert_rows, verdict_rows_key="verdict"):
    """alert_rows: dicts with llm_view and verdict TRUE/FALSE (from the labelled CSV). Gives how the model's call lines up with the human's."""
    done = [r for r in alert_rows if str(r.get(verdict_rows_key, "")).strip().upper() in ("TRUE", "FALSE") and r.get("llm_view") not in (None, "unscored")]
    if not done:
        return None
    t = [str(r[verdict_rows_key]).strip().upper() == "TRUE" for r in done]
    n_real = sum(t)
    kept_real = sum(1 for r, x in zip(done, t) if x and r["llm_view"] != "normal")
    rejected_false = sum(1 for r, x in zip(done, t) if (not x) and r["llm_view"] == "normal")
    return dict(labelled=len(done), real=n_real, false=len(done) - n_real, model_kept_real=kept_real, model_rejected_false=rejected_false,
                model_accuracy=pct(kept_real + rejected_false, len(done)))
