"""Tests for the LLM part of the AS-path test harness (llm_eval.py and its use in eval.py / live_eval.py / cluster_events.py).
   python -m pytest -q test_llm_eval.py
Needs no model and no internet: the model is replaced by small fakes. The pure scoring tests need nothing from the PoC at all."""
import csv, json, os, subprocess, sys, tempfile

import llm_eval as le

HERE = os.path.dirname(os.path.abspath(__file__))


def test_view_vocabulary():
    assert le.view("path hijack") == "hijack" and le.view("PATH_HIJACK") == "hijack"
    assert le.view("route leak") == "leak" and le.view("route_leak") == "leak"
    assert le.view("normal") == "normal" and le.view("benign") == "normal"
    for none in (None, "", "no model", "No Model", "skipped", "rate-limited"):
        assert le.view(none) == "unscored", none
    assert le.view("none") == "normal"                       # the model's own "none" = it saw no anomaly: a real verdict
    assert le.view("path hijack", "no model") == "unscored"  # the PoC marks 'no model ran' in llm_agrees
    assert le.view("banana") == "other"


def row(truth, label, kind, pred=True, llm="path hijack", agrees=True):
    return dict(truth=truth, label=label, kind=kind, pred=pred, llm_label=llm, llm_agrees=agrees)


def metrics(rows, key):
    tp = sum(r["truth"] and r[key] for r in rows); fp = sum((not r["truth"]) and r[key] for r in rows)
    fn = sum(r["truth"] and not r[key] for r in rows); tn = sum((not r["truth"]) and not r[key] for r in rows)
    return dict(tp=tp, fp=fp, fn=fn, tn=tn)


def test_sim_summary_counts():
    rows = [row(True, "path hijack", "a", llm="path hijack"),                 # kept, type right
            row(True, "route leak", "b", llm="route leak"),                   # kept, type right
            row(True, "path hijack", "a", llm="normal", agrees=False),        # real anomaly the model would veto
            row(False, "normal", "new_peer", llm="normal", agrees=False),     # false alarm the model rejects
            row(False, "normal", "new_peer", llm="path hijack"),              # false alarm the model keeps
            row(True, "path hijack", "a", llm=None, agrees="no model"),      # unscored (no model ran)
            row(False, "normal", "repeat", pred=False, llm=None)]             # never flagged: model never asked
    s = le.sim_summary(rows)
    assert (s["detections"], s["scored"]) == (6, 5) and s["coverage"] == round(5 / 6, 3)
    assert (s["tp_scored"], s["tp_kept"], s["tp_vetoed"], s["tp_type_right"]) == (3, 2, 1, 2)
    assert (s["fp_scored"], s["fp_rejected"], s["fp_kept"]) == (2, 1, 1)
    assert s["confusion"]["normal"] == {"normal": 1, "hijack": 1} and s["other"] == 0


def test_unknown_label_is_flagged_not_hidden():
    s = le.sim_summary([row(True, "path hijack", "a", llm="suspicious-ish")])
    assert s["other"] == 1 and "WARNING" in "\n".join(le.sim_markdown(s, "x", "t"))


def test_veto_metrics_never_invents_detections():
    rows = [row(True, "path hijack", "a", llm="normal"), row(False, "normal", "n", llm="normal"), row(True, "route leak", "b", pred=False, llm=None)]
    le.sim_summary(rows)
    m = le.veto_metrics(rows, lambda r, k: metrics(r, k))
    base, veto = m["Rules only"], m["Rules + model veto (drop alert if model says normal)"]
    assert base["tp"] == 1 and base["fp"] == 1 and base["fn"] == 1
    assert veto["tp"] == 0 and veto["fp"] == 0 and veto["fn"] == 2           # veto lost the real one and removed the false one
    assert not rows[2]["pred_veto"]                                          # an undetected case stays undetected


def test_stability():
    a = [row(True, "x", "k", llm="path hijack"), row(True, "x", "k", llm="normal"), row(False, "normal", "k", pred=False, llm=None)]
    b = [row(True, "x", "k", llm="path hijack"), row(True, "x", "k", llm="route leak"), row(False, "normal", "k", pred=False, llm=None)]
    assert le.stability(a, b) == dict(compared=2, same=1, rate=0.5)


def test_live_summary_and_model_vs_verdict():
    alerts = [dict(llm_label="route leak", llm_agrees=True, anomaly_type="route_leak", subtype="valley_violation", model="m", compute_ms=900.0),
              dict(llm_label="normal", llm_agrees=False, anomaly_type="path_hijack", subtype="new_as_link", model="m", compute_ms=800.0),
              dict(llm_label=None, llm_agrees="no model", anomaly_type="route_leak", subtype="valley_violation", model=None, compute_ms=0.01)]
    s = le.live_summary(alerts)
    assert (s["alerts"], s["scored"], s["agrees_with_rule"], s["says_normal"], s["type_same_as_rule"]) == (3, 2, 1, 1, 1)
    assert s["compute_ms_unscored"] == [0.01]
    rows = [dict(llm_view="leak", verdict="TRUE"), dict(llm_view="normal", verdict="FALSE"), dict(llm_view="normal", verdict="TRUE"),
            dict(llm_view="unscored", verdict="TRUE"), dict(llm_view="leak", verdict="")]
    mv = le.model_vs_verdict(rows)
    assert mv == dict(labelled=3, real=2, false=1, model_kept_real=1, model_rejected_false=1, model_accuracy=0.667)
    assert le.model_vs_verdict([dict(llm_view="leak", verdict="")]) is None


# ------------------------------------------------------------------ the scripts themselves (need the PoC modules next to them)
def _poc_here():
    return all(os.path.exists(os.path.join(HERE, f)) for f in ("aspath.py", "llm.py", "detector.py"))


def test_eval_with_mock_model_end_to_end():
    if not _poc_here():
        import pytest; pytest.skip("run from the aspath_poc folder")
    d = tempfile.mkdtemp()
    out = os.path.join(d, "r")
    p = subprocess.run([sys.executable, "eval.py", "eval_set.jsonl", "--llm", "mock", "--out", out], cwd=HERE, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr[-800:]
    j = json.load(open(out + ".json"))
    assert j["llm"] and j["llm"]["detections"] == j["overall"]["tp"] + j["overall"]["fp"]
    assert "MOCK" in open(out + ".md", encoding="utf-8").read()
    head = open(out + ".csv", encoding="utf-8").readline()
    assert "llm_view" in head and "llm_agrees" in head
    rules_only = subprocess.run([sys.executable, "eval.py", "eval_set.jsonl", "--llm", "none", "--out", os.path.join(d, "n")], cwd=HERE, capture_output=True, text=True)
    assert json.load(open(os.path.join(d, "n.json")))["overall"] == j["overall"]     # model run must not change rule accuracy numbers
    assert rules_only.returncode == 0


def test_live_selftest_fails_when_no_model(monkeypatch):
    if not _poc_here():
        import pytest; pytest.skip("run from the aspath_poc folder")
    import argparse, live_eval
    live_eval._LLM.clear()
    monkeypatch.setattr(live_eval, "make_llm", lambda a: None)
    ok, detail = live_eval.llm_selftest(argparse.Namespace(llm="hf", min_support=1, len_delta=3, origin_policy="authorized"))
    assert not ok and "no model" in detail
    live_eval._LLM.clear()


def test_live_selftest_passes_with_mock_model():
    if not _poc_here():
        import pytest; pytest.skip("run from the aspath_poc folder")
    import argparse, live_eval
    from llm import make_llm
    live_eval._LLM.clear()
    a = argparse.Namespace(llm="mock", min_support=1, len_delta=3, origin_policy="authorized")
    try:
        if make_llm(a) is None:
            import pytest; pytest.skip("mock model not available")
    except Exception:
        import pytest; pytest.skip("mock model not available")
    ok, detail = live_eval.llm_selftest(a)
    assert ok, detail
    live_eval._LLM.clear()


if __name__ == "__main__":
    sys.exit(subprocess.call([sys.executable, "-m", "pytest", "-q", __file__]))
