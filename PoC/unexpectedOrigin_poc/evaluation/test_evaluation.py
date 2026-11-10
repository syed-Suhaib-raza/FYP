import argparse, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]
import netfeed                     # noqa: E402
from evalcore import classification  # noqa: E402

ROWS = [json.loads(l) for l in open(os.path.join(HERE, "labelled_updates.jsonl"), encoding="utf-8")]


def test_dataset_shape():
    assert 180 <= len(ROWS) <= 230
    for r in ROWS:
        t = r["truth"]
        assert t["label"] in ("benign", "anomalous")
        assert (t["type"] == "none") == (t["label"] == "benign")
        if t["label"] == "anomalous" and t["in_scope"]:
            assert t["type"] in ("unexpected_origin", "unexpected_deaggregation")


def test_delivery_plan_keeps_prefix_order():
    plan = netfeed.plan_delivery(ROWS, 20.0, netfeed.DelayModel("uniform", a=0, b=4), 0.0)
    seen = {}
    for t, i, e in plan:
        assert t >= e
        p = ROWS[i]["data"]["announcements"][0]["prefixes"][0]
        assert i > seen.get(p, -1)
        seen[p] = i


def test_classification():
    m = classification([("anomalous", "anomalous"), ("benign", "anomalous"), ("benign", "benign")])
    assert (m["tp"], m["fp"], m["tn"]) == (1, 1, 1)


def test_offline_pipeline_with_mock(tmp_path):
    from evaluate import Pipeline, run_offline
    from asrel import ASRel
    from llm import MockLLM
    a = argparse.Namespace(only_exact=False, cooldown=600, top_k=8, ownership_evidence=True)
    wl = json.load(open(os.path.join(HERE, "eval_whitelist.json")))
    recs = run_offline(ROWS, Pipeline(str(tmp_path / "e.db"), wl, ASRel(os.path.join(HERE, "eval_asrel.txt")), MockLLM(), a))
    for r in recs:
        if r["category"] in ("expected_origin_exact", "unwatched_prefix", "as_set_origin"):
            assert r["rule_pred"] == "benign" and not r["triggered"]
        if r["truth"] == "anomalous" and r["in_scope"]:
            assert r["rule_pred"] == "anomalous"                       # every in-scope hijack is a candidate
    assert any(r["suppressed"] for r in recs)                          # cooldown repeats exercised
