import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]
import netfeed                     # noqa: E402
from evalcore import classification  # noqa: E402

ROWS = [json.loads(l) for l in open(os.path.join(HERE, "labelled_updates.jsonl"), encoding="utf-8")]


def test_dataset_shape():
    assert 180 <= len(ROWS) <= 230
    for r in ROWS:
        assert r["type"] == "ris_message" and r["data"]["type"] == "UPDATE"
        assert r["truth"]["label"] in ("benign", "anomalous") and isinstance(r["truth"]["in_scope"], bool)
    assert {r["truth"]["label"] for r in ROWS} == {"benign", "anomalous"}
    ts = [r["data"]["timestamp"] for r in ROWS]
    assert ts == sorted(ts)


def test_delivery_plan_keeps_prefix_order_and_delays():
    delays = [5.0, 0.0, 3.0, 0.1] * 60
    plan = netfeed.plan_delivery(ROWS, 20.0, netfeed.DelayModel("trace", delays), 1000.0)
    assert sorted(i for _, i, _ in plan) == list(range(len(ROWS)))
    assert all(t >= e for t, _, e in plan)                        # never delivered before it happened
    seen = {}
    for _, i, _ in plan:
        p = ROWS[i]["data"]["announcements"][0]["prefixes"][0]
        assert i > seen.get(p, -1)                                 # same-prefix order preserved
        seen[p] = i
    applied = sum(t - e for t, _, e in plan) / len(plan)
    wanted = sum(delays[i % len(delays)] for i in range(len(ROWS))) / len(ROWS)
    assert abs(applied - wanted) < 1e-6                            # mean delay unchanged


def test_classification_counts_uncertain_as_alert_and_wrong():
    m = classification([("anomalous", "anomalous"), ("anomalous", "uncertain"), ("benign", "uncertain"), ("benign", "benign")])
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 0, 1) and m["accuracy"] == 0.5 and m["uncertain"] == 2


def test_offline_pipeline_end_to_end(tmp_path):
    from evaluate import Pipeline, run_offline
    from ai_layer import BaselineBackend
    wl = json.load(open(os.path.join(HERE, "eval_whitelist.json")))
    recs = run_offline(ROWS, Pipeline(str(tmp_path / "e.db"), 3600, wl, BaselineBackend()))
    first_hijack = next(r for r in recs if r["scenario"] == "A01" and r["truth"] == "anomalous")
    assert first_hijack["pred"] == "anomalous" and first_hijack["triggered"]
    assert recs[-1]["decision_s"] >= 0 and len(recs) == len(ROWS)
