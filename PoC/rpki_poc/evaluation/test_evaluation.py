"""Tests for the evaluation (run from rpki_poc: python -m pytest -q)."""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import evaluate                                    # noqa: E402
import make_dataset                                # noqa: E402
import netfeed                                     # noqa: E402


def rows():
    return [json.loads(l) for l in open(os.path.join(HERE, "labelled_updates.jsonl"), encoding="utf-8") if l.strip()]


def test_dataset_is_reproducible():
    assert [json.dumps(r) for r in make_dataset.build(7)] == [json.dumps(r) for r in rows()]


def test_every_line_has_checks_with_a_known_state():
    for r in rows():
        assert r["truth"]["checks"], r
        for c in r["truth"]["checks"]:
            assert c["state"] in evaluate.STATES and c["label"] in ("anomalous", "benign")


def test_full_config_is_exact(tmp_path):
    wl = json.load(open(os.path.join(HERE, "eval_whitelist.json")))
    cust = set(json.load(open(os.path.join(HERE, "eval_customers.json"))))
    pipe = evaluate.Pipeline(str(tmp_path / "e.db"), evaluate.CONFIGS["full"], wl, cust)
    recs = [r for r in evaluate.run_offline(rows(), pipe) if r["in_scope"]]
    assert all(r["truth"] == r["pred"] for r in recs)
    assert all(r["truth_state"] == r["pred_state"] for r in recs)
    assert all(r["truth_severity"] == r["pred_severity"] for r in recs if r["truth"] == "anomalous")
    assert sum(c["severity"] == "MEDIUM" for c in pipe.roa_events) == 2


def test_without_revalidation_the_roa_change_is_missed(tmp_path):
    wl = json.load(open(os.path.join(HERE, "eval_whitelist.json")))
    pipe = evaluate.Pipeline(str(tmp_path / "e.db"), evaluate.CONFIGS["no-revalidation"], wl, {64510})
    recs = evaluate.run_offline(rows(), pipe)
    missed = {r["scenario"] for r in recs if r["truth"] == "anomalous" and r["pred"] == "benign"}
    assert "S17" in missed and "S02" in missed


def test_global_order_keeps_every_message_in_place():
    netfeed.ORDER = "global"
    recs = [{"data": {"announcements": [{"prefixes": [p]}]}} for p in ("a", "b", "a", "c")]
    plan = netfeed.plan_delivery(recs, rate=10, delay=lambda i: [3, 0, 0, 0][i], t_start=0)
    assert [i for _, i, _ in plan] == [0, 1, 2, 3]
