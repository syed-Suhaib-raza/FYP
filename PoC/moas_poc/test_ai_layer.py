"""Layer 2 tests: features, baseline scoring, LLM backend plumbing, and the scoring pipeline."""
import json, sqlite3
import pytest
from moas import MoasCatalog, Store, read_events
from ai_layer import (BaselineBackend, LLMBackend, asn_class, build_features, parse_verdict, run_once)

WL = {"1.1.1.0/24": [13335], "66.167.90.0/24": [3257]}


def upd(ts, path, prefix, peer, host="rrc00"):
    return {"type": "UPDATE", "timestamp": ts, "peer_asn": str(peer), "host": host, "path": path,
            "announcements": [{"prefixes": [prefix]}]}


def make_event(*updates):
    c = MoasCatalog()
    for u in updates:
        c.process(upd(*u))
    return next(iter(c.open.values())).to_dict()


def baseline(ev, wl=WL):
    return BaselineBackend().score(ev, build_features(ev, wl))


# -- features ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("asn,cls", [("0", "as0"), ("23456", "as_trans"), ("64500", "documentation"), ("64666", "private"),
                                     ("4200000001", "private"), ("65535", "reserved"), ("13335", None), ("{1,2}", None)])
def test_asn_class(asn, cls):
    assert asn_class(asn) == cls


def test_features_watched_prefix_with_unexpected_origin():
    ev = make_event((0, [3333, 13335], "1.1.1.0/24", 3333), (1, [6939, 64666], "1.1.1.0/24", 6939),
                    (2, [1299, 64666], "1.1.1.0/24", 1299, "rrc04"))
    f = build_features(ev, WL)
    assert f["watched"] and f["expected_origins"] == ["13335"] and f["unexpected_origins"] == ["64666"]
    assert f["special_asns"] == {"64666": "private"} and f["incumbent"] == "13335" and f["total_peers"] == 3
    new = f["per_origin"][1]
    assert new["authorised"] is False and new["n_peers"] == 2 and new["peer_share"] == 0.67 and new["first_seen_offset_s"] == 1


def test_features_without_whitelist_have_no_authorisation_opinion():
    ev = make_event((0, [1, 2], "9.9.9.0/24", 1), (1, [5, 3], "9.9.9.0/24", 5))
    f = build_features(ev)
    assert not f["watched"] and f["unexpected_origins"] == [] and f["per_origin"][0]["authorised"] is None


def test_features_upstream_pair_and_non_global():
    ev = make_event((0, [3333, 3356, 65001], "203.0.113.0/24", 3333), (1, [6939, 65001, 65002], "203.0.113.0/24", 6939))
    f = build_features(ev)
    assert f["upstream_pairs"] == [["65001", "65002"]] and f["globally_routable"] is False


# -- baseline ------------------------------------------------------------------------------------------------
def test_baseline_flags_unauthorised_origin_on_watched_prefix():
    v = baseline(make_event((0, [3333, 13335], "1.1.1.0/24", 3333), (1, [6939, 64666], "1.1.1.0/24", 6939)))
    assert v.label == "anomalous" and v.score >= 0.9 and "not authorised" in v.reason


def test_baseline_planned_multi_origin_is_benign():
    wl = {"9.9.9.0/24": [2, 3]}
    v = baseline(make_event((0, [1, 2], "9.9.9.0/24", 1), (1, [5, 3], "9.9.9.0/24", 5)), wl)
    assert v.label == "benign"


def test_baseline_unknown_public_prefix_is_uncertain():
    v = baseline(make_event((0, [1, 1299, 3320], "5.5.5.0/24", 1), (1, [5, 3356, 6830], "5.5.5.0/24", 5)))
    assert v.label == "uncertain" and v.score == 0.4


def test_baseline_upstream_relation_lowers_score_to_benign():
    v = baseline(make_event((0, [3333, 1299, 3320], "77.77.77.0/24", 3333), (1, [6939, 3320, 6830], "77.77.77.0/24", 6939)))
    assert v.label == "benign" and "upstream" in v.reason


def test_baseline_private_origin_on_unwatched_prefix_is_anomalous():
    v = baseline(make_event((0, [3333, 174, 65001], "203.0.113.0/24", 3333), (1, [3333, 3356, 65002], "203.0.113.0/24", 3333)))
    assert v.label == "anomalous"


# -- LLM backend ---------------------------------------------------------------------------------------------
def test_parse_verdict_variants():
    assert parse_verdict('{"label":"anomalous","score":0.91,"reason":"x"}') == ("anomalous", 0.91, "x")
    wrapped = 'Sure!\n```json\n{"label": "Benign", "score": 7, "reason": "anycast"}\n```'
    assert parse_verdict(wrapped) == ("benign", 1.0, "anycast")             # case-insensitive label, score clamped
    for bad in ("no json here", '{"label":"maybe","score":0.5}', '{"label":"benign","score":"high"}'):
        with pytest.raises(ValueError):
            parse_verdict(bad)


def test_llm_backend_request_and_parse():
    seen = {}

    def fake_post(url, payload, headers, timeout):
        seen.update(url=url, payload=payload, headers=headers)
        return {"choices": [{"message": {"content": '{"label":"uncertain","score":0.5,"reason":"needs RPKI"}'}}]}

    ev = make_event((0, [3333, 13335], "1.1.1.0/24", 3333), (1, [6939, 64666], "1.1.1.0/24", 6939))
    b = LLMBackend("my-model", "http://host:1/v1/", api_key="k", post=fake_post)
    v = b.score(ev, build_features(ev, WL))
    assert v.label == "uncertain" and b.name == "llm:my-model"
    assert seen["url"] == "http://host:1/v1/chat/completions" and seen["headers"]["Authorization"] == "Bearer k"
    assert seen["payload"]["model"] == "my-model" and seen["payload"]["temperature"] == 0
    user = json.loads(seen["payload"]["messages"][1]["content"])
    assert user["prefix"] == "1.1.1.0/24" and user["unexpected_origins"] == ["64666"]
    assert "peers" not in user["per_origin"][0] and user["per_origin"][0]["n_peers"] == 1   # counts, not peer lists


# -- pipeline ------------------------------------------------------------------------------------------------
@pytest.fixture
def catalog(tmp_path):
    c = MoasCatalog(Store(str(tmp_path / "t.db")), window=100)
    c.process(upd(0, [3333, 13335], "1.1.1.0/24", 3333)); c.process(upd(1, [6939, 64666], "1.1.1.0/24", 6939))
    return c


def verdict_rows(con):
    return con.execute("SELECT event_id,revision,backend,label FROM verdicts ORDER BY event_id,revision,backend").fetchall()


def test_pipeline_scores_each_revision_once(catalog):
    con = catalog.store.con
    out = run_once(con, [BaselineBackend()], WL)
    assert [(e["id"], n, v.label) for e, n, v in out] == [(1, "baseline", "anomalous")]
    assert run_once(con, [BaselineBackend()], WL) == []                         # nothing new -> nothing rescored
    catalog.process(upd(2, [1, 3356, 4637], "1.1.1.0/24", 1))                  # a third origin joins: revision 2
    assert [(e["revision"], v.label) for e, _, v in run_once(con, [BaselineBackend()], WL)] == [(2, "anomalous")]
    catalog.sweep(1000)                                                        # episode closes: revision 3, rescored
    run_once(con, [BaselineBackend()], WL)
    assert [r[1] for r in verdict_rows(con)] == [1, 2, 3]


def test_pipeline_two_backends_and_failure_isolation(catalog):
    con = catalog.store.con

    class Broken:
        name = "llm:down"
        def score(self, ev, f): raise ConnectionError("model server unreachable")

    logs = []
    out = run_once(con, [BaselineBackend(), Broken()], WL, log=logs.append)
    assert [n for _, n, _ in out] == ["baseline"] and "unreachable" in logs[0]
    assert verdict_rows(con) == [(1, 1, "baseline", "anomalous")]

    class Fixed:
        name = "llm:down"
        def score(self, ev, f): return parse_verdict('{"label":"anomalous","score":0.8,"reason":"r"}')

    out = run_once(con, [BaselineBackend(), Fixed()], WL)                      # failed backend is retried, baseline is not
    assert [n for _, n, _ in out] == ["llm:down"]
    assert len(verdict_rows(con)) == 2


def test_replay_of_sample_files_end_to_end(tmp_path):
    msgs = [json.loads(l)["data"] for f in ("sample_updates.jsonl", "sample_updates_extra.jsonl") for l in open(f)]
    msgs.sort(key=lambda m: m["timestamp"])
    c = MoasCatalog(Store(str(tmp_path / "s.db")))
    for m in msgs:
        c.process(m)
    c.flush()
    con = c.store.con
    run_once(con, [BaselineBackend()], json.load(open("whitelist.json")))
    got = {e["prefix"]: l for e, l in
           ((e, con.execute("SELECT label FROM verdicts WHERE event_id=?", (e["id"],)).fetchone()[0]) for e in read_events(con))}
    assert got == {"1.1.1.0/24": "anomalous", "203.0.113.0/24": "anomalous", "77.77.77.0/24": "benign",
                   "5.5.5.0/24": "uncertain", "66.167.90.0/24": "anomalous"}
