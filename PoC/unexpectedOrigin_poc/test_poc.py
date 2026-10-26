import json
from asrel import ASRel
from detector import OriginCandidates
from prompt import build_messages, parse_label
WL = {"1.1.1.0/24": [13335]}
def msg(path, pf, ts=0): return {"type": "UPDATE", "timestamp": ts, "host": "rrc00", "peer_asn": "1", "path": path, "announcements": [{"prefixes": [pf]}]}
def test_expected_origin_ignored(): assert OriginCandidates(WL).candidates(msg([1, 13335], "1.1.1.0/24")) == []
def test_unexpected_exact(): c = OriginCandidates(WL).candidates(msg([1, 666], "1.1.1.0/24")); assert c[0]["subtype"] == "origin" and c[0]["origin"] == 666
def test_deagg_and_only_exact():
    assert OriginCandidates(WL).candidates(msg([1, 666], "1.1.1.0/25"))[0]["subtype"] == "deaggregation"
    assert OriginCandidates(WL, only_exact=True).candidates(msg([1, 666], "1.1.1.0/25")) == []
def test_unwatched_and_as_set_ignored():
    d = OriginCandidates(WL); assert d.candidates(msg([1, 666], "9.9.9.0/24")) == [] and d.candidates(msg([1, [5, 6]], "1.1.1.0/24")) == []
def test_cooldown():
    d = OriginCandidates(WL, cooldown=100); assert len(d.candidates(msg([1, 666], "1.1.1.0/24", 0))) == 1
    assert d.candidates(msg([2, 666], "1.1.1.0/24", 50)) == [] and len(d.candidates(msg([2, 666], "1.1.1.0/24", 500))) == 1
def test_parse_label():
    assert parse_label("prefix hijack") == "prefix hijack" and parse_label('{"anomaly_type": "none"}') == "none"
    assert parse_label("Route_Leak") == "route leak" and parse_label("???") == "unparsed"
def test_evidence_and_prompt():
    r = ASRel("sample_asrel.txt"); ev = r.evidence([3333, 1299, 13335, 64500], 64500, {13335})
    assert ev[0] == "AS13335 is a provider of AS64500." and len(ev) <= 8
    assert "No known relationship between AS64666 and expected origin AS13335." in r.evidence([1, 64666], 64666, {13335})
    assert "<BGP Update:>" in build_messages({"a": 1}, ev)[1]["content"]

def test_metrics():
    from eval import metrics
    m = metrics([(True, True), (True, False), (False, True), (False, False), (False, False)])
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 1, 1, 2) and m["precision"] == 0.5 and m["recall"] == 0.5 and m["accuracy"] == 0.6
def test_cone2_and_related():
    r = ASRel("sample_asrel.txt")
    assert r.related(13335, {"sibling"}) == {64501} and r.related(13335, {"customer"}) == {64500} and r.cone2(13335) == set()

def test_anomaly_type():
    from pipeline import anomaly_type as t
    assert t("origin", "prefix hijack") == "unexpected_origin" and t("deaggregation", "prefix hijack") == "unexpected_deaggregation"
    assert t("deaggregation", "none") == "unexpected_deaggregation" and t("origin", "none") == "unexpected_origin" and t("origin", "unparsed") == "unexpected_origin"
