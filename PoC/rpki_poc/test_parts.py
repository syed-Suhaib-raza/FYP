"""test_parts.py - the smaller modules: VRP loading, ROA diff, feed parsing, subscriptions. Run: python -m pytest -q"""

import ipaddress
import json

from bgp_feed import build_subscriptions, parse_data, replay_events
from roa_watch import diff_vrps, expiring
from rules import is_alertable
from validator import validate_route
from vrp_store import VRP, VrpStore, parse_asn, parse_roas


def net(t):
    return ipaddress.ip_network(t)


def test_parse_asn_formats():
    assert parse_asn("AS9541") == parse_asn("as9541") == parse_asn("9541") == parse_asn(9541) == 9541


def test_parse_roas_reads_jsonext_expiry_and_ta():
    data = {"roas": [{"asn": "AS9541", "prefix": "72.255.0.0/18", "maxLength": 20,
                      "source": [{"type": "roa", "tal": "apnic", "validity": {"notAfter": "2026-12-01T00:00:00Z"},
                                  "chainValidity": {"notAfter": "2026-11-30T00:00:00Z"}}]}]}
    v = parse_roas(data)[0]
    assert (v.asn, v.max_length, v.ta) == (9541, 20, "apnic")
    assert v.expires is not None
    assert v.expires <parse_roas({"roas": [dict(data["roas"][0], source=[{"validity": {"notAfter": "2026-12-01T00:00:00Z"}}])]})[0].expires


def test_plain_json_has_no_expiry():
    v = parse_roas({"roas": [{"asn": "AS9541", "prefix": "72.255.0.0/18", "maxLength": 20, "ta": "apnic"}]})[0]
    assert v.expires is None and v.ta == "apnic"


def test_covering_and_relevant():
    s = VrpStore([VRP(9541, net("72.255.0.0/18"), 20), VRP(64496, net("198.51.100.0/24"), 24),
                  VRP(15169, net("8.8.8.0/24"), 24)], source="t")
    assert [v.asn for v in s.covering(net("72.255.4.0/24"))] == [9541]
    assert s.covering(net("72.254.0.0/24")) == []
    rel = s.relevant({9541}, [net("198.51.100.0/24")])
    assert {v.asn for v in rel} == {9541, 64496}                      # Google's ROA is not Cybernet's business
    assert s.prefixes_for_asns({9541}) == [net("72.255.0.0/18")]


def test_diff_vrps_classifies_changes():
    a = {VRP(9541, net("72.255.0.0/18"), 20), VRP(24440, net("203.0.113.0/24"), 24)}
    b = {VRP(9541, net("72.255.0.0/18"), 18), VRP(9541, net("72.255.128.0/18"), 18)}
    got = {(c["change"], c["prefix"], c["severity"]) for c in diff_vrps(a, b, now=1)}
    assert got == {("MAXLENGTH_REDUCED", "72.255.0.0/18", "MEDIUM"), ("REMOVED", "203.0.113.0/24", "MEDIUM"),
                   ("ADDED", "72.255.128.0/18", "INFO")}
    assert diff_vrps(a, a) == []


def test_expiring_only_inside_the_window():
    vs = {VRP(9541, net("72.255.0.0/18"), 20, expires=1000 + 10 * 3600), VRP(9541, net("2001:db8::/32"), 48, expires=1000 + 99 * 3600)}
    assert [c["prefix"] for c in expiring(vs, 1000, 24)] == ["72.255.0.0/18"]


def test_parse_data_withdrawals_peer_state_and_reload():
    upd = {"type": "UPDATE", "host": "rrc00", "peer": "10.0.0.1", "peer_asn": 3333, "timestamp": 5,
           "path": [3333, 9541], "announcements": [{"next_hop": "x", "prefixes": ["72.255.0.0/18", "72.255.64.0/18"]}],
           "withdrawals": ["72.255.128.0/18"]}
    evs = parse_data(upd)
    assert [(e.kind, str(e.prefix), e.origin_asn) for e in evs] == [
        ("announce", "72.255.0.0/18", 9541), ("announce", "72.255.64.0/18", 9541), ("withdraw", "72.255.128.0/18", None)]
    assert parse_data({"type": "RIS_PEER_STATE", "host": "rrc00", "peer": "10.0.0.1", "state": "down"})[0].kind == "peer_down"
    assert parse_data({"type": "RIS_PEER_STATE", "state": "connected"}) == []
    assert parse_data({"type": "VRP_RELOAD", "file": "v2.json"})[0].file == "v2.json"


def test_subscriptions_cover_origin_prefixes_and_peer_state():
    subs = [s["data"] for s in build_subscriptions([net("72.255.0.0/18")], {9541, 24440})]
    assert {s.get("path") for s in subs if "path" in s} == {"9541$", "24440$"}
    assert [s for s in subs if s.get("prefix") == "72.255.0.0/18"][0]["moreSpecific"] is True
    assert any(s["type"] == "RIS_PEER_STATE" for s in subs)


def test_replay_skips_comments(tmp_path):
    f = tmp_path / "r.jsonl"
    f.write_text("# comment\n" + json.dumps({"type": "ris_message", "data": {"type": "UPDATE", "path": [1, 9541],
                 "announcements": [{"prefixes": ["72.255.0.0/18"]}]}}) + "\n")
    assert [e.kind for e in replay_events(str(f))] == ["announce"]


def test_is_alertable_rules():
    s = VrpStore([VRP(9541, net("72.255.0.0/18"), 20)], source="t")
    r = validate_route(net("72.255.0.0/24"), 64666, s)
    assert is_alertable(r, 64666, monitored={9541}, in_cybernet_space=False)       # covered by a Cybernet ROA
    nf = validate_route(net("9.9.9.0/24"), 9541, s)
    assert is_alertable(nf, 9541, monitored={9541}, in_cybernet_space=False)       # Cybernet originates, no ROA
    assert not is_alertable(nf, 64666, monitored={9541}, in_cybernet_space=False)
