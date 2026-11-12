"""test_engine.py - the detector end to end: alert lifecycle, peer threshold, severity rules, history,
ROA changes and re-validation, peer sessions, SQLite persistence. Run: python -m pytest -q"""

import ipaddress

import pytest

from bgp_feed import RouteEvent
from engine import ACTIVE, DROPPED, PENDING, RESOLVED, RpkiDetector
from store import Store
from validator import INVALID_AS, INVALID_AS_AND_ML, INVALID_ML, NOT_FOUND
from vrp_store import VRP, VrpStore


def net(t):
    return ipaddress.ip_network(t)


def vrps(*items):
    return VrpStore([VRP(a, net(p), m, "test") for a, p, m in items], source="test")


BASE = vrps((9541, "72.255.0.0/18", 20), (24440, "203.0.113.0/24", 24), (64496, "198.51.100.0/24", 24),
            (0, "192.0.2.0/24", 24), (9541, "2001:db8:100::/40", 48), (15169, "8.8.8.0/24", 24))
WL = {"72.255.0.0/18": [9541], "72.255.128.0/18": [9541], "203.0.113.0/24": [24440], "198.51.100.0/24": [9541],
      "192.0.2.0/24": [9541], "2001:db8:100::/40": [9541]}
PEERS = [("rrc00", "10.0.0.1", 3333), ("rrc01", "10.0.0.2", 2914), ("rrc03", "10.0.0.3", 6939), ("rrc12", "10.0.0.4", 1299)]


def det(store=None, min_peers=2, revalidate=True, vrp_set=BASE):
    return RpkiDetector(vrp_set, store, WL, {64510}, {9541, 24440}, min_peers=min_peers, revalidate=revalidate)


def ann(d, prefix, origin, peer, ts=100.0, path=None):
    h, ip, asn = PEERS[peer]
    path = path if path is not None else [asn, 3491, origin]
    return d.process(RouteEvent("announce", net(prefix), origin if not isinstance(origin, list) else None, path, h, ip, asn, ts))


def wd(d, prefix, peer, ts=200.0):
    h, ip, asn = PEERS[peer]
    return d.process(RouteEvent("withdraw", net(prefix), None, [], h, ip, asn, ts))


def alert(d, prefix, origin):
    return next(a for k, a in d.alerts.items() if k[0] == prefix and k[1] == origin)


# ---- peer threshold and lifecycle ----------------------------------------------------------------------------
def test_one_peer_is_pending_two_peers_is_active():
    d = det()
    assert ann(d, "72.255.40.0/24", 9541, 0) == []
    assert alert(d, "72.255.40.0/24", 9541)["status"] == PENDING
    out = ann(d, "72.255.40.0/24", 9541, 1)
    assert [o["event"] for o in out] == ["ACTIVE"]
    a = out[0]["alert"]
    assert (a["state"], a["cause"], a["severity"], a["seen_by_peers"]) == (INVALID_ML, "OWN_MAXLENGTH", "HIGH", 2)


def test_min_peers_one_alerts_immediately():
    d = det(min_peers=1)
    assert [o["event"] for o in ann(d, "72.255.40.0/24", 9541, 0)] == ["ACTIVE"]


def test_alert_stays_active_until_last_peer_withdraws():
    d = det()
    for p in (0, 1, 2):
        ann(d, "72.255.40.0/24", 9541, p)
    assert wd(d, "72.255.40.0/24", 0) == [] and wd(d, "72.255.40.0/24", 1) == []
    assert d.active_alert("72.255.40.0/24", 9541)["seen_by_peers"] == 1          # no flip-flop below the threshold
    out = wd(d, "72.255.40.0/24", 2)
    assert [o["event"] for o in out] == ["RESOLVED"] and d.active_alert("72.255.40.0/24", 9541) is None


def test_pending_that_disappears_is_dropped_not_resolved():
    d = det()
    ann(d, "72.255.60.0/24", 9541, 0)
    assert wd(d, "72.255.60.0/24", 0) == []
    assert alert(d, "72.255.60.0/24", 9541)["status"] == DROPPED


def test_reopen_after_resolve_keeps_the_same_alert_id():
    d = det()
    ann(d, "72.255.40.0/24", 9541, 0); ann(d, "72.255.40.0/24", 9541, 1)
    aid = d.active_alert("72.255.40.0/24", 9541)["alert_id"]
    wd(d, "72.255.40.0/24", 0); wd(d, "72.255.40.0/24", 1)
    ann(d, "72.255.40.0/24", 9541, 0, ts=300)
    out = ann(d, "72.255.40.0/24", 9541, 2, ts=310)
    assert out[0]["event"] == "REOPENED" and out[0]["alert"]["alert_id"] == aid


# ---- severity rules (doc table) ---------------------------------------------------------------------------
@pytest.mark.parametrize("prefix,origin,state,cause,severity", [
    ("72.255.0.0/18", 64666, INVALID_AS, "FOREIGN_NEW_ORIGIN", "CRITICAL"),          # exact-prefix hijack
    ("72.255.8.0/24", 64667, INVALID_AS_AND_ML, "FOREIGN_NEW_ORIGIN", "CRITICAL"),   # sub-prefix hijack
    ("72.255.48.0/20", 64510, INVALID_AS, "CUSTOMER_NOT_IN_ROA", "HIGH"),            # customer, ROA not updated
    ("72.255.40.0/24", 9541, INVALID_ML, "OWN_MAXLENGTH", "HIGH"),                   # our own maxLength mistake
    ("198.51.100.0/24", 9541, INVALID_AS, "OWN_NOT_AUTHORISED", "HIGH"),             # ROA names another AS
    ("192.0.2.0/24", 64668, INVALID_AS, "FOREIGN_NEW_ORIGIN", "CRITICAL"),           # AS0 ROA
    ("72.255.128.0/18", 9541, NOT_FOUND, "NO_ROA", "LOW"),                           # Cybernet prefix, no ROA
    ("2001:db8:100:ff00::/56", 9541, INVALID_ML, "OWN_MAXLENGTH", "HIGH"),           # IPv6
])
def test_severity_table(prefix, origin, state, cause, severity):
    d = det()
    ann(d, prefix, origin, 0)
    a = ann(d, prefix, origin, 1)[0]["alert"]
    assert (a["state"], a["cause"], a["severity"]) == (state, cause, severity)


def test_as_set_origin_in_cybernet_space_is_critical():
    d = det()
    ann(d, "72.255.12.0/22", [64700, 64701], 0, path=[3333, [64700, 64701]])
    a = ann(d, "72.255.12.0/22", [64700, 64701], 1, path=[2914, [64700, 64701]])[0]["alert"]
    assert a["origin_asn"] is None and a["state"] == INVALID_AS_AND_ML and a["severity"] == "CRITICAL"


@pytest.mark.parametrize("prefix,origin", [
    ("72.255.0.0/18", 9541),          # valid
    ("72.255.32.0/20", 9541),         # valid more-specific
    ("8.8.8.0/24", 64669),            # invalid, but not Cybernet: not our alert
    ("9.9.9.0/24", 64669),            # not found, not Cybernet
])
def test_no_alert(prefix, origin):
    d = det()
    for p in range(4):
        assert ann(d, prefix, origin, p) == []
    assert not any(a["status"] == ACTIVE for a in d.alerts.values())


def test_foreign_origin_with_history_is_high_not_critical():
    d = det()
    ann(d, "72.255.16.0/20", 64520, 0, ts=100); ann(d, "72.255.16.0/20", 64520, 1, ts=110)
    assert d.active_alert("72.255.16.0/20", 64520)["severity"] == "CRITICAL"         # first episode
    wd(d, "72.255.16.0/20", 0, ts=200); wd(d, "72.255.16.0/20", 1, ts=210)
    ann(d, "72.255.16.0/20", 64520, 2, ts=5000)
    a = ann(d, "72.255.16.0/20", 64520, 3, ts=5010)[0]["alert"]                       # second episode
    assert (a["severity"], a["cause"]) == ("HIGH", "FOREIGN_KNOWN_ORIGIN")


# ---- route table ------------------------------------------------------------------------------------------
def test_same_peer_new_origin_replaces_the_old_route():
    d = det()
    ann(d, "72.255.0.0/18", 64666, 0); ann(d, "72.255.0.0/18", 64666, 1)
    assert d.active_alert("72.255.0.0/18", 64666)
    ann(d, "72.255.0.0/18", 9541, 0); out = ann(d, "72.255.0.0/18", 9541, 1)        # both peers back to Cybernet
    assert [o["event"] for o in out] == ["RESOLVED"]


def test_peer_session_down_removes_its_routes():
    d = det()
    ann(d, "2001:db8:100:ff00::/56", 9541, 2); ann(d, "2001:db8:100:ff00::/56", 9541, 3)
    h, ip, asn = PEERS[2]
    d.process(RouteEvent("peer_down", collector=h, peer=ip, peer_asn=asn, timestamp=300))
    assert d.active_alert("2001:db8:100:ff00::/56", 9541)["seen_by_peers"] == 1
    h, ip, asn = PEERS[3]
    out = d.process(RouteEvent("peer_down", collector=h, peer=ip, peer_asn=asn, timestamp=310))
    assert [o["event"] for o in out] == ["RESOLVED"]


# ---- ROA changes and re-validation ------------------------------------------------------------------------
TIGHT = vrps((9541, "72.255.0.0/18", 18), (64496, "198.51.100.0/24", 24), (0, "192.0.2.0/24", 24),
             (9541, "2001:db8:100::/40", 48), (15169, "8.8.8.0/24", 24))


def test_roa_change_alerts_without_any_bgp_update():
    d = det()
    for p in (0, 1):
        ann(d, "72.255.32.0/20", 9541, p); ann(d, "203.0.113.0/24", 24440, p)
    assert not d.alerts                                                              # all valid
    out, pfx_changed = d.reload_vrps(TIGHT, ts=500)
    roa = sorted((o["change"]["change"], o["change"]["severity"]) for o in out if o["kind"] == "roa")
    assert roa == [("MAXLENGTH_REDUCED", "MEDIUM"), ("REMOVED", "MEDIUM")]
    raised = {(o["alert"]["prefix"], o["alert"]["state"], o["alert"]["severity"]) for o in out if o["kind"] == "alert"}
    assert raised == {("72.255.32.0/20", INVALID_ML, "HIGH"), ("203.0.113.0/24", NOT_FOUND, "LOW")}
    assert pfx_changed                                                               # 203.0.113.0/24 left the ROA list
    out, _ = d.reload_vrps(BASE, ts=600)                                             # fixed again
    assert {o["event"] for o in out if o["kind"] == "alert"} == {"RESOLVED"}


def test_without_revalidation_the_roa_change_is_missed():
    d = det(revalidate=False)
    for p in (0, 1):
        ann(d, "72.255.32.0/20", 9541, p)
    out, _ = d.reload_vrps(TIGHT, ts=500)
    assert [o for o in out if o["kind"] == "alert"] == []                            # the gap the fix closes


def test_expiring_roa_is_reported_once():
    soon = VrpStore([VRP(9541, net("72.255.0.0/18"), 20, "test", expires=1000 + 3600)], source="t")
    d = det(vrp_set=soon)
    out1, _ = d.reload_vrps(soon, ts=1000)
    out2, _ = d.reload_vrps(soon, ts=1100)
    assert [o["change"]["change"] for o in out1] == ["EXPIRING"] and out2 == []


# ---- persistence ------------------------------------------------------------------------------------------
def test_alerts_and_history_are_saved_to_sqlite(tmp_path):
    db = str(tmp_path / "t.db")
    d = det(store=Store(db))
    ann(d, "72.255.0.0/18", 64666, 0, ts=100); ann(d, "72.255.0.0/18", 64666, 1, ts=110)
    s = Store(db)
    saved = s.load_alerts()
    assert len(saved) == 1 and saved[0]["status"] == ACTIVE and saved[0]["severity"] == "CRITICAL"
    events = [r[0] for r in s.con.execute("SELECT event FROM alert_events ORDER BY id")]
    assert events == ["SEEN", "ACTIVE"]
    assert ("72.255.0.0/18", 64666) in s.load_history()
    d2 = det(store=Store(db))                     # restart: the route table is empty, so the alert is resolved
    assert d2.alerts[("72.255.0.0/18", 64666, INVALID_AS)]["status"] == RESOLVED
    ann(d2, "72.255.0.0/18", 64666, 0, ts=9000)   # and the origin is now known from history
    assert ann(d2, "72.255.0.0/18", 64666, 1, ts=9010)[0]["alert"]["severity"] == "HIGH"
