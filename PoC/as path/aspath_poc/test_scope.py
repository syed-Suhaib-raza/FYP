"""--scope all (every update, leak rule only) and ASN-key history."""
import ipaddress, history, test_history as T
from aspath import Monitor, ASRel
from detector import Baseline, PathCandidates

LEAK, OK = [1299, 64500, 3356, 17557, 9541], [1299, 3356, 17557, 9541]   # demo_as_rel.txt: AS64500 re-exports a provider route to a provider


def upd(path, prefix, peer="1", ts=1.0):
    return dict(type="UPDATE", timestamp=ts, peer_asn=peer, host="rrc00", peer="1.1.1.1", path=path, announcements=[dict(next_hop="1.1.1.1", prefixes=[prefix])])


def mon(**kw):
    m = Monitor(None, {}, ASRel("demo_as_rel.txt"), None, (), 0, **kw)
    m.det.watch = {"GLOBAL": (None, set())}; m.ownership = False
    return m


def test_global_scope_flags_a_leak_on_any_prefix():
    out = mon().process(upd(LEAK, "203.0.113.0/24"))
    assert len(out) == 1 and out[0]["anomaly_type"] == "route_leak" and out[0]["subtype"] == "valley_violation"


def test_global_scope_ignores_normal_paths_and_unknown_links():
    m = mon()
    assert m.process(upd(OK, "203.0.113.0/24")) == []
    assert m.process(upd([1, 2, 3, 4], "198.51.100.0/24")) == []          # unknown relationships: no valley, no baseline -> no alert


def test_global_scope_one_incident_for_same_leak_across_prefixes():
    m = mon(); a = m.process(upd(LEAK, "203.0.113.0/24"))[0]
    b = m.process(upd(LEAK, "198.51.100.0/24", peer="2"))[0]
    assert b["count"] == 2 and b["affected"] == 2 and b["peers_seen"] == 2


def test_model_rate_limit_keeps_alert_but_skips_model():
    calls = []
    class Fake:
        name = "fake"
        def generate(self, m): calls.append(1); return '{"anomaly": "route leak"}'
    m = mon(max_llm_per_min=1); m.llm = Fake()
    c1 = m.det.candidates(upd(LEAK, "10.0.0.0/24"))[0]; c2 = m.det.candidates(upd(LEAK, "10.0.1.0/24"))[0]
    r1, r2 = m._result(c1, 1.0), m._result(c2, 1.0)
    assert len(calls) == 1 and r1["label"] is not None and r2["label"] is None and r2["severity"] == "medium" and m.stats["llm_skipped"] == 1


def test_history_for_an_asn_watch_keeps_only_origin_routes_and_any_prefix(tmp_path):
    exp = {9541}
    def get(resource, ts):
        assert resource == "AS9541"
        rs = [dict(target_prefix=p, source_id=f"00-10.0.0.{i}", path=[60000 + i, 1299, 9541], community=[]) for i in range(4) for p in ("72.255.12.0/24", "72.255.61.0/24")]
        rs.append(dict(target_prefix="1.1.1.0/24", source_id="00-10.0.0.1", path=[60001, 3356, 15169], community=[]))      # other origin: ignored
        return dict(bgp_state=rs)
    b = Baseline(); n = history.fill(b, {"AS9541": (None, exp)}, T.NOW, folder=str(tmp_path), get=get, log=lambda *x: None)
    assert n == 12 and b.support(1299, 9541) >= 2 and b.support(3356, 15169) == 0 and b.nobs["AS9541"] > 0