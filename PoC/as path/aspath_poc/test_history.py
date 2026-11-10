"""Offline tests for history.py (fake RIPEstat answers, no network)."""
import time, ipaddress
from asrel import ASRel
from detector import Baseline, PathCandidates
import history

WL = {"72.255.0.0/18": [9541]}
DAY = 86400
NOW = 1_800_000_000


def route(peer, path, prefix="72.255.0.0/18"):
    return dict(target_prefix=prefix, source_id=peer, path=path, community=[])


def fake(attack_snaps=(), attack_path=(60999, 3356, 666, 9541), normal=((1299, 9541), (3356, 17557, 9541))):
    """get(resource, ts) -> data dict.  Normal routes from 4 peers in every snapshot; an attack route in the snapshots whose index is in attack_snaps."""
    times = history.sample_times(NOW)
    def get(resource, ts):
        rs = [route(f"00-10.0.0.{i}", [60000 + i, *p]) for i in range(4) for p in normal]
        if times.index(ts) in attack_snaps:
            rs += [route("00-10.9.9.9", list(attack_path))] * 5
        rs.append(route("00-10.0.0.1", [60001, 1299, 64999], "72.255.0.0/18"))   # foreign origin: must be ignored
        return dict(bgp_state=rs)
    return get


def build(tmp_path, **kw):
    b = Baseline(); det = PathCandidates(WL, ASRel(), b)
    n = history.fill(b, det.watch, NOW, folder=str(tmp_path), get=kw.pop("get"), log=lambda *a: None, **kw)
    return b, det, n


def test_sample_times_embargo_and_span():
    t = history.sample_times(NOW, 60, 12, 3)
    day0 = NOW - NOW % DAY
    assert len(t) == 12 and t[-1] == day0 - 3 * DAY and t[0] == day0 - 60 * DAY and t == sorted(t)
    assert history.sample_times(NOW + 3600) == t                      # same day -> same timestamps -> cache hits


def test_normal_links_are_established_and_foreign_origin_ignored(tmp_path):
    b, det, n = build(tmp_path, get=fake())
    assert n == 12 and b.support(1299, 9541) >= 2 and b.support(17557, 9541) >= 2
    assert 64999 not in b.upstreams["72.255.0.0/18"]
    assert b.nobs["72.255.0.0/18"] > 0 and b.typical_path("72.255.0.0/18")
    assert b.meta["source"] == "history" and b.meta["snapshots"] == 12


def test_short_attack_in_history_is_not_established(tmp_path):
    """Attack visible in 2 adjacent snapshots (hours-days) from 1 peer: stays 'rare' -> still alerts later."""
    b, det, _ = build(tmp_path, get=fake(attack_snaps=(5, 6)))
    assert 0 < b.support(666, 9541) < 2
    det.min_support = 2
    assert det.check("72.255.0.0/18", "72.255.0.0/18", [60001, 3356, 666, 9541])[0] == "candidate"
    assert b.typical_path("72.255.0.0/18") != "60001 3356 666 9541"      # attack path never becomes the typical path


def test_attack_needs_many_peers_too(tmp_path):
    """Even present in 6 snapshots over the whole window, ONE peer is not enough (min_peers=3)."""
    b, _, _ = build(tmp_path, get=fake(attack_snaps=(0, 2, 4, 6, 8, 10)))
    assert b.support(666, 9541) == 1


def test_long_lived_multi_peer_attack_IS_learned_known_limit(tmp_path):
    """Documented limitation: a hijack that lasted weeks and was seen by >= 3 peers looks normal. Raise the thresholds or add CAIDA to reduce it."""
    def get(resource, ts):
        d = fake(attack_snaps=range(12))(resource, ts)
        d["bgp_state"] += [route(f"00-10.8.8.{i}", [60100 + i, 3356, 666, 9541]) for i in range(4)]
        return d
    b, _, _ = build(tmp_path, get=get)
    assert b.support(666, 9541) >= 2


def test_api_down_returns_zero(tmp_path):
    b, _, n = build(tmp_path, get=lambda r, t: None)
    assert n == 0 and not b.nobs


def test_cache_prevents_second_fetch(tmp_path):
    calls = []
    def get(r, t):
        calls.append(t); return fake()(r, t)
    build(tmp_path, get=get); build(tmp_path, get=get)
    assert len(calls) == 12


def test_caida_known_floor():
    b = Baseline(); b.known = lambda a, c: {a, c} == {1, 2}
    assert b.support(1, 2) == 2 and b.support(1, 3) == 0
    b.upstreams["k"]; assert b.upstream_support("k", 1, 2) == 2 and b.upstream_support("k", 5, 2) == 0


def test_meta_roundtrip(tmp_path):
    b, _, _ = build(tmp_path, get=fake()); b.save(tmp_path / "b.json")
    b2 = Baseline(); assert b2.load(str(tmp_path / "b.json")) and b2.meta["links_established"] == b.meta["links_established"]


def test_object_with_too_few_snapshots_is_ignored_not_half_learned(tmp_path):
    """One good snapshot out of 12 (what AS9541 did) must not add 'rare' links that would raise false alerts later."""
    times = history.sample_times(NOW)
    def get(resource, ts):
        return fake()(resource, ts) if ts == times[-1] else None
    b, det, n = build(tmp_path, get=get)
    assert not b.edges and not b.nobs