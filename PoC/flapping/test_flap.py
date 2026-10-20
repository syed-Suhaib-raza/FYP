import json, subprocess, sys
import pytest
from flap import FlapDetector, Store, fmt

P = "10.0.0.0/24"


def ann(t, path=(1, 2), prefix=P, peer="p1", host="h"):
    return {"type": "UPDATE", "timestamp": t, "peer": peer, "peer_asn": "1", "host": host, "path": list(path),
            "announcements": [{"prefixes": [prefix]}]}


def wd(t, prefix=P, peer="p1", host="h"):
    return {"type": "UPDATE", "timestamp": t, "peer": peer, "peer_asn": "1", "host": host, "withdrawals": [prefix]}


def do_flaps(d, n, t0=0, **kw):
    ev = d.process(ann(t0, **kw))
    for i in range(n):
        ev += d.process(wd(t0 + 100 + 120 * i, **kw)) + d.process(ann(t0 + 160 + 120 * i, **kw))
    return ev


def test_one_blip_is_not_a_flap():
    assert do_flaps(FlapDetector(), 1) == []                      # 1000 < 2000


def test_repeated_withdrawals_alert_once():
    ev = do_flaps(FlapDetector(), 5)
    assert [e["event"] for e in ev] == ["onset"] and ev[0]["withdrawals"] >= 2 and ev[0]["penalty"] >= 2000


def test_slow_flapping_decays_and_never_alerts():
    d = FlapDetector(); ev = d.process(ann(0))
    for i in range(6):                                        # one withdrawal every 30 min: decays between them
        ev += d.process(wd(1800 * i + 100)) + d.process(ann(1800 * i + 160))
    assert ev == []


def test_clears_when_penalty_decays():
    d = FlapDetector(); do_flaps(d, 3)
    ev = d.tick(100000)
    assert [e["event"] for e in ev] == ["cleared"] and not d.active


def test_clear_has_hysteresis():
    d = FlapDetector(); do_flaps(d, 3)                            # alerted at ~2743; reuse is 750 (about 2 half-lives)
    assert d.tick(1500) == []                                 # still above reuse
    assert d.tick(4000)[0]["event"] == "cleared"


def test_path_changes_alone_can_flap():
    d, ev = FlapDetector(), []
    ev += d.process(ann(0, path=(1, 2)))
    for i in range(6):
        ev += d.process(ann(60 * (i + 1), path=(1, 3) if i % 2 == 0 else (1, 2)))
    assert ev and ev[0]["path_changes"] >= 4 and ev[0]["withdrawals"] == 0


def test_same_path_reannounce_is_free():
    d = FlapDetector(); ev = d.process(ann(0))
    for i in range(10):
        ev += d.process(ann(10 * (i + 1)))
    assert ev == []


def test_peer_session_reset_is_not_a_flap():
    d = FlapDetector(); d.process(ann(0)); d.process(ann(0, prefix="10.0.1.0/24"))
    d.process({"type": "RIS_PEER_STATE", "timestamp": 10, "peer": "p1", "peer_asn": "1", "host": "h", "state": "down"})
    ev = d.process(wd(11)) + d.process(wd(11, prefix="10.0.1.0/24"))
    assert ev == [] and d.stats["peer_resets"] == 1 and not d.routes


def test_reset_closes_an_open_flap_without_charging():
    d = FlapDetector(); do_flaps(d, 3)
    ev = d.process({"type": "RIS_PEER_STATE", "timestamp": 900, "peer": "p1", "peer_asn": "1", "host": "h", "state": "down"})
    assert [e["event"] for e in ev] == ["cleared"] and "session" in ev[0]["reason"] and not d.active


def test_peers_are_independent_and_min_peers():
    d = FlapDetector(min_peers=2)
    assert do_flaps(d, 4, peer="a") == []                         # one session flapping is not enough for min_peers=2
    ev = do_flaps(d, 4, peer="b")
    assert sorted(e["peer_asn"] for e in ev) == ["1", "1"] and {e["peers_flapping"] for e in ev} == {2} and len(d.active) == 2
    d1 = FlapDetector(); do_flaps(d1, 4, peer="a")
    assert do_flaps(d1, 0, peer="b") == [] and len(d1.active) == 1


def test_severity_whitelist():
    d = FlapDetector(whitelist={"10.0.0.0/16": [1]})
    assert do_flaps(d, 3)[0]["severity"] == "high"                # inside a monitored prefix (more-specific counts)
    other = [e for e in do_flaps(d, 3, prefix="192.0.2.0/24", t0=50000) if e["event"] == "onset"]
    assert other[0]["severity"] == "medium"


def test_ipv6_spellings_are_one_route():
    d = FlapDetector(); d.process(ann(0, prefix="2a12:ca40::/32"))
    d.process(wd(5, prefix="2a12:ca40:0:0:0:0:0:0/32"))
    assert len(d.routes) == 1 and not list(d.routes.values())[0].up


def test_withdrawal_of_unknown_route_is_ignored():
    assert FlapDetector().process(wd(0)) == []


def test_penalty_is_capped():
    d = FlapDetector(); do_flaps(d, 40, 0)
    assert max(r.penalty for r in d.routes.values()) <= 12000


def test_sample_replay_end_to_end(tmp_path):
    d = FlapDetector(Store(str(tmp_path / "t.db")), json.load(open("whitelist.json")), source="demo")
    ev = []
    for line in open("sample_updates.jsonl"):
        ev += d.process(json.loads(line)["data"])
    got = {e["prefix"]: e["severity"] for e in ev if e["event"] == "onset"}
    assert got == {"66.167.15.0/24": "high", "1.1.1.0/24": "high", "203.0.113.0/24": "medium"}   # not 8.8.8.0/24, not IPv6
    assert d.stats["peer_resets"] == 1
    assert len(d.store.con.execute("SELECT * FROM alerts").fetchall()) == 3
    line = fmt([e for e in ev if e["prefix"] == "1.1.1.0/24"][0])
    assert "DEMO route flapping: HIGH 1.1.1.0/24" in line
    rows = d.store.con.execute("select source, anomaly from alerts").fetchall()
    assert set(rows) == {("demo", "route_flapping")}


def test_ris_live_client_loop_with_a_fake_websocket(monkeypatch, capsys, tmp_path):
    """drives the real ris_live.run() with a fake RIS Live socket fed from the sample file."""
    import argparse, asyncio, ris_live
    lines = [l.strip() for l in open("sample_updates.jsonl")]

    class FakeWS:
        sent = []
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def send(self, s): FakeWS.sent.append(json.loads(s))
        def __aiter__(self): return self._gen()
        async def _gen(self):
            for l in lines:
                yield l

    calls = []
    def fake_connect(url, **kw):
        calls.append(url)
        if len(calls) > 1:
            raise KeyboardInterrupt                              # stop the endless reconnect loop
        return FakeWS()

    monkeypatch.setattr(ris_live.websockets, "connect", fake_connect)
    monkeypatch.setattr(ris_live, "STATUS_EVERY", 0)
    db = str(tmp_path / "r.db")
    args = argparse.Namespace(whitelist="whitelist.json", prefix=["1.1.1.0/24"], more_specific=True, half_life=900,
                              suppress=2000, reuse=750, min_peers=1, db=db)
    with pytest.raises(KeyboardInterrupt):
        asyncio.run(ris_live.run(args))
    out = capsys.readouterr().out
    assert "connected to RIS Live" in out and "listening:" in out and "ONLINE route flapping: HIGH 1.1.1.0/24" in out
    assert {s["data"]["type"] for s in FakeWS.sent} == {"UPDATE", "RIS_PEER_STATE"} and FakeWS.sent[0]["type"] == "ris_subscribe"
    import sqlite3
    assert sqlite3.connect(db).execute("select distinct source, anomaly from alerts").fetchall() == [("online", "route_flapping")]


def test_replay_script_writes_demo_db(tmp_path):
    db = str(tmp_path / "d.db")
    r = subprocess.run([sys.executable, "replay.py", "sample_updates.jsonl", "--whitelist", "whitelist.json", "--db", db],
                       capture_output=True, text=True, check=True)
    assert r.stdout.count("DEMO route flapping: ") == 6 and "ONLINE" not in r.stdout
    import sqlite3
    assert sqlite3.connect(db).execute("select distinct source from alerts").fetchall() == [("demo",)]
