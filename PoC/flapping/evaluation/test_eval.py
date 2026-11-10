import asyncio, json, os, subprocess, sys, time
from types import SimpleNamespace
import pytest
import eval as ev
import live_eval, make_eval_set, timing
from timing import TimedDetector, changes, oracle, qualifies

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = make_eval_set.build(42)


def U(t, host="rrc00", peer="1.1.1.1", asn="1", w=None, ann=None, path=(1, 2)):
    m = {"timestamp": t, "host": host, "peer": peer, "peer_asn": asn, "type": "UPDATE"}
    if w: m["withdrawals"] = [w]
    if ann: m["announcements"] = [{"prefixes": [ann]}]; m["path"] = list(path)
    return m


# ------------------------------------------------------------ the 250-case set
def test_set_shape():
    from collections import Counter
    assert len(CASES) == 250 and Counter(c["label"] for c in CASES) == {"flap": 125, "normal": 125}
    assert len({c["id"] for c in CASES}) == 250
    assert Counter(c["kind"] for c in CASES)["classic"] == 35

def test_set_is_reproducible():
    assert make_eval_set.build(42) == CASES and make_eval_set.build(43) != CASES

def test_every_label_agrees_with_the_independent_rule():
    bad = [c["id"] for c in CASES if bool(oracle(c["updates"])) != (c["label"] == "flap")]
    assert bad == []

def test_t0_is_a_real_first_change():
    for c in CASES:
        if c["label"] == "flap":
            first = min(min(ts) for ts in changes(c["updates"]).values() if ts)
            assert abs(c["t0"] - first) < 1e-6 or any(abs(c["t0"] - t) < 1e-6 for ts in changes(c["updates"]).values() for t in ts)
        else:
            assert c["t0"] is None


# ------------------------------------------------------------ ground-truth rule
def test_oracle_thresholds():
    ups = [U(0, ann="10.0.0.0/24")] + [m for i in range(3) for m in (U(10 + 60 * i, w="10.0.0.0/24"), U(40 + 60 * i, ann="10.0.0.0/24"))]
    assert oracle(ups) == {}                                    # 3 changes: not flapping
    ups += [U(190, w="10.0.0.0/24")]
    assert list(oracle(ups).values()) == [190]                  # 4th change within 15 min: flapping, satisfied at t=190

def test_oracle_ignores_session_reset_noise_and_unseen_routes():
    ups = [U(0, ann="10.0.0.0/24"), U(10, w="10.0.0.0/24"),
           {"timestamp": 20, "host": "rrc00", "peer": "1.1.1.1", "peer_asn": "1", "type": "RIS_PEER_STATE", "state": "down"}]
    ups += [U(21 + i, w="10.0.0.0/24") for i in range(10)]     # withdrawals during the reset
    assert oracle(ups) == {} and len(changes(ups)[("10.0.0.0/24", "rrc00", "1.1.1.1")]) == 1
    assert changes([U(5, w="10.9.9.0/24")]) == {}               # route never announced: nothing to flap

def test_qualifies_long_window():
    assert qualifies([0, 1000, 2000, 3000, 4000]) == 4000       # 5 changes in 90 min
    assert qualifies([0, 2000, 4000, 6000, 8000]) is None


# ------------------------------------------------------------ timing wrapper does not change detection
def test_timed_detector_first_ts_and_events():
    d = TimedDetector(source="t"); d.process(U(0, ann="10.0.0.0/24"))
    out = []
    for i in range(3):
        out += d.process(U(100 + 60 * i, w="10.0.0.0/24")); out += d.process(U(130 + 60 * i, ann="10.0.0.0/24"))
    on = [a for a in out if a["event"] == "onset"]
    assert len(on) == 1 and on[0]["first_ts"] == 100 and on[0]["events_to_detect"] == 3 and on[0]["key"][0] == "10.0.0.0/24"

def test_timed_detector_same_alerts_as_plain_detector():
    from flap import FlapDetector
    for c in CASES[:60]:
        a, b = FlapDetector(source="x"), TimedDetector(source="x")
        ra = [(x["event"], x["prefix"], x["ts"]) for m in c["updates"] for x in a.process(m)]
        rb = [(x["event"], x["prefix"], x["ts"]) for m in c["updates"] for x in b.process(m)]
        assert ra == rb

def test_new_flap_run_resets_first_ts():
    d = TimedDetector(source="t"); d.process(U(0, ann="10.0.0.0/24"))
    d.process(U(100, w="10.0.0.0/24")); d.process(U(130, ann="10.0.0.0/24"))
    d.process(U(100000, w="10.0.0.0/24"))                       # hours later: penalty long decayed -> new run
    assert d.first[("10.0.0.0/24", "rrc00", "1.1.1.1")] == 100000


# ------------------------------------------------------------ simulated test: results
def test_metrics_toy():
    rows = [dict(truth=True, pred=True, delay=10, total=10, events=3), dict(truth=True, pred=False, delay=None, total=None, events=None),
            dict(truth=False, pred=True, delay=None, total=None, events=None), dict(truth=False, pred=False, delay=None, total=None, events=None)]
    m = ev.metrics(rows)
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 1, 1) and m["accuracy"] == 0.5 and m["precision"] == 0.5 and m["delay_median_s"] == 10

def test_detector_on_the_set():
    rows, _, _ = ev.evaluate(CASES, dict(half_life=900, suppress=2000, reuse=750, min_peers=1))
    det = [r for r in rows if r["method"] == "detector"]
    m = ev.metrics(det)
    assert m["tp"] + m["fp"] + m["fn"] + m["tn"] == 250
    wrong = {r["kind"] for r in det if r["pred"] != r["truth"]}
    assert wrong == {"path_four", "three_withdrawals"}          # the two definition-boundary kinds, nothing else
    assert m["recall"] >= 0.9 and all(r["delay"] >= 0 for r in det if r["delay"] is not None)
    for kind in ("session_reset", "beacon", "single_flap", "double_flap", "spaced_flaps", "three_changes"):
        assert not any(r["pred"] for r in det if r["kind"] == kind)

def test_baselines_are_worse():
    rows, _, _ = ev.evaluate(CASES, dict(half_life=900, suppress=2000, reuse=750, min_peers=1))
    acc = {k: ev.metrics([r for r in rows if r["method"] == k])["accuracy"] for k in ("detector", "B1", "B2")}
    assert acc["detector"] > acc["B2"] > acc["B1"]

def test_eval_cli_writes_reports(tmp_path):
    cp = tmp_path / "set.jsonl"; cp.write_text("\n".join(json.dumps(c) for c in CASES[:40]))
    r = subprocess.run([sys.executable, os.path.join(HERE, "eval.py"), str(cp), "--out", str(tmp_path / "res"), "--sweep"],
                       capture_output=True, text=True, cwd=HERE)
    assert r.returncode == 0, r.stderr
    md = (tmp_path / "res.md").read_text()
    assert "SIMULATED test (40 cases)" in md and "Threshold sweep" in md and "Sensitivity" in md
    assert (tmp_path / "res.json").exists() and (tmp_path / "res.csv").exists()


# ------------------------------------------------------------ live test
def test_live_dry_run_and_analyze(tmp_path):
    cap, al, out = str(tmp_path / "c.jsonl"), str(tmp_path / "a.jsonl"), str(tmp_path / "rep")
    r = subprocess.run([sys.executable, os.path.join(HERE, "live_eval.py"), "record", "--from-file", os.path.join(HERE, "sample_updates.jsonl"),
                        "--capture", cap, "--alerts", al, "--out", out], capture_output=True, text=True, cwd=HERE)
    assert r.returncode == 0, r.stderr
    rep = json.load(open(out + ".json"))
    assert rep["alerts_replay"] == 3 and len(rep["alerts_live"]) == 3 and rep["accuracy"]["tp"] == 1
    assert all(a["total_time_s"] >= a["detection_delay_s"] >= 0 for a in rep["alerts_live"])
    # manual labels are read back
    import csv
    rows = list(csv.DictReader(open(out + "_alerts.csv")))
    for k, r in enumerate(rows):
        r["verdict"] = "TRUE" if k < 2 else "FALSE"
    with open(tmp_path / "lab.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    live_eval.analyze(cap, al, out, str(tmp_path / "lab.csv"))
    assert "2 of 3 alerts confirmed as real flapping = precision 0.667" in open(out + ".md").read()
    live_eval.analyze(cap, al, out, out + "_alerts.csv")        # unfilled sheet is reported, not ignored
    assert "no filled `verdict`" in open(out + ".md").read()


def test_live_websocket_path_against_a_local_fake_ris(tmp_path):
    """real websocket + real clock: a local server plays RIS Live and sends a genuine real-time flap."""
    websockets = pytest.importorskip("websockets")
    async def scenario():
        async def handler(ws):
            await ws.recv()                                     # the subscribe message(s)
            now = time.time()
            def send(**kw):
                return ws.send(json.dumps({"type": "ris_message", "data": {"host": "rrc00", "peer": "192.0.2.1", "peer_asn": "64500",
                                                                        "type": "UPDATE", **kw}}))
            await send(timestamp=time.time(), path=[64500, 3356, 65000], announcements=[{"prefixes": ["10.9.9.0/24"]}])
            for _ in range(4):
                await asyncio.sleep(0.15); await send(timestamp=time.time(), withdrawals=["10.9.9.0/24"])
                await asyncio.sleep(0.15); await send(timestamp=time.time(), path=[64500, 3356, 65000], announcements=[{"prefixes": ["10.9.9.0/24"]}])
            await asyncio.sleep(2)
        async with websockets.serve(handler, "localhost", 0) as server:
            live_eval.URL = f"ws://localhost:{server.sockets[0].getsockname()[1]}"
            rec = live_eval.Recorder(str(tmp_path / "c.jsonl"), str(tmp_path / "a.jsonl"), {"watching": "fake"},
                                     dict(half_life=900, suppress=2000, reuse=750, min_peers=1))
            args = SimpleNamespace(minutes=0.06, prefix=["10.9.9.0/24"], host=None, more_specific=True)
            await live_eval.live(rec, args)
            rec.close()
    asyncio.run(scenario())
    alerts = [json.loads(l) for l in open(tmp_path / "a.jsonl")]
    assert len(alerts) == 1
    a = alerts[0]
    assert a["prefix"] == "10.9.9.0/24" and a["events_to_detect"] == 3
    assert 0 <= a["feed_delay_s"] < 1 and 0.2 < a["detection_delay_s"] < 2.5      # ~0.3 s between changes, 3rd withdrawal fires
    assert a["total_time_s"] >= a["detection_delay_s"] - 0.05 and a["compute_ms"] < 50
    live_eval.analyze(str(tmp_path / "c.jsonl"), str(tmp_path / "a.jsonl"), str(tmp_path / "rep"))
    assert json.load(open(tmp_path / "rep.json"))["messages"] >= 9
