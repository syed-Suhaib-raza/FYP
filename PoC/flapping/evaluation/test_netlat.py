"""Tests for the network-latency additions (netlat.py + the network section of live_eval.analyze). No internet needed."""
import json, socket, struct, threading, time
import netlat, live_eval


def _fake_ntp(port, skew):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port)); s.settimeout(3)
    def run():
        try:
            for _ in range(8):
                d, addr = s.recvfrom(100)
                t = time.time() + skew + netlat.NTP_EPOCH
                f = struct.pack("!II", int(t), int((t % 1) * 2 ** 32))
                s.sendto(b"\x24" + b"\0" * 31 + f + f, addr)
        except OSError:
            pass
    threading.Thread(target=run, daemon=True).start()
    return s


def test_sntp_offset_recovers_known_skew():
    s = _fake_ntp(12411, 2.0)
    r = netlat.sntp_offset("127.0.0.1", 12411, samples=2, timeout=1)
    s.close()
    assert abs(r["offset_s"] - 2.0) < 0.05


def test_sntp_offset_none_when_unreachable():
    assert netlat.sntp_offset("127.0.0.1", 9, samples=1, timeout=0.2) is None


def test_connect_times_local_tcp():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
    r = netlat.connect_times("127.0.0.1", srv.getsockname()[1], tls=False, samples=2)
    srv.close()
    assert r and r["tcp_ms"] >= 0 and r["dns_ms"] >= 0


def test_analyze_corrects_feed_delay_and_total_for_clock_offset(tmp_path):
    """PC clock 1.5 s slow, true feed delay 0.2 s: raw feed delay is -1.3 s, corrected must be 0.2 s."""
    cap, al = tmp_path / "c.jsonl", tmp_path / "a.jsonl"
    rec = live_eval.Recorder(str(cap), str(al), {"watching": "t"}, dict(half_life=900, suppress=2000, reuse=750, min_peers=1))
    live_eval.Recorder._live = False
    try:
        base = 1_000_000.0
        for i, k in enumerate("AWAWAWA"):
            ts = base + i
            d = dict(type="UPDATE", timestamp=ts, host="rrc00", peer="1.1.1.1", peer_asn="1", path=[1, 2],
                     announcements=[dict(prefixes=["203.0.113.0/24"])] if k == "A" else [],
                     withdrawals=[] if k == "A" else ["203.0.113.0/24"])
            rec.handle(d, ts - 1.3)                       # recv (local clock) = true arrival - 1.5
        rec.net(dict(kind="ntp", t=0, offset_s=1.5, rtt_ms=10, server="x"))
        rec.net(dict(kind="ws_rtt", t=0, rtt_ms=100.0))
    finally:
        live_eval.Recorder._live = True
    rec.close()
    live_eval.analyze(str(cap), str(al), str(tmp_path / "r"))
    j = json.load(open(tmp_path / "r.json"))
    assert abs(j["feed_delay_s"]["median"] + 1.3) < 1e-6
    assert j["network"]["ntp_offset_s"] == 1.5 and j["network"]["ws_rtt_ms"]["median"] == 100.0
    md = open(tmp_path / "r.md", encoding="utf-8").read()
    assert "clock-corrected" in md and "'median': 0.2" in md
    a = j["alerts_live"][0]
    assert abs((a["total_time_s"] + 1.5) - (a["detection_delay_s"] + 0.2 + a["compute_ms"] / 1000)) < 1e-3


def test_analyze_still_works_without_net_lines(tmp_path):
    cap = tmp_path / "c.jsonl"
    cap.write_text(json.dumps({"header": {"config": {}}}) + "\n")
    live_eval.analyze(str(cap), None, str(tmp_path / "r"))
    assert "Network latency" not in open(tmp_path / "r.md", encoding="utf-8").read()
