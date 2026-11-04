"""Layer 1 tests: the catalog records every multi-origin prefix and judges none of them."""
from moas import MoasCatalog, Store, extract_origins, read_events


def upd(ts, path, prefix, peer=1, host="rrc00"):
    return {"type": "UPDATE", "timestamp": ts, "peer_asn": str(peer), "host": host, "path": path,
            "announcements": [{"prefixes": [prefix] if isinstance(prefix, str) else prefix}]}


def test_origin_extraction():
    assert extract_origins([1, 2, 3]) == [3]
    assert extract_origins([1, 2, [7, 8]]) == ['{7,8}']
    assert extract_origins([]) == []


def test_single_origin_no_event():
    c = MoasCatalog()
    assert c.process(upd(0, [1, 2], "10.0.0.0/8")) == []
    assert c.process(upd(1, [5, 2], "10.0.0.0/8", peer=5)) == []


def test_second_origin_opens_event_with_evidence():
    c = MoasCatalog()
    c.process(upd(0, [1, 2], "10.0.0.0/8", peer=1, host="rrc00"))
    ev, = c.process(upd(10, [5, 9], "10.0.0.0/8", peer=5, host="rrc03"))
    d = ev.to_dict()
    assert ev.kind == "new" and d["status"] == "open" and d["revision"] == 1
    assert [o["origin"] for o in d["origins"]] == ["2", "9"]          # ordered by first_seen
    assert d["origins"][1]["peers"] == ["5"] and d["origins"][1]["collectors"] == ["rrc03"]
    assert d["origins"][1]["paths"] == ["5 9"]
    assert "severity" not in d                                          # the catalog never judges


def test_every_instance_recorded_regardless_of_prefix():
    c = MoasCatalog()
    for pfx in ("10.0.0.0/8", "203.0.113.0/24", "1.1.1.0/24"):
        c.process(upd(0, [1, 2], pfx)); assert len(c.process(upd(1, [5, 9], pfx))) == 1
    assert c.stats["events_opened"] == 3


def test_no_duplicate_for_known_origin_but_evidence_accumulates():
    c = MoasCatalog()
    c.process(upd(0, [1, 2], "10.0.0.0/8"))
    ev, = c.process(upd(1, [5, 9], "10.0.0.0/8", peer=5))
    assert c.process(upd(2, [6, 9], "10.0.0.0/8", peer=6)) == []
    assert ev.origins["9"].peers == {"5", "6"} and ev.origins["9"].n_updates == 2 and ev.revision == 1


def test_third_origin_bumps_revision():
    c = MoasCatalog()
    c.process(upd(0, [1, 2], "10.0.0.0/8")); c.process(upd(1, [5, 9], "10.0.0.0/8"))
    ev, = c.process(upd(2, [7, 4], "10.0.0.0/8"))
    assert ev.kind == "origin_added" and ev.revision == 2 and set(ev.origins) == {"2", "9", "4"}
    assert len(c.open) == 1


def test_window_expiry_prevents_stale_conflict():
    c = MoasCatalog(window=100)
    c.process(upd(0, [1, 2], "10.0.0.0/8"))
    assert c.process(upd(500, [5, 9], "10.0.0.0/8")) == []


def test_sweep_closes_event_and_new_conflict_is_a_new_event():
    c = MoasCatalog(window=100)
    c.process(upd(0, [1, 2], "10.0.0.0/8")); ev, = c.process(upd(10, [5, 9], "10.0.0.0/8"))
    assert c.sweep(50) == []
    closed, = c.sweep(500)
    assert closed is ev and ev.status == "closed" and ev.kind == "closed" and ev.revision == 2 and not c.open
    c.process(upd(600, [1, 2], "10.0.0.0/8")); again, = c.process(upd(601, [5, 9], "10.0.0.0/8"))
    assert again is not ev and again.status == "open"


def test_one_origin_expiring_closes_event_but_two_remaining_keep_it_open():
    c = MoasCatalog(window=100)
    for t, path in ((0, [1, 2]), (1, [1, 9]), (2, [1, 4])):
        c.process(upd(t, path, "10.0.0.0/8"))
    c.process(upd(150, [1, 9], "10.0.0.0/8")); c.process(upd(151, [1, 4], "10.0.0.0/8"))  # 2 expired, 9 & 4 live
    assert c.sweep(160) == [] and len(c.open) == 1
    assert len(c.sweep(400)) == 1


def test_as_set_origin_is_one_key_and_no_self_conflict():
    c = MoasCatalog()
    assert c.process(upd(0, [1, 2, [65011, 65010]], "198.51.100.0/24")) == []
    assert c.process(upd(1, [3, 2, [65010, 65011]], "198.51.100.0/24")) == []
    ev, = c.process(upd(2, [3, 8], "198.51.100.0/24"))
    assert "{65010,65011}" in ev.origins


def test_non_update_and_empty_path_ignored():
    c = MoasCatalog()
    assert c.process({"type": "KEEPALIVE"}) == [] and c.process(upd(0, [], "10.0.0.0/8")) == []


def test_multiple_prefixes_in_one_message():
    c = MoasCatalog()
    c.process(upd(0, [1, 2], ["10.0.0.0/8", "11.0.0.0/8"]))
    evs = c.process(upd(1, [5, 9], ["10.0.0.0/8", "11.0.0.0/8"]))
    assert {e.prefix for e in evs} == {"10.0.0.0/8", "11.0.0.0/8"}


def test_persistence_roundtrip(tmp_path):
    db = str(tmp_path / "c.db")
    c = MoasCatalog(Store(db), window=100)
    c.process(upd(0, [1, 2], "10.0.0.0/8", peer=1, host="rrc00"))
    ev, = c.process(upd(5, [5, 9], "10.0.0.0/8", peer=5, host="rrc03"))
    c.process(upd(6, [6, 9], "10.0.0.0/8", peer=6, host="rrc04"))      # evidence only, saved by flush()
    c.flush()
    got, = read_events(c.store.con)
    assert got == ev.to_dict() and got["origins"][1]["peers"] == ["5", "6"] and got["origins"][1]["n_updates"] == 2
    c.sweep(1000)
    got, = read_events(c.store.con)
    assert got["status"] == "closed" and got["revision"] == 2


def test_reset_empties_catalog(tmp_path):
    c = MoasCatalog(Store(str(tmp_path / "c.db")))
    c.process(upd(0, [1, 2], "10.0.0.0/8")); c.process(upd(1, [5, 9], "10.0.0.0/8"))
    c.store.reset()
    assert read_events(c.store.con) == []


def test_lazy_close_is_reported_by_process():
    c = MoasCatalog(window=100)
    c.process(upd(0, [1, 2], "10.0.0.0/8")); ev, = c.process(upd(10, [5, 9], "10.0.0.0/8"))
    out = c.process(upd(500, [1, 2], "10.0.0.0/8"))        # origin 9 aged out as a side effect of this announcement
    assert out == [ev] and ev.kind == "closed" and ev.status == "closed"
    assert c.sweep(501) == []                                # not reported twice
