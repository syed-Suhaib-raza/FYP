"""Tests for the AS-path test harness (make_eval_set.py, eval.py, live_eval.py, cluster_events.py, build_results.py).
   python -m pytest -q test_eval.py          # or, without pytest:   python test_eval.py
No internet needed: the live loop is exercised through a fake `websockets` module and a dry run from a file.
The label oracle below is deliberately separate code from detector.py, so the 250 labels are not checked by the detector itself.
"""
import asyncio, csv, json, os, subprocess, sys, tempfile, time, types
from collections import Counter

import cluster_events, eval as ev, live_eval, make_eval_set
from aspath import ASRel

HERE = os.path.dirname(os.path.abspath(__file__))
CASES, RELS = make_eval_set.build(42)


def tmp():
    return tempfile.mkdtemp(prefix="aspath_test_")


# ------------------------------------------------------------------------ independent oracle
def parse_rels(rels):
    prov, peer = set(), set()
    for r in rels:
        a, b, k = r.split("|")
        if k == "-1":
            prov.add((int(a), int(b)))                       # a is provider of b
        else:
            peer.add(frozenset((int(a), int(b))))
    return prov, peer


def flatten(path):
    out = []
    for h in path:
        if not out or out[-1] != h:
            out.append(h)
    return out


def oracle_leak(path, rels):
    """True if the (flattened) path breaks valley-free routing under the given relationships. Own implementation, written separately from detector.valley."""
    prov, peer = parse_rels(rels)
    rev = list(reversed(path))                               # the route travelled origin -> collector
    state = "up"
    for x, y in zip(rev, rev[1:]):
        if (y, x) in prov:
            step = "up"                                      # y is the provider of x
        elif (x, y) in prov:
            step = "down"
        elif frozenset((x, y)) in peer:
            step = "peer"
        else:
            continue                                         # unknown relationship: skipped
        if state == "up":
            state = step
        elif step != "down":
            return True
        else:
            state = "down"
    return False


def learn_edges(c):
    es = set()
    for u in c["updates"][:3]:
        p = flatten(u["data"]["path"])
        es |= {frozenset(e) for e in zip(p, p[1:])}
    return es


def test_oracle_itself():
    rels = ["10|1|-1", "20|10|-1", "20|30|0", "30|40|-1", "30|50|0", "60|10|-1"]
    assert oracle_leak([40, 30, 20, 10, 1], rels) is False           # up, up, peer, down
    assert oracle_leak([50, 30, 20, 10, 1], rels) is True            # ... peer, peer
    assert oracle_leak([60, 10, 20, 30], rels) is True               # origin 30: peer, down, then up again
    assert oracle_leak([99, 20, 10, 1], rels) is False               # unknown relationship is skipped


# ------------------------------------------------------------------------ the 250-case set
def test_set_shape():
    assert len(CASES) == 250
    assert Counter(c["label"] for c in CASES) == {"path hijack": 70, "route leak": 80, "normal": 100}
    assert Counter(c["kind"] for c in CASES) == dict(make_eval_set.PLAN)
    assert len({c["id"] for c in CASES}) == 250 and len({c["prefix"] for c in CASES}) == 250


def test_set_is_reproducible_and_seeds_differ():
    assert make_eval_set.build(42) == (CASES, RELS) and make_eval_set.build(43)[0] != CASES
    assert Counter(c["kind"] for c in make_eval_set.build(43)[0]) == Counter(c["kind"] for c in CASES)


def test_case_layout():
    for c in CASES:
        ups = c["updates"]
        assert len(ups) == 5 and ups[-1]["data"]["timestamp"] == 65 > c["learn"]
        assert all(u["data"]["timestamp"] < c["learn"] for u in ups[:4])
        assert ups[-1]["data"]["announcements"][0]["prefixes"] == [c["prefix"]]
        assert ups[3]["data"]["announcements"][0]["prefixes"] != [c["prefix"]]          # unwatched background route


def test_every_label_agrees_with_the_independent_oracle():
    for c in CASES:
        test = flatten(c["updates"][-1]["data"]["path"]); k = c["kind"]
        new_edge = any(frozenset(e) not in learn_edges(c) for e in zip(test, test[1:]))
        leak = oracle_leak(test, RELS)
        if k in ("new_origin_upstream", "new_as_link"):
            assert test[-1] == c["origin"] and new_edge and not leak, c["id"]
            if k == "new_origin_upstream":
                assert frozenset((test[-2], test[-1])) not in learn_edges(c), c["id"]
        elif k in make_eval_set.LEAK_RELATION:
            assert test[-1] == c["origin"] and leak, c["id"]
        elif k == "leak_unknown_rel":
            assert not leak and new_edge and len(test) == 4, c["id"]                     # by design: invisible to the valley rule
        elif k == "normal_new_peer":
            assert test[-1] == c["origin"] and new_edge and not leak, c["id"]            # by design: looks like a hijack link
        elif k == "normal_foreign_origin":
            assert test[-1] != c["origin"], c["id"]
        else:                                                                            # repeat / prepend / alt_path
            assert test[-1] == c["origin"] and not new_edge and not leak, c["id"]


def test_leak_kinds_match_their_relations():
    prov, peer = parse_rels(RELS)
    for c in CASES:
        if c["kind"] in make_eval_set.LEAK_RELATION:
            exp, atk, u1, _ = c["updates"][-1]["data"]["path"]
            learned, exported = make_eval_set.LEAK_RELATION[c["kind"]]
            assert ((u1, atk) in prov) == (learned == "provider") and (frozenset((u1, atk)) in peer) == (learned == "peer"), c["id"]
            assert ((exp, atk) in prov) == (exported == "provider") and (frozenset((exp, atk)) in peer) == (exported == "peer"), c["id"]


# ------------------------------------------------------------------------ TEST 1 evaluator
def run_eval(**kw):
    d = tmp(); rel = os.path.join(d, "rel.txt"); make_eval_set.write(CASES, RELS, os.path.join(d, "c.jsonl"), rel)
    kw = dict(min_support=1, len_delta=3, origin_policy="authorized", **kw)
    return ev.evaluate(CASES, ASRel(rel), None, kw["min_support"], kw["len_delta"], kw["origin_policy"], kw.get("enabled")), rel


def test_metrics_arithmetic():
    rows = [dict(truth=True, pred=True)] * 3 + [dict(truth=True, pred=False)] + [dict(truth=False, pred=True)] * 2 + [dict(truth=False, pred=False)] * 4
    m = ev.metrics(rows)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (3, 2, 1, 4)
    assert m["accuracy"] == 0.7 and m["precision"] == 0.6 and m["recall"] == 0.75 and m["fpr"] == 0.333 and m["f1"] == 0.667


def test_detector_result_on_the_250_cases():
    (rows, _, false_learn), _ = run_eval()
    assert false_learn == 0                                                  # NFR3: no alert from a learning message
    wrong = Counter(r["kind"] for r in rows if r["pred"] != r["truth"])
    assert wrong == {"normal_new_peer": 25}                                  # the ONLY errors are the deliberate hard false alarms
    bad_type = Counter(r["kind"] for r in rows if r["truth"] and r["pred"] and not r["type_ok"])
    assert bad_type == {"leak_unknown_rel": 12}                              # leaks without relationships are caught via new links, but typed as hijack
    m = ev.metrics(rows)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (150, 25, 0, 75)
    assert ev.metrics(rows, "pred_b1")["fp"] > m["fp"]                       # the naive any-new-edge baseline is worse
    assert all(r["rule"] == "valley_violation" for r in rows if r["kind"] in make_eval_set.LEAK_RELATION)


def test_ablation_valley_only_catches_exactly_the_known_leaks():
    (rows, _, _), _ = run_eval(enabled=("valley_violation",))
    assert sum(r["pred"] for r in rows) == 68 and not any(r["pred"] for r in rows if r["label"] != "route leak")
    assert not any(r["pred"] for r in rows if r["kind"] == "leak_unknown_rel")


def test_sweep_direction():
    d = tmp(); rel = os.path.join(d, "rel.txt"); make_eval_set.write(CASES, RELS, os.path.join(d, "c.jsonl"), rel)
    fp = lambda ms, pol: ev.metrics(ev.evaluate(CASES, ASRel(rel), None, ms, 3, pol)[0])["fp"]
    assert fp(2, "authorized") > fp(1, "authorized")                         # the alternate path's links are seen once -> flagged at min-support 2
    assert fp(1, "any") > fp(1, "authorized")                                # foreign-origin cases run the path rules too


def test_eval_cli_writes_all_outputs():
    d = tmp(); cases, rel = os.path.join(d, "c.jsonl"), os.path.join(d, "r.txt")
    make_eval_set.write(CASES, RELS, cases, rel)
    out = os.path.join(d, "res")
    r = subprocess.run([sys.executable, "eval.py", cases, "--as-rel", rel, "--out", out, "--sweep", "--llm", "mock"], cwd=HERE, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    md = open(out + ".md", encoding="utf-8").read()
    assert "SIMULATED test (250 cases)" in md and "Sensitivity" in md and "Rule ablation" in md and "(should be 0, NFR3): 0" in md
    js = json.load(open(out + ".json", encoding="utf-8"))
    assert js["overall"]["n"] == 250 and len(js["rows"]) == 250 and js["sweep"]
    assert len(list(csv.DictReader(open(out + ".csv", encoding="utf-8")))) == 250


# ------------------------------------------------------------------------ TEST 2 helpers
def parse(argv):
    import argparse
    from aspath import common
    c = common(); ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("record", parents=[c])
    r.add_argument("--minutes", type=float, default=60); r.add_argument("--host"); r.add_argument("--prefix", action="append"); r.add_argument("--from-file")
    r.add_argument("--capture", default="live_capture.jsonl"); r.add_argument("--alerts", default="live_alerts.jsonl"); r.add_argument("--out", default="live_report")
    return live_eval.resolve(ap.parse_args(argv), argv)


def test_run_a_command_maps_to_whole_collector():
    a = parse("record --minutes 45 --host rrc00 --capture full_capture.jsonl --alerts full_alerts.jsonl --out full_report".split())
    assert a.scope == "all" and a.collector == "rrc00"


def test_run_b_command_maps_to_prefix_scope_with_fresh_learnt_baseline():
    a = parse("record --minutes 45 --host rrc00 --prefix 193.0.0.0/8 --prefix 194.0.0.0/8 --prefix 195.0.0.0/8 --capture pfx_capture.jsonl --alerts pfx_alerts.jsonl --out pfx_report".split())
    assert a.scope == "watch" and a.collector == "rrc00" and a.prefix == ["193.0.0.0/8", "194.0.0.0/8", "195.0.0.0/8"]
    assert a.baseline_source == "learn" and a.baseline == "pfx_report_baseline.json" and a.auto_baseline       # never touches baseline.json


def test_explicit_flags_win():
    a = parse("record --host rrc00 --scope watch --out x".split())
    assert a.scope == "watch"
    a = parse("record --host rrc00 --prefix 1.0.0.0/8 --baseline-source history --baseline my.json --out x".split())
    assert a.baseline_source == "history" and a.baseline == "my.json" and not a.auto_baseline
    assert parse("record --from-file f.jsonl --host rrc00 --out x".split()).scope == "watch"                    # dry run never goes to scope all


def test_subscriptions_carry_the_host():
    a = parse("record --host rrc00 --prefix 193.0.0.0/8 --out x".split())
    subs = live_eval.build_subs(a, {"193.0.0.0/8": []}, [])
    assert subs and all(s["host"] == "rrc00" and s["prefix"] == "193.0.0.0/8" and s["moreSpecific"] for s in subs)
    a = parse("record --host rrc00 --out x".split())
    assert live_eval.build_subs(a, {}, []) == [{"type": "UPDATE", "socketOptions": {"includeRaw": False}, "host": "rrc00"}]


def test_any_origin_accepts_everything():
    s = live_eval.AnyOrigin()
    assert 1 in s and 4200000000 in s and not s                                # falsy, so the candidate falls back to the path's own origin


def test_scope_all_uses_the_real_relationship_file():
    called = []
    real = live_eval.use_real_asrel
    live_eval.use_real_asrel = lambda a: called.append(a.scope) or a
    try:
        a = parse("record --host rrc00 --out x".split())
        live_eval.setup_monitor(a)
    finally:
        live_eval.use_real_asrel = real
    assert called == ["all"]                                                    # the old script skipped this, which silenced the valley rule in Run A


# ------------------------------------------------------------------------ live loop through a fake websocket
def fake_websockets(messages, sent):
    mod = types.ModuleType("websockets")

    class WS:
        def __init__(self): self.q = list(messages)
        async def send(self, s): sent.append(json.loads(s))
        async def recv(self):
            await asyncio.sleep(0.01)
            return json.dumps(self.q.pop(0)) if self.q else json.dumps({"type": "pong"})
    class CM:
        async def __aenter__(self): return WS()
        async def __aexit__(self, *a): return False
    mod.connect = lambda url, **kw: CM()
    return mod


def ris(case_idx_kind, host="rrc00"):
    c = next(c for c in CASES if c["kind"] == case_idx_kind)
    d = dict(c["updates"][-1]["data"]); d["host"] = host
    return c, d


def run_live(argv, messages):
    sent = []
    sys.modules["websockets"] = fake_websockets(messages, sent)
    try:
        live_eval.main(argv)
    finally:
        del sys.modules["websockets"]
    return sent


def test_live_run_a_whole_collector_raises_leak_alerts_and_writes_everything():
    d = tmp(); rel = os.path.join(d, "rel.txt"); make_eval_set.write(CASES, RELS, os.path.join(d, "c.jsonl"), rel)
    msgs = []
    for k in ("transit-to-transit", "peer-to-peer"):
        _, m = ris(k); m = dict(m, timestamp=time.time() - 0.3); msgs.append({"type": "ris_message", "data": m})
    _, ok = ris("normal_repeat"); msgs.append({"type": "ris_message", "data": dict(ok, timestamp=time.time() - 0.3)})
    out = os.path.join(d, "full_report")
    sent = run_live(["record", "--llm", "none", "--minutes", "0.03", "--host", "rrc00", "--as-rel", rel, "--capture", os.path.join(d, "cap.jsonl"),
                     "--alerts", os.path.join(d, "al.jsonl"), "--out", out], msgs)
    assert sent == [{"type": "ris_subscribe", "data": {"type": "UPDATE", "socketOptions": {"includeRaw": False}, "host": "rrc00"}}]
    al = [json.loads(l) for l in open(os.path.join(d, "al.jsonl"))]
    assert [a["subtype"] for a in al] == ["valley_violation"] * 2 and all(0.2 < a["feed_delay_s"] < 5 and a["compute_ms"] >= 0 for a in al)
    assert os.path.exists(out + ".md") and os.path.exists(out + ".json") and os.path.exists(out + "_alerts.csv") and os.path.exists(out + "_runstats.json")
    md = open(out + ".md", encoding="utf-8").read()
    assert "3 messages" in md and "2 logged live" in md and "valley_violation" in md
    assert json.load(open(out + "_runstats.json"))["compute_ms_all_messages"]["n"] == 3
    assert not os.path.exists(os.path.join(d, "baseline.json"))


def test_live_run_b_prefix_scope_learns_then_detects():
    d = tmp(); rel = os.path.join(d, "rel.txt"); make_eval_set.write(CASES, RELS, os.path.join(d, "c.jsonl"), rel)
    c, _ = ris("new_origin_upstream"); base = c["updates"][0]["data"]; test = c["updates"][-1]["data"]
    now = time.time()
    msgs = [{"type": "ris_message", "data": dict(base, timestamp=now - 5)}, {"type": "ris_message", "data": dict(base, timestamp=now - 4)},
            {"type": "ris_message", "data": dict(test, timestamp=now - 0.2)}]
    out = os.path.join(d, "pfx_report")
    sent = run_live(["record", "--llm", "none", "--minutes", "0.03", "--host", "rrc00", "--prefix", "10.0.0.0/8", "--as-rel", rel, "--learn", "2",
                     "--capture", os.path.join(d, "cap.jsonl"), "--alerts", os.path.join(d, "al.jsonl"), "--out", out], msgs)
    assert sent and sent[0]["data"]["prefix"] == "10.0.0.0/8" and sent[0]["data"]["host"] == "rrc00"
    al = [json.loads(l) for l in open(os.path.join(d, "al.jsonl"))]
    assert len(al) == 1 and al[0]["subtype"] == "new_origin_upstream" and al[0]["anomaly_type"] == "path_hijack"
    assert os.path.exists(out + "_baseline.json")                                # saved per run, baseline.json untouched


def test_dry_run_from_file_needs_no_internet():
    d = tmp(); out = os.path.join(d, "dry")
    r = subprocess.run([sys.executable, "live_eval.py", "record", "--llm", "none", "--from-file", "sample_updates.jsonl", "--prefix", "72.255.0.0/18", "--prefix", "8.8.8.0/24",
                        "--learn", "100", "--capture", out + "_c.jsonl", "--alerts", out + "_a.jsonl", "--out", out], cwd=HERE, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert len(open(out + "_a.jsonl").read().splitlines()) > 0 and os.path.exists(out + "_alerts.csv")


def test_missing_scope_is_refused():
    r = subprocess.run([sys.executable, "live_eval.py", "record", "--llm", "none", "--whitelist", "does_not_exist.json", "--asns", "none.json", "--out", "x"], cwd=HERE, capture_output=True, text=True)
    assert r.returncode != 0 and "nothing to watch" in (r.stderr + r.stdout)


def alert(prefix="10.0.0.0/24", ts=1000.0, collector="rrc00", typ="route_leak", sub="valley_violation", signals="valley_violation: AS1 learned ... (peer-to-peer)", fd=0.5):
    return dict(prefix=prefix, watched=prefix, peer_asn="1", collector=collector, anomaly_type=typ, subtype=sub, severity="medium", as_path="1 2 3", origin="3",
                expected_origin="AS3", signals=signals, llm_label=None, llm_agrees="no model", model=None, msg_ts=ts, recv_wall=ts + fd, alert_wall=ts + fd,
                feed_delay_s=fd, compute_ms=0.1)


def capture(path, n=30, header=None):
    with open(path, "w") as f:
        f.write(json.dumps({"header": header or {}}) + "\n")
        for i in range(n):
            f.write(json.dumps({"recv": 1000 + i + 0.5, "data": {"timestamp": 1000 + i, "type": "UPDATE", "host": "rrc00", "announcements": [{"prefixes": ["10.0.0.0/24"]}]}}) + "\n")


def test_analyze_streams_and_reads_manual_verdicts():
    d = tmp(); cap, al, out = os.path.join(d, "c.jsonl"), os.path.join(d, "a.jsonl"), os.path.join(d, "rep")
    capture(cap, 30)
    with open(al, "w") as f:
        for i in range(4):
            f.write(json.dumps(alert(prefix=f"10.0.{i}.0/24", ts=1000 + i)) + "\n")
    live_eval.analyze(cap, al, out)
    rows = list(csv.DictReader(open(out + "_alerts.csv", encoding="utf-8")))
    assert len(rows) == 4 and set(r["verdict"] for r in rows) == {""}
    for r, v in zip(rows, ("TRUE", "TRUE", "FALSE", "")):
        r["verdict"] = v
    with open(out + "_alerts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    live_eval.analyze(cap, al, out, out + "_alerts.csv")
    js = json.load(open(out + ".json"))
    assert js["manual"] == dict(unit="alerts", labelled=3, total=4, true=2, precision=0.667) and js["messages"] == 30
    assert "peer-to-peer" in open(out + ".md", encoding="utf-8").read()


def test_analyze_accepts_events_csv_as_labels():
    d = tmp(); cap, al, out = os.path.join(d, "c.jsonl"), os.path.join(d, "a.jsonl"), os.path.join(d, "rep"); ev_csv = os.path.join(d, "e.csv")
    capture(cap, 30)
    open(al, "w").write(json.dumps(alert()) + "\n")
    cluster_events.main([al, ev_csv])
    rows = list(csv.DictReader(open(ev_csv, encoding="utf-8"))); rows[0]["verdict"] = "TRUE"
    with open(ev_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    live_eval.analyze(cap, al, out, ev_csv)
    assert json.load(open(out + ".json"))["manual"]["unit"] == "events"


def test_analyze_with_no_alerts():
    d = tmp(); cap, out = os.path.join(d, "c.jsonl"), os.path.join(d, "rep")
    capture(cap, 25)
    live_eval.analyze(cap, os.path.join(d, "none.jsonl"), out)
    assert "No alert fired" in open(out + ".md", encoding="utf-8").read() and not os.path.exists(out + "_alerts.csv")


# ------------------------------------------------------------------------ clustering
def test_clustering_gap_and_causes():
    rows = [alert(ts=1000), alert(ts=1100), alert(ts=1500), alert(prefix="10.9.9.0/24", ts=1000),
            alert(ts=1000, collector="rrc01"), alert(prefix="10.0.1.0/24", ts=1000, signals="valley_violation: AS1 learned ... (peer-to-peer)")]
    events, by_key = cluster_events.cluster(rows, 300)
    assert sorted(len(e) for e in events) == [1, 1, 1, 1, 2]                          # 1000+1100 merge (100 s); 1500 is 400 s later -> new event
    assert len(cluster_events.cluster(rows, 500)[0]) == 4                             # a wider gap merges all three
    assert len(cluster_events.cluster(rows, 50)[0]) == 6
    assert len({cluster_events.cause_key(r) for r in rows}) == 1                       # same leaker, prefixes ignored


def test_cluster_cli_and_empty_input():
    d = tmp(); al, out = os.path.join(d, "a.jsonl"), os.path.join(d, "e.csv")
    open(al, "w").write(json.dumps(alert()) + "\n" + json.dumps(alert(ts=5000, typ="path_hijack", sub="new_as_link", signals="new_as_link: AS1-AS2 never observed in the baseline")) + "\n")
    cluster_events.main([al, out])
    rows = list(csv.DictReader(open(out, encoding="utf-8")))
    assert len(rows) == 2 and rows[0]["types_in_event"] == "route_leak" and rows[0]["verdict"] == ""
    open(al, "w").write("")
    cluster_events.main([al, out])
    assert list(csv.DictReader(open(out, encoding="utf-8"))) == []


# ------------------------------------------------------------------------ workbook
def test_build_results_workbook():
    import build_results
    from openpyxl import load_workbook
    d = tmp(); sim = os.path.join(d, "sim")
    (rows, _, fl), _ = run_eval()
    with open(sim + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["id", "kind", "label", "truth_anomalous", "predicted_anomalous", "rule_type", "type_correct", "llm_label", "compute_ms"])
        for r in rows:
            w.writerow([r["id"], r["kind"], r["label"], r["truth"], r["pred"], r["rtype"], r["type_ok"], r["llm_label"], round(r["compute_ms"], 4)])
    json.dump(dict(overall=ev.metrics(rows)), open(sim + ".json", "w"))
    cases = os.path.join(d, "c.jsonl"); open(cases, "w").write("x\n")
    al = os.path.join(d, "a.jsonl"); open(al, "w").write(json.dumps(alert()) + "\n")
    evp = os.path.join(d, "e.csv"); cluster_events.main([al, evp])
    xlsx = os.path.join(d, "r.xlsx")
    sys.argv = ["build_results.py", "--cases", cases, "--sim", sim, "--run", f"Run A=nothing,{al},{evp}", "--out", xlsx]
    build_results.main()
    wb = load_workbook(xlsx)
    assert wb.sheetnames == ["README", "Sim_Metrics", "Sim_PerKind", "LLM", "Live_A", "Sim_Cases"]
    assert wb["Sim_Cases"].max_row == 251 and wb["Live_A"]["B10"].value == 1


if __name__ == "__main__":                                                          # run without pytest
    fails = 0
    for name, fn in sorted((n, f) for n, f in globals().items() if n.startswith("test_") and callable(f)):
        try:
            fn(); print("PASS", name)
        except Exception as e:
            fails += 1; print("FAIL", name, "->", type(e).__name__, e)
    print(f"\n{'ALL PASSED' if not fails else str(fails) + ' FAILED'}")
    sys.exit(1 if fails else 0)
