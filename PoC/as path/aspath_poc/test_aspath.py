import json, os, sqlite3, subprocess, sys
import pytest
from asrel import ASRel
from detector import RULES, Baseline, PathCandidates, edge, flat, valley
from pipeline import Store, agreement, classify, evidence_lines, severity
from prompt import build_messages, flagged, parse_label
import aspath
from aspath import Monitor, load_watch

HERE = os.path.dirname(os.path.abspath(__file__))
REL = ASRel(os.path.join(HERE, "demo_as_rel.txt"))
WL = {"72.255.0.0/18": [9541], "8.8.8.0/24": [15169], "2001:db8:100::/40": [9541]}
P = "72.255.0.0/18"


def upd(path, prefix=P, ts=1760001000, peer=None, wd=None, host="rrc00"):
    d = dict(timestamp=ts, peer="192.0.2.1", peer_asn=str(peer or (path[0] if path else 1)), host=host, type="UPDATE", path=path, origin="igp",
             announcements=[dict(prefixes=[prefix])] if prefix else [])
    if wd: d["withdrawals"] = wd
    return d


def learned(paths=None, key=P, n=3):
    b = Baseline()
    for path in paths or [[1299, 3356, 17557, 9541], [3356, 17557, 9541], [6762, 17557, 9541]]:
        for _ in range(n): b.learn(key, path)
    return b


def det(base=None, **kw):
    return PathCandidates(WL, REL, base or learned(), **kw)


class Fake:
    name = "FAKE"
    def __init__(self, out='{"label": "anomalous", "anomaly_type": "path_hijack"}'): self.out, self.calls, self.last = out, 0, None
    def generate(self, messages, max_new_tokens=64): self.calls += 1; self.last = messages; return self.out


# ------------------------------------------------------------ the model is called like in the unexpectedOrigin PoC
FYP_USER = ("Please analyze the BGP routing update information following <BGP Update:> to determine whether the update is normal. If any anomalies are detected, "
            "please clearly identify the type of anomaly including prefix hijack, path hijack, or route leak. If you do not determine any anomaly type, anomaly_type is filled in as none.")
CAND = dict(ts=1760001100.0, prefix=P, path=[1299, 64510, 9541], origin=9541, peer_asn="1299", peer_ip="192.0.2.49", next_hop="", origin_attr="igp", med=None, community=None)


def test_prompt_identical_to_unexpected_origin_poc():
    ev = [f"{P} is originated by AS9541 (the expected origin configured by the network operator).", f"AS9541 is an authorized origin for {P}.",
          "No known relationship between AS1299 and AS64510."]
    m = build_messages(CAND, ev)      # strings below were produced by unexpectedOrigin_poc/prompt.py build_messages(render_update(cand), ev)
    assert m[0] == {"role": "system", "content": "You are an Internet expert, good at judging the routing anomaly."}
    assert m[1]["content"] == (FYP_USER + "\n\n<BGP Update:> TIME: 1760001100, TYPE: A, FROM: 192.0.2.49 AS1299, PREFIX: 72.255.0.0/18, ASPATH: 1299 64510 9541, ORIGIN: IGP"
                               "\n\nRetrieved AS relationship knowledge:\n1. 72.255.0.0/18 is originated by AS9541 (the expected origin configured by the network operator)."
                               "\n2. AS9541 is an authorized origin for 72.255.0.0/18.\n3. No known relationship between AS1299 and AS64510.")
    assert build_messages(CAND, [])[1]["content"].endswith("\n\nNo relevant AS relationship knowledge was retrieved.")


@pytest.mark.parametrize("raw,want", [('{"label": "anomalous", "anomaly_type": "route_leak"}', "route leak"), ('{"label": "normal", "anomaly_type": "none"}', "none"),
                                      ("Prefix hijack", "prefix hijack"), ("path_hijack", "path hijack"), ("none", "none"), ("normal", "none"),
                                      ('{"is_anomaly": false}', "none"), ("blah", "unparsed"), ("anomalous", "unknown")])
def test_parse_label(raw, want):
    assert parse_label(raw) == want


def test_other_prompt_styles_build():
    f = dict(watched=P, expected=[9541], origin=9541, links=[(1299, 64510, 0), (64510, 9541, 2)], rels=[(17557, 9541, -1)])
    p = build_messages(CAND, None, "paper", f)[1]["content"]
    assert "<EVIDENCE>" in p and "AS1299-AS64510 never observed before event time." in p and "AS64510-AS9541 observed before." in p
    assert "exactly one of the following" in build_messages(CAND, [], "infer", f)[1]["content"]


# ------------------------------------------------------------ rule: valley_violation (route leak, FR6 kinds)
@pytest.mark.parametrize("path,kind,leaker,src,dst", [
    ([1299, 64500, 3356, 17557, 9541], "transit-to-transit", 64500, 3356, 1299),
    ([6939, 64501, 3356, 17557, 9541], "transit-to-peer", 64501, 3356, 6939),
    ([1299, 64504, 17557, 9541], "peer-to-transit", 64504, 17557, 1299),
    ([2914, 64502, 17557, 9541], "peer-to-peer", 64502, 17557, 2914)])
def test_valley_kinds(path, kind, leaker, src, dst):
    v = valley(path, REL)
    assert (v["kind"], v["leaker"], v["learned_from"], v["exported_to"]) == (kind, leaker, src, dst)


def test_valley_free_paths_are_clean_and_unknown_links_skipped():
    for p in ([1299, 3356, 17557, 9541], [2914, 3356, 17557, 9541], [6762, 17557, 9541], [3356, 9541]):
        assert valley(p, REL) is None
    assert valley([1299, 64999, 9541], REL) is None          # no relationship data -> no verdict (paper: incomplete data is what the model is for)


# ------------------------------------------------------------ rules: link rules, precedence, guards
def test_normal_path_is_clean():
    assert det().candidates(upd([1299, 3356, 17557, 9541])) == []


def test_forged_origin_link_is_path_hijack_with_both_link_rules():
    c, = det().candidates(upd([1299, 64510, 9541]))
    assert (c["subtype"], c["anomaly_type"]) == ("new_origin_upstream", "path_hijack")
    assert {h["rule"] for h in c["hits"]} == {"new_as_link", "new_origin_upstream"} and c["origin"] == 9541 and c["expected"] == [9541]


def test_midpath_new_link_is_path_hijack():
    c, = det().candidates(upd([1299, 64511, 3356, 17557, 9541]))
    assert c["subtype"] == "new_as_link" and c["anomaly_type"] == "path_hijack"


def test_leak_is_route_leak_even_with_new_links():
    c, = det().candidates(upd([1299, 64500, 3356, 17557, 9541]))
    assert (c["subtype"], c["anomaly_type"], c["leak"]["kind"]) == ("valley_violation", "route_leak", "transit-to-transit")


def test_links_are_undirected_and_prepending_removed():
    assert edge(1, 2) == edge(2, 1) and flat([1299, 3356, 3356, 3356, 17557, [1, 2], 9541]) == [1299, 3356, 17557, 9541]
    assert det().candidates(upd([1299, 3356, 3356, 17557, 17557, 9541])) == []


def test_min_support_rarely_observed():
    b = learned([[3356, 17557, 9541]], n=3); b.learn(P, [1299, 3356, 17557, 9541])          # 1299-3356 seen once
    assert det(b).candidates(upd([1299, 3356, 17557, 9541])) == []
    c, = det(b, min_support=2).candidates(upd([1299, 3356, 17557, 9541]))
    assert "rarely observed" in c["hits"][0]["detail"]


def test_foreign_origin_is_deferred_to_origin_poc():
    d = det()
    assert d.candidates(upd([1299, 65000], "72.255.4.0/24")) == [] and d.counts["deferred_origin"] == 1
    c, = det(origin_policy="any").candidates(upd([1299, 64510, 65000], "72.255.4.0/24"))
    assert c["origin"] == 65000


def test_more_specific_with_authorised_origin_is_checked():
    c, = det().candidates(upd([1299, 64510, 9541], "72.255.4.0/24"))
    assert c["prefix"] == "72.255.4.0/24" and c["watched"] == P


def test_no_baseline_no_link_alert_but_leak_still_found():
    d = det(Baseline())
    assert d.candidates(upd([1299, 64510, 9541])) == [] and d.counts["no_baseline"] == 1
    assert d.candidates(upd([1299, 64500, 3356, 17557, 9541]))[0]["subtype"] == "valley_violation"


def test_path_length_is_supporting_only():
    long_ok = [1299, 3356, 17557, 9541]                                  # 4 hops vs baseline median 3, but every link is known
    assert det(len_delta=1).candidates(upd(long_ok)) == []              # a length change alone never makes a candidate
    c, = det(len_delta=2).candidates(upd([1299, 64511, 64512, 64513, 3356, 17557, 9541]))
    assert any(h["rule"] == "path_length_deviation" for h in c["hits"]) and c["subtype"] == "new_as_link"


def test_as_set_origin_skipped_and_ipv6_and_asn_watch():
    assert det().candidates(upd([1299, [9541, 17557]])) == []
    b = learned([[3356, 17557, 9541]], key="2001:db8:100::/40"); d = PathCandidates(WL, REL, b)
    assert d.candidates(upd([1299, 64510, 9541], "2001:db8:100:1::/48"))[0]["watched"] == "2001:db8:100::/40"
    b2 = learned([[2914, 3356, 15169]], key="AS15169"); d2 = PathCandidates({}, REL, b2, asns=[15169])
    c, = d2.candidates(upd([2914, 64511, 15169], "142.250.0.0/15"))
    assert c["key"] == "AS15169" and c["watched"] == "142.250.0.0/15"


def test_ablation_switches():
    only = PathCandidates(WL, REL, learned(), enabled=("valley_violation",))
    assert only.candidates(upd([1299, 64510, 9541])) == [] and only.candidates(upd([1299, 64500, 3356, 17557, 9541]))


def test_baseline_save_load(tmp_path):
    b = learned(); b.save(tmp_path / "b.json"); b2 = Baseline()
    assert b2.load(tmp_path / "b.json") and b2.support(3356, 1299) == 3 and b2.typical_path(P) and b2.upstreams[P][17557] == 9


# ------------------------------------------------------------ pipeline: same verdict rules as unexpectedOrigin
def test_severity_agreement_and_type():
    assert severity("path hijack") == severity("route leak") == "high"
    assert all(severity(x) == "medium" for x in ("none", "unparsed", "unknown")) and severity(None, False) == "medium"
    assert agreement("route leak", "route_leak") == "yes" and agreement("none", "route_leak") == "model: none"
    assert agreement("prefix hijack", "path_hijack").startswith("type differs") and agreement(None, "x") == "no model"
    assert flagged("route leak") and not flagged("none") and not flagged(None)


def test_evidence_and_classify():
    d = det(); c, = d.candidates(upd([1299, 64510, 9541]))
    ev = evidence_lines(c, REL, d.base)
    assert ev[0].startswith(f"{P} is originated by AS9541") and ev[1] == f"AS9541 is an authorized origin for {P}."
    assert any("AS64510-AS9541 was never observed before event time." in e for e in ev) and any("No known relationship between AS1299 and AS64510" in e for e in ev)
    assert not any("never observed" in e for e in evidence_lines(c, REL, d.base, history=False))
    f = Fake(); r = classify(c, REL, f, d.base)
    assert r["label"] == "path hijack" and r["severity"] == "high" and r["agrees"] == "yes" and "Retrieved AS relationship knowledge" in f.last[1]["content"]
    assert classify(c, REL, Fake('{"label": "normal", "anomaly_type": "none"}'), d.base)["severity"] == "medium"


def test_model_failure_does_not_stop_monitor():
    class Boom:
        name = "boom"
        def generate(self, *a, **k): raise RuntimeError("oom")
    d = det(); c, = d.candidates(upd([1299, 64510, 9541])); r = classify(c, REL, Boom(), d.base)
    assert r["raw_output"].startswith("ERROR: RuntimeError") and r["label"] == "unparsed" and r["severity"] == "medium"


# ------------------------------------------------------------ monitor: learning, correlation, recovery, cooldown
def run(path):
    mon = Monitor(None, WL, REL, Fake(), learn=600)
    for line in open(os.path.join(HERE, path)):
        mon.process(json.loads(line)["data"])
    return mon


def test_demo_file_end_to_end():
    mon = Monitor(None, WL, REL, None, learn=600); seen = []
    for line in open(os.path.join(HERE, "sample_updates.jsonl")):
        seen += [(i["anomaly_type"], i["subtype"], i["count"]) for i in mon.process(json.loads(line)["data"])]
    assert mon.stats["candidates"] == 9 and mon.stats["deferred_origin"] == 1 and mon.stats["learned"] == 24
    assert [s[0] for s in seen if s[2] == 1].count("route_leak") == 5 and [s[0] for s in seen if s[2] == 1].count("path_hijack") == 3   # 5 leak incidents, 3 hijack/benign incidents
    assert len(mon.drain_recovered()) == 5


def test_correlation_one_incident_for_one_cause_and_no_second_model_call():
    llm = Fake(); mon = Monitor(None, WL, REL, llm, learn=0, base=learned())
    a = mon.process(upd([1299, 64510, 9541], ts=1760001000, peer=1299))[0]
    b = mon.process(upd([2914, 3356, 64510, 9541], ts=1760001010, peer=2914))[0]
    assert a is b and b["count"] == 2 and b["peers_seen"] == 2 and llm.calls == 1


def test_recovery_on_clean_announce_and_on_withdrawal():
    mon = Monitor(None, WL, REL, None, learn=0, base=learned())
    mon.process(upd([1299, 64510, 9541], ts=1, peer=1299)); mon.process(upd([6762, 64510, 9541], ts=2, peer=6762))
    mon.process(upd([1299, 3356, 17557, 9541], ts=50, peer=1299)); assert not mon.drain_recovered()      # one peer still shows it
    mon.process(upd(None, prefix=None, ts=90, peer=6762, wd=[P]))
    r, = mon.drain_recovered(); assert r["status"] == "recovered" and r["recovered_ts"] - r["first_ts"] == 89


def test_cooldown_caches_model_calls():
    llm = Fake(); mon = Monitor(None, WL, REL, llm, learn=0, base=learned(), cooldown=600)
    for ts, peer in ((1000, 1299), (1100, 1299)):          # same (prefix, path) again after recovery in between
        mon.process(upd([1299, 64510, 9541], ts=ts, peer=peer)); mon.process(upd([1299, 3356, 17557, 9541], ts=ts + 10, peer=peer))
    assert llm.calls == 1


def test_learning_window_only_learns_authorised_routes():
    mon = Monitor(None, WL, REL, None, learn=100)
    mon.process(upd([1299, 3356, 17557, 9541], ts=1000)); mon.process(upd([1299, 65000], "72.255.4.0/24", ts=1010))
    assert mon.stats["learned"] == 1 and mon.base.support(1299, 65000) == 0
    assert mon.process(upd([1299, 64511, 9541], ts=1050)) == []                       # still learning: no alert (the window is assumed clean; it learns this link)
    assert mon.process(upd([1299, 64511, 9541], ts=1200)) == []                       # ... so the same link is normal afterwards
    assert mon.process(upd([1299, 64512, 9541], ts=1210))                             # a link first seen after the window is flagged


# ------------------------------------------------------------ store, catalogue, watch list, adapter, dashboard
def test_store_migrates_old_schema(tmp_path):
    db = str(tmp_path / "old.db"); con = sqlite3.connect(db); con.execute("CREATE TABLE incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT, signals TEXT)"); con.commit(); con.close()
    Store(db); cols = {r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(incidents)")}
    assert {"anomaly_type", "subtype", "llm_agrees", "severity"} <= cols


def test_rule_catalogue_is_sourced_and_complete():
    src = open(os.path.join(HERE, "detector.py")).read()
    for r, d in RULES.items():
        assert d["paper"] and d["proposal"] and d["role"] in ("primary", "supporting") and d["type"] in ("path_hijack", "route_leak") and f'"{r}"' in src.split("class Baseline")[1]


def test_watch_cmd(tmp_path):
    wl, asn = str(tmp_path / "w.json"), str(tmp_path / "a.json")
    base = ["--whitelist", wl, "--asns", asn]
    aspath.main(["watch", "add", "72.255.64.0/18", "--origin", "9541", *base]); aspath.main(["watch", "add-asn", "15169", *base])
    assert load_watch(wl, asn) == ({"72.255.64.0/18": [9541]}, [15169])
    aspath.main(["watch", "remove", "72.255.64.0/18", *base]); aspath.main(["watch", "remove-asn", "15169", *base]); assert load_watch(wl, asn) == ({}, [])


def test_bundled_adapter_matches_llama31_8b_shapes(tmp_path):
    from llm import adapter_fits_base
    cfg = tmp_path / "config.json"      # published Llama-3.1-8B architecture
    cfg.write_text(json.dumps(dict(hidden_size=4096, intermediate_size=14336, num_attention_heads=32, num_key_value_heads=8, num_hidden_layers=32)))
    ok, msg = adapter_fits_base(os.path.join(HERE, "models", "route-llm-llama3.1-8b-instruct-lora"), str(cfg)); assert ok, msg


def test_cli_demo_and_mock_run(tmp_path):
    for extra in ([], ["--llm", "mock"]):
        r = subprocess.run([sys.executable, "aspath.py", "demo", "--db", str(tmp_path / "d.db"), *extra], cwd=HERE, capture_output=True, text=True); assert r.returncode == 0, r.stderr
        assert "route_leak" in r.stdout and "RECOVERED" in r.stdout
    n, = sqlite3.connect(str(tmp_path / "d.db")).execute("SELECT count(*) FROM incidents").fetchone(); assert n > 0


def test_dashboard_renders_demo_db(tmp_path):
    from streamlit.testing.v1 import AppTest
    subprocess.run([sys.executable, "aspath.py", "demo", "--llm", "mock", "--db", str(tmp_path / "d.db")], cwd=HERE, check=True, capture_output=True)
    at = AppTest.from_file(os.path.join(HERE, "dashboard.py"), default_timeout=60); sys.argv += ["--db", str(tmp_path / "d.db"), "--no-refresh"]
    try: at.run()
    finally: del sys.argv[-3:]
    assert not at.exception and len(at.metric) == 5


def test_live_subscriptions_and_learn_cli(tmp_path):
    subs = aspath.subscriptions(["72.255.0.0/18"], [15169])
    assert subs[0]["prefix"] == "72.255.0.0/18" and subs[0]["moreSpecific"] is True and subs[1]["path"] == "15169$"
    r = subprocess.run([sys.executable, "aspath.py", "learn", "sample_updates.jsonl", "--db", str(tmp_path / "l.db"), "--baseline", str(tmp_path / "b.json")],
                       cwd=HERE, capture_output=True, text=True); assert r.returncode == 0, r.stderr
    b = Baseline(); assert b.load(tmp_path / "b.json") and b.support(3356, 17557) > 0


# ---------------------------------------------------------------------------------------------------- 4-bit CPU route (llama.cpp)
class _FakeLlama:
    last = None

    def __init__(self, **kw):
        self.kw, self.calls = kw, []; _FakeLlama.last = self

    def tokenize(self, b, add_bos=True, special=False):
        self.calls.append(("tokenize", add_bos, special)); return list(range(len(b) // 4))

    def create_completion(self, ids, **kw):
        self.calls.append(("completion", len(ids), kw)); return {"choices": [{"text": ' {"label": "anomalous", "anomaly_type": "path_hijack"}\n'}]}

    def create_chat_completion(self, **kw):
        self.calls.append(("chat", kw)); return {"choices": [{"message": {"content": " none "}}]}


class _FakeTok:
    def apply_chat_template(self, messages, add_generation_prompt, tokenize):
        assert add_generation_prompt and tokenize is False
        return "<|begin_of_text|>" + "".join(m["content"] for m in messages)


def _llamacpp(tmp_path, tok=True, n_ctx=2048):
    import sys, types
    from llm import LlamaCpp
    g, l = tmp_path / "base.gguf", tmp_path / "lora.gguf"; g.write_bytes(b"x"); l.write_bytes(b"x")
    mod = types.ModuleType("llama_cpp"); mod.Llama = _FakeLlama; old = sys.modules.get("llama_cpp"); sys.modules["llama_cpp"] = mod
    try:
        m = LlamaCpp(str(g), str(l), None, threads=4, n_ctx=n_ctx)
    finally:
        sys.modules.pop("llama_cpp") if old is None else sys.modules.__setitem__("llama_cpp", old)
    m.tok = _FakeTok() if tok else None
    return m


def test_llamacpp_loads_base_and_adapter_with_cpu_settings(tmp_path):
    m = _llamacpp(tmp_path); kw = _FakeLlama.last.kw
    assert kw["model_path"].endswith("base.gguf") and kw["lora_path"].endswith("lora.gguf") and kw["n_threads"] == 4 and kw["n_ctx"] == 2048 and kw["use_mmap"]


def test_llamacpp_renders_hf_template_tokenises_without_extra_bos_and_stops_at_eot(tmp_path):
    m = _llamacpp(tmp_path); out = m.generate([{"role": "system", "content": "S"}, {"role": "user", "content": "U" * 40}])
    c = _FakeLlama.last.calls
    assert c[0] == ("tokenize", False, True)                         # the template already holds <|begin_of_text|>: no second BOS, special tokens parsed
    assert c[1][0] == "completion" and c[1][2]["temperature"] == 0.0 and c[1][2]["max_tokens"] == 64 and "<|eot_id|>" in c[1][2]["stop"]
    from prompt import parse_label
    assert parse_label(out) == "path hijack"


def test_llamacpp_falls_back_to_llamacpp_chat_template_without_tokenizer(tmp_path):
    m = _llamacpp(tmp_path, tok=False); assert m.generate([{"role": "user", "content": "x"}]) == "none"
    assert _FakeLlama.last.calls[0][0] == "chat"


def test_llamacpp_refuses_prompts_that_do_not_fit_the_context(tmp_path):
    m = _llamacpp(tmp_path, n_ctx=64)
    try:
        m.generate([{"role": "user", "content": "U" * 400}])
    except ValueError as e:
        assert "--n-ctx" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_llamacpp_missing_files_tell_the_user_what_to_run(tmp_path):
    from llm import LlamaCpp
    try:
        LlamaCpp(str(tmp_path / "no.gguf"), str(tmp_path / "no2.gguf"))
    except SystemExit as e:
        assert "cpu_setup.py" in str(e)
    else:
        raise AssertionError("expected SystemExit")


def test_hf_route_stops_early_on_a_small_ram_cpu_machine():
    import sys, types
    from llm import _cpu_guard
    ps = types.ModuleType("psutil"); ps.virtual_memory = lambda: types.SimpleNamespace(total=16 * 2 ** 30); old = sys.modules.get("psutil"); sys.modules["psutil"] = ps
    try:
        for q in ("bf16", "4bit"):
            try:
                _cpu_guard(q)
            except SystemExit as e:
                assert "llamacpp" in str(e)
            else:
                raise AssertionError("expected SystemExit")
        ps.virtual_memory = lambda: types.SimpleNamespace(total=32 * 2 ** 30); assert _cpu_guard("bf16") is None      # plenty of RAM: allowed
    finally:
        sys.modules.pop("psutil") if old is None else sys.modules.__setitem__("psutil", old)


def test_cli_exposes_cpu_route_options_with_defaults():
    from aspath import common
    a = common().parse_args(["--llm", "llamacpp"])
    assert a.gguf.endswith("Q4_K_M.gguf") and a.lora_gguf.endswith("route-llm-lora-F16.gguf") and a.threads == 6 and a.n_ctx == 2048 and a.tokenizer_dir == "models/llama31-config"


def test_cpu_setup_helpers_and_dry_run(tmp_path, capsys=None):
    import cpu_setup, io, contextlib
    assert cpu_setup.missing_module("ModuleNotFoundError: No module named 'sentencepiece'") == "sentencepiece"
    assert cpu_setup.missing_module("ModuleNotFoundError: No module named 'google.protobuf'") == "google"
    assert cpu_setup.missing_module("all fine") is None
    cmd = cpu_setup.converter_cmd("tools/llama.cpp", "cfg", "adapter", "out.gguf")
    assert cmd[1].endswith("convert_lora_to_gguf.py") and cmd[cmd.index("--base") + 1] == "cfg" and cmd[cmd.index("--outtype") + 1] == "f16" and cmd[-1] == "adapter"
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cpu_setup.main(["--dry-run", "--gguf-dir", str(tmp_path / "g"), "--config-dir", str(tmp_path / "c"), "--tools-dir", str(tmp_path / "t")])
    out = buf.getvalue()
    assert rc == 0 and "Q4_K_M" in out and "convert_lora_to_gguf.py" in out and not (tmp_path / "g").exists()      # dry run writes nothing


# ---------------------------------------------------------------------------------------------------- real CAIDA file (public download)
def test_caida_newest_and_local_pick_the_latest_file(tmp_path):
    import caida
    html = '<a href="20250501.as-rel2.txt.bz2">x</a> <a href="20251001.as-rel2.txt.bz2">y</a> <a href="20250601.as-rel2.txt.bz2">z</a> <a href="README.txt">r</a>'
    assert caida.newest(html) == "20251001.as-rel2.txt.bz2" and caida.newest("nothing here") is None and caida.newest(None) is None
    assert caida.local(str(tmp_path)) is None
    for n in ("20250501.as-rel2.txt.bz2", "20250901.as-rel2.txt", "notes.txt"):
        (tmp_path / n).write_text("x")
    assert os.path.basename(caida.local(str(tmp_path))) == "20250901.as-rel2.txt"


def test_caida_download_from_a_local_stand_in_server(tmp_path):
    import bz2, functools, http.server, threading
    import caida
    srv_dir, out = tmp_path / "srv", tmp_path / "data"; srv_dir.mkdir()
    (srv_dir / "index.html").write_text('<a href="20250501.as-rel2.txt.bz2">a</a><a href="20250601.as-rel2.txt.bz2">b</a>')
    (srv_dir / "20250601.as-rel2.txt.bz2").write_bytes(bz2.compress(b"# comment\n3356|17557|-1|bgp\n1299|3356|0|bgp\n"))
    h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(srv_dir))
    h.log_message = lambda *a, **k: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), h); threading.Thread(target=srv.serve_forever, daemon=True).start()
    old = caida.URL; caida.URL = f"http://127.0.0.1:{srv.server_address[1]}/"
    try:
        p = caida.download(str(out))
        assert os.path.basename(p) == "20250601.as-rel2.txt.bz2" and os.path.isfile(p) and not any(f.endswith(".part") for f in os.listdir(out))
        r = ASRel(p); assert r.role(3356, 17557) == "customer" and r.role(1299, 3356) == "peer"
        assert caida.download(str(out)) == p                            # second call: already there, no new download
    finally:
        caida.URL = old; srv.shutdown()


def test_live_prefers_real_caida_file_and_never_overrides_explicit_choice(tmp_path):
    import types
    a = types.SimpleNamespace(as_rel=aspath.DEMO_ASREL)
    aspath.use_real_asrel(a, str(tmp_path)); assert a.as_rel == aspath.DEMO_ASREL                       # nothing downloaded: stays on the demo file (with a warning)
    (tmp_path / "20250601.as-rel2.txt.bz2").write_text("x")
    aspath.use_real_asrel(a, str(tmp_path)); assert a.as_rel.endswith("20250601.as-rel2.txt.bz2")      # real file found: used
    b = types.SimpleNamespace(as_rel="mine.txt"); aspath.use_real_asrel(b, str(tmp_path)); assert b.as_rel == "mine.txt"


def test_cli_has_caida_command_and_demo_keeps_the_synthetic_file():
    assert aspath.common().parse_args([]).as_rel == aspath.DEMO_ASREL
    assert "caida" in aspath.__doc__ and hasattr(aspath.caida, "download")
