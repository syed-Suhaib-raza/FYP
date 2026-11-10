"""AS-path anomaly PoC.  Rules from the ROUTE LLM paper + the proposal  ->  evidence  ->  ROUTE LLM (Llama-3.1-8B + LoRA)  ->  correlated incidents.

    python aspath.py rules                         # the rule catalogue with the paper / proposal sentence behind each rule
    python aspath.py demo                          # offline demo, rules only (no model needed)
    python aspath.py download                      # one-time: download Llama-3.1-8B-Instruct (~16 GB), needs HF_TOKEN
    python aspath.py caida                         # download the real CAIDA AS-relationship file (~2 MB, public) into ./data
    python aspath.py demo --llm hf                 # + the model, called exactly like the unexpectedOrigin PoC calls it
    python aspath.py history                       # build baseline.json from RIPEstat routing history (no learning window)
    python aspath.py learn history.jsonl           # build baseline.json from earlier updates (instead of a live learning window)
    python aspath.py live --llm hf --learn 900     # RIPE RIS Live for the prefixes in whitelist.json and the ASNs in watch_asns.json
    python aspath.py watch add 72.255.64.0/18 --origin 9541     # NOC edits the watch list (add / remove / add-asn / remove-asn / list)
    streamlit run dashboard.py                     # reads aspath.db

Flow (same stages as unexpectedOrigin_poc): detector.PathCandidates (rules) -> pipeline.classify (evidence + model) -> verdict -> Correlator -> SQLite.
An alert is suspicious routing, not a confirmed attack.
"""
import argparse, asyncio, json, os, time

import caida

from asrel import ASRel
from detector import RULES, Baseline, PathCandidates, norm
from pipeline import Correlator, Store, classify, rules_only
from prompt import STYLES


def load_watch(wl_path, asn_path=None):
    """whitelist.json (prefix -> [origin ASNs], same file as the other PoCs) + optional watch_asns.json ([ASN, ...])."""
    wl = json.load(open(wl_path)) if os.path.exists(wl_path) else {}
    asns = json.load(open(asn_path)) if asn_path and os.path.exists(asn_path) else []
    return wl, [int(a) for a in asns]


class Monitor:
    """Feeds RIS-Live-shaped messages through the stages. Learning window first (baseline only), then detection."""

    def __init__(self, store=None, whitelist=None, asrel=None, llm=None, asns=(), learn=600, source="online", style="repo", top_k=8, cooldown=600,
                 min_support=1, len_delta=3, origin_policy="authorized", ownership=True, history=True, base=None, enabled=None, max_llm_per_min=0):
        self.asrel, self.llm, self.style, self.top_k, self.cooldown = asrel or ASRel(), llm, style, top_k, cooldown
        self.ownership, self.history, self.learn, self.t0 = ownership, history, learn, None
        self.base = base or Baseline()
        self.det = PathCandidates(whitelist or {}, self.asrel, self.base, asns, min_support, len_delta, origin_policy, enabled)
        self.corr = Correlator(store, source, style)
        self.max_llm_per_min, self._llm_times = max_llm_per_min, []     # 0 = unlimited; over the limit an alert is raised with rules only (severity medium), never dropped
        self.cache = {}                                      # (prefix, path) -> (ts, result): the 'cooldown' of unexpectedOrigin = seconds before re-classifying
        self.stats = {"updates": 0, "learned": 0, "candidates": 0, "deferred_origin": 0, "llm_calls": 0}

    def set_watch(self, whitelist, asns=()):
        self.det.set_watch(whitelist, asns)

    def load_baseline(self, path):
        if self.base.load(path):
            self.learn = 0

    def save_baseline(self, path):
        self.base.save(path)

    def drain_recovered(self):
        return self.corr.drain()

    def _result(self, cand, now):
        ck = (cand["prefix"], tuple(cand["path"]))
        if ck in self.cache and now - self.cache[ck][0] < self.cooldown:
            return self.cache[ck][1]
        if self.llm and self.max_llm_per_min:
            self._llm_times = [t for t in self._llm_times if time.time() - t < 60]
            if len(self._llm_times) >= self.max_llm_per_min:
                self.stats["llm_skipped"] = self.stats.get("llm_skipped", 0) + 1
                res = rules_only(cand, self.asrel, self.base, self.top_k, self.ownership, self.history); self.cache[ck] = (now, res); return res
            self._llm_times.append(time.time())
        if self.llm:
            res = classify(cand, self.asrel, self.llm, self.base, self.top_k, self.ownership, self.history, self.style); self.stats["llm_calls"] += 1
        else:
            res = rules_only(cand, self.asrel, self.base, self.top_k, self.ownership, self.history)
        self.cache[ck] = (now, res)
        return res

    def process(self, msg):
        """UPDATE -> list of new or updated incidents."""
        if msg.get("type") != "UPDATE":
            return []
        now = float(msg["timestamp"]) if msg.get("timestamp") is not None else time.time()
        self.t0 = now if self.t0 is None else self.t0
        learning, peer, out = now < self.t0 + self.learn, str(msg.get("peer_asn", "")), []
        self.stats["updates"] += 1
        if not learning:
            for w in msg.get("withdrawals") or []:
                self.corr.recover(norm(w), peer, now)
        for key, prefix, path, ann in self.det.covered(msg):
            if learning:                                     # baseline = authorised-origin routes only
                if path[-1] in self.det.watch[key][1]:
                    self.base.learn(key, path); self.stats["learned"] += 1
                continue
            state, hits = self.det.check(key, prefix, path)
            if state == "deferred":
                self.stats["deferred_origin"] += 1
            elif state == "candidate":
                cand = self.det.candidate(msg, ann, key, prefix, path, hits)
                self.stats["candidates"] += 1
                # same cause already open (e.g. seen by another peer): merge without calling the model again
                out.append(self.corr.add(cand, None if self.corr.is_open(cand) else self._result(cand, now), now, self.base.typical_path(key)))
            elif state == "clean":
                self.corr.recover(prefix, peer, now)
        return out


# ---------------------------------------------------------------------------------------------------- output
def fmt(a):
    t = time.strftime("%H:%M:%S", time.gmtime(a["first_ts"]))
    llm = "rules only" if a["llm_label"] is None else f"[{a['model']}] LLM={a['llm_label']} ({a['llm_agrees']}, {a['llm_ms']} ms) raw={a['raw_output']!r}"
    return f"[{t}] {a['source'].upper()} {a['severity'].upper():6} {a['anomaly_type']:11} {a['prefix']} path {a['as_path']} | {llm} | {a['signals']}"


def show_recovered(mon):
    for a in mon.drain_recovered():
        print(f"    RECOVERED {a['prefix']} after {a['recovered_ts'] - a['first_ts']:.0f}s ({a['anomaly_type']})")


def replay(mon, path):
    for line in open(path):
        for a in mon.process(json.loads(line)["data"]):
            if a["count"] == 1:
                print(fmt(a))
            else:
                print(f"    (same incident again: {a['peers_seen']} peer(s), {a['affected']} prefix(es) affected: {a['affected_prefixes'][:80]})")
        show_recovered(mon)
    print(mon.stats)


def rules_cmd():
    for r, d in RULES.items():
        print(f"\n{r}   [{d['role']}, indicates {d['type']}]\n  checks  : {d['check']}\n  paper   : {d['paper']}\n  proposal: {d['proposal']}")
    print("\nWhere several primary rules fire on one update the candidate is named by the first of: new_origin_upstream, valley_violation, new_as_link (our precedence choice).")


# ---------------------------------------------------------------------------------------------------- live (RIPE RIS Live)
URL = "wss://ris-live.ripe.net/v1/ws/?client=fyp-aspath-poc"
DEMO_ASREL = "demo_as_rel.txt"


def subscriptions(prefixes, asns):
    base = {"type": "UPDATE", "socketOptions": {"includeRaw": False}}
    return [dict(base, prefix=p, moreSpecific=True) for p in prefixes] + [dict(base, path=f"{a}$") for a in asns]   # ASN: routes originated by it


async def live(mon, a):
    import websockets
    mt = lambda f: os.path.getmtime(f) if os.path.exists(f) else 0
    last, chk, stamp = time.time(), time.time(), (mt(a.whitelist), mt(a.asns))
    wl, asns = load_watch(a.whitelist, a.asns)
    if a.prefix:
        wl = {p: wl.get(p, []) for p in a.prefix}
    mon.set_watch(wl, asns)
    first = subscriptions(wl, asns)
    if a.scope == "all":                                     # every update, leak rule only
        mon.det.watch = {"GLOBAL": (None, set())}; mon.learn = 0; mon.ownership = False; wl, asns = {}, []
        first = [{"type": "UPDATE", "socketOptions": {"includeRaw": False}, **({"host": a.collector} if a.collector else {})}]
    while True:
        try:
            async with websockets.connect(URL, ping_interval=30) as ws:
                for s in first:
                    await ws.send(json.dumps({"type": "ris_subscribe", "data": s}))
                print("connected to RIS Live, " + (f"checking ALL updates{' from ' + a.collector if a.collector else ''} (leak rule only)" if a.scope == "all" else f"watching prefixes {list(wl)} and ASNs {asns}"), flush=True)
                while True:
                    try:
                        raw = await asyncio.wait_for(ws.recv(), 15)
                    except asyncio.TimeoutError:
                        raw = None
                    if a.scope != "all" and time.time() - chk >= 15 and (mt(a.whitelist), mt(a.asns)) != stamp:    # NOC edited the watch list (FR7): reload without restart
                        chk, stamp = time.time(), (mt(a.whitelist), mt(a.asns))
                        new_wl, new_asns = load_watch(a.whitelist, a.asns)
                        mon.set_watch(new_wl, new_asns)
                        for s in subscriptions([p for p in new_wl if p not in wl], [x for x in new_asns if x not in asns]):
                            await ws.send(json.dumps({"type": "ris_subscribe", "data": s}))
                        wl, asns = new_wl, new_asns
                        print(f"watch list reloaded: prefixes {list(wl)}, ASNs {asns}", flush=True)
                    if raw:
                        m = json.loads(raw)
                        if m.get("type") == "ris_message":
                            for inc in await asyncio.to_thread(mon.process, m["data"]):
                                if inc["count"] == 1:
                                    print(fmt(inc), flush=True)
                            show_recovered(mon)
                    if time.time() - last >= 30:
                        last = time.time(); print(f"[{time.strftime('%H:%M:%S')}] listening: {mon.stats}", flush=True)
        except Exception as e:                                # feed interruption: reconnect, never raise false alerts (NFR3)
            print("connection lost:", e, "- retrying in 5s", flush=True)
            await asyncio.sleep(5)


def watch_cmd(a):
    """NOC watch list (FR7): python aspath.py watch add 72.255.64.0/18 --origin 9541 | add-asn 15169 | remove ... | list"""
    wl, asns = load_watch(a.whitelist, a.asns)
    if a.action == "add":
        wl[norm(a.value)] = a.origin or []
    elif a.action == "remove":
        wl.pop(norm(a.value), None)
    elif a.action == "add-asn" and int(a.value) not in asns:
        asns.append(int(a.value))
    elif a.action == "remove-asn" and int(a.value) in asns:
        asns.remove(int(a.value))
    if a.action != "list":
        json.dump(wl, open(a.whitelist, "w"), indent=2); json.dump(asns, open(a.asns, "w"))
    print("monitored prefixes:", json.dumps(wl)); print("monitored ASNs:", asns)


# ---------------------------------------------------------------------------------------------------- CLI
def common():
    c = argparse.ArgumentParser(add_help=False)
    c.add_argument("--whitelist", default="whitelist.json", help="monitored prefixes -> expected origins (same file as the other PoCs)")
    c.add_argument("--asns", default="watch_asns.json", help="monitored ASNs (all prefixes they originate)"); c.add_argument("--db", default="aspath.db")
    c.add_argument("--as-rel", default=DEMO_ASREL, help="CAIDA as-rel file (.txt/.bz2); default: the tiny SYNTHETIC demo file (live mode prefers the newest file in ./data, get it with: python aspath.py caida)")
    c.add_argument("--baseline", default="baseline.json"); c.add_argument("--learn", type=int, default=600, help="learning window, seconds of feed time")
    c.add_argument("--baseline-source", choices=["history", "learn"], default="history", help="live/history: history = routing history from RIPEstat before start (no learning window; falls back to learn if RIPEstat is unreachable); learn = live window")
    c.add_argument("--history-days", type=int, default=60); c.add_argument("--history-snapshots", type=int, default=12, help="snapshots sampled across the window"); c.add_argument("--embargo-days", type=int, default=3, help="skip the most recent days so a fresh attack is not in the baseline")
    c.add_argument("--min-snapshots", type=int, default=3, help="a link is ESTABLISHED if seen in at least this many snapshots ..."); c.add_argument("--min-peers", type=int, default=3, help="... from at least this many RIS peers ...")
    c.add_argument("--min-span-days", type=int, default=10, help="... and the snapshots are at least this many days apart (a short attack cannot satisfy this)")
    c.add_argument("--as-of", default=None, help="YYYY-MM-DD: build the history as it was on that date (replaying an old incident)"); c.add_argument("--history-dir", default="data/history")
    c.add_argument("--history-max-age-hours", type=int, default=24, help="live: reuse baseline.json if it was built from history less than this many hours ago (no RIPEstat calls)")
    c.add_argument("--history-rrcs", default=None, help="history: only these RIS collectors, e.g. 0,1,3 (smaller answers; use if an ASN watch times out)")
    c.add_argument("--caida-known", action=argparse.BooleanOptionalAction, default=True, help="a link listed in CAIDA counts as known (history mode)")
    c.add_argument("--scope", choices=["watch", "all"], default="watch", help="live: watch = prefixes/ASNs in the watch list (history baseline); all = EVERY update from RIS Live, valley (route-leak) rule only, no baseline")
    c.add_argument("--collector", default=None, help="live --scope all: only this RIS collector, e.g. rrc00 (less load than the whole feed)")
    c.add_argument("--max-llm-per-min", type=int, default=0, help="cap model calls per minute (0 = unlimited; --scope all defaults to 3 because the model needs ~17 s per alert on CPU)")
    c.add_argument("--min-support", type=int, default=1, help="an AS link seen fewer times than this in the baseline is 'new' (1 = never seen; 2 = never or rarely seen, Fig. 4 wording)")
    c.add_argument("--len-delta", type=int, default=3, help="path_length_deviation: hops away from the baseline median")
    c.add_argument("--origin-policy", choices=["authorized", "any"], default="authorized", help="authorized: announcements from a non-authorised origin are left to the unexpectedOrigin PoC")
    c.add_argument("--cooldown", type=int, default=600, help="seconds before re-classifying the same (prefix, path) with the model (unexpectedOrigin: same meaning)")
    c.add_argument("--ownership-evidence", action=argparse.BooleanOptionalAction, default=True, help="ownership lines in the evidence (default on; as in unexpectedOrigin)")
    c.add_argument("--history-evidence", action=argparse.BooleanOptionalAction, default=True, help="baseline facts in the evidence, Fig. 4 wording (default on)")
    c.add_argument("--llm", choices=["none", "hf", "llamacpp", "mock"], default="none")
    c.add_argument("--prompt", choices=STYLES, default="repo", help="repo = identical to the unexpectedOrigin PoC (default), paper = Fig.3 + bgpdump + Fig.4 evidence, infer = inference.py")
    c.add_argument("--top-k", type=int, default=8)
    c.add_argument("--quant", choices=["bf16", "8bit", "4bit"], default="bf16", help="--llm hf only. 8bit/4bit need an NVIDIA GPU (bitsandbytes). No GPU? use --llm llamacpp (4-bit on CPU)")
    c.add_argument("--base", default="meta-llama/Llama-3.1-8B-Instruct", help="HF repo id (auto-downloaded) or a local model folder")
    c.add_argument("--model-dir", default="models/llama31-8b-instruct", help="where the PoC stores the downloaded base model")
    c.add_argument("--hf-token", default=None, help="HF read token (or set HF_TOKEN, or run huggingface-cli login)")
    c.add_argument("--adapter", default="models/route-llm-llama3.1-8b-instruct-lora")
    c.add_argument("--gguf", default="models/gguf/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf", help="--llm llamacpp: 4-bit base model (python cpu_setup.py downloads it)")
    c.add_argument("--lora-gguf", default="models/gguf/route-llm-lora-F16.gguf", help="--llm llamacpp: the adapter converted to GGUF (python cpu_setup.py makes it)")
    c.add_argument("--tokenizer-dir", default="models/llama31-config", help="--llm llamacpp: HF tokenizer/config files, so the prompt is rendered exactly as in the HF route")
    c.add_argument("--threads", type=int, default=6, help="--llm llamacpp: CPU threads (i5-1345U has 2 P + 8 E cores: try 6, then 4 or 8)")
    c.add_argument("--n-ctx", type=int, default=2048, help="--llm llamacpp: context window in tokens")
    return c


def build(a, source):
    from llm import make_llm
    wl, asns = load_watch(a.whitelist, a.asns)
    return Monitor(Store(a.db), wl, ASRel(a.as_rel if os.path.exists(a.as_rel) else None), make_llm(a), asns, a.learn, source, a.prompt, a.top_k, a.cooldown,
                   a.min_support, a.len_delta, a.origin_policy, a.ownership_evidence, a.history_evidence)


def use_real_asrel(a, folder=caida.DIR):
    """Live traffic needs real relationships, not the synthetic demo file: use the newest CAIDA file in ./data, or warn if there is none.
    An explicit --as-rel is never overridden."""
    if a.as_rel != DEMO_ASREL:
        return a
    real = caida.local(folder)
    if real:
        a.as_rel = real; print("using the real CAIDA file:", real, flush=True)
    else:
        print("WARNING: using the SYNTHETIC demo relationships; most real AS links are unknown, so the valley rule stays silent. "
              "Get the real file with:  python aspath.py caida", flush=True)
    return a


def history_baseline(a, mon, force=False):
    """Fill mon.base from RIPEstat history. True = used (learning window switched off), False = unreachable (caller keeps the learning window)."""
    import calendar, history
    history.RRCS = a.history_rrcs
    now = calendar.timegm(time.strptime(a.as_of, "%Y-%m-%d")) if a.as_of else time.time()
    if a.caida_known and mon.asrel.rel and a.as_rel != DEMO_ASREL:
        mon.base.known = lambda x, y: mon.asrel.pair(x, y) is not None
    if not force and not a.as_of and os.path.exists(a.baseline):          # fresh enough? reuse it instead of asking RIPEstat again
        try:
            m = json.load(open(a.baseline)).get("meta", {})
        except (ValueError, OSError):
            m = {}
        age = time.time() - m.get("built", 0)
        if m.get("source") == "history" and age < a.history_max_age_hours * 3600 and set(m.get("watch", [])) == set(mon.det.watch) and mon.base.load(a.baseline):
            mon.learn = 0; mon.det.min_support = max(mon.det.min_support, 2)
            print(f"reusing history baseline built {age / 3600:.1f} h ago ({m.get('links_established')} established links); 'python aspath.py history' rebuilds it", flush=True)
            return True
    n = history.fill(mon.base, mon.det.watch, now, a.history_days, a.history_snapshots, a.embargo_days, a.min_snapshots, a.min_peers, a.min_span_days, a.history_dir)
    if n:
        mon.learn = 0; mon.det.min_support = max(mon.det.min_support, 2)       # established links have count >= 2
    else:
        print("WARNING: no history available, falling back to the live learning window (an attack inside it would be learned as normal).", flush=True)
    return bool(n)


def main(argv=None):
    c = common()
    p = argparse.ArgumentParser(description="AS-path anomaly PoC"); sub = p.add_subparsers(dest="mode", required=True)
    d = sub.add_parser("demo", parents=[c]); d.add_argument("file", nargs="?", default="sample_updates.jsonl")
    ln = sub.add_parser("learn", parents=[c]); ln.add_argument("file")
    sub.add_parser("history", parents=[c])
    l = sub.add_parser("live", parents=[c]); l.add_argument("--prefix", action="append")
    sub.add_parser("download", parents=[c]); sub.add_parser("rules", parents=[c]); sub.add_parser("caida", parents=[c])
    w = sub.add_parser("watch", parents=[c]); w.add_argument("action", choices=["list", "add", "remove", "add-asn", "remove-asn"])
    w.add_argument("value", nargs="?"); w.add_argument("--origin", type=int, action="append")
    a = p.parse_args(argv)
    if a.mode == "rules":
        return rules_cmd()
    if a.mode == "download":
        from llm import resolve_base
        print("base model ready at:", resolve_base(a.base, a.model_dir, a.hf_token)); return
    if a.mode == "caida":
        caida.download(); return
    if a.mode == "watch":
        return watch_cmd(a)
    if a.mode in ("live", "history"):
        use_real_asrel(a)
    if a.mode == "history":                                  # build baseline.json from RIPEstat history and show what is NOT established
        import history; a.llm = "none"; mon = build(a, "history")
        if history_baseline(a, mon, force=True):
            mon.save_baseline(a.baseline); print(f"baseline saved to {a.baseline}:", mon.base.stats(), mon.base.meta)
            print("rarest links (seen in history but not established; look here first):", history.rarest(mon.base))
        return
    if a.mode == "learn":                                    # historical bootstrap: every authorised-origin announcement in the file becomes baseline
        a.llm = "none"; mon = build(a, "learn"); mon.learn = 10 ** 12
        for line in open(a.file):
            mon.process(json.loads(line)["data"])
        mon.save_baseline(a.baseline); print(f"baseline saved to {a.baseline}:", mon.base.stats()); return
    mon = build(a, "demo" if a.mode == "demo" else "online")
    if a.mode == "live" and a.scope == "all":
        a.max_llm_per_min = a.max_llm_per_min or 3
    mon.max_llm_per_min = a.max_llm_per_min if a.mode == "live" else 0
    if a.mode == "live" and a.scope != "all":
        if a.prefix:
            wl0, asns0 = load_watch(a.whitelist, a.asns); mon.set_watch({p: wl0.get(p, []) for p in a.prefix}, asns0)
        if not (a.baseline_source == "history" and history_baseline(a, mon)):
            mon.load_baseline(a.baseline)
    try:
        replay(mon, a.file) if a.mode == "demo" else asyncio.run(live(mon, a))
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        if a.mode == "live" and a.scope != "all":            # never overwrite baseline.json with the empty baseline of --scope all
            mon.save_baseline(a.baseline)


if __name__ == "__main__":
    main()