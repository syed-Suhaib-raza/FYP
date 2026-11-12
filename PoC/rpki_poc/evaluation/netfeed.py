"""Network side of the ONLINE evaluation (copied from moas_poc/evaluation; only change: the ORDER switch).

Three pieces:
  probe_ris_live()  connects to the real RIPE RIS Live websocket, measures how late real updates arrive
                    (arrival wall-clock - collector timestamp) and the websocket round-trip time, and keeps the
                    raw messages so the PoC can also be timed on real (unlabelled) traffic.
  serve_feed()      a websocket server that speaks the RIS Live protocol (client sends `ris_subscribe`, server
                    pushes `ris_message`s). It streams the LABELLED dataset at a fixed rate and holds each message
                    back by a delay drawn from a delay model (by default the delays measured by the probe), so the
                    PoC receives labelled updates over a real socket with realistic feed latency.
  stream_client()   the PoC side: connect, subscribe, and hand every `ris_message` to a callback, the same way
                    ris_live.py / live.py do.

Timing fields stamped on every message (wall clock, time.time()):
  emit  when the update "happened" (the moment the collector would have received it)
  sent  when the server actually wrote it to the socket  (sent - emit = network/feed delay)
The client adds `recv` (read from the socket) and the decision time. If the server runs on another machine the two
clocks must be NTP-synchronised, otherwise the emit->recv component is off by the clock skew.
"""
import asyncio, json, random, statistics, time

RIS_URL = "wss://ris-live.ripe.net/v1/ws/?client=fyp-eval"
ORDER = "prefix"   # "prefix": updates of the same prefix keep their order (MOAS / Unexpected Origin);
                   # "global": every message keeps its place (RPKI: ROA changes and peer-down events affect
                   # several prefixes at once, so the labels need the global order). Same delay values either way.
STALE_S = 120   # a timestamp older than this is a replay / table re-send by the collector, not feed delay


# ------------------------------------------------------------------------------------------------------------
def _connect(url, **kw):
    import websockets
    if url.startswith("ws://"):            # local/LAN feed: never route through an HTTP proxy
        try:
            return websockets.connect(url, proxy=None, **kw)
        except TypeError:                  # websockets < 15 has no proxy argument
            pass
    return websockets.connect(url, **kw)


async def _probe(seconds, subscribe, max_keep, url, n_pings):
    out = dict(url=url, subscribe=subscribe, seconds=seconds, delays=[], rtts=[], messages=[], n_received=0, error=None)
    try:
        async with _connect(url, ping_interval=None, open_timeout=15, max_size=None) as ws:
            for _ in range(n_pings):
                t = time.perf_counter()
                pong = await ws.ping()
                await asyncio.wait_for(pong, 10)
                out["rtts"].append(time.perf_counter() - t)
            await ws.send(json.dumps({"type": "ris_subscribe", "data": subscribe}))
            end = time.time() + seconds
            while time.time() < end:
                try:
                    raw = await asyncio.wait_for(ws.recv(), max(0.1, end - time.time()))
                except asyncio.TimeoutError:
                    break
                now = time.time()
                m = json.loads(raw)
                if m.get("type") != "ris_message":
                    if m.get("type") == "ris_error":
                        out["error"] = f"ris_error: {m.get('data')}"
                    continue
                out["n_received"] += 1
                ts = m["data"].get("timestamp")
                if ts is not None:
                    out["delays"].append(now - float(ts))
                if len(out["messages"]) < max_keep:
                    out["messages"].append(m["data"])
            try:                           # best effort: under a heavy feed the pong sits behind unread messages
                t = time.perf_counter()
                pong = await ws.ping()
                await asyncio.wait_for(pong, 5)
                out["rtts"].append(time.perf_counter() - t)
            except Exception:  # noqa: BLE001
                out["note"] = "final ping unanswered (feed backlog); RTT taken from the pings before subscribing"
    except Exception as e:  # noqa: BLE001 - report, the caller falls back
        out["error"] = f"{type(e).__name__}: {e}"
    raw = out["delays"]
    out["delays"] = [d for d in raw if d <= STALE_S]
    stale = [d for d in raw if d > STALE_S]
    out["n_stale"], out["stale_median_s"] = len(stale), (statistics.median(stale) if stale else None)
    return out


def probe_text(pr):
    """One-line human summary of a probe result."""
    if not pr["delays"]:
        return f"FAILED ({pr['error'] or 'no usable messages'}); network component = socket transport only"
    d = pr["delays"]
    t = (f"{pr['n_received']} messages in {pr['seconds']:.0f} s from {pr['subscribe'].get('host', 'all collectors')}; "
         f"{len(d)} usable delay samples (median {statistics.median(d):.2f} s, p95 {pctl(d, 95):.2f} s)")
    if pr.get("n_stale"):
        t += (f"; {pr['n_stale']} messages with timestamps older than {STALE_S} s (median {pr['stale_median_s'] / 86400:.1f} days: "
              f"collector replay / table re-send) excluded")
    if statistics.median(d) > 10:
        t += "; NOTE: the feed itself was lagging during the probe (burst on the collector or limited bandwidth)"
    if pr.get("error"):
        t += f"; probe ended with {pr['error']}"
    return t


def probe_ris_live(seconds=60, subscribe=None, max_keep=20000, url=RIS_URL, n_pings=5):
    """Returns dict(delays=[s], rtts=[s], messages=[data...], n_received, error). error is None on success."""
    try:
        import websockets  # noqa: F401
    except ImportError:
        return dict(url=url, subscribe=subscribe, seconds=seconds, delays=[], rtts=[], messages=[], n_received=0,
                    error="the 'websockets' package is not installed (pip install websockets)")
    subscribe = subscribe or {"type": "UPDATE", "host": "rrc00", "socketOptions": {"includeRaw": False}}
    return asyncio.run(_probe(seconds, subscribe, max_keep, url, n_pings))


# ------------------------------------------------------------------------------------------------------------
class DelayModel:
    """Per-message feed delay in seconds. `trace` replays measured delays in arrival order (keeps their burstiness)."""

    def __init__(self, kind="none", values=None, a=0.0, b=0.0, seed=1):
        self.kind, self.values, self.a, self.b = kind, list(values or []), a, b
        self.rnd = random.Random(seed)
        self.stride = 1

    def fit(self, n):
        """Spread n messages evenly over the whole trace instead of using only its first n samples."""
        if self.kind == "trace" and self.values:
            self.stride = max(1, len(self.values) // max(1, n))
        return self

    @classmethod
    def parse(cls, spec, probe_delays=None):
        if spec in (None, "none"):
            return cls("none")
        if spec in ("ris", "auto"):
            vals = [max(0.0, d) for d in (probe_delays or []) if d <= STALE_S]
            return cls("trace", vals) if vals else cls("none")
        if spec.startswith("trace:"):
            d = json.load(open(spec[6:], encoding="utf-8"))
            vals = d["delays"] if isinstance(d, dict) else d
            return cls("trace", [max(0.0, float(x)) for x in vals if float(x) <= STALE_S])
        if spec.startswith("fixed:"):
            return cls("fixed", a=float(spec[6:]))
        if spec.startswith("uniform:"):
            lo, hi = map(float, spec[8:].split(","))
            return cls("uniform", a=lo, b=hi)
        raise ValueError(f"unknown delay model {spec!r} (none | ris | trace:FILE | fixed:S | uniform:A,B)")

    def __call__(self, i):
        if self.kind == "trace" and self.values:
            return self.values[(i * self.stride) % len(self.values)]
        if self.kind == "fixed":
            return self.a
        if self.kind == "uniform":
            return self.rnd.uniform(self.a, self.b)
        return 0.0

    def describe(self):
        if self.kind == "trace":
            v = self.values
            return (f"trace of {len(v)} measured delays (median {statistics.median(v) * 1000:.0f} ms, "
                    f"p95 {pctl(v, 95) * 1000:.0f} ms)") if v else "trace (empty)"
        return {"none": "none (socket transport only)", "fixed": f"fixed {self.a:.3f} s",
                "uniform": f"uniform {self.a:.3f}-{self.b:.3f} s"}[self.kind]


def pctl(v, p):
    if not v:
        return float("nan")
    s = sorted(v)
    k = (len(s) - 1) * p / 100
    f = int(k)
    return s[f] + (s[min(f + 1, len(s) - 1)] - s[f]) * (k - f)


# ------------------------------------------------------------------------------------------------------------
def _first_prefix(data):
    return next((p for a in data.get("announcements", []) for p in a.get("prefixes", [])), None)


def plan_delivery(records, rate, delay, t_start):
    """[(deliver_time, seq, emit_time)] in delivery order. Update i "happens" at emit_i = t_start + i/rate and is
    delivered at emit_i + delay(i). Like RIS Live, messages for different prefixes may overtake each other; updates
    of the SAME prefix keep their order (the ground truth is a per-prefix sequence). To keep that order without
    inflating delays, each prefix's delivery times {emit_i + delay(i)} are sorted and handed out in sequence order:
    the per-prefix set of delivery times (hence the mean delay) is unchanged and no delay becomes negative."""
    groups, emit = {}, {}
    for i, rec in enumerate(records):
        emit[i] = t_start + i / rate
        groups.setdefault(_first_prefix(rec["data"]) if ORDER == "prefix" else None, []).append(i)
    plan = []
    for idx in groups.values():
        times = sorted(emit[i] + max(0.0, delay(i)) for i in idx)
        for t, i in zip(times, idx):
            plan.append((t, i, emit[i]))
    plan.sort()
    return plan


async def _stream(ws, records, rate, delay):
    for deliver, i, emit in plan_delivery(records, rate, delay, time.time() + 0.2):
        wait = deliver - time.time()
        if wait > 0:
            await asyncio.sleep(wait)
        await ws.send(json.dumps({"type": "ris_message", "data": records[i]["data"],
                                  "eval": {"seq": i, "emit": emit, "sent": time.time()}}))
    await ws.send(json.dumps({"type": "ris_eval_end", "data": {"n": len(records)}}))


def make_handler(records, rate, delay, done=None):
    async def handler(ws, path=None):              # websockets <10.1 passes `path`, newer versions do not
        async for raw in ws:
            m = json.loads(raw)
            if m.get("type") == "ris_subscribe":   # stream once per connection, on the first subscribe
                await _stream(ws, records, rate, delay)
                break
        try:
            await ws.wait_closed()
        finally:
            if done is not None and not done.done():
                done.set_result(True)
    return handler


async def serve_feed(records, host="127.0.0.1", port=0, rate=20.0, delay=None):
    """Start the feed server; returns (server, url). port=0 picks a free port."""
    import websockets
    delay = (delay or DelayModel()).fit(len(records))
    server = await websockets.serve(make_handler(records, rate, delay), host, port, max_size=None)
    sock = next(iter(server.sockets))
    return server, f"ws://{host if host not in ('0.0.0.0', '') else '127.0.0.1'}:{sock.getsockname()[1]}"


async def stream_client(url, on_message, subscribe=None, max_wait=None):
    """Connect like ris_live.py/live.py, subscribe, and call on_message(data, timing) for each ris_message.
    timing = dict(emit, sent, recv, seq) (emit/sent are None on a real RIS feed). Returns when the feed ends."""
    subscribe = subscribe or {"type": "UPDATE", "socketOptions": {"includeRaw": False}}
    async with _connect(url, ping_interval=30, open_timeout=15, max_size=None) as ws:
        await ws.send(json.dumps({"type": "ris_subscribe", "data": subscribe}))
        while True:
            try:
                raw = await (asyncio.wait_for(ws.recv(), max_wait) if max_wait else ws.recv())
            except asyncio.TimeoutError:
                raise TimeoutError(f"no message from the feed at {url} for {max_wait:.0f} s") from None
            recv = time.time()
            m = json.loads(raw)
            if m.get("type") == "ris_eval_end":
                return
            if m.get("type") != "ris_message":
                continue
            ev = m.get("eval") or {}
            on_message(m["data"], dict(seq=ev.get("seq"), emit=ev.get("emit"), sent=ev.get("sent"), recv=recv))


async def close_server(server):
    server.close()
    try:
        await asyncio.wait_for(server.wait_closed(), 5)
    except asyncio.TimeoutError:
        pass
