"""Route flapping detection: logic + SQLite. No network code (same role as moas.py in the MOAS PoC).

Rule (deterministic, as classified in the Anomaly Classification paper; RFC 2439 "figure of merit"):
one penalty per (prefix, peer session). It is used to DETECT only, nothing is suppressed.
  route withdrawn                        -> +1000
  route re-announced with a new AS path  -> +500
  penalty halves every 15 minutes        P(t) = P0 * 0.5 ** (dt / half_life)
  penalty >= 2000 (suppress)             -> FLAP alert        (repeated instability)
  penalty <  750  (reuse)                -> CLEARED           (stable again; the gap stops alert chatter)
  penalty is capped at 750 * 2**(3600/900) = 12000
A peer session that goes down is NOT a flap: its routes are forgotten and nothing is charged.
"""
import ipaddress, sqlite3, threading, time
from functools import lru_cache

COLS = [("ts", "REAL"), ("event", "TEXT"), ("prefix", "TEXT"), ("peer_asn", "TEXT"), ("collector", "TEXT"),
        ("penalty", "REAL"), ("flaps", "INTEGER"), ("withdrawals", "INTEGER"), ("path_changes", "INTEGER"),
        ("peers_flapping", "INTEGER"), ("severity", "TEXT"), ("as_path", "TEXT"), ("reason", "TEXT"), ("source", "TEXT"), ("anomaly", "TEXT")]


@lru_cache(maxsize=100000)
def norm(prefix):
    """one spelling per prefix (RIS writes some IPv6 withdrawals as 2a12:ca40:0:0:0:0:0:0/32)."""
    try:
        return str(ipaddress.ip_network(prefix, strict=False))
    except ValueError:
        return prefix


def path_text(path):
    return " ".join("{" + ",".join(map(str, h)) + "}" if isinstance(h, list) else str(h) for h in path or [])


class Store:
    def __init__(self, db="flap.db"):
        self.con, self.lock = sqlite3.connect(db, check_same_thread=False), threading.Lock()
        self.con.execute("CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                         + ", ".join(f"{n} {t}" for n, t in COLS) + ")")
        self.con.commit()

    def add(self, a):
        with self.lock:
            self.con.execute(f"INSERT INTO alerts({','.join(n for n, _ in COLS)}) VALUES({','.join('?' * len(COLS))})",
                             [a.get(n) for n, _ in COLS])
            self.con.commit()


class Route:
    def __init__(self, now):
        self.penalty, self.t, self.path, self.up = 0.0, now, None, True
        self.w = self.p = 0              # withdrawals / path changes counted in the current flap


class FlapDetector:
    """The single detector. whitelist {prefix: [asn]} (same file as the MOAS PoC): flapping inside a monitored prefix is
    "high", anything else "medium". min_peers: peer sessions that must be over the threshold for the same prefix.
    source: "demo" (offline replay) or "online" (live RIS Live); stored on every alert so the dashboard can tell them apart."""

    ANOMALY = "route_flapping"

    def __init__(self, store=None, whitelist=None, half_life=900, suppress=2000, reuse=750, withdraw_penalty=1000,
                 path_penalty=500, max_suppress=3600, min_peers=1, source="online"):
        self.store, self.half_life, self.suppress, self.reuse = store, half_life, suppress, reuse
        self.wp, self.pp, self.min_peers, self.source = withdraw_penalty, path_penalty, min_peers, source
        self.cap = reuse * 2 ** (max_suppress / half_life)
        self.nets = [ipaddress.ip_network(p, strict=False) for p in (whitelist or {})]
        self.routes = {}                 # (prefix, router, peer) -> Route
        self.peer_asn = {}               # (router, peer) -> ASN, for the alert text
        self.active = set()              # keys with an open flap alert
        self.stats = {"updates": 0, "withdrawals": 0, "announcements": 0, "alerts": 0, "cleared": 0, "peer_resets": 0}

    # ---- helpers ----
    def _severity(self, prefix):
        net = ipaddress.ip_network(prefix, strict=False)
        return "high" if any(net.version == w.version and net.subnet_of(w) for w in self.nets) else "medium"

    def _decay(self, r, now):
        r.penalty *= 0.5 ** (max(0.0, now - r.t) / self.half_life)
        r.t = max(now, r.t)

    def _emit(self, event, key, r, ts, reason=""):
        prefix, host, peer = key
        peer_asn = self.peer_asn.get((host, peer), peer)
        flapping = sum(1 for k in self.active if k[0] == prefix)
        a = dict(ts=ts, event=event, prefix=prefix, peer_asn=peer_asn, collector=host, penalty=round(r.penalty),
                 flaps=r.w + r.p, withdrawals=r.w, path_changes=r.p, peers_flapping=flapping,
                 severity=self._severity(prefix), as_path=path_text(r.path), reason=reason, source=self.source,
                 anomaly=self.ANOMALY)
        self.stats["alerts" if event == "onset" else "cleared"] += 1
        if self.store:
            self.store.add(a)
        return a

    def _charge(self, key, peer_asn, now, amount):
        self.peer_asn[(key[1], key[2])] = peer_asn
        r = self.routes[key]
        self._decay(r, now)
        r.penalty = min(self.cap, r.penalty + amount)
        if r.penalty < self.suppress or key in self.active:
            return []
        same = [k for k in self.routes if k[0] == key[0]]
        for k in same:
            self._decay(self.routes[k], now)
        over = [k for k in same if k in self.active or self.routes[k].penalty >= self.suppress]
        if len(over) < self.min_peers:
            return []
        new = [k for k in over if k not in self.active]          # every session that is over the limit alerts together
        self.active.update(new)
        return [self._emit("onset", k, self.routes[k], now) for k in new]

    def tick(self, now=None):
        """call regularly on a live feed so CLEARED fires even when a prefix goes quiet."""
        now, out = time.time() if now is None else now, []
        for key in list(self.active):
            r = self.routes[key]
            self._decay(r, now)
            if r.penalty < self.reuse:
                self.active.discard(key)
                out.append(self._emit("cleared", key, r, now, "stable again, penalty decayed below the reuse limit"))
                r.w = r.p = 0
        return out

    def _drop(self, match, now, reason):
        out = []
        for key in [k for k in self.routes if match(k)]:
            if key in self.active:
                self.active.discard(key)
                out.append(self._emit("cleared", key, self.routes[key], now, reason))
            del self.routes[key]
        return out

    # ---- input: RIS-Live-shaped dict ----
    def process(self, msg):
        host, peer = msg.get("host", ""), str(msg.get("peer") or msg.get("peer_asn", ""))
        peer_asn = str(msg.get("peer_asn", ""))
        now = float(msg["timestamp"]) if msg.get("timestamp") is not None else time.time()
        if msg.get("type") == "RIS_PEER_STATE":          # a session reset is not a route flap
            if msg.get("state") == "down":
                self.stats["peer_resets"] += 1
                return self._drop(lambda k: (k[1], k[2]) == (host, peer), now, "peer session went down (not a flap)")
            return []
        if msg.get("type") != "UPDATE":
            return []
        self.stats["updates"] += 1
        out = self.tick(now)
        for prefix in map(norm, msg.get("withdrawals") or []):
            self.stats["withdrawals"] += 1
            r = self.routes.get((prefix, host, peer))
            if r and r.up:                                # only a route we saw announced can flap
                r.up, r.w = False, r.w + 1
                out += self._charge((prefix, host, peer), peer_asn, now, self.wp)
        path = tuple(map(lambda h: tuple(h) if isinstance(h, list) else h, msg.get("path") or []))
        for ann in msg.get("announcements") or []:
            for prefix in map(norm, ann.get("prefixes", [])):
                self.stats["announcements"] += 1
                key = (prefix, host, peer)
                r = self.routes.get(key)
                if r is None:                             # first sighting: baseline, no penalty
                    r = self.routes[key] = Route(now)
                    r.path = path
                    continue
                changed, was_up = r.path != path, r.up
                r.up, r.path = True, path
                if was_up and changed:                    # replaced while up = path change; back from withdrawn = free
                    r.p += 1
                    out += self._charge(key, peer_asn, now, self.pp)
        return out


def fmt(a):
    t = time.strftime("%H:%M:%S", time.gmtime(a["ts"]))
    tag = f"{a['source'].upper()} route flapping"
    if a["event"] == "cleared":
        return f"[{t}] {tag}: CLEARED {a['prefix']} via {a['collector']} peer AS{a['peer_asn']} ({a['reason']})"
    return (f"[{t}] {tag}: {a['severity'].upper()} {a['prefix']} via {a['collector']} peer AS{a['peer_asn']}: "
            f"penalty {a['penalty']}, {a['withdrawals']} withdrawals + {a['path_changes']} path changes, "
            f"{a['peers_flapping']} peer(s) flapping, path {a['as_path']}")
