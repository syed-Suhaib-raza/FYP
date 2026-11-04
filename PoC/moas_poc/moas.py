"""Layer 1 (deterministic): the MOAS catalog. No network code, no judgement.

Records every instance of a prefix being announced by 2+ different origin ASes inside a time window, plus
the raw evidence (who announced it, who saw it, which paths, when). It never decides whether a MOAS is good
or bad: no severity, no whitelist. That is the job of layer 2 (ai_layer.py), which reads this catalog.

Data model (SQLite):
  moas_events   one row per conflict episode of a prefix (opens when a 2nd origin becomes active,
                closes when fewer than 2 origins are still active). `revision` goes up when a new
                origin joins and when the episode closes, so layer 2 knows when to look again.
  moas_origins  one row per (event, origin): first/last seen, update count, peers, collectors, AS paths.
"""
import json, sqlite3, time

DB_DEFAULT = "moas.db"
MAX_PATHS = 5  # distinct AS paths kept per (event, origin) as evidence


def extract_origins(path):
    """Origin AS = last hop of the AS path. A trailing AS_SET (aggregate) is kept as ONE origin key,
    e.g. "{65010,65011}", so an aggregate does not raise a MOAS against itself."""
    if not path:
        return []
    last = path[-1]
    if isinstance(last, list):
        return ['{' + ','.join(map(str, sorted(map(int, last)))) + '}']
    return [int(last)]


def flatten_path(path):
    out = []
    for hop in path:
        out.append("{" + ",".join(map(str, hop)) + "}" if isinstance(hop, list) else str(hop))
    return " ".join(out)


class OriginObs:
    """Evidence for one origin AS of one prefix."""
    __slots__ = ("origin", "first_seen", "last_seen", "n_updates", "peers", "collectors", "paths")

    def __init__(self, origin, ts):
        self.origin, self.first_seen, self.last_seen = origin, ts, ts
        self.n_updates, self.peers, self.collectors, self.paths = 0, set(), set(), []

    def touch(self, ts, peer, collector, path_str):
        self.last_seen = max(self.last_seen, ts)  # collectors can deliver slightly out of order
        self.n_updates += 1
        if peer:
            self.peers.add(peer)
        if collector:
            self.collectors.add(collector)
        if path_str not in self.paths and len(self.paths) < MAX_PATHS:
            self.paths.append(path_str)

    @classmethod
    def from_dict(cls, d):
        o = cls(d["origin"], d["first_seen"])
        o.last_seen, o.n_updates = d["last_seen"], d["n_updates"]
        o.peers, o.collectors, o.paths = set(d["peers"]), set(d["collectors"]), list(d["paths"])
        return o

    def to_dict(self):
        return dict(origin=self.origin, first_seen=self.first_seen, last_seen=self.last_seen,
                    n_updates=self.n_updates, peers=sorted(self.peers), collectors=sorted(self.collectors),
                    paths=list(self.paths))


class MoasEvent:
    """One MOAS episode for one prefix."""

    def __init__(self, prefix, ts):
        self.id = None
        self.prefix = prefix
        self.first_seen = self.last_seen = ts
        self.status = "open"
        self.revision = 1
        self.origins = {}      # origin (str) -> OriginObs
        self.kind = "new"      # "new" | "origin_added" | "closed": why process()/sweep() returned it

    @classmethod
    def from_dict(cls, d, keep_id=False):
        ev = cls(d["prefix"], d["first_seen"])
        ev.id = d["id"] if keep_id else None
        ev.last_seen, ev.status, ev.revision = d["last_seen"], d["status"], d["revision"]
        ev.origins = {o["origin"]: OriginObs.from_dict(o) for o in d["origins"]}
        return ev

    def to_dict(self):
        obs = sorted(self.origins.values(), key=lambda o: (o.first_seen, o.origin))
        return dict(id=self.id, prefix=self.prefix, first_seen=self.first_seen, last_seen=self.last_seen,
                    status=self.status, revision=self.revision, origins=[o.to_dict() for o in obs])


class Store:
    def __init__(self, db=DB_DEFAULT):
        self.con = sqlite3.connect(db, check_same_thread=False, timeout=30)
        try:  # lets the dashboard / AI layer read while the catalog writes
            self.con.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass
        self.con.executescript("""
            CREATE TABLE IF NOT EXISTS moas_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT, prefix TEXT, first_seen REAL, last_seen REAL,
                status TEXT, revision INTEGER, origins TEXT);
            CREATE TABLE IF NOT EXISTS moas_origins(
                event_id INTEGER, origin TEXT, first_seen REAL, last_seen REAL, n_updates INTEGER,
                peers TEXT, collectors TEXT, paths TEXT, PRIMARY KEY(event_id, origin));
            CREATE INDEX IF NOT EXISTS ix_moas_events_prefix ON moas_events(prefix);
        """)
        self.con.commit()

    def save(self, ev):
        if ev.id is None:
            cur = self.con.execute(
                "INSERT INTO moas_events(prefix,first_seen,last_seen,status,revision,origins) VALUES(?,?,?,?,?,?)",
                (ev.prefix, ev.first_seen, ev.last_seen, ev.status, ev.revision, self._origin_list(ev)))
            ev.id = cur.lastrowid
        else:
            self.con.execute(
                "UPDATE moas_events SET last_seen=?, status=?, revision=?, origins=? WHERE id=?",
                (ev.last_seen, ev.status, ev.revision, self._origin_list(ev), ev.id))
        for o in ev.origins.values():
            self.con.execute(
                "INSERT OR REPLACE INTO moas_origins VALUES(?,?,?,?,?,?,?,?)",
                (ev.id, o.origin, o.first_seen, o.last_seen, o.n_updates,
                 json.dumps(sorted(o.peers)), json.dumps(sorted(o.collectors)), json.dumps(o.paths)))
        self.con.commit()

    @staticmethod
    def _origin_list(ev):
        return json.dumps([o.origin for o in sorted(ev.origins.values(), key=lambda o: (o.first_seen, o.origin))])

    def reset(self):
        """Empty the catalog (and any layer-2 verdicts, which would otherwise be orphaned)."""
        for t in ("moas_origins", "moas_events", "verdicts"):
            try:
                self.con.execute(f"DELETE FROM {t}")
            except sqlite3.OperationalError:
                pass  # verdicts table only exists once layer 2 has run
        self.con.commit()


def read_events(con, where="1=1", params=()):
    """Catalog rows as plain dicts (same shape as MoasEvent.to_dict), for layer 2 and the dashboard."""
    out = []
    for id_, prefix, fs, ls, status, rev in con.execute(
            f"SELECT id,prefix,first_seen,last_seen,status,revision FROM moas_events WHERE {where} ORDER BY id", params):
        origins = []
        for o, ofs, ols, n, peers, cols, paths in con.execute(
                "SELECT origin,first_seen,last_seen,n_updates,peers,collectors,paths FROM moas_origins "
                "WHERE event_id=? ORDER BY first_seen, origin", (id_,)):
            origins.append(dict(origin=o, first_seen=ofs, last_seen=ols, n_updates=n, peers=json.loads(peers),
                                collectors=json.loads(cols), paths=json.loads(paths)))
        out.append(dict(id=id_, prefix=prefix, first_seen=fs, last_seen=ls, status=status, revision=rev,
                        origins=origins))
    return out


class MoasCatalog:
    """
    Tracks prefix -> {origin: evidence}. An origin is *active* for `window` seconds after it was last
    announced. When a prefix has >= 2 active origins a MOAS event is opened (and persisted); it stays open
    while >= 2 origins remain active. Every instance is recorded: there is no filtering and no severity.

    process(msg) -> events that were opened, gained a new origin, or closed (event.kind says which)
    sweep(now)   -> events that closed because origins aged out (call periodically on a live feed)
    flush()      -> persist evidence counters (peers, update counts) accumulated since the last save
    """

    def __init__(self, store=None, window=3600):
        self.window = window
        self.store = store
        self.active = {}   # prefix -> {origin: OriginObs} for origins announced within `window`
        self.open = {}     # prefix -> open MoasEvent
        self._dirty = set()
        self._closed = []  # events closed since the last process()/sweep() call returned
        self.stats = {"updates": 0, "announcements": 0, "events_opened": 0, "events_closed": 0}

    # -- internals -------------------------------------------------------------------------------------
    def _close(self, ev):
        ev.status, ev.kind = "closed", "closed"
        ev.revision += 1
        self.open.pop(ev.prefix, None)
        self.stats["events_closed"] += 1
        self._closed.append(ev)
        self._persist(ev)

    def _drain_closed(self):
        out, self._closed = self._closed, []
        return out

    def _expire(self, prefix, now):
        active = self.active.get(prefix)
        if not active:
            return None
        for o in [o for o, ob in active.items() if now - ob.last_seen > self.window]:
            del active[o]
        closed = None
        ev = self.open.get(prefix)
        if ev is not None and len(active) < 2:
            self._close(ev)
            closed = ev
        if not active:
            del self.active[prefix]
        return closed

    def _persist(self, ev):
        self._dirty.discard(ev)
        if self.store:
            self.store.save(ev)

    def _observe(self, prefix, origins, now, peer, collector, path_str):
        self._expire(prefix, now)
        active = self.active.setdefault(prefix, {})
        ev = self.open.get(prefix)
        result = None
        for o in origins:
            obs = ev.origins.get(o) if ev is not None else None
            if obs is None:
                obs = active.get(o)
            if obs is None:
                obs = OriginObs(o, now)
            obs.touch(now, peer, collector, path_str)
            active[o] = obs
            if ev is not None:
                ev.last_seen = max(ev.last_seen, now)
                if o not in ev.origins:
                    ev.origins[o] = obs
                    ev.revision += 1
                    ev.kind, result = "origin_added", ev
                self._dirty.add(ev)
        if ev is None and len(active) >= 2:
            ev = MoasEvent(prefix, now)
            ev.origins = dict(active)
            self.open[prefix] = ev
            self.stats["events_opened"] += 1
            result = ev
        if result is not None:
            self._persist(result)
        return result

    # -- public ----------------------------------------------------------------------------------------
    def process(self, msg):
        """msg = the 'data' dict of a RIS Live ris_message. Withdrawals are ignored (see README)."""
        if msg.get("type") != "UPDATE":
            return []
        self.stats["updates"] += 1
        path = msg.get("path") or []
        origins = [str(o) for o in extract_origins(path)]
        if not origins:
            return []
        ts = msg.get("timestamp")
        now = float(ts) if ts is not None else time.time()
        peer, collector, path_str = str(msg.get("peer_asn", "")), msg.get("host", ""), flatten_path(path)
        changed = {}
        for ann in msg.get("announcements", []):
            for prefix in ann.get("prefixes", []):
                self.stats["announcements"] += 1
                ev = self._observe(prefix, origins, now, peer, collector, path_str)
                if ev is not None:
                    changed[prefix] = ev
        return self._drain_closed() + list(changed.values())

    def sweep(self, now=None):
        """Expire stale origins everywhere; return the events that closed as a result."""
        now = time.time() if now is None else now
        for prefix in list(self.active):
            self._expire(prefix, now)
        return self._drain_closed()

    def flush(self):
        for ev in list(self._dirty):
            self._persist(ev)

    def tick(self, now=None):
        closed = self.sweep(now)
        self.flush()
        return closed


def fmt_event(ev):
    t = time.strftime("%H:%M:%S", time.gmtime(ev.last_seen))
    origins = ", ".join("AS" + o.origin for o in sorted(ev.origins.values(), key=lambda o: (o.first_seen, o.origin)))
    what = {"new": "NEW   ", "origin_added": "+ORIGIN", "closed": "CLOSED"}.get(ev.kind, ev.kind)
    return f"[{t}] MOAS/{what} #{ev.id} {ev.prefix} origins=[{origins}] peers={len(set().union(*[o.peers for o in ev.origins.values()]))}"
