"""Core MOAS (Multiple Origin AS) detection logic + SQLite storage. No network code."""
import json, sqlite3, time, ipaddress

DB_DEFAULT = "moas.db"


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


class Store:
    def __init__(self, db=DB_DEFAULT):
        self.con = sqlite3.connect(db, check_same_thread=False)
        self.con.execute("""CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, prefix TEXT,
            origins TEXT, new_origin INTEGER, expected TEXT, severity TEXT,
            peer_asn TEXT, collector TEXT, as_path TEXT)""")
        self.con.commit()

    def add(self, a):
        self.con.execute(
            "INSERT INTO alerts(ts,prefix,origins,new_origin,expected,severity,peer_asn,collector,as_path)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (a["ts"], a["prefix"], json.dumps(sorted(a["origins"], key=str)), a["new_origin"],
             json.dumps(sorted(a["expected"], key=str)), a["severity"], a["peer_asn"], a["collector"], a["as_path"]))
        self.con.commit()


class MoasDetector:
    """
    Tracks prefix -> {origin_as: last_seen}. When a prefix has >= 2 origins seen inside
    `window` seconds, a MOAS alert is raised (once per new origin, so no alert storms).

    whitelist: {prefix: {asn, ...}} of legitimate origins (e.g. the company's own ASNs).
      - origin not in whitelist for a watched prefix -> severity "high" (likely hijack / misconfig)
      - all origins whitelisted                       -> severity "info" (planned multi-origin)
      - prefix not in whitelist                       -> severity "medium" (unknown, needs review)
    """

    def __init__(self, store=None, window=3600, whitelist=None, min_peers=1):
        self.window = window
        self.store = store
        self.whitelist = {str(ipaddress.ip_network(p)): set(a) for p, a in (whitelist or {}).items()}
        self.min_peers = min_peers
        self.seen = {}      # prefix -> {origin: last_seen_ts}
        self.peers = {}     # (prefix, origin) -> set(peer_asn)
        self.alerted = set()  # (prefix, origin) already reported
        self.stats = {"updates": 0, "announcements": 0, "alerts": 0}

    def _expire(self, prefix, now):
        origins = self.seen.get(prefix, {})
        for o in [o for o, t in origins.items() if now - t > self.window]:
            del origins[o]
            self.peers.pop((prefix, o), None)
            self.alerted.discard((prefix, o))

    def process(self, msg):
        """msg = the 'data' dict of a RIS Live ris_message. Returns list of new alerts."""
        if msg.get("type") != "UPDATE":
            return []
        self.stats["updates"] += 1
        path = msg.get("path") or []
        origins = extract_origins(path)
        if not origins:
            return []
        ts = msg.get("timestamp")
        now = float(ts) if ts is not None else time.time()
        peer = str(msg.get("peer_asn", ""))
        alerts = []
        for ann in msg.get("announcements", []):
            for prefix in ann.get("prefixes", []):
                self.stats["announcements"] += 1
                self._expire(prefix, now)
                cur = self.seen.setdefault(prefix, {})
                for o in origins:
                    cur[o] = now
                    self.peers.setdefault((prefix, o), set()).add(peer)
                if len(cur) < 2:
                    continue
                for o in origins:
                    if (prefix, o) in self.alerted:
                        continue
                    if len(self.peers[(prefix, o)]) < self.min_peers:
                        continue
                    self.alerted.add((prefix, o))
                    expected = self.whitelist.get(prefix, set())
                    if prefix in self.whitelist:
                        sev = "high" if set(cur) - expected else "info"
                    else:
                        sev = "medium"
                    a = dict(ts=now, prefix=prefix, origins=set(cur), new_origin=o, expected=expected,
                             severity=sev, peer_asn=peer, collector=msg.get("host", ""),
                             as_path=flatten_path(path))
                    alerts.append(a)
                    self.stats["alerts"] += 1
                    if self.store:
                        self.store.add(a)
        return alerts
