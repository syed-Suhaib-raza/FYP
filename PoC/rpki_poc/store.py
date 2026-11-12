"""store.py - SQLite storage for alerts, alert history, origin history, ROA changes and run status.

The dashboard reads the same file. WAL mode lets the dashboard read while the detector writes.
Tables
    alerts          one row per (prefix, origin, state): current status, severity, evidence
    alert_events    every status change of every alert (NEW, ACTIVE, RESOLVED, REOPENED)
    origin_history  first/last time each origin AS was seen for each prefix (for "seen before?")
    roa_changes     ROA added / removed / maxLength changed / expiring, for Cybernet
    meta            key/value status: VRP source, VRP load time, counts per RPKI state ...
"""

import json
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts(
    alert_id TEXT PRIMARY KEY, prefix TEXT, origin_asn INTEGER, state TEXT, cause TEXT, severity TEXT,
    status TEXT, explanation TEXT, likely_meaning TEXT, suggested_action TEXT, authorised_vrps TEXT,
    as_path TEXT, seen_by_peers INTEGER, peers TEXT, first_seen REAL, last_seen REAL, activated_at REAL,
    resolved_at REAL, routinator_check TEXT, source TEXT);
CREATE TABLE IF NOT EXISTS alert_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT, ts REAL, event TEXT, status TEXT, severity TEXT,
    seen_by_peers INTEGER, detail TEXT);
CREATE TABLE IF NOT EXISTS origin_history(
    prefix TEXT, origin_asn INTEGER, first_seen REAL, last_seen REAL, PRIMARY KEY(prefix, origin_asn));
CREATE TABLE IF NOT EXISTS roa_changes(
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, change TEXT, prefix TEXT, asn INTEGER, old_max INTEGER,
    new_max INTEGER, severity TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
"""

ALERT_COLS = ["alert_id", "prefix", "origin_asn", "state", "cause", "severity", "status", "explanation",
              "likely_meaning", "suggested_action", "authorised_vrps", "as_path", "seen_by_peers", "peers",
              "first_seen", "last_seen", "activated_at", "resolved_at", "routinator_check", "source"]


class Store:
    def __init__(self, path: str, log_path: str | None = None):
        self.path, self.log_path = path, log_path
        self.con = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.executescript(SCHEMA)
        self.con.commit()

    # ---- alerts ------------------------------------------------------------------------------------------
    def save_alert(self, a: dict, event: str | None = None, detail: str = "") -> None:
        row = dict(a)
        for k in ("authorised_vrps", "peers", "as_path", "routinator_check"):
            if not isinstance(row.get(k), (str, type(None))):
                row[k] = json.dumps(row[k])
        self.con.execute(f"INSERT OR REPLACE INTO alerts({','.join(ALERT_COLS)}) VALUES({','.join('?' * len(ALERT_COLS))})",
                         [row.get(c) for c in ALERT_COLS])
        if event:
            self.con.execute("INSERT INTO alert_events(alert_id, ts, event, status, severity, seen_by_peers, detail) "
                             "VALUES(?,?,?,?,?,?,?)", (a["alert_id"], a["last_seen"], event, a["status"], a["severity"],
                                                       a["seen_by_peers"], detail))
            if self.log_path:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(dict(a, event=event, detail=detail), default=str) + "\n")
        self.con.commit()

    def load_alerts(self) -> list[dict]:
        cur = self.con.execute(f"SELECT {','.join(ALERT_COLS)} FROM alerts")
        out = []
        for r in cur.fetchall():
            a = dict(zip(ALERT_COLS, r))
            for k in ("authorised_vrps", "peers", "as_path", "routinator_check"):
                if a.get(k):
                    try:
                        a[k] = json.loads(a[k])
                    except ValueError:
                        pass
            out.append(a)
        return out

    def next_alert_number(self) -> int:
        r = self.con.execute("SELECT COUNT(*) FROM alerts").fetchone()
        return (r[0] or 0) + 1

    # ---- origin history ----------------------------------------------------------------------------------
    def load_history(self) -> dict:
        return {(p, o): (f, l) for p, o, f, l in self.con.execute(
            "SELECT prefix, origin_asn, first_seen, last_seen FROM origin_history")}

    def save_history(self, prefix: str, origin, first: float, last: float) -> None:
        self.con.execute("INSERT INTO origin_history(prefix, origin_asn, first_seen, last_seen) VALUES(?,?,?,?) "
                         "ON CONFLICT(prefix, origin_asn) DO UPDATE SET last_seen=excluded.last_seen",
                         (prefix, -1 if origin is None else origin, first, last))
        self.con.commit()

    # ---- ROA changes / meta ------------------------------------------------------------------------------
    def add_roa_change(self, c: dict) -> None:
        self.con.execute("INSERT INTO roa_changes(ts, change, prefix, asn, old_max, new_max, severity, detail) "
                         "VALUES(?,?,?,?,?,?,?,?)", (c["ts"], c["change"], c["prefix"], c["asn"], c["old_max"],
                                                     c["new_max"], c["severity"], c["detail"]))
        self.con.commit()
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(dict(c, event="ROA_CHANGE")) + "\n")

    def set_meta(self, **kv) -> None:
        for k, v in kv.items():
            self.con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)", (k, json.dumps(v, default=str)))
        self.con.commit()

    def get_meta(self, key, default=None):
        r = self.con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(r[0]) if r else default
