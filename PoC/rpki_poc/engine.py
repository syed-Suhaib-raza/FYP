"""engine.py - the RPKI Invalid detector (deterministic). One object, used by main.py, the tests and the evaluation.

Chosen approach (RPKI_Invalid doc, "Our Solution"): Routinator VRPs + RFC 6811 validation + cause/severity rules.

How it works
  1. route table   : the route every RIS peer currently carries for each watched prefix, (prefix, collector, peer)
                     -> origin, AS path. Announcements replace, withdrawals and peer-down remove.
  2. validation    : every (prefix, origin) is validated with RFC 6811 against the current VRPs (validator.py).
  3. alertable?    : Invalid and touching Cybernet, or NotFound inside Cybernet space (rules.is_alertable).
  4. peer threshold: an alert is PENDING until MIN_PEERS different RIS peers carry the route, then ACTIVE. It is
                     RESOLVED only when no peer carries it any more (so it does not flip on and off).
  5. severity      : rules.assess(): foreign first-time origin CRITICAL, customer / own mistakes HIGH, NotFound LOW.
                     "First time" uses origin_history: has this origin announced this prefix in an earlier episode?
  6. VRP change    : reload_vrps() reports ROA changes for Cybernet (roa_watch.py) and RE-VALIDATES every route in the
                     table, so a ROA edit that makes a stable route Invalid raises an alert without any BGP update.
"""

import ipaddress
import time
from collections import Counter
from dataclasses import dataclass, field

from roa_watch import diff_vrps, expiring
from rules import assess, is_alertable
from validator import validate_route

PENDING, ACTIVE, RESOLVED, DROPPED = "PENDING", "ACTIVE", "RESOLVED", "DROPPED"


@dataclass
class Route:
    """What one RIS peer currently carries for one prefix."""
    prefix: str
    origin: int | None
    path: list = field(default_factory=list)
    collector: str = ""
    peer: str = ""
    peer_asn: int = 0
    ts: float = 0.0


class RpkiDetector:
    def __init__(self, vrps, store=None, whitelist=None, customers=None, monitored=None, min_peers=2,
                 revalidate=True, cross_check=None, source="live", warn_hours=24, history_write_every=60):
        self.vrps, self.store = vrps, store
        self.monitored = set(monitored or ())
        self.customers = set(customers or ())
        self.cyber_nets = [ipaddress.ip_network(p, strict=False) for p in (whitelist or {})]
        self.min_peers, self.revalidate, self.cross_check = max(1, min_peers), revalidate, cross_check
        self.source, self.warn_hours, self.history_write_every = source, warn_hours, history_write_every

        self.routes: dict[tuple, Route] = {}            # (prefix, collector, peer) -> Route
        self.by_prefix: dict[str, set] = {}             # prefix -> route keys
        self.episode: dict[tuple, float] = {}           # (prefix, origin) -> when the current episode started
        self.alerts: dict[tuple, dict] = {}             # (prefix, origin, state) -> alert
        self.alerts_by_prefix: dict[str, set] = {}
        self.history: dict[tuple, list] = {}            # (prefix, origin) -> [first_seen, last_seen]
        self._cache: dict[tuple, object] = {}           # (prefix, origin) -> ValidationResult for current VRPs
        self._warned: set = set()                       # expiry warnings already sent
        self.counts = Counter()                         # announcements per RPKI state
        self.stats = Counter()
        self._n = 0

        if store is not None:                           # continue where the last run stopped
            for a in store.load_alerts():
                o = a["origin_asn"]
                key = (a["prefix"], None if o == -1 else o, a["state"])
                a["origin_asn"] = key[1]
                if a["status"] in (ACTIVE, PENDING):    # the route table starts empty: re-learn from the feed
                    a["status"], a["seen_by_peers"], a["peers"] = (RESOLVED if a["status"] == ACTIVE else DROPPED), 0, []
                self._index(key, a)
            self.history = {(p, None if o == -1 else o): list(v) for (p, o), v in store.load_history().items()}
            self._n = store.next_alert_number() - 1
        self.relevant_vrps = vrps.relevant(self.monitored, self.cyber_nets)

    # ---- helpers -----------------------------------------------------------------------------------------
    def in_cybernet(self, prefix: str) -> bool:
        net = ipaddress.ip_network(prefix, strict=False)
        return any(net.version == n.version and net.subnet_of(n) for n in self.cyber_nets)

    def result(self, prefix: str, origin):
        k = (prefix, origin)
        if k not in self._cache:
            self._cache[k] = validate_route(ipaddress.ip_network(prefix, strict=False), origin, self.vrps)
        return self._cache[k]

    def _index(self, key, a):
        self.alerts[key] = a
        self.alerts_by_prefix.setdefault(key[0], set()).add(key)

    def active_alert(self, prefix: str, origin):
        """The ACTIVE alert for (prefix, origin), or None. Used by the evaluation and the tests."""
        for key in self.alerts_by_prefix.get(prefix, ()):
            if key[1] == origin and self.alerts[key]["status"] == ACTIVE:
                return self.alerts[key]
        return None

    def _touch_history(self, prefix, origin, ts):
        h = self.history.get((prefix, origin))
        if h is None:
            self.history[(prefix, origin)] = [ts, ts]
            if self.store:
                self.store.save_history(prefix, origin, ts, ts)
        elif ts - h[1] >= self.history_write_every:
            h[1] = ts
            if self.store:
                self.store.save_history(prefix, origin, h[0], ts)

    def _save(self, a, event=None, detail=""):
        if self.store:
            self.store.save_alert(a, event, detail)

    # ---- input: route events -----------------------------------------------------------------------------
    def process(self, ev) -> list[dict]:
        """ev has .kind ('announce' | 'withdraw' | 'peer_down'), .prefix, .origin_asn, .as_path, .collector, .peer,
        .peer_asn, .timestamp. Returns the alert changes it caused."""
        ts = ev.timestamp or time.time()
        touched = set()
        if ev.kind == "announce":
            prefix = str(ev.prefix)
            key = (prefix, ev.collector, ev.peer)
            self.routes[key] = Route(prefix, ev.origin_asn, list(ev.as_path), ev.collector, ev.peer, ev.peer_asn, ts)
            self.by_prefix.setdefault(prefix, set()).add(key)
            self._touch_history(prefix, ev.origin_asn, ts)
            self.counts[self.result(prefix, ev.origin_asn).state] += 1
            self.stats["announcements"] += 1
            touched.add(prefix)
        elif ev.kind == "withdraw":
            prefix = str(ev.prefix)
            key = (prefix, ev.collector, ev.peer)
            self.stats["withdrawals"] += 1
            if self.routes.pop(key, None) is not None:
                self.by_prefix[prefix].discard(key)
                touched.add(prefix)
        elif ev.kind == "peer_down":
            self.stats["peer_down"] += 1
            for key in [k for k in self.routes if (k[1], k[2]) == (ev.collector, ev.peer)]:
                del self.routes[key]
                self.by_prefix[key[0]].discard(key)
                touched.add(key[0])
        return self._reconcile(touched, ts)

    # ---- input: a new VRP set ----------------------------------------------------------------------------
    def reload_vrps(self, new_vrps, ts=None) -> tuple[list[dict], bool]:
        """Swap in a new VRP set. Returns (changes, cybernet_prefixes_changed). Changes are ROA changes for Cybernet
        and, when revalidation is on, the alerts that the new VRPs open or resolve."""
        ts = time.time() if ts is None else ts
        new_rel = new_vrps.relevant(self.monitored, self.cyber_nets)
        old_pfx = set(self.vrps.prefixes_for_asns(self.monitored))
        roa = diff_vrps(self.relevant_vrps, new_rel, ts)
        for c in expiring(new_rel, ts, self.warn_hours):
            k = (c["prefix"], c["asn"])             # warn once per ROA
            if k not in self._warned:
                self._warned.add(k)
                roa.append(c)
        out = []
        for c in roa:
            if self.store:
                self.store.add_roa_change(c)
            out.append(dict(kind="roa", change=c))
        self.vrps, self.relevant_vrps, self._cache = new_vrps, new_rel, {}
        self.stats["vrp_reloads"] += 1
        if self.revalidate:
            out += self._reconcile(set(self.by_prefix), ts, reason="VRP set changed")
        return out, set(new_vrps.prefixes_for_asns(self.monitored)) != old_pfx

    # ---- core: bring alerts in line with the route table -------------------------------------------------
    def _reconcile(self, prefixes, ts, reason="") -> list[dict]:
        out = []
        for p in prefixes:
            groups: dict = {}
            for key in self.by_prefix.get(p, ()):
                r = self.routes[key]
                groups.setdefault(r.origin, []).append(r)
            for k in [k for k in self.episode if k[0] == p and k[1] not in groups]:
                del self.episode[k]                     # that origin's episode ended
            desired = {}
            for origin, rs in groups.items():
                self.episode.setdefault((p, origin), min(r.ts for r in rs))
                res = self.result(p, origin)
                if is_alertable(res, origin, monitored=self.monitored, in_cybernet_space=self.in_cybernet(p)):
                    desired[(p, origin, res.state)] = (res, rs)
            for key in list(self.alerts_by_prefix.get(p, ())):
                if key not in desired and self.alerts[key]["status"] in (ACTIVE, PENDING):
                    out += self._vanish(key, ts, reason or "no RIS peer carries this route any more")
            for key, (res, rs) in desired.items():
                out += self._upsert(key, res, rs, ts)
        return out

    def _origin_known(self, prefix, origin) -> bool:
        h = self.history.get((prefix, origin))
        start = self.episode.get((prefix, origin))
        return bool(h and start is not None and h[0] < start)

    def _assess(self, res, origin, prefix):
        return assess(res, origin, monitored=self.monitored, customers=self.customers,
                      origin_known=self._origin_known(prefix, origin))

    def _upsert(self, key, res, rs, ts) -> list[dict]:
        prefix, origin, state = key
        peers = sorted({f"{r.collector}|{r.peer}" for r in rs})
        newest = max(rs, key=lambda r: r.ts)
        a = self.alerts.get(key)
        if a is None:
            self._n += 1
            a = dict(alert_id=f"RPKI-{self._n:05d}", prefix=prefix, origin_asn=origin, state=state, status=PENDING,
                     explanation=res.explanation, as_path=newest.path, seen_by_peers=len(peers), peers=peers,
                     first_seen=ts, last_seen=ts, activated_at=None, resolved_at=None, routinator_check=None,
                     authorised_vrps=[dict(prefix=str(v.prefix), max_length=v.max_length, asn=v.asn, ta=v.ta)
                                      for v in res.covering_vrps], source=self.source)
            a.update(self._assess(res, origin, prefix))
            self._index(key, a)
            self._save(a, "SEEN", "first RIS peer carries it; waiting for more peers" if len(peers) < self.min_peers else "")
        a.update(seen_by_peers=len(peers), peers=peers, last_seen=ts, as_path=newest.path,
                 explanation=res.explanation)
        if len(peers) >= self.min_peers and a["status"] != ACTIVE:
            event = "REOPENED" if a["status"] == RESOLVED else "ACTIVE"
            a.update(self._assess(res, origin, prefix))        # severity is decided when the alert goes ACTIVE
            a.update(status=ACTIVE, activated_at=ts, resolved_at=None)
            if self.cross_check is not None:
                a["routinator_check"] = self.cross_check(prefix, origin)
            self._save(a, event, f"seen by {len(peers)} RIS peers")
            self.stats["alerts_" + event.lower()] += 1
            return [dict(kind="alert", event=event, alert=a)]
        if a["status"] == DROPPED:
            a["status"] = PENDING
        self._save(a)
        return []

    def _vanish(self, key, ts, reason) -> list[dict]:
        a = self.alerts[key]
        a.update(seen_by_peers=0, peers=[], last_seen=ts)
        if a["status"] == ACTIVE:
            a.update(status=RESOLVED, resolved_at=ts)
            self._save(a, "RESOLVED", reason)
            self.stats["alerts_resolved"] += 1
            return [dict(kind="alert", event="RESOLVED", alert=a)]
        a["status"] = DROPPED                            # never reached MIN_PEERS: not a NOC alert
        self._save(a, "DROPPED", reason)
        return []

    # ---- status for the dashboard ------------------------------------------------------------------------
    def status(self) -> dict:
        by = Counter(a["status"] for a in self.alerts.values())
        return dict(routes_tracked=len(self.routes), prefixes_tracked=sum(1 for v in self.by_prefix.values() if v),
                    alerts_active=by[ACTIVE], alerts_pending=by[PENDING], alerts_resolved=by[RESOLVED],
                    state_counts=dict(self.counts), stats=dict(self.stats))
