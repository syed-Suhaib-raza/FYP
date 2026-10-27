"""alert_store.py - keeps one alert per (prefix, origin, class) and tracks which RIS peers still see it."""

import json                                         # alerts are saved as JSON text
from datetime import datetime, timezone             # readable UTC time stamps


def _iso(ts: float) -> str:
    """Unix seconds -> '2026-10-21T09:00:10+00:00'."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


class AlertStore:
    """In-memory list of alerts, mirrored to a JSON Lines file."""

    def __init__(self, path: str):
        self.path = path                            # output file, e.g. alerts.jsonl
        self.alerts = {}                            # key -> alert dictionary
        self.viewers = {}                           # key -> set of (collector, peer) that currently carry it
        self._next_id = 1                           # counter for readable IDs: RPKI-00001, RPKI-00002 ...

    @staticmethod
    def key_of(result) -> tuple:
        """What makes an alert unique: the same prefix, origin and Invalid class."""
        return (result.prefix, result.origin_asn, result.state)

    def is_known(self, key) -> bool:
        """True if this problem already has an ACTIVE alert (so no need to cross-check again)."""
        return key in self.alerts and self.alerts[key]["status"] == "ACTIVE"

    def _write(self, alert: dict, event: str) -> None:
        """Append one line to the alert file: a copy of the alert plus what just happened."""
        record = dict(alert, event=event,           # event = NEW, REOPENED or RESOLVED
                      written_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        with open(self.path, "a", encoding="utf-8") as fh:   # "a" = append, never overwrite history
            fh.write(json.dumps(record) + "\n")    # one JSON object per line (JSON Lines)

    def record_invalid(self, result, event, severity, meaning, action, cross_check=None):
        """Store one Invalid sighting. Returns (alert, changed); changed=True means 'print it'."""
        key = self.key_of(result)                   # which problem this is
        viewer = (event.collector, event.peer)      # which RIS peer saw it
        when = _iso(event.timestamp)                # when the collector received it

        if key not in self.alerts:                  # FIRST time we see this problem -> new alert
            alert = {
                "alert_id": f"RPKI-{self._next_id:05d}",          # e.g. RPKI-00001
                "status": "ACTIVE",                 # ACTIVE until no peer carries the route
                "state": result.state,              # INVALID_AS / INVALID_ML / INVALID_AS_AND_ML
                "severity": severity,               # CRITICAL or HIGH (decided in main.py)
                "prefix": result.prefix,            # the announced prefix
                "origin_asn": result.origin_asn,    # who originated it
                "as_path": event.as_path,           # AS path of the first sighting (evidence)
                "authorised_vrps": [{"prefix": str(v.prefix), "max_length": v.max_length,
                                     "asn": v.asn, "ta": v.ta} for v in result.covering_vrps],
                "explanation": result.explanation,  # which rule failed
                "likely_meaning": meaning,          # what it probably means for Cybernet
                "suggested_action": action,         # what the NOC should do next
                "routinator_cross_check": cross_check,   # Routinator's own verdict (live mode)
                "first_seen": when,                 # first sighting time
                "last_seen": when,                  # updated on every new sighting
                "seen_by_peers": 1,                 # how many RIS peers currently carry it
            }
            self._next_id += 1                      # next alert gets the next number
            self.alerts[key] = alert                # remember the alert
            self.viewers[key] = {viewer}            # remember who sees it
            self._write(alert, "NEW")               # save to file
            return alert, True                      # print it

        alert = self.alerts[key]                    # KNOWN problem -> just update it
        self.viewers[key].add(viewer)               # one more peer may now see it
        alert["last_seen"] = when                   # refresh the time
        alert["seen_by_peers"] = len(self.viewers[key])   # refresh the count
        if alert["status"] == "RESOLVED":           # it had gone away and has come back
            alert["status"] = "ACTIVE"
            self._write(alert, "REOPENED")
            return alert, True                      # print it again
        return alert, False                         # nothing new to print

    def record_gone(self, prefix: str, collector: str, peer: str, keep_key=None) -> list[dict]:
        """This peer no longer carries its old route for `prefix` (withdrawn or replaced)."""
        viewer = (collector, peer)                  # the peer that changed its route
        resolved = []                               # alerts that just closed
        for key, viewers in self.viewers.items():   # look at every alert
            if key[0] != prefix or key == keep_key or viewer not in viewers:
                continue                            # other prefix, the route we keep, or not this peer
            viewers.discard(viewer)                 # this peer stopped carrying that Invalid route
            alert = self.alerts[key]
            alert["seen_by_peers"] = len(viewers)   # update the count
            if not viewers and alert["status"] == "ACTIVE":   # nobody carries it any more
                alert["status"] = "RESOLVED"
                self._write(alert, "RESOLVED")      # save the closing event
                resolved.append(alert)
        return resolved                             # main.py prints these