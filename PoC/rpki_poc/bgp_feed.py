"""bgp_feed.py - turns RIS Live messages (live, or replayed from a file) into simple RouteEvent objects."""

import ipaddress
import json
import time
from dataclasses import dataclass, field
from typing import Iterator

from vrp_store import Network


@dataclass
class RouteEvent:
    """One thing that happened: a prefix announced/withdrawn by one RIS peer, a peer session going down,
    a new VRP file (demo / evaluation), or a timer tick (live mode, so VRPs refresh even when RIS is quiet)."""
    kind: str                                       # announce | withdraw | peer_down | vrp_reload | tick
    prefix: Network | None = None
    origin_asn: int | None = None                   # last AS of the path (None for withdraws / AS_SET)
    as_path: list = field(default_factory=list)
    collector: str = ""                             # RIS collector, e.g. "rrc00"
    peer: str = ""                                  # IP address of the RIS peer
    peer_asn: int = 0
    timestamp: float = 0.0
    file: str = ""                                  # vrp_reload only: the VRP file to load


def origin_from_path(path: list) -> int | None:
    """Origin AS = last element of the AS path. An AS_SET (a list) has no single origin."""
    if not path:
        return None
    last = path[-1]
    if isinstance(last, list):                      # RFC 6811: no single origin -> can never be VALID
        return None
    return int(last)


def parse_data(data: dict) -> list[RouteEvent]:
    """The 'data' part of one RIS Live message -> RouteEvents (one per prefix)."""
    common = dict(collector=data.get("host", ""), peer=str(data.get("peer", "")),
                  peer_asn=int(data.get("peer_asn", 0) or 0), timestamp=float(data.get("timestamp", 0.0) or 0.0))
    kind = data.get("type")
    if kind == "RIS_PEER_STATE":                    # a session reset: that peer's routes are gone
        return [RouteEvent("peer_down", **common)] if data.get("state") == "down" else []
    if kind == "VRP_RELOAD":                        # demo / evaluation only: "the ROAs changed now"
        return [RouteEvent("vrp_reload", file=data.get("file", ""), timestamp=common["timestamp"])]
    if kind != "UPDATE":
        return []
    path = data.get("path", [])
    origin = origin_from_path(path)
    events = []
    for announcement in data.get("announcements", []):
        for text in announcement.get("prefixes", []):
            events.append(RouteEvent("announce", ipaddress.ip_network(text, strict=False), origin, path, **common))
    for text in data.get("withdrawals", []):
        events.append(RouteEvent("withdraw", ipaddress.ip_network(text, strict=False), None, [], **common))
    return events


def parse_ris_message(message: dict) -> list[RouteEvent]:
    """One full RIS Live message ({'type': 'ris_message', 'data': {...}}) -> RouteEvents."""
    if message.get("type") != "ris_message":        # ignore pong, ris_subscribe_ok and similar
        return []
    return parse_data(message.get("data", {}))


def build_subscriptions(prefixes: list[Network], asns: set[int]) -> list[dict]:
    """RIS Live filters: (1) anything ORIGINATED by Cybernet, (2) anything INSIDE Cybernet's prefixes
    (whitelist + ROA prefixes, with more-specifics), (3) peer session state, so dead sessions drop their routes."""
    subs = []
    for asn in sorted(asns):
        subs.append({"type": "ris_subscribe", "data": {"type": "UPDATE", "path": f"{asn}$",
                                                       "socketOptions": {"includeRaw": False}}})
    for p in prefixes:                              # one filter per prefix, like the other PoCs
        subs.append({"type": "ris_subscribe", "data": {"type": "UPDATE", "prefix": str(p), "moreSpecific": True,
                                                       "socketOptions": {"includeRaw": False}}})
    subs.append({"type": "ris_subscribe", "data": {"type": "RIS_PEER_STATE", "socketOptions": {"includeRaw": False}}})
    return subs


class LiveFeed:
    """RIS Live as an endless stream of RouteEvents. Reconnects on errors; resubscribe() reconnects with new filters
    (when Cybernet's ROA prefixes change); yields a 'tick' at least every `tick_seconds` so the caller can refresh VRPs."""

    def __init__(self, url, get_prefixes, asns, tick_seconds=30):
        self.url, self.get_prefixes, self.asns, self.tick_seconds = url, get_prefixes, asns, tick_seconds
        self._resubscribe = False

    def resubscribe(self):
        self._resubscribe = True

    def __iter__(self) -> Iterator[RouteEvent]:
        import websocket                            # third-party package "websocket-client"
        while True:
            ws = None
            try:
                ws = websocket.create_connection(self.url, timeout=self.tick_seconds)
                prefixes = self.get_prefixes()
                for sub in build_subscriptions(prefixes, self.asns):
                    ws.send(json.dumps(sub))
                self._resubscribe = False
                print(f"[feed] connected to RIS Live: {len(prefixes)} prefixes, origins {sorted(self.asns)}", flush=True)
                last_tick = time.time()
                while not self._resubscribe:
                    try:
                        raw = ws.recv()
                    except websocket.WebSocketTimeoutException:
                        ws.send(json.dumps({"type": "ping"}))    # quiet: keep the connection alive
                        raw = None
                    if raw:
                        message = json.loads(raw)
                        if message.get("type") == "ris_error":
                            print(f"[feed] RIS Live error: {message.get('data')}", flush=True)
                        else:
                            yield from parse_ris_message(message)
                    if time.time() - last_tick >= self.tick_seconds:
                        last_tick = time.time()
                        yield RouteEvent("tick", timestamp=last_tick)
                print("[feed] resubscribing with the new prefix list", flush=True)
            except Exception as exc:                # websocket / network / JSON errors: reconnect, never crash
                print(f"[feed] connection problem: {exc!r}; reconnecting in 5 s", flush=True)
                time.sleep(5)
            finally:
                if ws is not None:
                    ws.close()


def replay_events(path: str, delay: float = 0.0) -> Iterator[RouteEvent]:
    """Replay RIS Live messages saved one per line (offline demo). Lines may also be VRP_RELOAD / RIS_PEER_STATE."""
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            msg = json.loads(line)
            events = parse_ris_message(msg) if msg.get("type") == "ris_message" else parse_data(msg.get("data", msg))
            for ev in events:
                yield ev
            if delay:
                time.sleep(delay)


demo_events = replay_events                         # old name, kept so earlier commands still work
