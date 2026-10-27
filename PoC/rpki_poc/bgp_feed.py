"""bgp_feed.py - turns RIS Live messages (live, or replayed from a file) into simple RouteEvent objects."""

import ipaddress                                    # parse the prefixes inside each message
import json                                         # RIS Live sends and receives JSON text
import time                                         # sleep between reconnects and between demo lines
from dataclasses import dataclass, field            # small record class for one route event
from typing import Iterator                         # type hint for generator functions

import websocket                                    # third-party package "websocket-client"

from vrp_store import Network                       # IPv4/IPv6 prefix type


@dataclass
class RouteEvent:
    """One prefix announced or withdrawn by one RIS peer router."""
    kind: str                                       # "announce" or "withdraw"
    prefix: Network                                 # the prefix in the message
    origin_asn: int | None                          # last AS of the path (None for withdraws / AS_SET)
    as_path: list = field(default_factory=list)     # full AS path, kept as evidence for the alert
    collector: str = ""                             # RIS collector name, e.g. "rrc00"
    peer: str = ""                                  # IP address of the RIS peer that sent the update
    peer_asn: int = 0                               # AS number of that peer
    timestamp: float = 0.0                          # Unix time when the collector received it


def origin_from_path(path: list) -> int | None:
    """Origin AS = last element of the AS path. If it is an AS_SET (a list) there is no single origin."""
    if not path:                                    # an empty path: nothing to read
        return None
    last = path[-1]                                 # RIS Live lists the path from neighbour to origin
    if isinstance(last, list):                      # an AS_SET arrives as a JSON array, e.g. [64500, 64511]
        return None                                 # RFC 6811: no single origin -> can never be VALID
    return int(last)                                # normal case: an integer ASN


def parse_ris_message(message: dict) -> list[RouteEvent]:
    """Convert one RIS Live JSON message into a list of RouteEvents (one per prefix)."""
    if message.get("type") != "ris_message":        # ignore pong, ris_subscribe_ok and similar
        return []
    data = message.get("data", {})                  # the BGP message itself
    if data.get("type") != "UPDATE":                # only UPDATE messages carry routes
        return []

    path = data.get("path", [])                     # AS path of the announcements in this UPDATE
    origin = origin_from_path(path)                 # every prefix in this UPDATE shares this origin
    common = dict(collector=data.get("host", ""),   # fields copied into every event from this message
                  peer=str(data.get("peer", "")),
                  peer_asn=int(data.get("peer_asn", 0)),
                  timestamp=float(data.get("timestamp", 0.0)))

    events = []                                     # results
    for announcement in data.get("announcements", []):     # announcements are grouped by next hop
        for text in announcement.get("prefixes", []):       # each group lists one or more prefixes
            events.append(RouteEvent("announce", ipaddress.ip_network(text, strict=False),
                                     origin, path, **common))
    for text in data.get("withdrawals", []):                # prefixes this peer no longer has
        events.append(RouteEvent("withdraw", ipaddress.ip_network(text, strict=False),
                                 None, [], **common))
    return events                                   # may be empty, one, or many events


def build_subscriptions(prefixes: list[Network], asns: set[int]) -> list[dict]:
    """RIS Live filters: (1) anything ORIGINATED by Cybernet, (2) anything INSIDE Cybernet's prefixes."""
    subs = []                                       # list of ris_subscribe messages
    for asn in sorted(asns):                        # one subscription per Cybernet ASN
        subs.append({"type": "ris_subscribe",
                     "data": {"type": "UPDATE", "path": f"{asn}$"}})   # "$" = this ASN must be the origin
    if prefixes:                                    # only if Cybernet has ROA-covered prefixes
        subs.append({"type": "ris_subscribe",
                     "data": {"type": "UPDATE",
                              "prefix": [str(p) for p in prefixes],    # Cybernet's prefixes
                              "moreSpecific": True}})                  # also send /23, /24 ... inside them
    return subs


def live_events(prefixes, asns, url) -> Iterator[RouteEvent]:
    """Connect to RIS Live and yield RouteEvents forever; reconnect if the connection drops."""
    while True:                                     # outer loop = reconnect loop
        ws = None                                   # no socket yet
        try:
            ws = websocket.create_connection(url, timeout=60)    # open the WebSocket, 60 s read timeout
            for sub in build_subscriptions(prefixes, asns):      # send each filter to RIS Live
                ws.send(json.dumps(sub))
            print(f"[feed] connected to RIS Live: {len(prefixes)} prefixes, origins {sorted(asns)}")
            while True:                             # inner loop = read messages one by one
                try:
                    raw = ws.recv()                 # wait for the next message (JSON text)
                except websocket.WebSocketTimeoutException:
                    ws.send(json.dumps({"type": "ping"}))       # quiet for 60 s: ping and keep waiting
                    continue
                message = json.loads(raw)           # JSON text -> dict
                if message.get("type") == "ris_error":           # server reports a problem (e.g. bad filter)
                    print(f"[feed] RIS Live error: {message.get('data')}")
                    continue
                yield from parse_ris_message(message)            # hand each RouteEvent to main.py
        except (websocket.WebSocketException, OSError, json.JSONDecodeError) as exc:
            print(f"[feed] connection problem: {exc!r}; reconnecting in 5 s")
        finally:
            if ws is not None:                      # always release the socket
                ws.close()
        time.sleep(5)                               # wait before reconnecting (be polite to RIPE)


def demo_events(path: str, delay: float = 0.3) -> Iterator[RouteEvent]:
    """Replay RIS Live messages saved one per line in a file (offline demo)."""
    with open(path, encoding="utf-8") as fh:        # open the demo file
        for line in fh:                             # one JSON message per line
            line = line.strip()                     # remove the newline and spaces
            if not line or line.startswith("#"):    # skip blank lines and comment lines
                continue
            yield from parse_ris_message(json.loads(line))   # same parser as live mode
            time.sleep(delay)                       # slow down so the audience can follow