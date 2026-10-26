"""Candidate filter: announcements for a watched prefix (or a more-specific of it) whose origin is not an expected origin."""
import ipaddress, json, time


def origin_of(path):
    if not path:
        return None
    last = path[-1]
    return None if isinstance(last, list) else int(last)    # AS_SET origins are skipped (aggregates)


def flat_path(path):
    out = []
    for h in path:
        out.extend(int(x) for x in h) if isinstance(h, list) else out.append(int(h))
    return out


class OriginCandidates:
    def __init__(self, whitelist, only_exact=False, cooldown=600):
        self.watch = {ipaddress.ip_network(p): set(a) for p, a in whitelist.items()}
        self.only_exact, self.cooldown = only_exact, cooldown
        self.last = {}                                      # (prefix, origin) -> ts last sent to model
        self.suppressed = 0

    def candidates(self, msg):
        if msg.get("type") != "UPDATE" or not msg.get("path"):
            return []
        origin = origin_of(msg["path"])
        if origin is None:
            return []
        ts = float(msg["timestamp"]) if msg.get("timestamp") is not None else time.time()
        out = []
        for ann in msg.get("announcements", []):
            for p in ann.get("prefixes", []):
                try:
                    net = ipaddress.ip_network(p)
                except ValueError:
                    continue
                for w, expected in self.watch.items():
                    if net.version != w.version or not net.subnet_of(w):
                        continue
                    subtype = "origin" if net == w else "deaggregation"
                    if origin in expected or (self.only_exact and subtype != "origin"):
                        continue
                    key = (p, origin)
                    if ts - self.last.get(key, -1e18) < self.cooldown:
                        self.suppressed += 1
                        continue
                    self.last[key] = ts
                    out.append(dict(ts=ts, prefix=p, watched=str(w), subtype=subtype, origin=origin, expected=sorted(expected),
                                    path=flat_path(msg["path"]), collector=msg.get("host", ""), peer_asn=str(msg.get("peer_asn", "")),
                                    peer_ip=msg.get("peer", ""), next_hop=ann.get("next_hop", ""), origin_attr=msg.get("origin", ""),
                                    med=msg.get("med"), community=msg.get("community")))
        return out
