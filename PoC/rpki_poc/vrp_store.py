"""vrp_store.py - loads VRPs from Routinator (or a file) and finds the VRPs that cover a route."""

import ipaddress                                   # parse prefixes and test "is A inside B"
import json                                        # read VRP files from disk
from dataclasses import dataclass, field           # small record class
from datetime import datetime, timezone            # when we loaded the VRPs, ROA expiry times

import requests                                    # HTTP GET to Routinator

Network = ipaddress.IPv4Network | ipaddress.IPv6Network   # a prefix can be IPv4 or IPv6


@dataclass(frozen=True)
class VRP:
    """One Validated ROA Payload: 'asn may originate prefix, up to max_length'."""
    asn: int                                       # authorised origin AS (0 = "never route this")
    prefix: Network                                # authorised prefix
    max_length: int                                # longest length allowed
    ta: str = "unknown"                            # trust anchor (which RIR), e.g. "apnic"
    expires: float | None = field(default=None, compare=False, hash=False)   # ROA notAfter (Unix s), if known


def parse_asn(value) -> int:
    """Turn 'AS9541', 'as9541', '9541' or 9541 into 9541."""
    text = str(value).strip().upper()
    return int(text[2:] if text.startswith("AS") else text)


def _to_ts(text) -> float | None:
    """'2026-11-20T10:00:00Z' -> Unix seconds; anything unreadable -> None."""
    if not text:
        return None
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _expiry(item: dict) -> float | None:
    """Earliest notAfter in Routinator's jsonext 'source' list (ROA validity or chain validity), if present."""
    times = []
    for src in item.get("source", []) or []:
        for key in ("validity", "chainValidity"):
            t = _to_ts((src.get(key) or {}).get("notAfter"))
            if t is not None:
                times.append(t)
    if item.get("expires") is not None:            # our own demo/eval files may give "expires" directly
        t = _to_ts(item["expires"])
        if t is not None:
            times.append(t)
    return min(times) if times else None


def parse_roas(data: dict) -> list[VRP]:
    """Routinator's JSON / jsonext ('roas' list) -> VRP objects."""
    vrps = []
    for item in data.get("roas", []):
        src = (item.get("source") or [{}])[0]
        vrps.append(VRP(
            asn=parse_asn(item["asn"]),
            prefix=ipaddress.ip_network(item["prefix"], strict=False),
            max_length=int(item["maxLength"]),
            ta=str(item.get("ta") or src.get("tal") or "unknown"),
            expires=_expiry(item),
        ))
    return vrps


class VrpStore:
    """Keeps all VRPs in memory and answers: which VRPs cover this prefix?"""

    def __init__(self, vrps: list[VRP], source: str, generated_time: str | None = None):
        self.source = source
        self.generated_time = generated_time
        self.loaded_at = datetime.now(timezone.utc).timestamp()
        self.vrps = list(vrps)
        self.count = len(self.vrps)
        self._by_prefix: dict[Network, list[VRP]] = {}
        for vrp in self.vrps:
            self._by_prefix.setdefault(vrp.prefix, []).append(vrp)

    # ---- loading -----------------------------------------------------------------------------------------
    @classmethod
    def from_routinator(cls, url: str, fallback_url: str | None = None, timeout: int = 120) -> "VrpStore":
        """Download the full VRP list. Tries `url` (jsonext, has expiry) and falls back to `fallback_url` (json)."""
        last_exc = None
        for u in [url] + ([fallback_url] if fallback_url else []):
            try:
                response = requests.get(u, timeout=timeout)
                response.raise_for_status()
                data = response.json()
                meta = data.get("metadata", {})
                return cls(parse_roas(data), source=u, generated_time=meta.get("generatedTime"))
            except (requests.RequestException, ValueError) as exc:
                last_exc = exc
        raise requests.RequestException(f"could not load VRPs from Routinator: {last_exc!r}")

    @classmethod
    def from_file(cls, path: str) -> "VrpStore":
        """Load VRPs from a JSON file in Routinator's format (used by --demo and the evaluation)."""
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        meta = data.get("metadata", {})
        return cls(parse_roas(data), source=path, generated_time=meta.get("generatedTime"))

    # ---- queries -----------------------------------------------------------------------------------------
    def covering(self, prefix: Network) -> list[VRP]:
        """Every VRP whose prefix contains `prefix` (RFC 6811 'covering' VRPs)."""
        found: list[VRP] = []
        for length in range(prefix.prefixlen, -1, -1):           # for a /24: try /24, /23 ... /0
            found.extend(self._by_prefix.get(prefix.supernet(new_prefix=length), []))
        return found

    def prefixes_for_asns(self, asns: set[int]) -> list[Network]:
        """All VRP prefixes that belong to one of `asns` (Cybernet's ROA-covered address space)."""
        return sorted({v.prefix for v in self.vrps if v.asn in asns}, key=lambda n: (n.version, n))

    def relevant(self, asns: set[int], nets: list[Network]) -> set[VRP]:
        """VRPs that matter to Cybernet: authorise a Cybernet ASN, or overlap Cybernet's own prefixes."""
        out = set()
        for v in self.vrps:
            if v.asn in asns or any(v.prefix.version == n.version and v.prefix.overlaps(n) for n in nets):
                out.add(v)
        return out
