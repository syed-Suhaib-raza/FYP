"""vrp_store.py - loads VRPs from Routinator (or a demo file) and finds the VRPs that cover a route."""

import ipaddress                                   # built-in: parse prefixes and test "is A inside B"
import json                                        # built-in: read the demo VRP file from disk
from dataclasses import dataclass                  # built-in: short way to write a small record class
from datetime import datetime, timezone            # built-in: time stamp of when we loaded the VRPs

import requests                                    # third-party: HTTP GET to Routinator's /json endpoint

Network = ipaddress.IPv4Network | ipaddress.IPv6Network   # type name: a prefix can be IPv4 or IPv6


@dataclass(frozen=True)                            # frozen = read-only after creation, and hashable
class VRP:
    """One Validated ROA Payload: 'asn may originate prefix, up to max_length'."""
    asn: int                                       # authorised origin AS, e.g. 9541 (0 = "never route this")
    prefix: Network                                # authorised prefix, e.g. 198.18.0.0/22
    max_length: int                                # longest length allowed, e.g. 23 means /22 and /23 are OK
    ta: str                                        # trust anchor (which RIR it came from), e.g. "apnic"


def parse_asn(value) -> int:
    """Turn 'AS9541', '9541' or 9541 into the integer 9541."""
    text = str(value).strip().upper()              # make it text, remove spaces, turn 'as' into 'AS'
    if text.startswith("AS"):                      # Routinator writes ASNs with an "AS" in front
        text = text[2:]                            # cut off the "AS"
    return int(text)                               # the digits that are left become an integer


def parse_roas(data: dict) -> list[VRP]:
    """Convert Routinator's JSON (the 'roas' list) into VRP objects."""
    vrps = []                                      # the result list starts empty
    for item in data.get("roas", []):              # each item: {"asn", "prefix", "maxLength", "ta"}
        vrps.append(VRP(                           # build one VRP object per item
            asn=parse_asn(item["asn"]),            # "AS9541" -> 9541
            prefix=ipaddress.ip_network(item["prefix"], strict=False),   # "198.18.0.0/22" -> network object
            max_length=int(item["maxLength"]),     # make sure MaxLength is an integer
            ta=str(item.get("ta", "unknown")),     # trust anchor name, if Routinator gave one
        ))
    return vrps                                    # hand back the full list


class VrpStore:
    """Keeps all VRPs in memory and answers: which VRPs cover this prefix?"""

    def __init__(self, vrps: list[VRP], source: str, generated_time: str | None = None):
        self.source = source                       # URL or file the VRPs came from (shown in logs)
        self.generated_time = generated_time       # when Routinator produced this VRP set
        self.loaded_at = datetime.now(timezone.utc).isoformat()   # when this program loaded it
        self.count = len(vrps)                     # number of VRPs, printed at start-up
        self._by_prefix: dict[Network, list[VRP]] = {}            # index: exact prefix -> its VRPs
        for vrp in vrps:                           # build the index once, at load time
            self._by_prefix.setdefault(vrp.prefix, []).append(vrp)   # one prefix may have several VRPs

    @classmethod
    def from_routinator(cls, url: str, timeout: int = 120) -> "VrpStore":
        """Download the full VRP list from Routinator's HTTP /json endpoint."""
        response = requests.get(url, timeout=timeout)   # the list is several MB, so allow up to 120 s
        response.raise_for_status()                # stop with an error if Routinator is not ready (4xx/5xx)
        data = response.json()                     # JSON text -> Python dict
        meta = data.get("metadata", {})            # Routinator's metadata block holds generatedTime
        return cls(parse_roas(data), source=url, generated_time=meta.get("generatedTime"))

    @classmethod
    def from_file(cls, path: str) -> "VrpStore":
        """Load VRPs from a JSON file in Routinator's format (used by --demo)."""
        with open(path, encoding="utf-8") as fh:   # open the file as UTF-8 text
            data = json.load(fh)                   # parse the JSON
        meta = data.get("metadata", {})            # same metadata block as the live endpoint
        return cls(parse_roas(data), source=path, generated_time=meta.get("generatedTime"))

    def covering(self, prefix: Network) -> list[VRP]:
        """Return every VRP whose prefix contains `prefix` (RFC 6811 'covering' VRPs)."""
        found: list[VRP] = []                      # results are collected here
        for length in range(prefix.prefixlen, -1, -1):        # for a /24: try /24, /23, /22 ... /0
            parent = prefix.supernet(new_prefix=length)       # the block of that size that contains it
            found.extend(self._by_prefix.get(parent, []))     # add VRPs registered for exactly that block
        return found                               # empty list means "no ROA covers this prefix"

    def prefixes_for_asns(self, asns: set[int]) -> list[Network]:
        """All VRP prefixes that belong to one of `asns` (Cybernet's ROA-covered address space)."""
        result = set()                             # a set removes duplicate prefixes
        for vrps in self._by_prefix.values():      # walk every group of VRPs
            for vrp in vrps:                       # and every VRP in the group
                if vrp.asn in asns:                # this VRP authorises Cybernet
                    result.add(vrp.prefix)         # remember its prefix
        return sorted(result, key=lambda n: (n.version, n.network_address, n.prefixlen))   # tidy order