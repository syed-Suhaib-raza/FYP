"""validator.py - deterministic Route Origin Validation (RFC 6811) with APNIC's three Invalid classes."""

from dataclasses import dataclass, field          # small record class for the result

from vrp_store import VRP, Network, VrpStore      # our own types from vrp_store.py

VALID = "VALID"                                    # at least one covering VRP matches
NOT_FOUND = "NOT_FOUND"                            # no VRP covers the prefix at all
INVALID_AS = "INVALID_AS"                          # covered, wrong origin AS, length would be fine
INVALID_ML = "INVALID_ML"                          # covered, right origin AS, but too specific (MaxLength)
INVALID_AS_AND_ML = "INVALID_AS_AND_ML"            # covered, wrong origin AS AND too specific
INVALID_STATES = {INVALID_AS, INVALID_ML, INVALID_AS_AND_ML}   # group used to ask "is it invalid?"


@dataclass
class ValidationResult:
    """Everything needed to understand (and defend) one decision."""
    prefix: str                                    # route prefix as text, e.g. "198.18.1.0/24"
    origin_asn: int | None                         # origin AS, or None if the path ended in an AS_SET
    state: str                                     # one of the five constants above
    covering_vrps: list[VRP] = field(default_factory=list)   # the evidence: VRPs that cover the prefix
    explanation: str = ""                          # plain-English reason, shown to the NOC

    @property
    def is_invalid(self) -> bool:                  # lets main.py write result.is_invalid
        return self.state in INVALID_STATES        # True for any of the three Invalid classes


def _vrp_matches(vrp: VRP, origin_asn: int | None, route_len: int) -> bool:
    """RFC 6811 'match': same AS (never AS0) and the route is not longer than MaxLength."""
    return (
        origin_asn is not None                     # an AS_SET origin can never match (RFC 6811)
        and vrp.asn != 0                           # an AS0 VRP means "do not route"; it never matches
        and vrp.asn == origin_asn                  # the VRP authorises exactly this origin AS
        and route_len <= vrp.max_length            # and the route is not too specific
    )


def validate_route(prefix: Network, origin_asn: int | None, store: VrpStore) -> ValidationResult:
    """Return the RPKI state of one route (prefix + origin AS). Same input -> same output, always."""
    text = str(prefix)                             # keep a text copy of the prefix for the result
    covering = store.covering(prefix)              # STEP 1: find every VRP that covers this prefix

    if not covering:                               # STEP 2: nothing covers it
        return ValidationResult(text, origin_asn, NOT_FOUND, [],
                                "No ROA covers this prefix, so RPKI gives no opinion.")

    route_len = prefix.prefixlen                   # e.g. 24 for a /24
    for vrp in covering:                           # STEP 3: does ANY covering VRP match?
        if _vrp_matches(vrp, origin_asn, route_len):          # one match is enough for VALID
            return ValidationResult(text, origin_asn, VALID, covering,
                                    f"Matches VRP {vrp.prefix} (max /{vrp.max_length}) for AS{vrp.asn}.")

    # STEP 4: covered, but nothing matched -> RPKI INVALID. Now work out WHY (APNIC classes).
    authorised = sorted({f"AS{v.asn}" for v in covering})     # e.g. ["AS9541"], used in the message
    same_as = [v for v in covering                             # covering VRPs that name this origin AS
               if origin_asn is not None and v.asn != 0 and v.asn == origin_asn]

    if same_as:                                    # right AS -> the only problem is the length
        allowed = max(v.max_length for v in same_as)          # longest length this AS may announce
        return ValidationResult(text, origin_asn, INVALID_ML, covering,
                                f"AS{origin_asn} is authorised, but only up to /{allowed}; "
                                f"this route is /{route_len} (MaxLength exceeded).")

    origin_txt = f"AS{origin_asn}" if origin_asn is not None else "an AS_SET"   # readable origin
    if any(route_len <= v.max_length for v in covering):      # the length alone would be acceptable
        return ValidationResult(text, origin_asn, INVALID_AS, covering,
                                f"Origin {origin_txt} is not authorised. Authorised: {', '.join(authorised)}.")

    longest = max(v.max_length for v in covering)  # most specific length any covering VRP allows
    return ValidationResult(text, origin_asn, INVALID_AS_AND_ML, covering,     # both checks fail
                            f"Origin {origin_txt} is not authorised ({', '.join(authorised)}) AND "
                            f"/{route_len} is longer than every MaxLength (longest allowed /{longest}).")