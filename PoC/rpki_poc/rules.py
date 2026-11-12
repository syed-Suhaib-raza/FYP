"""rules.py - turns a validation result into a NOC alert: cause class, severity, meaning, action.

This is the "Cause rules" + "Severity rules" box of the chosen approach (RPKI_Invalid doc, Our Solution, section 1).
Everything here is deterministic: the same inputs always give the same alert.

    Case                                                   Severity   cause
    Invalid, origin is a foreign AS seen for the first time CRITICAL   FOREIGN_NEW_ORIGIN
    Invalid, origin is a foreign AS seen before (history)   HIGH       FOREIGN_KNOWN_ORIGIN
    Invalid, origin is a known Cybernet customer AS         HIGH       CUSTOMER_NOT_IN_ROA
    Invalid-Length, origin is AS9541 / AS24440              HIGH       OWN_MAXLENGTH
    Invalid-ASN, Cybernet originates a prefix whose ROA     HIGH       OWN_NOT_AUTHORISED
      names another AS
    NotFound on a Cybernet prefix                           LOW        NO_ROA
    ROA removed / expiring / maxLength reduced              MEDIUM     (roa_watch.py)
"""

from validator import INVALID_AS, INVALID_AS_AND_ML, INVALID_ML, NOT_FOUND

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def assess(result, origin_asn, *, monitored: set[int], customers: set[int], origin_known: bool) -> dict:
    """Return dict(cause, severity, likely_meaning, suggested_action) for an Invalid or NotFound result that concerns Cybernet."""
    who = f"AS{origin_asn}" if origin_asn is not None else "an AS_SET"
    authorised = ", ".join(sorted({f"AS{v.asn}" for v in result.covering_vrps})) or "nobody"

    if result.state == NOT_FOUND:
        note = "" if (origin_asn in monitored or origin_asn in customers) else (
            f" The origin {who} is not Cybernet: also check the Unexpected Origin module.")
        return dict(cause="NO_ROA", severity="LOW",
                    likely_meaning="No ROA covers this Cybernet prefix, so networks running ROV cannot protect it." + note,
                    suggested_action="Create a ROA for this prefix in MyAPNIC with the exact maxLength Cybernet announces.")

    if origin_asn in monitored and result.state == INVALID_ML:
        return dict(cause="OWN_MAXLENGTH", severity="HIGH",
                    likely_meaning="Cybernet announces a more-specific prefix than its ROA maxLength allows; "
                            "networks that drop Invalid routes cannot reach it (APNIC: the most common cause).",
                    suggested_action="Raise maxLength in the ROA via MyAPNIC, or stop announcing the more-specific.")

    if origin_asn in monitored:                    # INVALID_AS or INVALID_AS_AND_ML with Cybernet as origin
        return dict(cause="OWN_NOT_AUTHORISED", severity="HIGH",
                    likely_meaning=f"Cybernet originates a prefix whose ROA authorises {authorised}, not Cybernet "
                            "(for example a leased or customer block).",
                    suggested_action="Ask the prefix holder to add a ROA for AS9541/AS24440, or stop originating it.")

    if origin_asn in customers:
        return dict(cause="CUSTOMER_NOT_IN_ROA", severity="HIGH",
                    likely_meaning=f"Cybernet customer {who} originates Cybernet space, but the ROA only authorises "
                            f"{authorised}: the ROA was not updated for this customer.",
                    suggested_action=f"Add a ROA for {who} (with the right maxLength) via MyAPNIC.")

    if origin_known:
        return dict(cause="FOREIGN_KNOWN_ORIGIN", severity="HIGH",
                    likely_meaning=f"{who} is not authorised, but it has announced this prefix before: possibly a "
                            "leasing or DDoS-scrubbing partner missing from the ROA (Noction: Invalid is not always a hijack).",
                    suggested_action=f"Confirm the arrangement with {who}; if legitimate add it to the ROA, else treat as a hijack.")

    return dict(cause="FOREIGN_NEW_ORIGIN", severity="CRITICAL",
                likely_meaning=f"{who} originates Cybernet address space for the first time and no ROA authorises it: "
                        "possible hijack.",
                suggested_action=f"Identify {who}. If it is not a known partner, treat as a hijack: alert upstreams and "
                       "consider announcing the more-specifics yourself.")


def is_alertable(result, origin_asn, *, monitored: set[int], in_cybernet_space: bool) -> bool:
    """Does this (prefix, origin) need an alert? Invalid routes that touch Cybernet, and NotFound in Cybernet space."""
    if result.state in (INVALID_AS, INVALID_ML, INVALID_AS_AND_ML):
        return (origin_asn in monitored or in_cybernet_space
                or any(v.asn in monitored for v in result.covering_vrps))
    if result.state == NOT_FOUND:
        return in_cybernet_space or origin_asn in monitored
    return False
