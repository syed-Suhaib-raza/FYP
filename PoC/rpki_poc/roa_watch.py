"""roa_watch.py - compares two VRP sets and reports what changed for Cybernet (BGPalerter monitorROAS idea).

A ROA that is removed, expires, or gets a smaller maxLength can turn Cybernet's own stable routes Invalid or
NotFound without any BGP update happening. Reporting the change itself warns the NOC before (or while) it hurts.
"""

import time


def _key(v):
    return (str(v.prefix), v.asn)


def diff_vrps(old: set, new: set, now: float | None = None) -> list[dict]:
    """Changes between two sets of Cybernet-relevant VRPs.
    REMOVED (MEDIUM), maxLength reduced (MEDIUM), ADDED (INFO), maxLength raised (INFO)."""
    now = time.time() if now is None else now
    before, after = {}, {}
    for v in old:
        before.setdefault(_key(v), set()).add(v.max_length)
    for v in new:
        after.setdefault(_key(v), set()).add(v.max_length)
    out = []
    for k in sorted(set(before) | set(after)):
        prefix, asn = k
        b, a = before.get(k), after.get(k)
        if b and not a:
            out.append(dict(ts=now, change="REMOVED", prefix=prefix, asn=asn, old_max=max(b), new_max=None,
                            severity="MEDIUM", detail=f"ROA {prefix} for AS{asn} (max /{max(b)}) was removed or expired; "
                                                      "routes it covered are now NotFound or Invalid."))
        elif a and not b:
            out.append(dict(ts=now, change="ADDED", prefix=prefix, asn=asn, old_max=None, new_max=max(a),
                            severity="INFO", detail=f"New ROA {prefix} for AS{asn} (max /{max(a)})."))
        elif max(a) < max(b):
            out.append(dict(ts=now, change="MAXLENGTH_REDUCED", prefix=prefix, asn=asn, old_max=max(b), new_max=max(a),
                            severity="MEDIUM", detail=f"ROA {prefix} for AS{asn}: maxLength /{max(b)} -> /{max(a)}; "
                                                      "more-specifics longer than /" + str(max(a)) + " become Invalid."))
        elif max(a) > max(b):
            out.append(dict(ts=now, change="MAXLENGTH_RAISED", prefix=prefix, asn=asn, old_max=max(b), new_max=max(a),
                            severity="INFO", detail=f"ROA {prefix} for AS{asn}: maxLength /{max(b)} -> /{max(a)}."))
    return out


def expiring(vrps: set, now: float, warn_hours: float) -> list[dict]:
    """Cybernet-relevant VRPs whose ROA expires within `warn_hours` (only when the VRP source gives expiry)."""
    out = []
    for v in sorted(vrps, key=lambda v: (str(v.prefix), v.asn)):
        if v.expires is not None and now <= v.expires <= now + warn_hours * 3600:
            hours = (v.expires - now) / 3600
            out.append(dict(ts=now, change="EXPIRING", prefix=str(v.prefix), asn=v.asn, old_max=v.max_length,
                            new_max=v.max_length, severity="MEDIUM",
                            detail=f"ROA {v.prefix} for AS{v.asn} expires in {hours:.1f} h; renew it in MyAPNIC."))
    return out
