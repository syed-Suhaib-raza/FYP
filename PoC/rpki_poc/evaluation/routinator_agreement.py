"""Agreement with Routinator (doc metric: target 100%), measured on a LIVE run.

    python evaluation/routinator_agreement.py --db rpki.db

In live mode main.py asks Routinator's /api/v1/validity for its own verdict every time an alert becomes ACTIVE and
stores it in the alert (routinator_check). This script compares the two verdicts:
    our INVALID_AS / INVALID_ML / INVALID_AS_AND_ML  <->  Routinator "invalid"  (reason "as" / "length")
    our NOT_FOUND                                     <->  Routinator "not-found"
It needs a live run with Routinator (the evaluation's VRPs are synthetic, so Routinator cannot judge them).
"""
import argparse, json, sqlite3
from collections import Counter

OURS = {"INVALID_AS": "invalid", "INVALID_ML": "invalid", "INVALID_AS_AND_ML": "invalid", "NOT_FOUND": "not-found",
        "VALID": "valid"}
REASON = {"INVALID_AS": {"as"}, "INVALID_ML": {"length"}, "INVALID_AS_AND_ML": {"as", "length"}}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="rpki.db")
    a = p.parse_args()
    rows = sqlite3.connect(a.db).execute("SELECT alert_id, prefix, origin_asn, state, routinator_check FROM alerts "
                                         "WHERE routinator_check IS NOT NULL").fetchall()
    n = agree = reason_ok = reason_n = 0
    errors, disagree = Counter(), []
    for aid, prefix, origin, state, check in rows:
        c = json.loads(check) if check else None
        if not c or c.get("error") or not c.get("state"):
            errors[(c or {}).get("error", "no answer")[:60]] += 1
            continue
        n += 1
        if OURS.get(state) == c["state"]:
            agree += 1
            if state in REASON and c.get("reason"):
                reason_n += 1
                reason_ok += c["reason"] in REASON[state]
        else:
            disagree.append((aid, prefix, origin, state, c))
    print(f"alerts with a Routinator verdict: {n}")
    if n:
        print(f"state agreement: {agree}/{n} = {100 * agree / n:.1f}%  (target 100%)")
    if reason_n:
        print(f"invalid reason agreement (as / length): {reason_ok}/{reason_n}")
    for d in disagree:
        print("  DISAGREE", d)
    if errors:
        print("cross-check errors:", dict(errors))


if __name__ == "__main__":
    main()
