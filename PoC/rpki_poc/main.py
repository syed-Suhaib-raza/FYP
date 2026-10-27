"""main.py - RPKI Invalid detector for Cybernet (deterministic, external routing anomalies)."""

import argparse                                     # reads --demo from the command line
import time                                         # used to decide when to refresh VRPs
from collections import Counter                     # counts how many routes ended in each state

import requests                                     # HTTP calls to Routinator (cross-check, refresh errors)

import config                                       # our settings file
from alert_store import AlertStore                  # de-duplicates and saves alerts
from bgp_feed import demo_events, live_events       # where BGP routes come from
from validator import INVALID_ML, validate_route    # the deterministic engine
from vrp_store import VrpStore                      # where RPKI truth comes from


def load_vrps(demo: bool) -> VrpStore:
    """Demo: read the small test file. Live: download from Routinator."""
    if demo:                                        # --demo was given
        return VrpStore.from_file(config.DEMO_VRP_FILE)
    return VrpStore.from_routinator(config.ROUTINATOR_JSON_URL)    # live Routinator /json


def touches_cybernet(result, origin_asn) -> bool:
    """True if Cybernet originates the route, or the route lies inside a Cybernet ROA."""
    if origin_asn in config.MONITORED_ASNS:         # Cybernet is the origin
        return True
    return any(v.asn in config.MONITORED_ASNS for v in result.covering_vrps)   # inside Cybernet's ROA


def assess_impact(result) -> tuple[str, str, str]:
    """Map a deterministic result to (severity, likely meaning, suggested action)."""
    ours = result.origin_asn in config.MONITORED_ASNS          # is Cybernet itself the origin?
    if ours and result.state == INVALID_ML:         # Cybernet's own route, too specific
        return ("HIGH",
                "Cybernet announces a more-specific prefix than its ROA MaxLength allows "
                "(APNIC: the most common cause of RPKI Invalid).",
                "Raise MaxLength in the ROA via MyAPNIC, or stop announcing the more-specific.")
    if ours:                                        # Cybernet originates a prefix whose ROA names another AS
        return ("HIGH",
                "Cybernet originates a prefix whose ROA authorises a different AS "
                "(for example a customer or leased block).",
                "Ask the prefix holder to add a ROA for AS9541/AS24440, or stop originating it.")
    return ("CRITICAL",                             # someone else originates Cybernet space
            "Another network originates Cybernet address space: possible hijack, or a leasing / "
            "DDoS-scrubbing arrangement missing from the ROA (Noction: invalid is not always a hijack).",
            "Identify the origin AS. If it is not a known partner, treat as a hijack and alert upstreams.")


def routinator_cross_check(prefix: str, origin_asn: int | None) -> dict | None:
    """Ask Routinator for its own verdict on this route (an independent second opinion)."""
    if origin_asn is None:                          # the API needs one origin AS (not an AS_SET)
        return None
    url = f"{config.ROUTINATOR_VALIDITY_URL}/AS{origin_asn}/{prefix}"   # /api/v1/validity/AS<n>/<prefix>
    try:
        body = requests.get(url, timeout=10).json() # call Routinator and parse its JSON answer
    except (requests.RequestException, ValueError) as exc:
        return {"error": repr(exc)}                 # record the failure instead of crashing
    route = body.get("validated_route") or (body.get("validated_routes") or [{}])[0]   # accept both shapes
    validity = route.get("validity", {})            # holds "state" and "reason"
    return {"state": validity.get("state"), "reason": validity.get("reason")}   # e.g. invalid / length


def print_alert(alert: dict) -> None:
    """Show a new or reopened alert on the screen."""
    print(f"\n[{alert['severity']}] {alert['alert_id']}  {alert['state']}  "
          f"{alert['prefix']} originated by AS{alert['origin_asn']}")
    print(f"   why    : {alert['explanation']}")
    print(f"   meaning: {alert['likely_meaning']}")
    print(f"   action : {alert['suggested_action']}")
    if alert.get("routinator_cross_check"):         # only present in live mode
        print(f"   routinator says: {alert['routinator_cross_check']}")


def print_resolved(alerts: list[dict]) -> None:
    """Show alerts that just closed."""
    for alert in alerts:
        print(f"\n[RESOLVED] {alert['alert_id']} {alert['prefix']} AS{alert['origin_asn']} "
              f"no longer seen by any RIS peer")


def main() -> None:
    parser = argparse.ArgumentParser(description="Cybernet RPKI Invalid detector (PoC)")
    parser.add_argument("--demo", action="store_true", help="use demo_data/ instead of live sources")
    args = parser.parse_args()                      # args.demo is True or False

    store = load_vrps(args.demo)                    # STEP 1: load the RPKI truth
    our_prefixes = store.prefixes_for_asns(config.MONITORED_ASNS)   # Cybernet's ROA-covered prefixes
    print(f"[vrp] loaded {store.count} VRPs from {store.source} (generated {store.generated_time})")
    print(f"[vrp] {len(our_prefixes)} ROA-covered prefixes belong to ASNs {sorted(config.MONITORED_ASNS)}")
    for p in our_prefixes[:20]:                     # show up to 20 of them
        print(f"      {p}")

    alerts = AlertStore(config.ALERT_FILE)          # STEP 2: prepare the alert store
    events = (demo_events(config.DEMO_UPDATES_FILE) if args.demo        # STEP 3: choose the BGP source
              else live_events(our_prefixes, config.MONITORED_ASNS, config.RIS_LIVE_URL))
    counts = Counter()                              # statistics for the summary
    last_refresh = time.time()                      # when VRPs were last loaded

    try:
        for event in events:                        # STEP 4: handle every route event as it arrives
            if not args.demo and time.time() - last_refresh > config.VRP_REFRESH_SECONDS:
                try:                                # time to reload VRPs (ROAs may have changed)
                    store = load_vrps(demo=False)
                    print(f"[vrp] refreshed: {store.count} VRPs")
                except requests.RequestException as exc:
                    print(f"[vrp] refresh failed, keeping old VRPs: {exc!r}")
                last_refresh = time.time()          # try again after another interval

            prefix = str(event.prefix)              # prefix as text, the alert key uses text
            if event.kind == "withdraw":            # the peer removed the route
                print_resolved(alerts.record_gone(prefix, event.collector, event.peer))
                continue                            # nothing to validate for a withdrawal

            result = validate_route(event.prefix, event.origin_asn, store)   # STEP 5: deterministic check
            counts[result.state] += 1               # count VALID / NOT_FOUND / INVALID_*

            if not (result.is_invalid and touches_cybernet(result, event.origin_asn)):
                print_resolved(alerts.record_gone(prefix, event.collector, event.peer))  # peer's route is fine now
                continue                            # no alert needed

            key = AlertStore.key_of(result)         # STEP 6: this route is Invalid and concerns Cybernet
            print_resolved(alerts.record_gone(prefix, event.collector, event.peer, keep_key=key))

            check = None                            # Routinator's second opinion (live, first sighting only)
            if config.CROSS_CHECK_WITH_ROUTINATOR and not args.demo and not alerts.is_known(key):
                check = routinator_cross_check(prefix, event.origin_asn)

            severity, meaning, action = assess_impact(result)            # STEP 7: how serious is it?
            alert, changed = alerts.record_invalid(result, event, severity, meaning, action, check)
            if changed:                             # new or reopened -> show it
                print_alert(alert)
    except KeyboardInterrupt:                       # Ctrl+C stops live mode cleanly
        print("\n[main] stopped by user")
    finally:                                        # always print a summary at the end
        print(f"\n[summary] routes checked by state: {dict(counts)}")
        active = sum(1 for a in alerts.alerts.values() if a["status"] == "ACTIVE")
        print(f"[summary] alerts: {len(alerts.alerts)} total, {active} still active -> {config.ALERT_FILE}")


if __name__ == "__main__":                          # run main() only when started as a program
    main()