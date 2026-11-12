"""main.py - RPKI Invalid detector for Cybernet (deterministic, external routing anomalies).

    python main.py --demo                    # offline demo: demo_data/ -> demo.db (no Routinator, no internet)
    python main.py                           # live: Routinator + RIPE RIS Live -> rpki.db
    python -m streamlit run dashboard.py     # in a second window (add  -- --db demo.db  for the demo)

Options: --db FILE, --min-peers N, --no-cross-check, --no-revalidate, --delay S (demo speed)
"""

import argparse
import json
import os
import time

import requests

import config
from bgp_feed import LiveFeed, replay_events
from engine import RpkiDetector
from store import Store
from vrp_store import VrpStore

HERE = os.path.dirname(os.path.abspath(__file__))


def path_here(p):
    return p if os.path.isabs(p) else os.path.join(HERE, p)


def load_json(path, default):
    p = path_here(path)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def load_live_vrps() -> VrpStore:
    return VrpStore.from_routinator(config.ROUTINATOR_JSON_URL, config.ROUTINATOR_JSON_FALLBACK_URL)


def routinator_cross_check(prefix: str, origin_asn: int | None) -> dict | None:
    """Ask Routinator for its own verdict on this route (an independent second opinion)."""
    if origin_asn is None:                          # the API needs one origin AS (not an AS_SET)
        return None
    try:
        body = requests.get(f"{config.ROUTINATOR_VALIDITY_URL}/AS{origin_asn}/{prefix}", timeout=10).json()
    except (requests.RequestException, ValueError) as exc:
        return {"error": repr(exc)}
    route = body.get("validated_route") or (body.get("validated_routes") or [{}])[0]
    validity = route.get("validity", {})
    return {"state": validity.get("state"), "reason": validity.get("reason")}


def show(out: dict) -> None:
    if out["kind"] == "roa":
        c = out["change"]
        print(f"\n[ROA {c['severity']}] {c['change']} {c['prefix']} AS{c['asn']}: {c['detail']}", flush=True)
        return
    a, ev = out["alert"], out["event"]
    origin = f"AS{a['origin_asn']}" if a["origin_asn"] is not None else "AS_SET"
    if ev == "RESOLVED":
        print(f"\n[RESOLVED] {a['alert_id']} {a['prefix']} {origin} {a['state']}", flush=True)
        return
    print(f"\n[{a['severity']}] {a['alert_id']} {ev} {a['state']} ({a['cause']}) {a['prefix']} originated by {origin}, "
          f"seen by {a['seen_by_peers']} RIS peers", flush=True)
    print(f"   why    : {a['explanation']}")
    print(f"   meaning: {a['likely_meaning']}")
    print(f"   action : {a['suggested_action']}")
    if a.get("routinator_check"):
        print(f"   routinator says: {a['routinator_check']}")


def write_status(store, det, vrps, vrp_ok_at, mode):
    store.set_meta(mode=mode, vrp_source=vrps.source, vrp_count=vrps.count, vrp_generated=vrps.generated_time,
                   vrp_loaded_at=vrp_ok_at, vrp_stale=(time.time() - vrp_ok_at) > config.VRP_STALE_SECONDS if mode == "live" else False,
                   updated_at=time.time(), min_peers=det.min_peers, **det.status())


def main() -> None:
    p = argparse.ArgumentParser(description="Cybernet RPKI Invalid detector (PoC)")
    p.add_argument("--demo", action="store_true", help="use demo_data/ instead of live sources")
    p.add_argument("--db", help=f"SQLite file (default {config.DB_FILE}, demo: {config.DEMO_DB_FILE})")
    p.add_argument("--min-peers", type=int, default=config.MIN_PEERS)
    p.add_argument("--no-cross-check", action="store_true", help="do not ask Routinator /validity for a second opinion")
    p.add_argument("--no-revalidate", action="store_true", help="do NOT re-check routes when the VRPs change (ablation)")
    p.add_argument("--delay", type=float, default=0.3, help="demo: seconds between replayed messages")
    a = p.parse_args()

    db = path_here(a.db or (config.DEMO_DB_FILE if a.demo else config.DB_FILE))
    if a.demo:                                      # each demo run starts clean
        for s in ("", "-wal", "-shm"):
            if os.path.exists(db + s):
                os.remove(db + s)
    store = Store(db, log_path=path_here(config.ALERT_LOG))
    whitelist = load_json(config.DEMO_WHITELIST_FILE if a.demo else config.WHITELIST_FILE, {})
    customers = set(load_json(config.DEMO_CUSTOMERS_FILE if a.demo else config.CUSTOMERS_FILE, []))

    vrps = VrpStore.from_file(path_here(config.DEMO_VRP_FILE)) if a.demo else load_live_vrps()
    vrp_ok_at = time.time()
    cross = None if (a.demo or a.no_cross_check or not config.CROSS_CHECK_WITH_ROUTINATOR) else routinator_cross_check
    det = RpkiDetector(vrps, store, whitelist, customers, config.MONITORED_ASNS, a.min_peers,
                       revalidate=not a.no_revalidate, cross_check=cross, source="demo" if a.demo else "live",
                       warn_hours=config.ROA_EXPIRY_WARN_HOURS)

    roa_pfx = vrps.prefixes_for_asns(config.MONITORED_ASNS)
    print(f"[vrp] loaded {vrps.count} VRPs from {vrps.source} (generated {vrps.generated_time})")
    print(f"[vrp] {len(roa_pfx)} ROA prefixes for {sorted(config.MONITORED_ASNS)}; whitelist {len(whitelist)} prefixes; "
          f"{len(customers)} customer ASNs; alert after {det.min_peers} RIS peers")
    outs, _ = det.reload_vrps(vrps, time.time())   # same set again: only reports ROAs that are about to expire
    for o in outs:
        show(o)

    def watched_prefixes():                         # whitelist + Cybernet ROA prefixes (recomputed on reconnect)
        nets = {str(n) for n in det.vrps.prefixes_for_asns(config.MONITORED_ASNS)} | set(whitelist)
        return sorted(nets)

    feed = (replay_events(path_here(config.DEMO_UPDATES_FILE), a.delay) if a.demo
            else LiveFeed(config.RIS_LIVE_URL, watched_prefixes, config.MONITORED_ASNS))
    last_refresh = last_status = time.time()
    write_status(store, det, det.vrps, vrp_ok_at, "demo" if a.demo else "live")

    try:
        for ev in feed:
            if ev.kind == "vrp_reload":             # demo: the ROAs change at this point of the replay
                outs, _ = det.reload_vrps(VrpStore.from_file(path_here(os.path.join("demo_data", ev.file))), ev.timestamp)
                print(f"\n[vrp] demo: loaded {ev.file}")
                for o in outs:
                    show(o)
                continue
            if not a.demo and time.time() - last_refresh > config.VRP_REFRESH_SECONDS:
                last_refresh = time.time()
                try:
                    new = load_live_vrps()
                    vrp_ok_at = time.time()
                    outs, pfx_changed = det.reload_vrps(new, vrp_ok_at)
                    print(f"[vrp] refreshed: {new.count} VRPs", flush=True)
                    for o in outs:
                        show(o)
                    if pfx_changed:
                        feed.resubscribe()
                except requests.RequestException as exc:
                    print(f"[vrp] refresh failed, keeping old VRPs: {exc!r}", flush=True)
                if time.time() - vrp_ok_at > config.VRP_STALE_SECONDS:
                    print(f"[vrp] WARNING: VRPs are {(time.time() - vrp_ok_at) / 60:.0f} min old; is Routinator running?")
            if ev.kind != "tick":
                for o in det.process(ev):
                    show(o)
            if time.time() - last_status > 5:
                last_status = time.time()
                write_status(store, det, det.vrps, vrp_ok_at, "demo" if a.demo else "live")
    except KeyboardInterrupt:
        print("\n[main] stopped by user")
    finally:
        write_status(store, det, det.vrps, vrp_ok_at, "demo" if a.demo else "live")
        s = det.status()
        print(f"\n[summary] announcements by RPKI state: {s['state_counts']}")
        print(f"[summary] alerts: {s['alerts_active']} active, {s['alerts_resolved']} resolved, "
              f"{s['alerts_pending']} pending -> {db}")


if __name__ == "__main__":
    main()
