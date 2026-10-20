"""Live route-flap monitor on RIPE RIS Live (wss://ris-live.ripe.net). No API key needed.

Examples:
  python ris_live.py --whitelist whitelist.json                        # watch the whitelisted prefixes
  python ris_live.py --prefix 1.1.1.0/24 --prefix 8.8.8.0/24          # watch specific prefixes
  python ris_live.py --prefix 193.0.0.0/8 --suppress 1000             # wider block, more sensitive (alerts sooner)
Alerts are stored in flap.db with source = online. Ctrl+C stops it.
"""
import argparse, asyncio, json, time
import websockets
from flap import FlapDetector, Store, fmt

URL = "wss://ris-live.ripe.net/v1/ws/?client=fyp-flap-poc"
STATUS_EVERY = 30        # seconds between "still listening" lines (flaps are rare, so silence is normal)


async def run(args):
    wl = json.load(open(args.whitelist)) if args.whitelist else {}
    det = FlapDetector(Store(args.db), whitelist=wl, half_life=args.half_life, suppress=args.suppress, reuse=args.reuse,
                       min_peers=args.min_peers, source="online")
    prefixes = args.prefix or list(wl)
    subs = [{"type": "UPDATE", "moreSpecific": args.more_specific, "socketOptions": {"includeRaw": False},
             **({"prefix": p} if p else {})} for p in (prefixes or [None])]
    subs.append({"type": "RIS_PEER_STATE", "socketOptions": {"includeRaw": False}})   # session resets are not flaps
    last_tick = last_status = time.time()
    while True:
        try:
            async with websockets.connect(URL, ping_interval=30) as ws:
                for s in subs:
                    await ws.send(json.dumps({"type": "ris_subscribe", "data": s}))
                print(f"connected to RIS Live, watching {prefixes or 'ALL prefixes'}", flush=True)
                async for raw in ws:
                    m = json.loads(raw)
                    if m.get("type") == "ris_error":
                        print("RIS error:", m.get("data")); continue
                    events = det.process(m["data"]) if m.get("type") == "ris_message" else []
                    if time.time() - last_tick > 10:
                        events += det.tick(); last_tick = time.time()      # CLEARED on quiet prefixes
                    for a in events:
                        print(fmt(a), flush=True)
                    if time.time() - last_status >= STATUS_EVERY:
                        last_status = time.time()
                        print(f"[{time.strftime('%H:%M:%S')}] listening: {det.stats['updates']} updates seen, "
                              f"{len(det.routes)} routes tracked, {len(det.active)} active flaps", flush=True)
        except Exception as e:                                             # a dropped feed is not a flap
            print("connection lost:", e, "- retrying in 5s", flush=True)
            await asyncio.sleep(5)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--prefix", action="append", help="prefix to watch (repeatable)")
    p.add_argument("--no-more-specific", dest="more_specific", action="store_false")
    p.add_argument("--whitelist", help="JSON {prefix: [legit origin ASNs]}; flaps inside these prefixes are 'high'")
    p.add_argument("--half-life", type=int, default=900, help="seconds for the penalty to halve")
    p.add_argument("--suppress", type=int, default=2000, help="penalty that raises an alert")
    p.add_argument("--reuse", type=int, default=750, help="penalty below which the alert clears")
    p.add_argument("--min-peers", type=int, default=1, help="peer sessions that must flap the same prefix before alerting")
    p.add_argument("--db", default="flap.db")
    a = p.parse_args()
    if not (a.prefix or a.whitelist):
        p.error("give --whitelist or --prefix (the whole table is too much for a demo)")
    try:
        asyncio.run(run(a))
    except KeyboardInterrupt:                                              # Ctrl+C
        print("\nstopped.", flush=True)
