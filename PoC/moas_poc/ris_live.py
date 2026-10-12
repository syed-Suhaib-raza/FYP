"""Live MOAS monitor on RIPE RIS Live (wss://ris-live.ripe.net). No API key needed.

Examples:
  python ris_live.py --prefix 1.1.1.0/24 --prefix 8.8.8.0/24          # watch specific prefixes
  python ris_live.py --whitelist whitelist.json                        # watch the whitelisted prefixes
  python ris_live.py                                                   # whole table (heavy, demo only)
"""
import argparse, asyncio, json, time
import websockets
from moas import MoasDetector, Store

URL = "wss://ris-live.ripe.net/v1/ws/?client=fyp-moas-poc"


def fmt(a):
    t = time.strftime("%H:%M:%S", time.gmtime(a["ts"]))
    return (f"[{t}] MOAS/{a['severity'].upper():6} {a['prefix']} origins={sorted(a['origins'], key=str)} "
            f"new=AS{a['new_origin']} via {a['collector']} peer AS{a['peer_asn']}\n           path: {a['as_path']}")


async def run(args):
    wl = json.load(open(args.whitelist)) if args.whitelist else {}
    det = MoasDetector(Store(args.db), window=args.window, whitelist=wl, min_peers=args.min_peers)
    prefixes = args.prefix or list(wl)
    subs = [{"type": "UPDATE", "moreSpecific": args.more_specific, "socketOptions": {"includeRaw": False},
             **({"prefix": p} if p else {})} for p in (prefixes or [None])]
    last_stat = time.time()
    while True:
        try:
            async with websockets.connect(URL, ping_interval=30) as ws:
                for s in subs:
                    await ws.send(json.dumps({"type": "ris_subscribe", "data": s}))
                print(f"connected; watching {prefixes or 'ALL prefixes'}", flush=True)
                async for raw in ws:
                    m = json.loads(raw)
                    if m.get("type") == "ris_error":
                        print("RIS error:", m.get("data")); continue
                    if m.get("type") != "ris_message":
                        continue
                    for a in det.process(m["data"]):
                        print(fmt(a), flush=True)
                    if time.time() - last_stat > 30:
                        print(f"  stats: {det.stats}", flush=True); last_stat = time.time()
        except Exception as e:
            print("connection lost:", e, "- retrying in 5s", flush=True)
            await asyncio.sleep(5)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--prefix", action="append", help="prefix to watch (repeatable)")
    p.add_argument("--no-more-specific", dest="more_specific", action="store_false")
    p.add_argument("--whitelist", help="JSON {prefix: [legit origin ASNs]}")
    p.add_argument("--window", type=int, default=3600, help="seconds an origin stays 'active'")
    p.add_argument("--min-peers", type=int, default=1, help="peers that must see an origin before alerting")
    p.add_argument("--db", default="moas.db")
    asyncio.run(run(p.parse_args()))
