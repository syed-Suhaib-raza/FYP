"""Live MOAS catalog on RIPE RIS Live (wss://ris-live.ripe.net). No API key needed.
Layer 1 only: it records every multi-origin prefix it sees and does not judge them (run ai_layer.py for that).

Examples:
  python ris_live.py --prefix 1.1.1.0/24 --prefix 8.8.8.0/24          # watch specific prefixes
  python ris_live.py --whitelist whitelist.json                        # watch the prefixes listed in the file
  python ris_live.py                                                   # whole table (heavy, demo only)
"""
import argparse, asyncio, json, time
import websockets
from moas import MoasCatalog, Store, fmt_event

URL = "wss://ris-live.ripe.net/v1/ws/?client=fyp-moas-poc"
TICK_SECONDS = 10   # how often stale origins are aged out and evidence counters are saved


async def ticker(cat):
    while True:
        await asyncio.sleep(TICK_SECONDS)
        for ev in cat.tick():
            print(fmt_event(ev), flush=True)


async def run(args):
    # The whitelist is only used here to pick which prefixes to subscribe to.
    wl = json.load(open(args.whitelist)) if args.whitelist else {}
    cat = MoasCatalog(Store(args.db), window=args.window)
    prefixes = args.prefix or list(wl)
    subs = [{"type": "UPDATE", "moreSpecific": args.more_specific, "socketOptions": {"includeRaw": False},
             **({"prefix": p} if p else {})} for p in (prefixes or [None])]
    asyncio.create_task(ticker(cat))
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
                    for ev in cat.process(m["data"]):
                        print(fmt_event(ev), flush=True)
                    if time.time() - last_stat > 30:
                        print(f"  stats: {cat.stats}", flush=True); last_stat = time.time()
        except Exception as e:
            print("connection lost:", e, "- retrying in 5s", flush=True)
            await asyncio.sleep(5)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--prefix", action="append", help="prefix to watch (repeatable)")
    p.add_argument("--no-more-specific", dest="more_specific", action="store_false")
    p.add_argument("--whitelist", help="JSON {prefix: [legit origin ASNs]}; only selects prefixes to subscribe to")
    p.add_argument("--window", type=int, default=3600, help="seconds an origin stays 'active' after its last announcement")
    p.add_argument("--db", default="moas.db")
    asyncio.run(run(p.parse_args()))
