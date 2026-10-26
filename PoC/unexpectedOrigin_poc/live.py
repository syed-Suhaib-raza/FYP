"""Live: RIPE RIS Live -> candidate filter -> RouteLLM.   python live.py --asrel data/20241201.as-rel.txt"""
import argparse, asyncio, json
import websockets
from common import add_args, build, show
from detector import OriginCandidates
from pipeline import Store, classify

URL = "wss://ris-live.ripe.net/v1/ws/?client=fyp-origin-poc"


async def run(a):
    wl, asrel, llm = build(a)
    det, store = OriginCandidates(wl, a.only_exact, a.cooldown), Store(a.db)
    subs = [{"type": "UPDATE", "prefix": p, "moreSpecific": not a.only_exact, "socketOptions": {"includeRaw": False}} for p in wl]
    while True:
        try:
            async with websockets.connect(URL, ping_interval=30) as ws:
                for s in subs:
                    await ws.send(json.dumps({"type": "ris_subscribe", "data": s}))
                print("connected; watching", list(wl), flush=True)
                async for raw in ws:
                    m = json.loads(raw)
                    if m.get("type") != "ris_message":
                        continue
                    for c in det.candidates(m["data"]):
                        r = classify(c, asrel, llm, a.top_k); store.add(r); show(r)
        except Exception as e:
            print("connection lost:", e, "- retrying in 5s", flush=True); await asyncio.sleep(5)

p = argparse.ArgumentParser(); add_args(p)
asyncio.run(run(p.parse_args()))
