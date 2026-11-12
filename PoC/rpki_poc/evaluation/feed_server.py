"""Stand-alone labelled feed server (RIS Live protocol), to put a real network hop between feed and PoC.

On machine A (feed):   python evaluation/feed_server.py --host 0.0.0.0 --port 8765 [--delay-model trace:evaluation/results/ris_probe_trace.json]
On machine B (PoC):    python evaluation/evaluate.py --mode online --feed-url ws://<machine-A-ip>:8765

Each connection that sends `ris_subscribe` gets the whole dataset once. Keep both clocks NTP-synchronised: the
end-to-end latency is computed from the server's emit time and the client's clock.
"""
import argparse, asyncio, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import netfeed  # noqa: E402


async def main(a):
    rows = [json.loads(l) for l in open(a.dataset, encoding="utf-8") if l.strip()]
    delay = netfeed.DelayModel.parse(a.delay_model)
    server, url = await netfeed.serve_feed(rows, a.host, a.port, a.rate, delay)
    print(f"serving {len(rows)} labelled updates on {url} (bound {a.host}:{a.port}), rate {a.rate}/s, delay: {delay.describe()}", flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", default=os.path.join(HERE, "labelled_updates.jsonl"))
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--rate", type=float, default=20.0)
    p.add_argument("--delay-model", default="none", help="none | trace:FILE | fixed:S | uniform:A,B")
    asyncio.run(main(p.parse_args()))
