"""Offline demo / test: replays RIS-Live-format messages (JSONL) through the detector (no internet needed).
   python replay.py sample_updates.jsonl --whitelist whitelist.json --db demo.db
Alerts are stored in demo.db with source = demo."""
import argparse, json
from flap import FlapDetector, Store, fmt

p = argparse.ArgumentParser()
p.add_argument("file"); p.add_argument("--whitelist"); p.add_argument("--db", default="demo.db")
p.add_argument("--half-life", type=int, default=900); p.add_argument("--suppress", type=int, default=2000)
p.add_argument("--reuse", type=int, default=750); p.add_argument("--min-peers", type=int, default=1)
a = p.parse_args()
wl = json.load(open(a.whitelist)) if a.whitelist else {}
det = FlapDetector(Store(a.db), whitelist=wl, half_life=a.half_life, suppress=a.suppress, reuse=a.reuse,
                   min_peers=a.min_peers, source="demo")
last = 0
for line in open(a.file):
    m = json.loads(line)["data"]
    last = max(last, m.get("timestamp", 0))
    for al in det.process(m):
        print(fmt(al))
for al in det.tick(last + 3 * 3600):                    # let the clock run on so quiet prefixes clear
    print(fmt(al))
print(det.stats)
