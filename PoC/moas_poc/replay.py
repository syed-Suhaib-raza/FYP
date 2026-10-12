"""Offline demo / test: replays RIS-Live-format messages (JSONL) through the detector.
   python replay.py sample_updates.jsonl --whitelist whitelist.json --db demo.db"""
import argparse, json
from moas import MoasDetector, Store
from ris_live import fmt

p = argparse.ArgumentParser()
p.add_argument("file"); p.add_argument("--whitelist"); p.add_argument("--db", default="demo.db")
p.add_argument("--window", type=int, default=3600)
a = p.parse_args()
wl = json.load(open(a.whitelist)) if a.whitelist else {}
det = MoasDetector(Store(a.db), window=a.window, whitelist=wl)
for line in open(a.file):
    for al in det.process(json.loads(line)["data"]):
        print(fmt(al))
print(det.stats)
