"""Offline test:  python replay.py sample_updates.jsonl --asrel sample_asrel.txt --mock --db demo.db"""
import argparse, json
from common import add_args, build, show
from detector import OriginCandidates
from pipeline import Store, classify

p = argparse.ArgumentParser(); p.add_argument("file"); add_args(p); a = p.parse_args()
wl, asrel, llm = build(a)
det, store = OriginCandidates(wl, a.only_exact, a.cooldown), Store(a.db)
n = 0
for line in open(a.file, encoding="utf-8"):
    for c in det.candidates(json.loads(line)["data"]):
        r = classify(c, asrel, llm, a.top_k, a.ownership_evidence); store.add(r); show(r); n += 1
print(f"{n} candidates classified, {det.suppressed} suppressed by cooldown")
