"""Offline demo: replays RIS-Live-format messages (JSONL) through the catalog layer only.
   python replay.py sample_updates.jsonl sample_updates_extra.jsonl --db demo.db
   python ai_layer.py --db demo.db --whitelist whitelist.json        # then score what was cataloged

Several files are merged by timestamp. The catalog tables in --db are emptied first (use --keep to append)."""
import argparse, json
from moas import MoasCatalog, Store, fmt_event

p = argparse.ArgumentParser()
p.add_argument("files", nargs="+")
p.add_argument("--db", default="demo.db")
p.add_argument("--window", type=int, default=3600)
p.add_argument("--keep", action="store_true", help="do not empty the catalog before replaying")
a = p.parse_args()

msgs = [json.loads(line)["data"] for f in a.files for line in open(f) if line.strip()]
msgs.sort(key=lambda m: m.get("timestamp", 0))
store = Store(a.db)
if not a.keep:
    store.reset()
cat = MoasCatalog(store, window=a.window)
for m in msgs:
    for ev in cat.process(m):
        print(fmt_event(ev))
cat.flush()
print(cat.stats)
