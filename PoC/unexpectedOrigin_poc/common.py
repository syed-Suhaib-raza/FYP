import argparse, json, os
from asrel import ASRel
from llm import RouteLLM, MockLLM


def add_args(p):
    p.add_argument("--whitelist", default="whitelist.json")
    p.add_argument("--asrel", default=os.environ.get("ROUTE_LLM_AS_RELATIONSHIPS"), help="CAIDA as-rel file (.txt/.bz2)")
    p.add_argument("--base-model", default=os.environ.get("ROUTE_LLM_BASE_MODEL", "meta-llama/Meta-Llama-3.1-8B-Instruct"))
    p.add_argument("--adapter", default=os.environ.get("ROUTE_LLM_ADAPTER", "models/route-llm-llama3.1-8b-instruct-lora"))
    p.add_argument("--quant", choices=["4bit", "8bit", "bf16"], default="4bit")
    p.add_argument("--mock", action="store_true", help="use MockLLM (no GPU) to test the pipeline only")
    p.add_argument("--only-exact", action="store_true", help="ignore more-specific (deaggregation) announcements")
    p.add_argument("--cooldown", type=int, default=600, help="seconds before re-classifying the same (prefix, origin)")
    p.add_argument("--top-k", type=int, default=8)
    p.add_argument("--ownership-evidence", action=argparse.BooleanOptionalAction, default=True,help="add explicit ownership lines to the evidence (default on; --no-ownership-evidence to disable)")
    p.add_argument("--db", default="origin.db")


def build(a):
    wl = json.load(open(a.whitelist, encoding="utf-8"))
    asrel = ASRel(a.asrel)
    llm = MockLLM() if a.mock else RouteLLM(a.base_model, a.adapter, a.quant)
    return wl, asrel, llm


def show(r):
    import time
    t = time.strftime("%H:%M:%S", time.gmtime(r["ts"]))
    print(f"[{t}] {r['severity'].upper():6} {r['anomaly_type']:24} {r['prefix']} origin=AS{r['origin']} (expected {r['expected']}) "
          f"-> model: {r['label']}  [{r['model']}, {r['latency']}s]\n         path: {' '.join(map(str, r['path']))}\n         raw: {r['raw_output']!r}", flush=True)
