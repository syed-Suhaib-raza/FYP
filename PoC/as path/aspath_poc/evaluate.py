"""Replay a labelled file (lines with a "gt" field: normal | path hijack | route leak), message level like the paper's Table III:
AC / PR / RC / F1 / FPR / FNR, then rule ablation (which rule catches what), type agreement and processing latency.
   python evaluate.py [file] [--llm hf|mock|none] [--prompt repo|paper|infer]
The default file is SYNTHETIC (make_sample.py): the numbers show the pipeline works, they are not a research result.
For real numbers replay incidents from the paper's benchmark (e.g. AS10990 hijack, AS11845 leak) - see README."""
import argparse, json, statistics as st, time
from aspath import ASRel, Monitor, common, load_watch
from llm import make_llm
from prompt import flagged

p = argparse.ArgumentParser(parents=[common()]); p.add_argument("file", nargs="?", default="sample_updates.jsonl")
a = p.parse_args()
wl, asns = load_watch(a.whitelist, a.asns); rel = ASRel(a.as_rel)
LINKS = ("new_as_link", "new_origin_upstream")


def run(llm, enabled=None):
    mon = Monitor(None, wl, rel, llm, asns, a.learn, "eval", a.prompt, a.top_k, a.cooldown, a.min_support, a.len_delta, a.origin_policy,
                  a.ownership_evidence, a.history_evidence, enabled=enabled)
    rows = []
    for line in open(a.file):
        d = json.loads(line); t = time.time(); out = mon.process(d["data"]); ms = (time.time() - t) * 1000
        if "gt" in d:
            inc = out[0] if out else None
            rows.append(dict(gt=d["gt"], bad=d["gt"] != "normal", rule=bool(inc), llm=bool(inc) and flagged(inc["llm_label"]), ms=ms,
                             rtype=inc["anomaly_type"].replace("_", " ") if inc else None, label=inc["llm_label"] if inc else None))
    return rows, mon


def report(name, rows, k):
    tp = sum(r["bad"] and r[k] for r in rows); fp = sum((not r["bad"]) and r[k] for r in rows)
    fn = sum(r["bad"] and not r[k] for r in rows); tn = sum((not r["bad"]) and not r[k] for r in rows)
    pr, rc = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    print(f"{name:<26} AC={(tp+tn)/max(len(rows),1):.2f} PR={pr:.2f} RC={rc:.2f} F1={2*pr*rc/max(pr+rc,1e-9):.2f} FPR={fp/max(fp+tn,1):.2f} FNR={fn/max(fn+tp,1):.2f}  (TP={tp} FP={fp} FN={fn} TN={tn})")


llm = make_llm(a)
rows, mon = run(llm)
print(f"{len(rows)} labelled messages, {sum(r['bad'] for r in rows)} anomalous | model={getattr(llm, 'name', 'none')} prompt={a.prompt} | stats {mon.stats}")
report("all rules (candidates)", rows, "rule")
if llm:
    report("rules + model corroborates", rows, "llm")
print("\nrule ablation (rules only, no model):")
for name, en in [("valley_violation only", ("valley_violation",)), ("link rules only", LINKS), ("new_as_link only", ("new_as_link",)), ("new_origin_upstream only", ("new_origin_upstream",))]:
    report(name, run(None, en)[0], "rule")
bad = [r for r in rows if r["bad"]]
print(f"\nrule type == ground-truth type: {sum(r['rtype'] == r['gt'] for r in bad)}/{len(bad)}")
if llm:
    print(f"model label == ground-truth type: {sum(r['label'] == r['gt'] for r in bad)}/{len(bad)}")
    for r in bad:
        print(f"   gt={r['gt']:<12} rule={r['rtype']}  model={r['label']}")
fl = [r["ms"] for r in rows if r["rule"]]
print(f"processing time of flagged messages: median {st.median(fl):.1f} ms, max {max(fl):.1f} ms" if fl else "nothing flagged")
