"""python diagnose.py sample_updates.jsonl --asrel sample_asrel.txt [--n 4]
Variants: A repo-style text, no evidence | B repo text + evidence | C old JSON + evidence | A0 = A with adapter OFF"""
import argparse, json, math
from common import add_args, build
from detector import OriginCandidates
from pipeline import ownership_lines
from prompt import build_messages, render_update, LABELS


def probe(llm, messages):
    torch = llm.torch
    ids = llm.tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt").to(llm.model.device)
    L = ids.shape[1]
    scores, first = {}, None
    for lab in LABELS:
        lab_ids = llm.tok(lab, add_special_tokens=False, return_tensors="pt").input_ids.to(ids.device)
        with torch.no_grad():
            logits = llm.model(torch.cat([ids, lab_ids], dim=1)).logits[0].float()
        scores[lab] = torch.log_softmax(logits[L - 1:-1], dim=-1).gather(1, lab_ids[0].unsqueeze(1)).sum().item()
        if first is None:
            top = torch.topk(torch.softmax(logits[L - 1], dim=-1), 8)
            first = [(llm.tok.decode([int(i)]), round(float(p), 3)) for p, i in zip(top.values, top.indices)]
    z = sum(math.exp(v) for v in scores.values()) or 1.0
    return L, llm.generate(messages), first, {k: round(math.exp(v) / z, 3) for k, v in scores.items()}


p = argparse.ArgumentParser(); p.add_argument("file"); p.add_argument("--n", type=int, default=4); add_args(p)
a = p.parse_args()
wl, asrel, llm = build(a)
det = OriginCandidates(wl, a.only_exact, cooldown=0)
cands = []
for line in open(a.file, encoding="utf-8"):
    cands += det.candidates(json.loads(line)["data"])
for c in cands[:a.n]:
    print(f"\n=== {c['prefix']} origin=AS{c['origin']} path={c['path']} ({c['subtype']}) ===")
    old = {"timestamp": int(c["ts"]), "prefix": c["prefix"], "as_path": c["path"], "origin_as": c["origin"],
           "announcement_type": "A", "collector": c["collector"], "peer_asn": c["peer_asn"]}
    ev = ownership_lines(c) + asrel.evidence(c["path"], c["origin"], c["expected"], a.top_k)
    print("repo-style text:", render_update(c))
    variants = [("A  repo text, no evidence   ", render_update(c), None, True), ("B  repo text + evidence   ", render_update(c), ev, True),
                ("C  old JSON + evidence     ", old, ev, True), ("A0 repo text, adapter OFF  ", render_update(c), None, False)]
    for name, upd, e, on in variants:
        msgs = build_messages(upd, e)
        if on:
            L, raw, first, probs = probe(llm, msgs)
        else:
            with llm.model.disable_adapter():
                L, raw, first, probs = probe(llm, msgs)
        print(f"{name}| tokens={L} raw={raw[:90]!r}\n    first: {first}\n    probs: {probs}")