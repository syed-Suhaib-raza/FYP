"""Prompt construction + label parsing for ROUTE LLM.

Default style "repo" is the unexpectedOrigin PoC's prompt, copied as is (same SYSTEM/USER text, same update rendering, same
"Retrieved AS relationship knowledge" block, same parse_label). tests/test_aspath.py compares its output with the strings the
unexpectedOrigin PoC code produced, so the model is called the same way in both PoCs.

Optional styles (compare them with:  python check_setup.py --load --compare):
  paper = paper Fig. 3 instruction + bgpdump-like update + Fig. 4 time-aware <EVIDENCE> block
  infer = the released repo's inference/inference.py format
"""
import json, time

STYLES = ("repo", "paper", "infer")
SYSTEM = "You are an Internet expert, good at judging the routing anomaly."
USER = ("Please analyze the BGP routing update information following <BGP Update:> to determine whether the update "
        "is normal. If any anomalies are detected, please clearly identify the type of anomaly including prefix hijack, "
        "path hijack, or route leak. If you do not determine any anomaly type, anomaly_type is filled in as none.")
LABELS = ["prefix hijack", "path hijack", "route leak", "none", "bgp hijack", "route hijack", "unknown"]
SYSTEM_INFER = "You are a helpful assistant specialized in BGP routing analysis."
NO_EVID = "No relevant AS relationship knowledge was retrieved."


def render_update(c):
    """Text format of the authors' data_processor.to_natural_language()  (identical to the unexpectedOrigin PoC)."""
    frm = " ".join(x for x in [c.get("peer_ip") or "", f"AS{c['peer_asn']}" if c.get("peer_asn") else ""] if x)
    comm = " ".join(f"{x[0]}:{x[1]}" if isinstance(x, (list, tuple)) else str(x) for x in (c.get("community") or []))
    parts = [f"TIME: {int(c['ts'])}", "TYPE: A", f"FROM: {frm}" if frm else None, f"PREFIX: {c['prefix']}",
             f"ASPATH: {' '.join(map(str, c['path']))}", f"ORIGIN: {str(c['origin_attr']).upper()}" if c.get("origin_attr") else None,
             f"NEXT_HOP: {c['next_hop']}" if c.get("next_hop") else None, f"COMMUNITIES: {comm}" if comm else None,
             f"MED: {c['med']}" if c.get("med") is not None else None]
    return ", ".join(x for x in parts if x)


def _t(ts, fmt):
    return time.strftime(fmt, time.gmtime(ts))


def rel_text(a, b, r, style="repo"):
    r = str(r)
    if style == "infer":
        return {"-1": f"AS{a} is the provider of AS{b}. AS{b} is the customer of AS{a}.", "0": f"AS{a} and AS{b} are peers.",
                "1": f"AS{a} and AS{b} have a sibling relationship."}.get(r, f"The relationship between AS{a} and AS{b} is unknown.")
    return {"-1": f"AS{a} is a provider AS of AS{b}.", "1": f"AS{a} is a customer AS of AS{b}.", "0": f"AS{a} is a peer AS of AS{b}.",
            "2": f"AS{a} is a sibling AS of AS{b}."}.get(r, f"AS{a} has relationship {r} with AS{b}.")


def paper_evidence(f, ts):
    """Fig. 4 time-aware evidence block. f = dict(watched, expected, origin, links=[(a, b, support)], rels=[(a, b, code)])."""
    L = ["<EVIDENCE>", f"Historical origins of {f['watched']} before {_t(ts, '%Y%m%d')}:"]
    L += [f" AS{o} observed before event time." for o in f["expected"]]
    L += ["Observed origin in current update:", f" AS{f['origin']}.", "AS path evidence:"]
    L += [f" AS{a}-AS{b} " + ("never observed before event time." if n == 0 else "rarely observed before event time." if n < 2 else "observed before.")
          for a, b, n in f["links"]]
    if f["rels"]:
        L += ["AS relationship evidence:"] + [f" {rel_text(a, b, r)}" for a, b, r in f["rels"]]
    return "\n".join(L + ["</EVIDENCE>"])


def build_messages(update, evidence, style="repo", facts=None):
    """update: dict(ts, prefix, path, peer_ip, peer_asn, origin_attr, next_hop, community, med).
    evidence: list of sentences (repo/infer styles) or None to omit the block.  facts: needed by style 'paper'."""
    if style == "infer":
        upd = {"time": _t(update["ts"], "%Y-%m-%d %H:%M:%S"), "type": "BGP4MP/MESSAGE/Update", "peer_asn": update.get("peer_asn"),
               "prefix": update["prefix"], "as_path": " ".join(map(str, update["path"]))}
        kb = "\n".join(f"{i}. {rel_text(a, b, r, 'infer')}" for i, (a, b, r) in enumerate((facts or {}).get("rels", []), 1)) or NO_EVID
        user = (f"Please analyze the BGP routing update following <BGP Update:>{json.dumps(upd, indent=2)}\n"
                "If an anomaly is detected, respond with exactly one of the following anomaly types: prefix hijack, "
                "route leak, bgp hijack, or route hijack. If no anomaly is detected, respond with: none. Only return one "
                "of the five exact strings. Do not include any additional explanation or variation.\n"
                f"Retrieved AS relationship knowledge:\n{kb}")
        return [{"role": "system", "content": SYSTEM_INFER}, {"role": "user", "content": user}]
    if style == "paper":
        frm = " ".join(x for x in [update.get("peer_ip") or "", f"AS{update['peer_asn']}" if update.get("peer_asn") else ""] if x)
        comm = " ".join(f"{x[0]}:{x[1]}" if isinstance(x, (list, tuple)) else str(x) for x in (update.get("community") or []))
        parts = [f"TIME: {_t(update['ts'], '%m/%d/%y %H:%M:%S')}", "TYPE: BGP4MP/MESSAGE/Update", f"FROM: {frm}" if frm else None,
                 f"ORIGIN: {str(update['origin_attr']).upper()}" if update.get("origin_attr") else None,
                 f"ASPATH: {' '.join(map(str, update['path']))}", f"NEXT_HOP: {update['next_hop']}" if update.get("next_hop") else None,
                 f"COMMUNITIES: {comm}" if comm else None, f"ANNOUNCE: {update['prefix']}"]
        body = ", ".join(p for p in parts if p)
        return [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"{USER}\n\n<BGP Update:> {body}\n{paper_evidence(facts, update['ts'])}"}]
    # "repo": identical to unexpectedOrigin pipeline.classify(style="repo") -> prompt.build_messages(render_update(cand), evidence)
    ev = ("Retrieved AS relationship knowledge:\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(evidence, 1))
          if evidence else NO_EVID)
    user = f"{USER}\n\n<BGP Update:> {render_update(update)}" + (f"\n\n{ev}" if evidence is not None else "")
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]


def parse_label(text: str) -> str:
    """The unexpectedOrigin PoC's parser first; only when that finds nothing, extra fallbacks for plain 'normal' / JSON is_anomaly."""
    try:                                   # the authors' training answers are JSON: {"label":..,"anomaly_type":..}
        j = json.loads(text)
        if isinstance(j, dict) and j.get("anomaly_type"):
            text = str(j["anomaly_type"])
    except (ValueError, TypeError):
        j = None
    t = (text or "").lower().replace("_", " ")
    hits = [(t.find(l), l) for l in LABELS if l in t]
    if hits:
        return min(hits)[1]
    if isinstance(j, dict) and j.get("is_anomaly") is False:
        return "none"
    if "anomalous" in t:
        return "unknown"
    if t.strip(' "{}.').startswith(("normal",)) or "label normal" in t:
        return "none"
    return "unparsed"


def flagged(label):
    """Does the model corroborate the rule candidate?  any anomaly label -> yes; none / unparsed / unknown / no model -> no."""
    return label not in (None, "none", "unparsed", "unknown")
