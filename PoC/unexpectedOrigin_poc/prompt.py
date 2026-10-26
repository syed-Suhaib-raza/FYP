"""Prompt construction + label parsing. System/user text is what the authors gave for Stage-2 training;
the update text follows the authors' data_processor format."""
import json

SYSTEM = "You are an Internet expert, good at judging the routing anomaly."
USER = ("Please analyze the BGP routing update information following <BGP Update:> to determine whether the update "
        "is normal. If any anomalies are detected, please clearly identify the type of anomaly including prefix hijack, "
        "path hijack, or route leak. If you do not determine any anomaly type, anomaly_type is filled in as none.")
LABELS = ["prefix hijack", "path hijack", "route leak", "none", "bgp hijack", "route hijack", "unknown"]


def render_update(c):
    """Text format of the authors' data_processor.to_natural_language()"""
    frm = " ".join(x for x in [c.get("peer_ip") or "", f"AS{c['peer_asn']}" if c.get("peer_asn") else ""] if x)
    comm = " ".join(f"{x[0]}:{x[1]}" if isinstance(x, (list, tuple)) else str(x) for x in (c.get("community") or []))
    parts = [f"TIME: {int(c['ts'])}", "TYPE: A", f"FROM: {frm}" if frm else None, f"PREFIX: {c['prefix']}",
             f"ASPATH: {' '.join(map(str, c['path']))}", f"ORIGIN: {str(c['origin_attr']).upper()}" if c.get("origin_attr") else None,
             f"NEXT_HOP: {c['next_hop']}" if c.get("next_hop") else None, f"COMMUNITIES: {comm}" if comm else None,
             f"MED: {c['med']}" if c.get("med") is not None else None]
    return ", ".join(x for x in parts if x)


def build_messages(update, evidence):
    """update: str (repo-style text) or dict (old JSON style). evidence: list, or None to omit the evidence block."""
    ev = ("Retrieved AS relationship knowledge:\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(evidence, 1))
          if evidence else "No relevant AS relationship knowledge was retrieved.")
    body = update if isinstance(update, str) else json.dumps(update, indent=2)
    user = f"{USER}\n\n<BGP Update:> {body}" + (f"\n\n{ev}" if evidence is not None else "")
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]


def parse_label(text: str) -> str:
    try:                                   # the authors' training answers are JSON: {"label":..,"anomaly_type":..}
        j = json.loads(text)
        if isinstance(j, dict) and j.get("anomaly_type"):
            text = str(j["anomaly_type"])
    except (ValueError, TypeError):
        pass
    t = (text or "").lower().replace("_", " ")
    hits = [(t.find(l), l) for l in LABELS if l in t]
    return min(hits)[1] if hits else "unparsed"