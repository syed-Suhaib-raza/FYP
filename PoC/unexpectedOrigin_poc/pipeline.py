"""candidate -> evidence -> model -> verdict -> SQLite"""
import json, sqlite3, time
from prompt import build_messages, parse_label, render_update


class Store:
    def __init__(self, db):
        self.con = sqlite3.connect(db, check_same_thread=False)
        self.con.execute("""CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, prefix TEXT,
            watched TEXT, subtype TEXT, origin INTEGER, expected TEXT, as_path TEXT, collector TEXT, peer_asn TEXT,
            label TEXT, raw_output TEXT, severity TEXT, evidence TEXT, latency REAL, model TEXT, anomaly_type TEXT)""")
        try:
            self.con.execute("ALTER TABLE alerts ADD COLUMN anomaly_type TEXT")   # older DBs
        except sqlite3.OperationalError:
            pass
        self.con.commit()

    def add(self, r):
        self.con.execute("INSERT INTO alerts(ts,prefix,watched,subtype,origin,expected,as_path,collector,peer_asn,label,raw_output,severity,evidence,latency,model,anomaly_type)"
                         " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (r["ts"], r["prefix"], r["watched"], r["subtype"], r["origin"], json.dumps(r["expected"]),
                          " ".join(map(str, r["path"])), r["collector"], r["peer_asn"], r["label"], r["raw_output"],
                          r["severity"], json.dumps(r["evidence"]), r["latency"], r["model"], r["anomaly_type"]))
        self.con.commit()

def severity(label):
   """The rule-based candidate is the alert. The model label only sets how strongly it is corroborated:
   any anomaly label -> high; 'none' (model disagrees) or unreadable/unknown -> medium."""
   return "medium" if label in ("none", "unparsed", "unknown") else "high"


def anomaly_type(subtype, label):
    """Type comes from prefix geometry only. The model label is advisory and does not decide whether an alert exists."""
    return "unexpected_origin" if subtype == "origin" else "unexpected_deaggregation"



def ownership_lines(c):
    """Explicit ownership statements taken from the operator's own whitelist (NOT from RPKI/IRR)."""
    exp = ", ".join(f"AS{e}" for e in c["expected"])
    out = [f"{c['watched']} is originated by {exp} (the expected origin configured by the network operator)."]
    if c["subtype"] == "deaggregation":
        out.append(f"AS{c['origin']} announced {c['prefix']}, a more-specific prefix of {c['watched']}, but AS{c['origin']} is not an authorized origin for {c['watched']}.")
    else:
        out.append(f"AS{c['origin']} is not an authorized origin for {c['watched']}.")
    return out


def classify(cand, asrel, llm, top_k=8, ownership=True, style="repo", use_evidence=True):
    ev = asrel.evidence(cand["path"], cand["origin"], cand["expected"], top_k)
    if ownership:
        ev = ownership_lines(cand) + ev
    update = {"timestamp": int(cand["ts"]), "prefix": cand["prefix"], "as_path": cand["path"],
              "origin_as": cand["origin"], "announcement_type": "A", "collector": cand["collector"], "peer_asn": cand["peer_asn"]}
    t = time.time()
    raw = llm.generate(build_messages(render_update(cand) if style == "repo" else update, ev if use_evidence else None))
    label = parse_label(raw)
    return dict(cand, anomaly_type=anomaly_type(cand["subtype"], label), label=label, raw_output=raw, severity=severity(label), evidence=ev,
                latency=round(time.time() - t, 2), model=llm.name)
