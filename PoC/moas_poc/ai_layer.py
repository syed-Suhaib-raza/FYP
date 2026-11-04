"""Layer 2 (AI): reads the MOAS catalog (moas_events / moas_origins) and flags the anomalous events.

The catalog layer never calls this. The two layers only talk through the SQLite file, so you can run,
restart or swap this layer without touching collection. Each (event, revision, backend) is scored once and
written to the `verdicts` table; the dashboard shows the latest verdict per event and backend.

Backends (--backend):
  baseline  transparent additive rule score. NOT a model: it is the reference to compare the model against.
            The weights are untuned placeholders to be replaced with values validated on labelled events.
  llm       any OpenAI-compatible chat endpoint (Ollama, llama.cpp server, vLLM, ...). Point it at the
            model you serve locally; see SYSTEM_PROMPT / llm_context() for what the model is shown.
  both      runs both, so each event gets two verdicts (handy for the FYP-I comparison).

    python ai_layer.py --db moas.db --whitelist whitelist.json --backend baseline --watch
    python ai_layer.py --backend llm --llm-model <served-model-name> --llm-url http://localhost:11434/v1
"""
import argparse, ipaddress, json, os, sqlite3, time, urllib.request
from typing import NamedTuple

from moas import read_events

LABELS = ("anomalous", "benign", "uncertain")
ANOMALOUS_AT, BENIGN_AT = 0.6, 0.3   # baseline score thresholds

DDL = """CREATE TABLE IF NOT EXISTS verdicts(
    event_id INTEGER, revision INTEGER, backend TEXT, ts REAL, label TEXT, score REAL, reason TEXT,
    PRIMARY KEY(event_id, revision, backend))"""


class Verdict(NamedTuple):
    label: str      # anomalous | benign | uncertain
    score: float    # 0..1, how likely the event is a hijack / leak / misconfiguration
    reason: str


# ---------------------------------------------------------------------------------------------------------
# Features: facts derived from the catalog entry (+ optional whitelist as prior knowledge). No judgement here.
# ---------------------------------------------------------------------------------------------------------
def asn_class(origin):
    """Name the IANA special-purpose class of an origin, or None for an ordinary public ASN."""
    if not str(origin).isdigit():
        return None  # AS_SET aggregate key like "{65010,65011}"
    n = int(origin)
    if n == 0:
        return "as0"
    if n == 23456:
        return "as_trans"
    if 64496 <= n <= 64511 or 65536 <= n <= 65551:
        return "documentation"
    if 64512 <= n <= 65534 or 4200000000 <= n <= 4294967294:
        return "private"
    if n in (65535, 4294967295) or 65552 <= n <= 131071:
        return "reserved"
    return None


def prefix_info(prefix):
    net = ipaddress.ip_network(prefix, strict=False)
    return dict(ip_version=net.version, prefix_len=net.prefixlen, globally_routable=net.is_global,
                more_specific_than_filter_limit=net.prefixlen > (24 if net.version == 4 else 48))


def build_features(ev, whitelist=None):
    whitelist = whitelist or {}
    prefix = ev["prefix"]
    origins = ev["origins"]                       # ordered by first_seen: origins[0] is the incumbent
    names = [o["origin"] for o in origins]
    wl = whitelist.get(prefix)
    expected = sorted(map(str, wl)) if wl is not None else []
    all_peers = set().union(*[set(o["peers"]) for o in origins]) if origins else set()
    t0 = min((o["first_seen"] for o in origins), default=ev["first_seen"])   # when the incumbent first appeared

    upstream_pairs = []                           # (x, y): x appears mid-path of y's announcements
    for y in origins:
        for p in y["paths"]:
            hops = p.split()[:-1]
            for x in names:
                if x != y["origin"] and x in hops and [x, y["origin"]] not in upstream_pairs:
                    upstream_pairs.append([x, y["origin"]])

    per_origin = []
    for o in origins:
        per_origin.append(dict(
            origin=o["origin"], asn_class=asn_class(o["origin"]),
            authorised=(o["origin"] in expected) if wl is not None else None,
            first_seen_offset_s=round(o["first_seen"] - t0), active_span_s=round(o["last_seen"] - o["first_seen"]),
            n_updates=o["n_updates"], n_peers=len(o["peers"]), n_collectors=len(o["collectors"]),
            peer_share=round(len(o["peers"]) / len(all_peers), 2) if all_peers else 0.0,
            paths=o["paths"][:3]))

    return dict(
        prefix=prefix, **prefix_info(prefix), status=ev["status"], n_origins=len(names),
        duration_s=round(ev["last_seen"] - ev["first_seen"]), total_peers=len(all_peers),
        watched=wl is not None, expected_origins=expected,
        unexpected_origins=[o for o in names if wl is not None and o not in expected],
        special_asns={o: asn_class(o) for o in names if asn_class(o)},
        upstream_pairs=upstream_pairs, incumbent=names[0] if names else None, per_origin=per_origin)


# ---------------------------------------------------------------------------------------------------------
# Backend 1: transparent rule baseline (reference point, not a model)
# ---------------------------------------------------------------------------------------------------------
WEIGHTS = dict(base=0.40, unauthorised_origin=+0.40, all_authorised=-0.30, special_asn=+0.40,
               not_globally_routable=+0.30, upstream_relation=-0.15)   # untuned placeholders


class BaselineBackend:
    name = "baseline"

    def score(self, ev, f):
        w, s, why = WEIGHTS, WEIGHTS["base"], []
        if f["watched"] and f["unexpected_origins"]:
            s += w["unauthorised_origin"]
            why.append("origin(s) AS" + ", AS".join(f["unexpected_origins"]) + " not authorised for this watched prefix")
        elif f["watched"]:
            s += w["all_authorised"]
            why.append("all origins are authorised for this watched prefix (planned multi-origin)")
        if f["special_asns"]:
            s += w["special_asn"]
            why.append("special-purpose origin ASN: " + ", ".join(f"AS{a} ({c})" for a, c in f["special_asns"].items()))
        if not f["globally_routable"]:
            s += w["not_globally_routable"]
            why.append("prefix is not globally routable space")
        if f["upstream_pairs"]:
            s += w["upstream_relation"]
            why.append("origin AS" + " / AS".join(f["upstream_pairs"][0]) + " are in an upstream relation (often benign)")
        s = round(min(1.0, max(0.0, s)), 2)
        label = "anomalous" if s >= ANOMALOUS_AT else "benign" if s <= BENIGN_AT else "uncertain"
        return Verdict(label, s, "; ".join(why) or "no distinguishing evidence either way")


# ---------------------------------------------------------------------------------------------------------
# Backend 2: LLM behind an OpenAI-compatible chat endpoint
# ---------------------------------------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "You are a BGP routing-security analyst triaging Multiple Origin AS (MOAS) events: a prefix announced by "
    "more than one origin AS. Many MOAS events are benign (anycast, multi-homing with provider aggregation, "
    "planned DDoS-scrubbing diversion, customer/provider overlap); others are hijacks, route leaks or "
    "misconfigurations. You get the evidence collected by a deterministic catalog. Judge only from that "
    "evidence and say 'uncertain' when it does not decide the case. Reply with ONE JSON object and nothing else: "
    '{"label": "anomalous" | "benign" | "uncertain", "score": <0..1 probability that this is a hijack, leak or '
    'misconfiguration>, "reason": "<at most two sentences>"}')


def llm_context(ev, f):
    """What the model is shown. Edit this (and SYSTEM_PROMPT) to match the format a fine-tuned model expects."""
    keep = ("prefix", "ip_version", "prefix_len", "globally_routable", "more_specific_than_filter_limit", "status",
            "n_origins", "duration_s", "total_peers", "watched", "expected_origins", "unexpected_origins",
            "special_asns", "upstream_pairs", "incumbent", "per_origin")
    return {k: f[k] for k in keep}


def parse_verdict(text):
    a, b = text.find("{"), text.rfind("}")
    if a < 0 or b < a:
        raise ValueError(f"no JSON object in model reply: {text[:120]!r}")
    d = json.loads(text[a:b + 1])
    label = str(d.get("label", "")).strip().lower()
    if label not in LABELS:
        raise ValueError(f"bad label {d.get('label')!r}")
    return Verdict(label, round(min(1.0, max(0.0, float(d.get("score", 0.5)))), 2), str(d.get("reason", ""))[:500])


def _http_post(url, payload, headers, timeout):
    req = urllib.request.Request(url, json.dumps(payload).encode(), headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


class LLMBackend:
    def __init__(self, model, url="http://localhost:11434/v1", api_key=None, timeout=180, post=_http_post):
        self.model, self.url, self.api_key, self.timeout, self._post = model, url.rstrip("/"), api_key, timeout, post
        self.name = f"llm:{model}"

    def score(self, ev, f):
        payload = {"model": self.model, "temperature": 0,
                   "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": json.dumps(llm_context(ev, f), indent=1)}]}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        resp = self._post(self.url + "/chat/completions", payload, headers, self.timeout)
        return parse_verdict(resp["choices"][0]["message"]["content"])


# ---------------------------------------------------------------------------------------------------------
# Pipeline: score every (event, revision) that a backend has not seen yet
# ---------------------------------------------------------------------------------------------------------
def ensure_schema(con):
    con.execute(DDL)
    con.commit()


def pending_ids(con, backend_name):
    return [r[0] for r in con.execute(
        "SELECT e.id FROM moas_events e WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.event_id=e.id "
        "AND v.revision=e.revision AND v.backend=?) ORDER BY e.id", (backend_name,))]


def run_once(con, backends, whitelist=None, log=lambda *a: None):
    """Returns [(event_dict, backend_name, Verdict)] for everything newly scored. A backend that raises
    (e.g. the model server is down) is logged and retried on the next pass; it never blocks the others."""
    ensure_schema(con)
    todo = {b.name: pending_ids(con, b.name) for b in backends}
    ids = sorted(set().union(*todo.values())) if todo else []
    if not ids:
        return []
    events = {e["id"]: e for e in read_events(con, f"id IN ({','.join('?' * len(ids))})", ids)}
    done = []
    for i in ids:
        ev = events[i]
        feats = build_features(ev, whitelist)
        for b in backends:
            if i not in todo[b.name]:
                continue
            try:
                v = b.score(ev, feats)
            except Exception as e:  # noqa: BLE001 - keep the loop alive whatever the backend does
                log(f"  [{b.name}] event #{i} failed: {e}")
                continue
            con.execute("INSERT OR REPLACE INTO verdicts VALUES(?,?,?,?,?,?,?)",
                        (i, ev["revision"], b.name, time.time(), v.label, v.score, v.reason))
            con.commit()
            done.append((ev, b.name, v))
    return done


def fmt(ev, backend, v):
    origins = ", ".join("AS" + o["origin"] for o in ev["origins"])
    return f"[AI/{backend}] {v.label.upper():9} {v.score:.2f} {ev['prefix']} ({origins}) event #{ev['id']} r{ev['revision']}: {v.reason}"


def make_backends(args):
    out = []
    if args.backend in ("baseline", "both"):
        out.append(BaselineBackend())
    if args.backend in ("llm", "both"):
        if not args.llm_model:
            raise SystemExit("--llm-model is required for the llm backend")
        out.append(LLMBackend(args.llm_model, args.llm_url, args.llm_api_key or os.environ.get("LLM_API_KEY")))
    return out


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default="moas.db")
    p.add_argument("--whitelist", help="JSON {prefix: [legit origin ASNs]}; used as prior knowledge, not as a verdict")
    p.add_argument("--backend", choices=["baseline", "llm", "both"], default="baseline")
    p.add_argument("--llm-url", default="http://localhost:11434/v1", help="OpenAI-compatible base URL")
    p.add_argument("--llm-model", help="model name as served by the endpoint")
    p.add_argument("--llm-api-key")
    p.add_argument("--watch", action="store_true", help="keep polling the catalog for new/changed events")
    p.add_argument("--interval", type=float, default=5, help="seconds between polls with --watch")
    a = p.parse_args()
    wl = json.load(open(a.whitelist)) if a.whitelist else {}
    backends = make_backends(a)
    con = sqlite3.connect(a.db, timeout=30)
    while True:
        for ev, name, v in run_once(con, backends, wl, log=print):
            print(fmt(ev, name, v), flush=True)
        if not a.watch:
            break
        time.sleep(a.interval)
