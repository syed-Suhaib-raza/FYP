"""streamlit run dashboard.py -- --db aspath.db --refresh 150"""
import ipaddress, re, sys, sqlite3, time
import pandas as pd, streamlit as st
from detector import RULES

db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "aspath.db"
refresh = int(sys.argv[sys.argv.index("--refresh") + 1]) if "--refresh" in sys.argv else 150
st.set_page_config(page_title="AS-Path Anomaly Monitor", layout="wide")
st.title("BGP AS-Path Anomaly Monitor")
st.caption("Rules from the ROUTE LLM paper / proposal pick the candidates (type = rule that fired); ROUTE LLM (Llama-3.1-8B + LoRA) is a second opinion: high = model agrees it is anomalous, medium = rule only or model says none. "
           "Rows with model MOCK are NOT real model output. An anomaly is suspicious routing, not a confirmed attack.")
if st.button("Refresh now"):
    st.rerun()
try:
    df = pd.read_sql("SELECT * FROM incidents ORDER BY last_ts DESC", sqlite3.connect(db))
except Exception:
    df = pd.DataFrame()
if df.empty:
    st.info("No incidents yet. Run `python aspath.py demo` or `python aspath.py live` first.")
else:
    df["first seen (UTC)"] = pd.to_datetime(df["first_ts"], unit="s")
    df["duration (s)"] = (df["recovered_ts"].fillna(df["last_ts"]) - df["first_ts"]).round(0)
    objs = sorted(set(df.prefix) | {f"AS{x}" for x in df.origin} | {x.strip() for v in df.affected_prefixes.dropna() for x in v.split(",")})
    c1, c2 = st.columns([2, 1])
    typed = c1.text_input("Investigate: IP address, prefix, ASN (AS15169) or peer")
    picked = c2.selectbox("...or click through to", [""] + objs)
    q = (typed or picked).strip()

    def match(r):
        """IP -> incidents whose prefix contains it; prefix -> overlapping; ASN -> in path / origin / expected; else substring."""
        try:
            ip = ipaddress.ip_address(q)
            return ip in ipaddress.ip_network(r.prefix, strict=False)
        except ValueError:
            pass
        try:
            n = ipaddress.ip_network(q, strict=False)
            return any(n.version == m.version and (n.subnet_of(m) or m.subnet_of(n)) for m in
                       [ipaddress.ip_network(x.strip(), strict=False) for x in str(r.affected_prefixes or r.prefix).split(",") if x.strip()])
        except ValueError:
            pass
        m = re.fullmatch(r"(?i)(?:AS)?(\d+)", q)
        if m:
            return m.group(1) in str(r.as_path).split() or m.group(1) == str(r.origin) or f"AS{m.group(1)}" in str(r.expected_origin).split(",") or m.group(1) == str(r.peer_asn)
        return q in f"{r.prefix} {r.as_path} {r.origin} {r.collector} {r.peer_asn}"
    if q:
        df = df[df.apply(match, axis=1)]
        st.caption(f"Investigation of {q}: {len(df)} incident(s), {int((df.status == 'active').sum())} active; previous occurrences and recovery below.")
    c = st.columns(5)
    c[0].metric("Incidents", len(df)); c[1].metric("Active", int((df.status == "active").sum()))
    c[2].metric("High severity", int((df.severity == "high").sum())); c[3].metric("Route leaks / path hijacks", f"{int((df.anomaly_type == 'route_leak').sum())} / {int((df.anomaly_type == 'path_hijack').sum())}")
    c[4].metric("Median LLM ms", int(df.llm_ms.dropna().median()) if df.llm_ms.notna().any() else 0)
    cols = ["first seen (UTC)", "status", "severity", "anomaly_type", "subtype", "prefix", "expected_origin", "origin", "as_path", "llm_label", "llm_agrees",
            "signals", "peers_seen", "affected", "duration (s)", "occurrence", "model", "source"]
    cols = [c_ for c_ in cols if c_ in df.columns]
    try:
        st.dataframe(df[cols], width="stretch", hide_index=True)
    except Exception:
        st.dataframe(df[cols], use_container_width=True, hide_index=True)
    st.subheader("Incident detail")
    for _, r in df.head(20).iterrows():
        with st.expander(f"[{r.severity}] {r.status} - {r.get('anomaly_type') or ''} - {r.prefix} via {r.as_path}"):
            st.markdown(f"**Expected vs observed**  \nExpected origin {r.expected_origin}, typical path `{r.expected_path}`  \n"
                        f"Observed origin AS{r.origin}, path `{r.as_path}`")
            st.markdown("**Change details (rules that fired)**  \n" + (r.signals or "-").replace("; ", "  \n"))
            for rule in [k for k in RULES if f"{k}:" in str(r.signals)]:
                st.caption(f"{rule}: {RULES[rule]['paper']}")
            rec = "not recovered" if pd.isna(r.recovered_ts) else f"recovered {pd.to_datetime(r.recovered_ts, unit='s')}"
            st.markdown(f"**Timing**  \nFirst seen {r['first seen (UTC)']}, last seen {pd.to_datetime(r.last_ts, unit='s')}, {rec}, "
                        f"occurrence #{int(r.occurrence or 1)}")
            st.markdown(f"**Impact / visibility**  \nSeen by {int(r.peers_seen or 1)} peer(s) at {int(r.collectors_seen or 1)} collector(s); {int(r['count'])} update(s); "
                        f"{int(r.affected or 1)} prefix(es) affected: {r.affected_prefixes}  \n**Paths seen (routing views):** {r.paths_seen}")
            st.markdown(f"**Evidence given to the model**  \n{r.evidence or '-'}  \n**LLM verdict:** {r.llm_label} - agrees with rule type: {r.get('llm_agrees')} ({r.model}, prompt style {r.prompt_style})  \n**Raw model output:** `{r.raw_output}`  \n**Priority:** {r.severity}")
if "--no-refresh" not in sys.argv:
    time.sleep(refresh); st.rerun()
