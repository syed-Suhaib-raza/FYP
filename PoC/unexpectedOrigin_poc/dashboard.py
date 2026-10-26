"""streamlit run dashboard.py -- --db origin.db"""
import sys, json, sqlite3, time
import pandas as pd, streamlit as st
db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "origin.db"
st.set_page_config(page_title="Unexpected Origin (RouteLLM)", layout="wide")
st.title("Unexpected Origin Monitor (RouteLLM PoC)")
st.caption("Deterministic candidate filter + LoRA-adapted Llama-3.1-8B classification. Model output is advisory; validate before acting.")
try:
    df = pd.read_sql("SELECT * FROM alerts ORDER BY ts DESC", sqlite3.connect(db))
    if "anomaly_type" not in df or df.anomaly_type.isna().any():   # rows from older runs
        df["anomaly_type"] = df.subtype.map(lambda s: "unexpected_origin" if s == "origin" else "unexpected_deaggregation")
except Exception:
    df = pd.DataFrame()
if df.empty:
    st.info("No candidates yet.")
else:
    if (df.model == "MOCK").any():
        st.warning("Some rows come from the MOCK model (pipeline test), not RouteLLM.")
    df["time (UTC)"] = pd.to_datetime(df.ts, unit="s")
    sev = st.multiselect("Severity", ["high", "medium", "low"], default=["high", "medium", "low"])
    d = df[df.severity.isin(sev)]
    c = st.columns(5)
    c[0].metric("Candidates", len(d)); c[1].metric("Unexpected Origin", int((d.anomaly_type == "unexpected_origin").sum()))
    c[2].metric("Unexpected Deaggregation", int((d.anomaly_type == "unexpected_deaggregation").sum()))
    c[3].metric("Model says none", int((d.label == "none").sum()))
    st.dataframe(d[["id", "time (UTC)", "severity", "anomaly_type", "label", "prefix", "origin", "expected", "peer_asn", "as_path", "model"]],
                 use_container_width=True, hide_index=True)
    pick = st.selectbox("Inspect alert id", d.id.tolist())
    row = d[d.id == pick].iloc[0]
    st.markdown(f"**Raw model output:** `{row.raw_output}`")
    st.markdown("**Evidence given to the model:**")
    for i, s in enumerate(json.loads(row.evidence), 1):
        st.write(f"{i}. {s}")
if "--no-refresh" not in sys.argv:
    time.sleep(5); st.rerun()
