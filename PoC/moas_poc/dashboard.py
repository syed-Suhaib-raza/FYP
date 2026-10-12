"""streamlit run dashboard.py -- --db moas.db   (auto-refreshes every 5s)"""
import sys, json, sqlite3, time
import pandas as pd, streamlit as st

db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "moas.db"
st.set_page_config(page_title="BGP MOAS Monitor", layout="wide")
st.title("BGP MOAS (Multiple Origin AS) Monitor")
st.caption("Proof of concept: RIPE RIS Live, deterministic origin-conflict rule")

try:
    df = pd.read_sql("SELECT * FROM alerts ORDER BY ts DESC", sqlite3.connect(db))
except Exception:
    df = pd.DataFrame()
if df.empty:
    st.info("No alerts yet. Run ris_live.py (or replay.py) first.")
else:
    df["time (UTC)"] = pd.to_datetime(df["ts"], unit="s")
    df["origins"] = df["origins"].apply(lambda s: ", ".join(f"AS{o}" for o in json.loads(s)))
    df["expected"] = df["expected"].apply(lambda s: ", ".join(f"AS{o}" for o in json.loads(s)) or "-")
    sev = st.multiselect("Severity", ["high", "medium", "info"], default=["high", "medium", "info"])
    d = df[df.severity.isin(sev)]
    c = st.columns(4)
    c[0].metric("Alerts", len(d)); c[1].metric("High", int((d.severity == "high").sum()))
    c[2].metric("Prefixes affected", d.prefix.nunique()); c[3].metric("Collectors", d.collector.nunique())
    st.dataframe(d[["time (UTC)", "severity", "prefix", "origins", "expected", "new_origin", "collector", "peer_asn", "as_path"]],
                 use_container_width=True, hide_index=True)
    st.subheader("Alerts over time")
    st.bar_chart(d.set_index("time (UTC)").resample("1min").size())
if "--no-refresh" not in sys.argv:
    time.sleep(5); st.rerun()
