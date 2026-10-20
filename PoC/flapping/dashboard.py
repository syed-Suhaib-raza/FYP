"""streamlit run dashboard.py                      # online alerts, reads flap.db
   streamlit run dashboard.py -- --db demo.db       # the offline demo, reads demo.db
   Auto-refreshes every --refresh seconds (default 150 = 2.5 min); --no-refresh turns it off; the button refreshes now."""
import sys, sqlite3, time
import pandas as pd, streamlit as st

db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "flap.db"
refresh = int(sys.argv[sys.argv.index("--refresh") + 1]) if "--refresh" in sys.argv else 150     # seconds
st.set_page_config(page_title="BGP Route Flapping Monitor", layout="wide")
st.title("BGP Route Flapping Monitor")
st.caption("Proof of concept: RIPE RIS Live, deterministic penalty-and-decay rule per (prefix, peer session)")


def show(frame):                      # full-width table on both old and new Streamlit versions
    try:
        st.dataframe(frame, width="stretch", hide_index=True)
    except Exception:
        st.dataframe(frame, use_container_width=True, hide_index=True)


if st.button("Refresh now"):
    st.rerun()
try:
    df = pd.read_sql("SELECT * FROM alerts ORDER BY ts DESC", sqlite3.connect(db))
except Exception:
    df = pd.DataFrame()
if df.empty:
    st.info("No flap alerts yet. Run ris_live.py (or replay.py) first.")
else:
    df["time (UTC)"] = pd.to_datetime(df["ts"], unit="s")
    df["alert"] = df.source.str.capitalize() + " route flapping"
    onsets = df[df.event == "onset"]
    last = df.sort_values("ts").groupby(["source", "prefix", "collector", "peer_asn"]).tail(1)   # open = latest event is an onset
    active = last[last.event == "onset"]

    c = st.columns(4)
    c[0].metric("Active flaps now", len(active)); c[1].metric("Flap alerts", len(onsets))
    c[2].metric("Prefixes affected", onsets.prefix.nunique()); c[3].metric("Peer sessions", onsets[["collector", "peer_asn"]].drop_duplicates().shape[0])

    st.subheader("Active flaps")
    cols = ["time (UTC)", "alert", "severity", "prefix", "collector", "peer_asn", "penalty", "withdrawals", "path_changes",
            "peers_flapping", "as_path"]
    if len(active):
        show(active[cols])
    else:
        st.write("None.")
    st.subheader("History (alerts and clears)")
    show(df[["time (UTC)", "alert", "event", "severity", "prefix", "collector", "peer_asn", "penalty", "withdrawals",
             "path_changes", "reason", "as_path"]])
    if len(onsets):
        st.subheader("Most unstable prefixes")
        st.bar_chart(onsets.groupby("prefix").size().sort_values(ascending=False))
        st.subheader("Flap alerts over time")
        st.bar_chart(onsets.set_index("time (UTC)").resample("1min").size())
if "--no-refresh" not in sys.argv:
    st.caption(f"Auto-refresh every {refresh} s")
    time.sleep(refresh); st.rerun()
