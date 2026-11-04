"""streamlit run dashboard.py -- --db moas.db   (auto-refreshes every 5s unless switched off)

Reads the two layers' tables: the catalog (moas_events / moas_origins) and the AI verdicts (verdicts)."""
import sys, json, sqlite3, time
import pandas as pd, streamlit as st

db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "moas.db"
st.set_page_config(page_title="BGP MOAS Monitor", layout="wide")
st.title("BGP MOAS (Multiple Origin AS) Monitor")
st.caption("Proof of concept: RIPE RIS Live. Layer 1 catalogs every multi-origin prefix; layer 2 (AI) flags the anomalous ones.")


def q(sql, params=()):
    try:
        return pd.read_sql(sql, sqlite3.connect(db, timeout=30), params=params)
    except Exception:
        return pd.DataFrame()


def table(df):
    """st.dataframe across Streamlit versions (width= is new, use_container_width= is the old spelling)."""
    try:
        st.dataframe(df, width="stretch", hide_index=True)
    except TypeError:
        st.dataframe(df, use_container_width=True, hide_index=True)


def asn_list(s):
    return ", ".join("AS" + o for o in json.loads(s))


events = q("SELECT * FROM moas_events ORDER BY first_seen DESC")
auto = st.sidebar.checkbox("Auto-refresh (5s)", value="--no-refresh" not in sys.argv)

if events.empty:
    st.info("Nothing cataloged yet. Run ris_live.py (or replay.py) first.")
else:
    events["time (UTC)"] = pd.to_datetime(events["first_seen"], unit="s")
    events["origins"] = events["origins"].apply(asn_list)
    events["n_origins"] = events["origins"].str.count("AS")
    ev_origins = q("SELECT * FROM moas_origins")
    stats = ev_origins.assign(n_peers=ev_origins["peers"].apply(lambda s: len(json.loads(s))),
                              cols=ev_origins["collectors"].apply(json.loads), peer_set=ev_origins["peers"].apply(json.loads))
    agg = stats.groupby("event_id").agg(
        peers=("peer_set", lambda x: len(set().union(*map(set, x)))),
        collectors=("cols", lambda x: len(set().union(*map(set, x))))).reset_index().rename(columns={"event_id": "id"})
    events = events.merge(agg, on="id", how="left")

    verdicts = q("SELECT v.* FROM verdicts v JOIN (SELECT event_id, backend, MAX(revision) r FROM verdicts "
                 "GROUP BY event_id, backend) m ON v.event_id=m.event_id AND v.backend=m.backend AND v.revision=m.r")
    backends = sorted(verdicts.backend.unique()) if not verdicts.empty else []
    backend = st.sidebar.selectbox("AI verdicts from", backends) if backends else None
    if backend:
        v = verdicts[verdicts.backend == backend][["event_id", "revision", "label", "score", "reason"]]
        v = v.rename(columns={"event_id": "id", "revision": "scored_rev"})
        events = events.merge(v, on="id", how="left")
        events["label"] = events["label"].fillna("unscored")
        events["stale"] = events["scored_rev"].notna() & (events["scored_rev"] < events["revision"])
    else:
        events["label"], events["score"], events["reason"], events["stale"] = "unscored", None, "", False
        st.sidebar.info("No AI verdicts yet. Run: python ai_layer.py --db " + db)

    c = st.columns(5)
    c[0].metric("Events cataloged", len(events))
    c[1].metric("Still open", int((events.status == "open").sum()))
    c[2].metric("Prefixes", events.prefix.nunique())
    c[3].metric("Flagged anomalous", int((events.label == "anomalous").sum()))
    c[4].metric("Uncertain / unscored", f"{int((events.label == 'uncertain').sum())} / {int((events.label == 'unscored').sum())}")

    t_flag, t_cat, t_detail = st.tabs(["Flagged by AI layer", "Full catalog", "Event detail"])

    with t_flag:
        show = st.multiselect("Labels", ["anomalous", "uncertain", "benign", "unscored"], default=["anomalous", "uncertain"])
        d = events[events.label.isin(show)].sort_values(["label", "score"], ascending=[True, False])
        table(d[["time (UTC)", "label", "score", "prefix", "origins", "status", "peers", "reason", "stale"]])
        if backend:
            st.caption(f"Verdicts by '{backend}'. 'stale' = the event changed after it was scored.")

    with t_cat:
        pf = st.text_input("Filter by prefix contains", "")
        d = events[events.prefix.str.contains(pf, regex=False)] if pf else events
        table(d[["time (UTC)", "id", "prefix", "status", "n_origins", "origins", "peers", "collectors", "label", "score"]])
        st.subheader("Events over time")
        st.bar_chart(d.set_index("time (UTC)").resample("1min").size())

    with t_detail:
        ids = events.sort_values("id", ascending=False).id.tolist()
        eid = st.selectbox("Event", ids, format_func=lambda i: f"#{i}  {events.loc[events.id == i, 'prefix'].iloc[0]}")
        o = ev_origins[ev_origins.event_id == eid].copy().sort_values("first_seen")
        o["first seen"] = pd.to_datetime(o["first_seen"], unit="s")
        o["last seen"] = pd.to_datetime(o["last_seen"], unit="s")
        o["peers"] = o["peers"].apply(lambda s: ", ".join("AS" + p for p in json.loads(s)))
        o["collectors"] = o["collectors"].apply(lambda s: ", ".join(json.loads(s)))
        o["paths"] = o["paths"].apply(lambda s: " | ".join(json.loads(s)))
        o["origin"] = "AS" + o["origin"]
        st.markdown("**Evidence from the catalog (layer 1)**")
        table(o[["origin", "first seen", "last seen", "n_updates", "peers", "collectors", "paths"]])
        st.markdown("**Verdict history (layer 2)**")
        h = q("SELECT backend, revision, label, score, reason, ts FROM verdicts WHERE event_id=? ORDER BY revision DESC, backend", (int(eid),))
        if h.empty:
            st.write("Not scored yet.")
        else:
            h["scored at (UTC)"] = pd.to_datetime(h["ts"], unit="s")
            table(h.drop(columns="ts"))

if auto:
    time.sleep(5); st.rerun()
