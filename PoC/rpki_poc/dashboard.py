"""python -m streamlit run dashboard.py -- --db rpki.db     (demo: -- --db demo.db; auto-refreshes every 5 s)

Reads the tables main.py writes: alerts, alert_events, roa_changes, meta."""
import json, sys, sqlite3, time
import pandas as pd, streamlit as st

db = sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "rpki.db"
st.set_page_config(page_title="RPKI Invalid Monitor", layout="wide")
st.title("RPKI Invalid Monitor (Cybernet AS9541 / AS24440)")
st.caption("Proof of concept, deterministic: Routinator VRPs + RFC 6811 Route Origin Validation on RIPE RIS Live. "
           "An alert is evidence for investigation, not a confirmed attack.")

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_ICON = {"CRITICAL": "🔴 CRITICAL", "HIGH": "🟠 HIGH", "MEDIUM": "🟡 MEDIUM", "LOW": "🔵 LOW", "INFO": "⚪ INFO"}


def q(sql, params=()):
    try:
        return pd.read_sql(sql, sqlite3.connect(db, timeout=30), params=params)
    except Exception:
        return pd.DataFrame()


def meta():
    m = q("SELECT key, value FROM meta")
    return {} if m.empty else {k: json.loads(v) for k, v in zip(m.key, m.value)}


def table(df):
    try:
        st.dataframe(df, width="stretch", hide_index=True)
    except TypeError:
        st.dataframe(df, use_container_width=True, hide_index=True)


def ts(col):
    return pd.to_datetime(col, unit="s", errors="coerce")


auto = st.sidebar.checkbox("Auto-refresh (5s)", value="--no-refresh" not in sys.argv)
m = meta()
alerts = q("SELECT * FROM alerts")
roa = q("SELECT * FROM roa_changes ORDER BY ts DESC")

# ---- status bar ----------------------------------------------------------------------------------------------
if m:
    age = time.time() - m.get("vrp_loaded_at", time.time())
    vrp_txt = f"{m.get('vrp_count', 0):,} VRPs, generated {m.get('vrp_generated') or '?'}"
    if m.get("mode") == "live" and m.get("vrp_stale"):
        st.error(f"VRPs are {age / 60:.0f} min old: Routinator may be down. ({vrp_txt})")
    else:
        st.sidebar.success(f"VRP source OK: {vrp_txt}")
    st.sidebar.write(f"Mode: **{m.get('mode', '?')}**, alert after **{m.get('min_peers', '?')}** RIS peers")
    st.sidebar.write(f"Routes tracked: {m.get('routes_tracked', 0)} on {m.get('prefixes_tracked', 0)} prefixes")

if alerts.empty and roa.empty:
    st.info("Nothing yet. Run  python main.py --demo  (or live: python main.py), then refresh.")
else:
    if not alerts.empty:
        alerts["origin"] = alerts["origin_asn"].apply(lambda o: "AS_SET" if pd.isna(o) or o == -1 else f"AS{int(o)}")
        alerts["severity "] = alerts["severity"].map(SEV_ICON).fillna(alerts["severity"])
        alerts["first seen (UTC)"] = ts(alerts["first_seen"])
        alerts["last seen (UTC)"] = ts(alerts["last_seen"])
        alerts["_sev"] = alerts["severity"].map(SEV_ORDER)
    active = alerts[alerts.status == "ACTIVE"] if not alerts.empty else alerts
    c = st.columns(6)
    c[0].metric("Active alerts", len(active))
    c[1].metric("Critical", int((active.severity == "CRITICAL").sum()) if len(active) else 0)
    c[2].metric("High", int((active.severity == "HIGH").sum()) if len(active) else 0)
    c[3].metric("Low (no ROA)", int((active.severity == "LOW").sum()) if len(active) else 0)
    c[4].metric("Resolved", int((alerts.status == "RESOLVED").sum()) if not alerts.empty else 0)
    c[5].metric("ROA changes (medium)", int((roa.severity == "MEDIUM").sum()) if not roa.empty else 0)

    t_act, t_all, t_roa, t_states, t_detail = st.tabs(
        ["Active alerts", "All alerts", "ROA changes", "Route states", "Alert detail"])
    cols = ["severity ", "alert_id", "prefix", "origin", "state", "cause", "seen_by_peers", "first seen (UTC)",
            "last seen (UTC)", "likely_meaning"]

    with t_act:
        if active.empty:
            st.success("No active alerts.")
        else:
            table(active.sort_values(["_sev", "first_seen"])[cols])
            st.caption("Severity rules: foreign origin first time CRITICAL; seen before, customer, or Cybernet's own "
                       "mistake HIGH; Cybernet prefix with no ROA LOW. PENDING alerts (fewer RIS peers than the "
                       "threshold) are not shown here.")

    with t_all:
        if not alerts.empty:
            status = st.multiselect("Status", ["ACTIVE", "RESOLVED", "PENDING", "DROPPED"], default=["ACTIVE", "RESOLVED"])
            pf = st.text_input("Prefix contains", "")
            d = alerts[alerts.status.isin(status)]
            if pf:
                d = d[d.prefix.str.contains(pf, regex=False)]
            table(d.sort_values("first_seen", ascending=False)[["status"] + cols])
            ev = q("SELECT ts, event FROM alert_events WHERE event IN ('ACTIVE','REOPENED')")
            if not ev.empty:
                st.subheader("Alerts raised over time")
                st.bar_chart(ev.assign(t=ts(ev.ts)).set_index("t").resample("1min").size())

    with t_roa:
        if roa.empty:
            st.write("No ROA changes seen for Cybernet.")
        else:
            roa["time (UTC)"] = ts(roa["ts"])
            roa["severity "] = roa["severity"].map(SEV_ICON)
            table(roa[["time (UTC)", "severity ", "change", "prefix", "asn", "old_max", "new_max", "detail"]])
            st.caption("A removed ROA, a smaller maxLength or a ROA about to expire can turn Cybernet's routes Invalid "
                       "without any BGP update. Every route held is re-validated when the VRPs change.")

    with t_states:
        counts = m.get("state_counts", {})
        if counts:
            st.write("Announcements seen for watched prefixes, by RPKI state (RFC 6811):")
            st.bar_chart(pd.Series(counts, name="announcements"))
        st.write(m.get("stats", {}))

    with t_detail:
        if not alerts.empty:
            ids = alerts.sort_values("first_seen", ascending=False).alert_id.tolist()
            aid = st.selectbox("Alert", ids, format_func=lambda i: f"{i}  {alerts.loc[alerts.alert_id == i, 'prefix'].iloc[0]}")
            a = alerts[alerts.alert_id == aid].iloc[0]
            st.markdown(f"**{SEV_ICON.get(a.severity, a.severity)}  {a.state} ({a.cause})**  {a.prefix} from {a.origin}, status **{a.status}**")
            st.write("**Why:**", a.explanation)
            st.write("**Likely meaning:**", a.likely_meaning)
            st.write("**Suggested action:**", a.suggested_action)
            st.write("**AS path (latest):**", " ".join(map(str, json.loads(a.as_path))) if a.as_path else "-")
            st.write("**ROAs covering the prefix:**")
            table(pd.DataFrame(json.loads(a.authorised_vrps or "[]")))
            st.write("**RIS peers carrying it now:**", ", ".join(json.loads(a.peers or "[]")) or "none")
            if a.routinator_check:
                st.write("**Routinator /validity second opinion:**", json.loads(a.routinator_check))
            h = q("SELECT ts, event, status, severity, seen_by_peers, detail FROM alert_events WHERE alert_id=? ORDER BY id", (aid,))
            h["time (UTC)"] = ts(h.ts)
            st.write("**History:**")
            table(h.drop(columns="ts"))

if auto:
    time.sleep(5); st.rerun()
