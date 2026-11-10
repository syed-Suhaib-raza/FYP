"""Builds results_and_calculations.xlsx: ONE file that stores every result and shows every calculation as an Excel
formula. Counterpart of flapping/build_results.py.

   python eval.py eval_set.jsonl                    # makes results_sim.csv / results_sim.json   (run first)
   python build_results.py                          # -> results_and_calculations.xlsx
   python build_results.py                          # after the live runs it also picks up (if present):
        #   full_report.json / full_alerts.jsonl / full_events.csv   (Run A)   and   pfx_report.json / pfx_alerts.jsonl / pfx_events.csv   (Run B)
   python build_results.py --run "Run A full rrc00=full_report,full_alerts.jsonl,full_events.csv" --run "Run B prefixes=pfx_report,pfx_alerts.jsonl,pfx_events.csv"

Raw per-case data are blue; everything else is a formula, so changing a raw cell recalculates the metrics.
The workbook also lists the numbers eval.py printed next to the formula result, with OK / CHECK, so the PoC output is verified.
Needs: openpyxl. Does not modify any existing file. Live sheets list one row per EVENT (cluster_events.py output; falls back to one row
per alert if there is no events CSV) and the manual `verdict` column you filled in is read from that CSV.
"""
import argparse, csv, json, os
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter as L

F = "Arial"
BLUE, BLACK = Font(name=F, size=10, color="0000FF"), Font(name=F, size=10)
BOLD, TITLE = Font(name=F, size=10, bold=True), Font(name=F, size=14, bold=True)
NOTE = Font(name=F, size=9, italic=True, color="595959")
HEAD = PatternFill("solid", fgColor="D9E1F2")
YEL = PatternFill("solid", fgColor="FFFF00")
GREY = PatternFill("solid", fgColor="EDEDED")
LABELS = ("path hijack", "route leak", "normal")


def put(ws, ref, v, font=BLACK, fmt=None, fill=None, wrap=False):
    c = ws[ref]; c.value = v; c.font = font
    if fmt: c.number_format = fmt
    if fill: c.fill = fill
    if wrap: c.alignment = Alignment(wrap_text=True, vertical="top")
    return c


def header(ws, row, labels, col=1):
    for i, t in enumerate(labels):
        c = ws.cell(row=row, column=col + i, value=t); c.font = BOLD; c.fill = HEAD
        c.alignment = Alignment(wrap_text=True, vertical="center")


def widths(ws, ws_widths):
    for i, w in enumerate(ws_widths, 1):
        ws.column_dimensions[L(i)].width = w


def b(x):
    return str(x).strip().lower() == "true"


def rng(col, a, z):
    return f"Sim_Cases!${col}${a}:${col}${z}"


# ======================================================================= simulated data
def sim_cases(wb, rows):
    ws = wb.create_sheet("Sim_Cases")
    header(ws, 1, ["id", "kind", "label", "truth_anomalous", "predicted_anomalous", "rule_type", "type_correct",
                   "llm_label", "compute_ms", "outcome", "type_check"])
    r = 2
    for row in rows:
        vals = [row["id"], row["kind"], row["label"], b(row["truth_anomalous"]), b(row["predicted_anomalous"]),
                row["rule_type"] or "", b(row["type_correct"]) if row["type_correct"] else "", row["llm_label"] or "", float(row["compute_ms"])]
        for j, v in enumerate(vals, 1):
            put(ws, f"{L(j)}{r}", v, BLUE, "0.0000" if j == 9 else None)
        put(ws, f"J{r}", f'=IF(AND(D{r},E{r}),"TP",IF(E{r},"FP",IF(D{r},"FN","TN")))')
        put(ws, f"K{r}", f'=IF(J{r}="TP",IF(G{r},"OK","WRONG TYPE"),"")')
        r += 1
    ws.freeze_panes = "A2"; ws.auto_filter.ref = f"A1:K{r - 1}"
    widths(ws, [11, 20, 11, 16, 18, 13, 12, 10, 12, 9, 11])
    return 2, r - 1


def sim_metrics(wb, a, z, overall):
    ws = wb.create_sheet("Sim_Metrics")
    put(ws, "A1", "Simulated test: accuracy, computed from Sim_Cases", TITLE)
    put(ws, "A2", "Outcome (Sim_Cases col J): TP = anomalous and flagged, FP = normal but flagged, FN = anomalous missed, TN = normal and quiet.", NOTE)
    cols = ["Scope", "n", "TP", "FP", "FN", "TN", "Accuracy", "Precision", "Recall", "F1", "FPR"]
    row, cell = 4, {}
    for title, crit in [("All cases", "")] + [(f"Label = {lab}", f',{rng("C", a, z)},"{lab}"') for lab in LABELS]:
        header(ws, row, cols); row += 1
        put(ws, f"A{row}", title, BLACK)
        put(ws, f"B{row}", f'=COUNTIFS({rng("D", a, z)},"<>"{crit})' if not crit else f'=COUNTIFS({rng("C", a, z)},"{title.split("= ")[1]}")')
        for col, o in zip("CDEF", ("TP", "FP", "FN", "TN")):
            c2 = f',{rng("C", a, z)},"{title.split("= ")[1]}"' if crit else ""
            put(ws, f"{col}{row}", f'=COUNTIFS({rng("J", a, z)},"{o}"{c2})')
        put(ws, f"G{row}", f"=IF(B{row}=0,0,(C{row}+F{row})/B{row})", fmt="0.000")
        put(ws, f"H{row}", f"=IF(C{row}+D{row}=0,0,C{row}/(C{row}+D{row}))", fmt="0.000")
        put(ws, f"I{row}", f"=IF(C{row}+E{row}=0,0,C{row}/(C{row}+E{row}))", fmt="0.000")
        put(ws, f"J{row}", f"=IF(H{row}+I{row}=0,0,2*H{row}*I{row}/(H{row}+I{row}))", fmt="0.000")
        put(ws, f"K{row}", f"=IF(D{row}+F{row}=0,0,D{row}/(D{row}+F{row}))", fmt="0.000")
        if title == "All cases":
            cell["all"] = row
        row += 2
    put(ws, f"A{row}", "Formulas", BOLD); row += 1
    for t in ("Accuracy = (TP + TN) / n", "Precision = TP / (TP + FP)", "Recall = TP / (TP + FN)",
              "F1 = 2 * Precision * Recall / (Precision + Recall)", "FPR (false positive rate) = FP / (FP + TN)"):
        put(ws, f"A{row}", t, NOTE); row += 1
    row += 1
    put(ws, f"A{row}", "Check: numbers printed by eval.py (results_sim.json) vs this workbook's formulas", BOLD); row += 1
    header(ws, row, ["Metric", "eval.py value", "Workbook formula", "Abs diff", "Tolerance", "Status"]); row += 1
    rown = cell["all"]
    for jk, col, label, tol in [("n", "B", "n", 0), ("tp", "C", "TP", 0), ("fp", "D", "FP", 0), ("fn", "E", "FN", 0),
                                ("tn", "F", "TN", 0), ("accuracy", "G", "Accuracy", 0.0006), ("precision", "H", "Precision", 0.0006),
                                ("recall", "I", "Recall", 0.0006), ("f1", "J", "F1", 0.0006), ("fpr", "K", "FPR", 0.0006)]:
        v = overall.get(jk)
        put(ws, f"A{row}", label)
        put(ws, f"B{row}", v, BLUE, "0.000" if isinstance(v, float) else None)
        put(ws, f"C{row}", f"=Sim_Metrics!{col}{rown}", fmt="0.000")
        put(ws, f"D{row}", f'=IFERROR(ABS(B{row}-C{row}),"-")', fmt="0.0000")
        put(ws, f"E{row}", tol, BLUE)
        put(ws, f"F{row}", f'=IF(ISNUMBER(D{row}),IF(D{row}<=E{row},"OK","CHECK"),"-")')
        row += 1
    ws.freeze_panes = "B4"
    widths(ws, [22, 10, 10, 10, 10, 10, 10, 10, 8, 8])


def sim_per_kind(wb, a, z):
    ws = wb.create_sheet("Sim_PerKind")
    put(ws, "A1", "Simulated test: detector result per scenario kind", TITLE)
    header(ws, 3, ["Kind", "Label", "Cases", "Correct", "Wrong"])
    ws0 = wb["Sim_Cases"]
    kinds = {}
    for r in range(a, z + 1):
        kinds[ws0[f"B{r}"].value] = ws0[f"C{r}"].value
    B_, J = rng("B", a, z), rng("J", a, z)
    for i, k in enumerate(sorted(kinds), 4):
        put(ws, f"A{i}", k, BLUE); put(ws, f"B{i}", kinds[k], BLUE)
        put(ws, f"C{i}", f'=COUNTIFS({B_},$A{i})')
        put(ws, f"D{i}", f'=COUNTIFS({B_},$A{i},{J},"TP")+COUNTIFS({B_},$A{i},{J},"TN")')
        put(ws, f"E{i}", f"=C{i}-D{i}")
    end = 3 + len(kinds)
    put(ws, f"A{end + 1}", "Total", BOLD)
    for c in "CDE":
        put(ws, f"{c}{end + 1}", f"=SUM({c}4:{c}{end})", BOLD)
    put(ws, f"A{end + 3}", "normal_new_peer is the known honest false-positive kind: a legitimate new peering AS looks "
        "identical to a hijacked link to a rules-only detector (no way to tell them apart from the AS path alone).", NOTE)
    widths(ws, [22, 11, 8, 9, 8])


# ======================================================================= live data
def read_jsonl(p):
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()] if p and os.path.exists(p) else []


def live_sheet(wb, sheet, label, rep_path, alerts_path, events_path):
    ws = wb.create_sheet(sheet)
    rep = json.load(open(rep_path + ".json", encoding="utf-8")) if os.path.exists(rep_path + ".json") else None
    rs = json.load(open(rep_path + "_runstats.json", encoding="utf-8")) if os.path.exists(rep_path + "_runstats.json") else None
    alerts = read_jsonl(alerts_path)
    ev = list(csv.DictReader(open(events_path, encoding="utf-8"))) if events_path and os.path.exists(events_path) else []
    use_events = bool(ev)
    put(ws, "A1", f"Live test: {label} (RIPE RIS Live). Inputs from the run (blue) and every derived number as a formula (black)", TITLE)
    put(ws, "A2", (f"Filled from {rep_path}.json, {alerts_path}, {events_path}") if rep else
       f"NO DATA YET for this run. After it finishes, run cluster_events.py, keep {rep_path}.json / {alerts_path} / {events_path} beside build_results.py and run it again.",
       NOTE, fill=None if rep else YEL)
    put(ws, "A3", "Blue = values copied from the run. Black = formulas. Yellow = fill in / missing.", NOTE)
    feed = (rep or {}).get("feed_delay_s") or {}
    comp = (rs or {}).get("compute_ms_all_messages") or {}
    put(ws, "A5", "Run", BOLD)
    run = [("Settings", json.dumps((rep or {}).get("header", {}))[:300], None), ("Messages recorded", (rep or {}).get("messages"), "#,##0"),
           ("Duration (s)", (rep or {}).get("duration_s"), "#,##0.0")]
    for i, (lab, v, fmt) in enumerate(run, 6):
        put(ws, f"A{i}", lab); put(ws, f"B{i}", v, BLUE, fmt)
    put(ws, "A9", "Messages per second"); put(ws, "B9", '=IF(OR(B7="",B8="",B8=0),"-",B7/B8)', fmt="0.0")
    put(ws, "A10", "Alerts logged live"); put(ws, "B10", len(alerts), BLUE, "#,##0")
    put(ws, "A12", "Latency over ALL messages", BOLD)
    header(ws, 13, ["Measure", "n", "median", "mean", "p95", "min", "max"])
    put(ws, "A14", "Feed delay (s) = PC receive time - RIS timestamp")
    for c, k in zip("BCDEFG", ("n", "median", "mean", "p95", "min", "max")):
        put(ws, f"{c}14", feed.get(k), BLUE, "0.000")
    put(ws, "A15", "Detector compute per message (ms)")
    for c, k in zip("BCDEFG", ("n", "median", "mean", "p95", "min", "max")):
        put(ws, f"{c}15", comp.get(k), BLUE, "0.0000")

    # ---- rows: one per event (or per alert)
    top = 19
    put(ws, f"A{top - 2}", "Events (cluster_events.py: same prefix + collector within 300 s = one event). Fill column L after checking RIPEstat / bgp.tools / CAIDA AS-rank."
        if use_events else "Alerts (one row per alert; no events CSV found). Fill column L after manual checking.", BOLD)
    header(ws, top - 1, ["#", "prefix", "collector", "alerts_in_event", "anomaly_type", "rule", "severity", "as_path", "feed_delay_s", "compute_ms", "first_alert_utc",
                         "manual verdict (TRUE/FALSE)"])
    src = ev if use_events else [dict(event_id=i, prefix=a["prefix"], collector=a["collector"], alerts_in_event=1, anomaly_type=a["anomaly_type"], rule=a["subtype"],
                                      severity=a["severity"], as_path=a["as_path"], feed_delay_s=a["feed_delay_s"], compute_ms=a["compute_ms"],
                                      first_alert_utc="", verdict="") for i, a in enumerate(alerts, 1)]
    num = lambda x: float(x) if x not in (None, "") else None
    for k, e in enumerate(src):
        r = top + k
        vals = [k + 1, e["prefix"], e["collector"], int(e["alerts_in_event"]), e["anomaly_type"], e["rule"], e["severity"], e["as_path"],
                num(e["feed_delay_s"]), num(e["compute_ms"]), e.get("first_alert_utc", "")]
        for j, v in enumerate(vals, 1):
            put(ws, f"{L(j)}{r}", v, BLUE, "0.000" if j in (9, 10) else None)
        v = (e.get("verdict") or "").strip().upper()
        put(ws, f"L{r}", v if v in ("TRUE", "FALSE") else None, BLUE)
    last = max(top + len(src) - 1, top)
    rg = lambda c: f"${c}${top}:${c}${last}"

    # ---- summary (placed to the right so the row count can grow freely)
    put(ws, "N5", "Summary (formulas over the rows on the left)", BOLD)
    items = [("Rows (events)" if use_events else "Rows (alerts)", f'=COUNT({rg("A")})', "0"), ("Alerts covered", f'=SUM({rg("D")})', "0"),
             ("path_hijack rows", f'=COUNTIF({rg("E")},"path_hijack")', "0"), ("route_leak rows", f'=COUNTIF({rg("E")},"route_leak")', "0"),
             ("valley_violation rows", f'=COUNTIF({rg("F")},"valley_violation")', "0"), ("new_as_link rows", f'=COUNTIF({rg("F")},"new_as_link")', "0"),
             ("new_origin_upstream rows", f'=COUNTIF({rg("F")},"new_origin_upstream")', "0"), ("high severity rows", f'=COUNTIF({rg("G")},"high")', "0"),
             ("Feed delay median (s), alert rows", f'=IFERROR(MEDIAN({rg("I")}),"-")', "0.000"), ("Feed delay p95 (s)", f'=IFERROR(PERCENTILE({rg("I")},0.95),"-")', "0.000"),
             ("Compute median (ms), alert rows", f'=IFERROR(MEDIAN({rg("J")}),"-")', "0.0000"), ("Compute p95 (ms)", f'=IFERROR(PERCENTILE({rg("J")},0.95),"-")', "0.0000"),
             ("Manual: rows labelled", f'=COUNTIF({rg("L")},"TRUE")+COUNTIF({rg("L")},"FALSE")', "0"), ("Manual: confirmed real (TRUE)", f'=COUNTIF({rg("L")},"TRUE")', "0")]
    for i, (lab, f, fmt) in enumerate(items, 6):
        put(ws, f"N{i}", lab); put(ws, f"O{i}", f, fmt=fmt)
    nl, nt = 6 + len(items) - 2, 6 + len(items) - 1
    put(ws, f"N{nt + 1}", "Precision (manual) = confirmed / labelled"); put(ws, f"O{nt + 1}", f'=IF(O{nl}=0,"n/a",O{nt}/O{nl})', fmt="0.000")
    put(ws, f"N{nt + 3}", "No automatic ground truth exists for live BGP path hijacks / route leaks: the manual sample above is the only real accuracy check for the live test. "
        "Report it as 'X of N sampled events confirmed', not as recall.", NOTE)
    widths(ws, [30, 18, 12, 14, 14, 20, 10, 30, 12, 12, 20, 18, 3, 40, 12])
    ws.freeze_panes = f"A{top}"


def llm_sheet(wb, res, runs):
    """Model (LLM) results: counts copied from results_sim.json / <run>.json (blue), rates are formulas (black)."""
    ws = wb.create_sheet("LLM")
    put(ws, "A1", "Model (LLM) results", TITLE)
    r = 3
    sim = res.get("llm")
    put(ws, f"A{r}", "SIMULATED (250 cases): model asked only on cases the rules flagged", BOLD); r += 1
    if not sim:
        put(ws, f"A{r}", "not run: python eval.py eval_set.jsonl --llm hf   (or --llm mock for a harness check only)", NOTE); r += 2
    else:
        rows = [("detections (rules flagged)", sim["detections"], None), ("model gave a verdict", sim["scored"], ("coverage", "=B{s}/B{d}")),
                ("model agreed with firing rule", sim["agrees_with_rule"], ("agree rate", "=B{a}/B{s}")),
                ("TP: scored by model", sim["tp_scored"], None), ("TP: kept (model not 'normal')", sim["tp_kept"], ("TP kept rate", "=B{k}/B{t}")),
                ("TP: model said 'normal' (lost if veto)", sim["tp_vetoed"], None), ("TP: type named right", sim["tp_type_right"], ("type accuracy", "=B{y}/B{t}")),
                ("FP: scored by model", sim["fp_scored"], None), ("FP: rejected by model", sim["fp_rejected"], ("false-alarm rejection rate", "=B{j}/B{f}"))]
        start = r
        pos = {}
        for i, (lab, v, _) in enumerate(rows):
            put(ws, f"A{r + i}", lab); put(ws, f"B{r + i}", v, BLUE)
        pos = dict(d=start, s=start + 1, a=start + 2, t=start + 3, k=start + 4, y=start + 6, f=start + 7, j=start + 8)
        for i, (_, _, rate) in enumerate(rows):
            if rate:
                put(ws, f"C{r + i}", rate[0], NOTE); put(ws, f"D{r + i}", rate[1].replace("B{", "B{").format(**pos), fmt="0.000")
        r += len(rows) + 1
        if res.get("llm_veto"):
            put(ws, f"A{r}", "Does the model improve the detector? (values from results_sim.json)", BOLD); r += 1
            header(ws, r, ["Method", "TP", "FP", "FN", "TN", "Accuracy", "Precision", "Recall", "F1"]); r += 1
            for k, m in res["llm_veto"].items():
                put(ws, f"A{r}", k)
                for j, key in enumerate(("tp", "fp", "fn", "tn")):
                    put(ws, f"{L(2 + j)}{r}", m[key], BLUE)
                put(ws, f"F{r}", f"=(B{r}+E{r})/(B{r}+C{r}+D{r}+E{r})", fmt="0.000")
                put(ws, f"G{r}", f"=IF(B{r}+C{r}=0,0,B{r}/(B{r}+C{r}))", fmt="0.000")
                put(ws, f"H{r}", f"=IF(B{r}+D{r}=0,0,B{r}/(B{r}+D{r}))", fmt="0.000")
                put(ws, f"I{r}", f"=IF(G{r}+H{r}=0,0,2*G{r}*H{r}/(G{r}+H{r}))", fmt="0.000"); r += 1
            r += 1
    put(ws, f"A{r}", "LIVE runs", BOLD); r += 1
    header(ws, r, ["Run", "alerts", "model scored", "coverage", "agreed with rule", "agree rate", "said normal", "manual: labelled", "model kept real", "model rejected false", "model agrees with you"]); r += 1
    for label, rep, _, _ in runs:
        put(ws, f"A{r}", label)
        p = rep + ".json"
        if not os.path.exists(p):
            put(ws, f"B{r}", "no report yet", NOTE); r += 1; continue
        js = json.load(open(p, encoding="utf-8")); lm = js.get("llm") or {}
        if not lm:
            put(ws, f"B{r}", "model off or no alerts", NOTE); r += 1; continue
        for col, key in (("B", "alerts"), ("C", "scored"), ("E", "agrees_with_rule"), ("G", "says_normal")):
            put(ws, f"{col}{r}", lm.get(key), BLUE)
        put(ws, f"D{r}", f"=IF(B{r}=0,0,C{r}/B{r})", fmt="0.000"); put(ws, f"F{r}", f"=IF(C{r}=0,0,E{r}/C{r})", fmt="0.000")
        mv = (js.get("manual") or {}).get("model_vs_verdict")
        if mv:
            put(ws, f"H{r}", mv["labelled"], BLUE); put(ws, f"I{r}", mv["model_kept_real"], BLUE); put(ws, f"J{r}", mv["model_rejected_false"], BLUE)
            put(ws, f"K{r}", f"=(I{r}+J{r})/H{r}", fmt="0.000")
        r += 1
    widths(ws, [52, 14, 14, 26, 18, 14, 14, 16, 16, 18, 18])


# ======================================================================= README + main
def readme(wb, n_cases, live_names):
    ws = wb["README"]
    put(ws, "A1", "AS-path anomaly PoC: results and calculations", TITLE)
    lines = [("What this file is", "Every number used in the report. Raw per-case results are stored (blue); every metric is an Excel formula over them (black), so you can click a cell and see the calculation."),
             ("How it was made", "python make_eval_set.py -> python eval.py eval_set.jsonl -> live runs A and B -> python cluster_events.py ... -> python build_results.py"),
             ("Cases", f"{n_cases} simulated cases (seed 42): path hijacks, the 4 CAIDA route-leak kinds (+ a leak with missing relationships), and normal traffic including deliberately hard benign cases."),
             ("", ""),
             ("Sheet", "Contents"),
             ("Sim_Cases", "Raw result of every simulated case, plus outcome (TP/FP/FN/TN) and rule-type-correct as formulas."),
             ("Sim_Metrics", "Accuracy, precision, recall, F1, FPR overall and per label, and a check of every figure against what eval.py printed (OK / CHECK)."),
             ("Sim_PerKind", "Result per scenario kind: where the errors are (should all be normal_new_peer, the honest FP kind). Mis-typed leaks (leak_unknown_rel) show as WRONG TYPE in Sim_Cases column K."),
             ("LLM", "Model results: simulated (detections, kept/rejected, type accuracy, rule+model-veto vs rules-only) and one row per live run."),
             ("Live sheets", ("; ".join(live_names) if live_names else "none yet") + ": run summary, latency, one row per event, summary formulas and the manual-verification precision."),
             ("", ""),
             ("Definitions", "Accuracy=(TP+TN)/n | Precision=TP/(TP+FP) | Recall=TP/(TP+FN) | F1=2PR/(P+R) | FPR=FP/(FP+TN)."),
             ("Colours", "Blue = data copied from the tests. Black = formula. Yellow = needs filling.")]
    for i, (a, t) in enumerate(lines, 3):
        put(ws, f"A{i}", a, BOLD if a else BLACK); put(ws, f"B{i}", t, wrap=True)
    widths(ws, [20, 120])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="eval_set.jsonl"); ap.add_argument("--sim", default="results_sim")
    ap.add_argument("--run", action="append", metavar="LABEL=REPORT,ALERTS,EVENTS",
                    help="a live run: label=report_prefix,alerts.jsonl,events.csv (repeatable). Default: Run A full_* and Run B pfx_*")
    ap.add_argument("--out", default="results_and_calculations.xlsx")
    a = ap.parse_args()
    for p in (a.sim + ".csv", a.sim + ".json", a.cases):
        if not os.path.exists(p):
            raise SystemExit(f"missing {p}: run  python make_eval_set.py && python eval.py {a.cases}  first")
    runs = []
    for spec in a.run or ["Run A full rrc00=full_report,full_alerts.jsonl,full_events.csv", "Run B prefixes=pfx_report,pfx_alerts.jsonl,pfx_events.csv"]:
        label, rest = spec.split("=", 1)
        rep, al, evp = (rest.split(",") + ["", ""])[:3]
        runs.append((label, rep, al, evp))
    res = json.load(open(a.sim + ".json", encoding="utf-8"))
    rows = list(csv.DictReader(open(a.sim + ".csv", encoding="utf-8")))
    wb = Workbook(); wb.active.title = "README"
    first, last = sim_cases(wb, rows)
    sim_metrics(wb, first, last, res["overall"])
    sim_per_kind(wb, first, last)
    names = []
    for i, (label, rep, al, evp) in enumerate(runs, 1):
        name = f"Live_{'A' if i == 1 else 'B' if i == 2 else i}"
        live_sheet(wb, name, label, rep, al, evp); names.append(f"{name} = {label}")
    llm_sheet(wb, res, runs)
    readme(wb, len(rows), names)
    wb._sheets = [wb[n] for n in ["README", "Sim_Metrics", "Sim_PerKind", "LLM"] + [x.split(" = ")[0] for x in names] + ["Sim_Cases"]]
    wb.save(a.out)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
