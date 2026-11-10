# AS-path PoC: accuracy + latency tests (simulated and live)

Adds two tests to `PoC/as path/aspath_poc/`. **Nothing existing was changed** (`aspath.py`, `detector.py`, `evaluate.py`, `baseline.json`,
`whitelist.json`, your existing tests are untouched). Extra dependency: `openpyxl` (only for the Excel workbook): `pip install openpyxl`.

| file | role |
|---|---|
| `make_eval_set.py` | builds the 250 labelled simulated cases (`eval_set.jsonl` + `eval_as_rel.txt`, seed 42; both already included) |
| `eval.py` | **TEST 1**: accuracy, type agreement, rule ablation, sensitivity sweep, compute time |
| `live_eval.py` | **TEST 2**: records live RIS data, measures latency live, writes the report + a manual-verification sheet |
| `cluster_events.py` | groups the raw live alerts into events (one cause = one row to verify) |
| `build_results.py` | one Excel workbook: every result stored, every metric an Excel formula |
| `preflight_live.py` | checks CAIDA file, clock, websockets, disk, RIS Live and the real rrc00 message rate before the long runs |
| `llm_eval.py` | **NEW**: scores the model (LLM) from the alert fields `llm_label` / `llm_agrees` / `model`; used by eval.py, live_eval.py, cluster_events.py |
| `test_eval.py` | 27 tests for the harness (no internet needed) |
| `test_llm_eval.py` | **NEW**: 9 tests for the model scoring, the start-up model check and `eval.py --llm` end to end |
| `run_simulated.ps1/.sh`, `run_live.ps1/.sh` | the whole of each test in one command, **rules + model** (`-Llm hf` default; `-Llm mock` = harness check) |

Run everything from the `aspath_poc` folder. PowerShell and Linux/macOS commands are identical.

---------------------------------------------------------------------------------------------------------------

## TEST 1: simulated data (no internet, ~10 seconds)

    python make_eval_set.py                  # only to regenerate; eval_set.jsonl is included
    python eval.py eval_set.jsonl --sweep --llm hf --llm-runs 2    # rules + the REAL model -> results_sim.md/.json/.csv
    python eval.py eval_set.jsonl --llm mock                      # fake model: harness check only
    python -m pytest -q test_eval.py test_llm_eval.py
    python build_results.py                  # -> results_and_calculations.xlsx
    (or just:  .\run_simulated.ps1 )

**The 250 cases** = 70 path hijack + 80 route leak + 100 normal. Each case is a short update sequence with a 3-message baseline, run through a
FRESH detector; it is predicted anomalous if the detector raises an alert for the one test message.

| group | kinds (count) |
|---|---|
| path hijack (70) | new_origin_upstream 35, new_as_link 35 |
| route leak (80) | transit-to-transit 17, transit-to-peer 17, peer-to-peer 17, peer-to-transit 17, **leak_unknown_rel 12** (hard: relationships missing) |
| normal (100) | repeat 30, prepend 15, alt_path 15 (multi-homed), **new_peer 25** (hard), foreign_origin 15 (deferred to unexpectedOrigin) |

The seed changes chain length, which hop is replaced/inserted, prepend counts and collectors; the results below are identical on all 20 seeds I tried.

**Result of the delivered code (seed 42)**: TP 150, FP 25, FN 0, TN 75 -> accuracy 0.90, precision 0.857, recall 1.00, F1 0.923, FPR 0.25.
The naive "any new link" baseline B1 gets FP 40 (accuracy 0.84). Type agreement 138/150: the 12 `leak_unknown_rel` leaks are caught through their
new links but named *path hijack*, because without relationship data the valley rule cannot name a leak (paper, App. E.6).
Rule ablation: `valley_violation` alone catches the 68 leaks that have known relationships and nothing else; `new_origin_upstream` alone catches only the
35 upstream-replacement hijacks; `new_as_link` catches everything (it is also the source of all 25 false alarms).
Sweep: min-support 2 adds the 15 `alt_path` cases as false alarms (a second path seen once in the baseline looks "rare").

**Read these numbers carefully.** Every error is one of the two deliberate hard kinds, so accuracy 0.90 = 1 - 25/250 measures *how many hard cases the
set contains*, not general accuracy. `normal_new_peer` is the honest result: a rules-only detector cannot tell a legitimate new peering AS from a hijacked
link, which is exactly what the model/evidence layer and the history baseline are for. Report accuracy per kind. Compute time is your machine's
(median per case is about 0.15 ms here).

**Labels are checked independently**: `test_eval.py` re-derives every label with its own valley-free implementation (not `detector.py`) and checks the
hard cases are hard for the stated reason.

### Model (LLM) in the simulated test (new)
`eval.py` now uses the model by DEFAULT (`--llm hf`); `--llm none` = rules only, on purpose (it prints a WARNING and the report's first line says RULES ONLY). If the model loads but gives no usable verdict on any detection, `eval.py` stops instead of writing a rules-only report.
`--llm hf` (or `llamacpp`; same names and flags as `aspath.py`) runs every case twice: rules only (this stays the main result, so numbers are comparable with
and without the model) and rules + model. The model is asked only about cases the rules flag, so it can reject or confirm, never find. The report adds:
- **coverage / agreement**: how many detections got a model verdict, and how often it agreed with the firing rule
- **on real anomalies (TP)**: how many the model kept, how many it wrongly called "normal", and whether it names hijack vs leak right
- **on the rules' false alarms (FP)**: how many it rejects. The 25 `normal_new_peer` cases are the point: rules alone cannot reject them; the model/evidence layer can
- **truth x model** confusion table and a per-kind table
- **"does the model improve the detector"**: rules only vs rules + model-veto vs rules + model-strict, scored on all 250 cases (a vetoed real attack becomes a miss)
- **repeatability** (`--llm-runs 2`): same answer in two runs? (a sampling model is not deterministic)
- **compute time with vs without the model**
`--llm mock` prints a banner that its numbers say nothing about the real model. If the real model uses label words this harness does not know, the report counts
them as `other` and prints a WARNING with every raw label; add the words to the lists at the top of `llm_eval.py`.

---------------------------------------------------------------------------------------------------------------

## TEST 2: live data (needs internet, 2 x 45 minutes)

Do first (once):

    pip install websockets openpyxl
    python aspath.py caida          # real CAIDA AS-relationships into ./data. WITHOUT this the route-leak rule is silent
    w32tm /resync                   # Windows clock sync (feed delay compares your clock with RIS's)
    python preflight_live.py        # checks all of the above and measures the real rrc00 message rate

**The live runs now include the model.** Add `--llm hf` (or `llamacpp`) to both commands; `run_live.ps1/.sh` do. Before recording, `live_eval.py` runs a **model self-test**
(a throwaway detector raises one hijack-shaped alert and the model must answer). If the model does not load or answer, the run **refuses to start**, so you never
spend 45 minutes on a run that was silently rules-only (`--skip-llm-check` / `--llm none` exist for deliberate exceptions, and the report then says the model was off).

**Run A** (whole collector rrc00, route-leak rule + model):

    python live_eval.py record --minutes 45 --host rrc00 --llm hf --capture full_capture.jsonl --alerts full_alerts.jsonl --out full_report

**Run B** (after A finishes; three /8 blocks on rrc00, all rules + model):

    python live_eval.py record --minutes 45 --host rrc00 --llm hf --prefix 193.0.0.0/8 --prefix 194.0.0.0/8 --prefix 195.0.0.0/8 --capture pfx_capture.jsonl --alerts pfx_alerts.jsonl --out pfx_report

**Afterwards**:

    python cluster_events.py full_alerts.jsonl full_events.csv
    python cluster_events.py pfx_alerts.jsonl pfx_events.csv
    python build_results.py
    (or everything above in one go:  .\run_live.ps1 )

Ctrl+C stops a run early and still analyses what was recorded. Try a 5-minute trial first:
`python live_eval.py record --minutes 5 --host rrc00 --capture trial.jsonl --alerts trial_alerts.jsonl --out trial_report`.
No-internet dry run (proves the scripts work on your machine): `python live_eval.py record --from-file sample_updates.jsonl --prefix 72.255.0.0/18 --prefix 8.8.8.0/24 --learn 100 --out dry_report`.

### What your two commands do in the AS-path PoC (important)
The AS-path PoC has no `--host`; `live_eval.py` adds it and maps the flapping-style commands like this:

| | Run A | Run B |
|---|---|---|
| scope | `--scope all`, collector rrc00 (every UPDATE) | watch scope: the 3 prefixes **and their more-specifics**, rrc00 only |
| rules that can fire | **valley_violation only** (route leak). A firehose has no per-prefix baseline, so the link rules cannot run | valley_violation + new_as_link + new_origin_upstream |
| baseline | none | learnt live in the first `--learn` seconds (default **600**) into `pfx_report_baseline.json` (new each run; your `baseline.json` is never touched) |
| expected origins | n/a | none: a /8 has thousands of origins, so ANY origin is accepted and learnt. Origin hijacks stay the unexpectedOrigin PoC's job |
| model | `--llm hf`: asked about each alert, **no cap now**: every alert is judged (`--max-llm-per-min N` to cap it) | `--llm hf`: asked about each alert, no cap |

Explicit flags always win (`--scope`, `--baseline-source history`, `--baseline x.json`, `--learn 300`, `--whitelist`).
Detector settings are the defaults of `aspath.py`; if you change one, use the same flags on both runs and say so in the report.

### What is measured, per run
- **feed delay** of every message (our receive time - RIS timestamp) and, for each alert, **compute time**. An AS-path alert fires on a *single* announcement, so feed delay + compute IS the total latency (no penalty build-up as in flapping).
- **detector compute for ALL messages** (`<out>_runstats.json`) and a **backlog check** (median feed delay in the first vs last 10% of the run: a clear rise = cannot keep up). On my machine the detector handles ~100,000 messages/s, far above rrc00's rate.
- alerts by anomaly type, rule, severity, leak kind; distinct prefixes / collectors; model agreement if a model was used.
- cluster_events: events and **distinct causes** (one misconfigured AS leaking 500 prefixes = 500 events but 1 cause).

### Accuracy on live data: manual verification
There is no ground truth for live path hijacks / leaks (unlike flapping's independent count rule). So:
1. open `full_events.csv` / `pfx_events.csv` (one row per event; far fewer than alerts),
2. for a sample (say 30-50 events per run, **write down how many you checked**) look up the prefix, path and AS links in RIPEstat / bgp.tools / CAIDA AS-rank, and put `TRUE` (real hijack/leak) or `FALSE` in `verdict`,
3. `python live_eval.py analyze full_capture.jsonl --alerts full_alerts.jsonl --out full_report --labels full_events.csv` (same for pfx) adds "N of M sampled events confirmed = precision P" to the report; `build_results.py` picks the verdicts up too.

Report it as "X of N sampled events confirmed", not as recall. If zero alerts fire, say so; do not force one. On a 193-195/8 + new baseline, expect MANY `new_as_link` alerts that are legitimate new routes (the baseline only knows the first 10 minutes): that is the honest false-positive rate of a rules-only detector and is the point of the manual sample.

**Disk and time**: Run A records every message. Roughly rate x 45 min x ~450 bytes: `preflight_live.py` prints the estimate for your connection (a busy rrc00 can mean 1-3 GB). Analysis streams the file, so memory stays small. Loading the real CAIDA file takes ~5 s and ~700 MB RAM.

### The model in the live runs (new)
`live_eval.py record` now uses the model by DEFAULT (`--llm hf`), so your exact Run A / Run B commands already include it; `--llm none` = rules only, on purpose (WARNING printed, report says the model was off).
Per run the report has a **Model (LLM)** section: model used, coverage (alerts that got a verdict; now ~100% on both runs; the report warns below 50%),
agreement with the firing rule, how many alerts it called "normal", verdict by rule, and alert compute time **with vs without** the model. The model runs inside the feed loop,
so a slow model delays the next message: the backlog check (first vs last 10% feed delay) shows whether it kept up. Model compute is inside the alert's `compute_ms`.
There is no ground truth for the model either: after you fill the `verdict` column, `analyze --labels` adds **"model vs your verdicts"** (of the real ones it kept N, of the false ones it rejected M).
`cluster_events.py` copies the model's verdict into the events CSV (`llm_label`, `llm_agrees`, `llm_view`) so you can see it while verifying. The workbook has an **LLM** sheet.

---------------------------------------------------------------------------------------------------------------

## What was fixed compared with the first version of these files
1. `live_eval.py` skipped the real CAIDA file for `--scope all`, so Run A would have used the synthetic demo relationships and the valley rule would have found almost nothing. Now always loaded (except in a `--from-file` dry run, whose sample needs the demo file).
2. `--host` did not exist; a bare `--host rrc00` fell into the whitelist watch scope. Now: alone = whole collector, with `--prefix` = prefix scope on that collector (the subscription carries the host).
3. A prefix scope with no expected origins deferred every announcement (zero alerts, forever). Now any origin is accepted and learnt.
4. `baseline.json` was loaded/overwritten by prefix runs. Now each run uses `<out>_baseline.json`.
5. `analyze` held the whole capture in memory (a 45-minute full capture can be gigabytes). Now streamed; it also reports compute time for ALL messages and a backlog check.
6. Simulated set: 115 -> **250 cases**, with prepending, multi-homed and missing-relationship cases, random topology per seed, background noise; plus rule ablation, sweep and an independent label oracle.
7. `build_results.py`: two live runs, one row per event (no 100-row cap), verdicts read from the events CSV. `cluster_events.py`: distinct causes, `types_in_event`, empty-file safe.

## Limitations (draft; finalise with your live numbers)
Simulated test
- The 250 cases are generated by us: they show the code behaves as designed on stated scenarios, not how it behaves on real BGP.
- Labels come from construction. Accuracy is fixed by the number of deliberate hard cases (25 new_peer + 12 unknown-relationship leaks), not general accuracy; only compute time varies with the machine.
- 60% anomalous is not a realistic base rate; on real traffic attacks are rare, so precision would be lower for the same FPR.
- Each case is one fresh detector, one prefix, a 3-message baseline, a tiny relationship file with full coverage: no table-scale interference, no long-running state, none of CAIDA's real coverage gaps.
- Unexpected-origin hijacks are not scored here (other PoC); they are only checked as "deferred, not flagged".
Live test
- No ground truth: precision is a manual sample, recall against real incidents cannot be measured.
- Run A can only find route leaks (valley rule), and only where CAIDA knows the relationships; Run B has no history baseline: an attack inside the first 10 minutes is learnt as normal, and legitimate-but-unseen links look new.
- RIS Live shows routes as seen by RIS collector peers, not Cybernet's network; it sends no initial table.
- One run, one 45-minute window, one collector: not generalisable. Timestamps are RIS collector time, so feed delay depends on your PC clock.

Model (LLM) additions
- The model only sees what the rules flag: the harness cannot measure the model finding attacks the rules miss.
- Model numbers depend on the prompt, top-k, evidence flags and the model itself; report them with the settings. The simulated cases are synthetic text-book shapes, which is easier for a model than real traffic.
- Run A is uncapped, so a slow model on a busy collector can fall behind the feed (each alert waits for the model). Watch the backlog check in the report; if feed delay climbs, cap it with `--max-llm-per-min N` and say so.
- Not verified here: these LLM additions were tested against stand-in modules for `aspath.py` / `llm.py` / `detector.py` (they were not in the upload) and a fake model; the real `hf` model has to be run on your machine. Run `python -m pytest -q test_eval.py test_llm_eval.py` in your aspath_poc folder first.
