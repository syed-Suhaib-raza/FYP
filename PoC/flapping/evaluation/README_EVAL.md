# Route flapping: accuracy + latency tests (simulated and live)

Adds two tests to `PoC/flapping/`. Nothing existing was changed (`flap.py`, `flap.db`, `demo.db`, your 17 tests are untouched).
No new dependencies (`websockets` is already needed by `ris_live.py`).

| file | role |
|---|---|
| `make_eval_set.py` | builds the 250 labelled simulated cases (`eval_set.jsonl`, seed 42) |
| `eval.py` | TEST 1: accuracy + detection latency on the 250 cases (+ threshold sweep) |
| `live_eval.py` | TEST 2: records live RIS data, measures latency live, scores accuracy |
| `timing.py` | the independent ground-truth rule + a thin wrapper that records first-change time on each alert |
| `test_eval.py` | 16 tests for all of the above (`python -m pytest -q` runs all 33) |

Run everything from the `PoC/flapping` folder. PowerShell and Linux/macOS commands are identical.

---------------------------------------------------------------------------------------------------------------

## TEST 1: simulated data (no internet, ~2 seconds)

    python make_eval_set.py                       # only needed to regenerate; eval_set.jsonl is already included
    python eval.py eval_set.jsonl                 # -> results_sim.md  results_sim.json  results_sim.csv
    python eval.py eval_set.jsonl --sweep         # same + accuracy-vs-latency table for suppress = 1000 ... 6000

**The 250 cases**: 125 flapping + 125 normal. Each case is one short update sequence, run through a FRESH detector;
the case is predicted FLAP if the detector raises at least one alert.
Flapping: classic withdraw/restore cycles 35, path flaps 18, mixed 12, fast bursts 10, multi-peer 15, slow (every 6-10 min) 15,
borderline (4 cycles in ~13 min) 10, four path changes in <=13 min 10.
Normal: stable 20, single withdraw+restore 20, RIPE-beacon style 15, maintenance outage 10, peer-session reset with
withdrawals 15, isolated path changes 10, widely spaced flaps 10, double flap 10, three changes 5, three fast withdrawals 10.
Every case also has 2-5 unrelated background routes.

**Ground truth** (`timing.py`, independent of the penalty model): a route is FLAPPING if it has >=4 changes within 15 min or
>=5 within 90 min (change = withdrawal of a route we saw announced, or its AS path replaced while up); changes caused by a
session reset are not counted. `test_eval.py` checks all 250 labels agree with this rule.

**Latency numbers** (flapping cases that were detected):
- detection delay = first alert time - first withdrawal/path change of the flap (stream time, seconds)
- compute time = CPU time the detector used up to that alert (milliseconds, depends on your machine)
- total time to detect = detection delay + compute time
- changes needed = withdrawals + path changes before the alert fired

**Read the accuracy number carefully.** On my run: accuracy 0.92, precision 0.92, recall 0.92, FPR 0.08 (115 TP, 10 FP, 10 FN,
115 TN). All 20 errors are the two "definition-boundary" kinds I deliberately included: `path_four` (a path change only costs
500 in the penalty model, so 4 of them stay under the 2000 threshold) and `three_withdrawals` (the penalty model fires on the
3rd fast withdrawal, the count rule needs 4). **92% = 1 - 20/250 on every random seed I tried (20 of 20 seeds, std 0.000)**,
so it measures how many boundary cases the set contains, not general accuracy. Report accuracy per kind and use the
sensitivity table (below the sweep in `results_sim.md`: 94% if "flapping" = 3 changes, 92% for 4, 86% for 5, 76% for 6).
Latency does vary by seed (median 141-173 s over 20 seeds).

---------------------------------------------------------------------------------------------------------------

## TEST 2: live data (needs internet, run >= 60 minutes)

Keep your PC clock synced first (Windows: `w32tm /resync`); feed delay compares your clock with RIS's.

    # 1) 5-minute trial to see the message rate (do this first)
    python live_eval.py record --minutes 5 --host rrc00 --prefix 193.0.0.0/8 --capture trial.jsonl --alerts trial_alerts.jsonl --out trial_report

    # 2) the real run: >= 60 minutes, same or wider address space
    python live_eval.py record --minutes 60 --host rrc00 --prefix 193.0.0.0/8 --prefix 194.0.0.0/8 --prefix 195.0.0.0/8

    # 3) (optional) dry run without internet, proves the scripts work on your machine
    python live_eval.py record --from-file sample_updates.jsonl --out dry_report

Ctrl+C stops early and still analyses what was recorded. Outputs: `live_capture.jsonl` (every message, keep it), `live_alerts.jsonl`
(each alert with its timings), `live_report.md`, `live_report.json`, `live_report_alerts.csv`.
Use `--host` and/or `--prefix`; `--host` alone is a whole collector (thousands of messages/s: try it only after the trial).
Detector settings are the defaults of `ris_live.py` (half-life 900, suppress 2000, reuse 750); change only with the same flags
on both runs and say so in the report.

**Latency measured live, per alert**: detection delay (trigger message time - first change), feed delay (when our PC
received the trigger message - its RIS timestamp), compute time, and TOTAL time to detect (alert wall-clock - first change).
`live_report.md` also gives feed delay and per-message compute for ALL messages, so it is useful even if no flap occurs.

**Accuracy on live data**: there is no ground truth, so two substitutes are reported:
1. agreement with the same independent count rule as Test 1, applied to the recorded stream (precision / recall vs that rule)
2. MANUAL verification: open `live_report_alerts.csv`, check each alert (RIPEstat "BGP Update Activity" or bgp.tools for that
   prefix around `first_change_utc`..`alert_utc`), write TRUE (real repeated withdraw/announce) or FALSE in the `verdict` column,
   then run:

       python live_eval.py analyze live_capture.jsonl --alerts live_alerts.jsonl --labels live_report_alerts.csv

   which adds "N of M alerts confirmed = precision P" to `live_report.md`.

If zero alerts fire, record longer or watch more address space; flaps are rare. Say so in the results instead of forcing one.

---------------------------------------------------------------------------------------------------------------

## What to send back for the results + limitations write-up
1. `results_sim.md` from your machine (compute times differ from mine; everything else should match exactly)
2. `live_report.md` and `live_report.json` from the 60-minute run, plus the number of minutes, prefixes and `--host` used
3. `live_report_alerts.csv` after you filled `verdict` (even a partial sample is fine; say how many you checked)

## Limitations (draft; I will finalise once I have your live numbers)
Simulated test
- The 250 cases are generated by us. They show the code behaves as designed on stated scenarios, not how it behaves on real BGP.
- The ground truth is our own count rule. Operators have no single definition of flapping; the sensitivity table shows the score
  moves with it. I chose the rule knowing how the penalty model behaves, so there is some circularity; independent
  implementation, 250/250 label checks and deliberate boundary cases reduce it but do not remove it.
- 50% flapping cases is not a realistic base rate; on real traffic flaps are rare, so precision would be lower for the same FPR.
- Accuracy is fixed by the number of boundary cases (see above); only latency varies with the seed.
- Each case runs in a fresh detector for one route plus 2-5 background routes: no table-scale interference, no load, no
  long-running state. Throughput figures are single-thread Python on one machine.
- No network/feed delay exists in this test; latency is stream time + compute only. t0 (flap start) is defined as the first change.
Live test
- No ground truth. Precision/recall are relative to our own rule or to manual checks (subjective, small sample); recall against
  real incidents cannot be measured.
- RIS Live shows routes as seen by RIS collector peers, not from Cybernet's network; Cybernet internal feeds (BMP) are not tested.
- RIS Live sends no initial table, so only routes announced after the recording starts can be tracked; withdrawals of unseen
  routes are ignored (by the detector and by the rule).
- Timestamps are RIS collector time; feed delay depends on your PC clock. Time spent queued before our code reads a message is not captured.
- One run, one time window, one prefix selection: results are not generalisable; flaps are rare so the alert count may be small.
- Detector thresholds are router-vendor damping defaults (half-life 15 min, suppress 2000, reuse 750), not tuned.

---------------------------------------------------------------------------------------------------------------

## UPDATE: network latency in the live test (netlat.py, live_eval.py v2)

`live_eval.py record` now also measures (skip with `--no-net`):
- set-up to ris-live.ripe.net: DNS, TCP connect (= one round trip), TLS, WebSocket upgrade
- WebSocket ping round trip every 10 s (network one-way ~ RTT/2)
- this PC's clock offset from NTP (pool.ntp.org, UDP 123) every 5 min

`live_report.md` gets a "Network latency (live probes)" section, clock-corrected feed delay and total time to detect, and the split
corrected feed delay = network one-way + RIS-side/other. Without the correction a PC clock that is 1.5 s slow shows a feed delay of
about -1.3 s (verified with a fake server in test_netlat.py). If UDP 123 is blocked the offset is not measured and the report says so.
Also fixed: the `peer` field in live_alerts.jsonl now holds the peer address (it held the collector name), and a note is printed when
no route met the rule (accuracy is then not meaningful). Tests: `python -m pytest -q` runs 38.
