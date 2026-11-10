# Route flapping: evaluation results

Detector settings in every test: half-life 900 s, suppress 2000, reuse 750, min-peers 1 (the defaults of `ris_live.py`).
Ground truth in every test is the independent count rule in `timing.py`: a route is flapping if it has at least 4 changes
within 15 min or at least 5 within 90 min (a change is a withdrawal of a route we saw announced, or its AS path being
replaced while up; changes caused by a peer-session reset are not counted).

## Simulated test (250 cases)

**Accuracy:** The flap detector scores accuracy 0.92, precision 0.92, recall 0.92 and F1 0.92, with a false positive rate of 0.08
(115 TP, 10 FP, 10 FN, 115 TN). All 20 errors come from two deliberately hard kinds. `path_four` (10 cases, all missed): four path
changes cost only 500 each, so the penalty stays under the 2000 threshold. `three_withdrawals` (10 cases, all false alarms): the
penalty fires on the third fast withdrawal, while the count rule needs four. Every other kind is correct. Because these two
boundary kinds fix the error count, the 92% measures how many boundary cases the set contains, not general accuracy.

**Latency:** Compute time is about 0.03 ms per case (about 393,766 messages/s on one thread, 2.5 us per message). The simulated
test has no network or feed delay, so total time to detect is the detection delay (stream time from the first change to the alert)
plus that compute time. The median detection delay is 150.6 s.

| Method | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| Flap detector (suppress = 2000) | 0.920 | 0.920 | 0.920 | 0.920 | 0.080 |
| Baseline B1: any withdrawal | 0.500 | 0.500 | 0.968 | 0.659 | 0.968 |
| Baseline B2: 3 or more changes in 10 min | 0.820 | 0.786 | 0.880 | 0.830 | 0.240 |

| Difficulty | Cases | Detector accuracy | Precision | Recall | FPR |
|---|---|---|---|---|---|
| Easy | 180 | 1.000 | 1.000 | 1.000 | 0.000 |
| Hard | 70 | 0.714 | 0.714 | 0.714 | 0.286 |

| Measure (correctly detected flaps) | Median | p95 | Max |
|---|---|---|---|
| Detection delay: alert time - first change (s) | 150.59 | 998.73 | 1,157.01 |
| Compute time to alert (ms) | 0.030 | 0.056 | 0.065 |
| Total time to detect (s) | 150.592 | 998.727 | 1,157.014 |
| Withdrawals / path changes needed before the alert | 3 | 5 | 5 |

Sensitivity to the ground-truth definition (accuracy only): flapping = 3 changes gives 0.94, 4 gives 0.92, 5 gives 0.856, 6 gives 0.756.
The threshold sweep (suppress 1000 to 6000) is in `results_sim.md`.

Files: `results_sim.md` (summary), `results_sim.csv` (one row per case and method: truth, prediction, timings), `results_sim.json`.
The input cases are `../eval_set.jsonl`.

## Live tests

**Accuracy:** There is no confirmed ground truth, so precision and recall are relative to the same count rule, not to verified
incidents. No alert was verified manually yet (the `verdict` column in the `*_report_alerts.csv` files is empty). Run A (all of rrc00)
raised 15,628 alerts in 779 events. Run B (3 x /8 blocks) raised 2,946 alerts in 488 events. The 5-minute trial raised 388 alerts.

**Latency:** The detector itself takes milliseconds per message. Almost all of the total time to detect is the flap unfolding
(detection delay), not the network: one-way network delay is about 1.4% of the median total in Run A and about 0.03% in Run B.

**Load:** Run A is a whole collector at 137 messages/s. Alerts arrive in large bursts: the largest single event in Run A is 1,380
alerts from one peer, which is typical of a peer session problem rather than 1,380 independent flaps.

| | Run A (all of rrc00) | Run B (3 x /8 blocks) | 5-min trial (193.0.0.0/8) |
|---|---|---|---|
| Duration | 45.0 min | 45.0 min | 5.0 min |
| Messages (rate) | 369,590 (137.0/s) | 39,186 (14.5/s) | 1,646 (5.5/s) |
| Alerts / events | 15,628 / 779 | 2,946 / 488 | 388 / not clustered |
| Median feed delay, all messages | 15.28 s | 2.75 s | 2.90 s |
| Median compute per message (replay) | 4.67 ms | 0.53 ms | 0.040 ms |
| Median detection delay | 171.2 s | 309.8 s | 64.1 s |
| Median total time to detect | 184.1 s | 311.7 s | 67.1 s |
| p95 total time to detect | 1,706.6 s | 1,237.6 s | 160.6 s |
| Network one-way delay (RTT / 2) | 2,604 ms | 90 ms | 70 ms |
| Precision vs count rule | 0.964 | 0.957 | 0.876 |
| Recall vs count rule | 0.713 | 0.912 | 0.771 |
| F1 vs count rule | 0.820 | 0.934 | 0.820 |
| TP / FP / FN / TN | 14,900 / 555 / 6,000 / 43,212 | 2,814 / 125 / 272 / 6,656 | 340 / 48 / 101 / 1,321 |

Accuracy in the live runs is dominated by true negatives (most routes change only once), so precision, recall and F1 are the
numbers to quote. Run A's network figures are poor (WebSocket ping median 5.2 s), which is why its feed delay is higher than Run B's.

## What is in this folder

| File | What it is |
|---|---|
| `results_sim.md` / `.csv` / `.json` | Simulated test, 250 cases |
| `full_report.md` / `.json`, `full_report_alerts.csv`, `full_alerts.jsonl`, `full_events.csv` | Run A: all of rrc00 (the raw capture `full_capture.jsonl`, 178 MB, is not included) |
| `pfx_report.md` / `.json`, `pfx_report_alerts.csv`, `pfx_alerts.jsonl`, `pfx_events.csv`, `pfx_capture.jsonl` | Run B: 193.0.0.0/8, 194.0.0.0/8, 195.0.0.0/8 |
| `trial_report.md` / `.json`, `trial_report_alerts.csv`, `trial_alerts.jsonl`, `trial.jsonl` | 5-minute trial run |

`*_events.csv` is made by `../cluster_events.py`: alerts from the same peer within 60 s count as one event.

## Limitations

- The 250 simulated cases are generated by us. They show the code behaves as designed on stated scenarios, not how it behaves on real BGP.
- The ground truth is our own count rule. Operators have no single definition of flapping; the sensitivity table shows the score moves with it.
- 50% flapping cases is not a realistic base rate. On real traffic flaps are rare, so precision would be lower for the same FPR.
- Live results have no confirmed ground truth, come from one time window and one collector, and cannot be generalised. RIS Live sends no
  initial table, so only routes announced after recording started can be tracked.
- Detector thresholds are router-vendor damping defaults, not tuned.
