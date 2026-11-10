# 5. Testing – AS-Path Anomaly PoC

## Simulated test (180 cases)

**Accuracy:** The rule engine scores accuracy 0.90, precision 0.856, recall 1.00 and F1 0.922, with a false positive rate of 0.247.

**Latency:** Compute time is about 0.097 ms per case (about 50,600 messages/s on one thread). The simulated test has no network or feed delay, so total time to detect is just the compute time.

| Method | Accuracy | Precision | Recall | F1 | FPR |
| --- | --- | --- | --- | --- | --- |
| Rule engine (all rules) | 0.900 | 0.856 | 1.000 | 0.922 | 0.247 |
| Baseline B1: any new edge | 0.850 | 0.799 | 1.000 | 0.888 | 0.370 |

| Measure | Median | p95 | Max |
| --- | --- | --- | --- |
| Compute time to alert (ms) | 0.097 | 0.119 | 0.909 |
| Compute time with LLM (ms) | 16,082 | 21,404 | 23,648 |

## Live tests

**Accuracy:** No live precision or recall is reported, because no alert was verified yet. Run A raised 148 alerts (all valley_violation) in 110 events. Run B raised 98 alerts (50 new_as_link, 42 new_origin_upstream, 6 valley_violation) in 30 events.

**Latency:** Rules alone take microseconds per message. With the LLM in the feed loop, delay rose to minutes because the detector waited on the model. It was busy about 93% of the time in Run A and about 89% in Run B.

**Load:** The model is slow (10 to 25 s per alert), and alerts arrive in bursts. The worst alert waited about 20 minutes.

| | Run A (all of rrc00) | Run B (3 x /8 blocks) |
| --- | --- | --- |
| Rules active | valley only (no baseline) | valley + new_as_link + new_origin_upstream (600 s live baseline) |
| Duration | 44.9 min | 40.7 min |
| Messages (rate) | 13,507 (5.0/s) | 7,582 (3.1/s) |
| Alerts / events | 148 / 110 | 98 / 30 |
| Median feed delay, all messages | 44.0 s | 2.68 s |
| Median feed delay, alerts | 47.9 s | 370.5 s |
| Median compute per message (rules) | 0.021 ms | 0.079 ms |
| Model time per alert | 14.6 s (median) | about 10 to 25 s |

| Test | Time from the last needed message to the alert |
| --- | --- |
| Live, Run A (with LLM) | about 48 s median (max about 313 s) |
| Live, Run B (with LLM) | about 370 s median (max about 1,184 s) |

