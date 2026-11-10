# Route flapping: SIMULATED test (250 cases)
Detector settings: half-life 900s, suppress 2000, reuse 750, min-peers 1. Positives: 125, negatives: 125.
Ground truth = independent count rule (>=4 changes in 15 min or >=5 in 90 min, session resets excluded); see timing.py.

## All cases
| Method | n | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 | FPR | Delay median (s) | Delay mean (s) | Delay p95 (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Flap detector (suppress=2000) | 250 | 115 | 10 | 10 | 115 | 0.92 | 0.92 | 0.92 | 0.92 | 0.08 | 150.6 | 281.5 | 998.7 |
| B1 any-withdrawal | 250 | 121 | 121 | 4 | 4 | 0.5 | 0.5 | 0.968 | 0.659 | 0.968 | 0.0 | 181.2 | 1534.9 |
| B2 count>=3 in 10 min | 250 | 110 | 30 | 15 | 95 | 0.82 | 0.786 | 0.88 | 0.83 | 0.24 | 136.0 | 192.4 | 514.8 |

## Easy cases
| Method | n | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 | FPR | Delay median (s) | Delay mean (s) | Delay p95 (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Flap detector (suppress=2000) | 180 | 90 | 0 | 0 | 90 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 132.1 | 144.8 | 256.7 |
| B1 any-withdrawal | 180 | 88 | 86 | 2 | 4 | 0.511 | 0.506 | 0.978 | 0.667 | 0.956 | 0.0 | 157.8 | 1349.6 |
| B2 count>=3 in 10 min | 180 | 90 | 15 | 0 | 75 | 0.917 | 0.857 | 1.0 | 0.923 | 0.167 | 119.2 | 131.2 | 256.7 |

## Hard cases (slow / borderline / near-threshold normals)
| Method | n | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 | FPR | Delay median (s) | Delay mean (s) | Delay p95 (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Flap detector (suppress=2000) | 70 | 25 | 10 | 10 | 25 | 0.714 | 0.714 | 0.714 | 0.714 | 0.286 | 805.1 | 773.7 | 1121.5 |
| B1 any-withdrawal | 70 | 33 | 35 | 2 | 0 | 0.471 | 0.485 | 0.943 | 0.641 | 1.0 | 0.0 | 243.8 | 1532.5 |
| B2 count>=3 in 10 min | 70 | 20 | 15 | 15 | 20 | 0.571 | 0.571 | 0.571 | 0.571 | 0.429 | 482.5 | 467.5 | 526.1 |

## Latency (detector, correctly detected flaps)
| Measure | median | mean | p95 | min | max |
|---|---|---|---|---|---|
| Detection delay (s): alert time - first change | 150.59 | 281.53 | 998.73 | 41.05 | 1157.01 |
| Compute time to alert (ms) | 0.03 | 0.035 | 0.056 | 0.023 | 0.065 |
| Total time to detect (s) = delay + compute | 150.592 | 281.527 | 998.727 | 41.046 | 1157.014 |
| Withdrawals/path changes needed before the alert | 3 | 3.3 | 5.0 | 3 | 5 |

Detector throughput: 4838 messages in 12.3 ms = 393,766 msg/s (2.5 us per message, this machine).

## Per kind (detector)
| Kind | Truth | Difficulty | Cases | Correct | Missed / false alarms | Median delay (s) |
|---|---|---|---|---|---|---|
| beacon | normal | easy | 15 | 15 | 0 | - |
| borderline_flap | flap | hard | 10 | 10 | 0 | 515.2 |
| classic | flap | easy | 35 | 35 | 0 | 202.4 |
| double_flap | normal | hard | 10 | 10 | 0 | - |
| fast_burst | flap | easy | 10 | 10 | 0 | 50.5 |
| isolated_changes | normal | easy | 10 | 10 | 0 | - |
| maintenance | normal | easy | 10 | 10 | 0 | - |
| mixed | flap | easy | 12 | 12 | 0 | 137.9 |
| multi_peer | flap | easy | 15 | 15 | 0 | 123.1 |
| path_flap | flap | easy | 18 | 18 | 0 | 131.2 |
| path_four | flap | hard | 10 | 0 | 10 | - |
| session_reset | normal | easy | 15 | 15 | 0 | - |
| single_flap | normal | easy | 20 | 20 | 0 | - |
| slow | flap | hard | 15 | 15 | 0 | 922.2 |
| spaced_flaps | normal | hard | 10 | 10 | 0 | - |
| stable | normal | easy | 20 | 20 | 0 | - |
| three_changes | normal | hard | 5 | 5 | 0 | - |
| three_withdrawals | normal | hard | 10 | 0 | 10 | - |

## Detector errors (20)
- case-125 (path_four): MISSED a flap
- case-123 (path_four): MISSED a flap
- case-124 (path_four): MISSED a flap
- case-122 (path_four): MISSED a flap
- case-121 (path_four): MISSED a flap
- case-120 (path_four): MISSED a flap
- case-119 (path_four): MISSED a flap
- case-248 (three_withdrawals): FALSE ALARM
- case-117 (path_four): MISSED a flap
- case-245 (three_withdrawals): FALSE ALARM
- case-243 (three_withdrawals): FALSE ALARM
- case-116 (path_four): MISSED a flap
- case-247 (three_withdrawals): FALSE ALARM
- case-250 (three_withdrawals): FALSE ALARM
- case-118 (path_four): MISSED a flap
- case-249 (three_withdrawals): FALSE ALARM
- case-242 (three_withdrawals): FALSE ALARM
- case-246 (three_withdrawals): FALSE ALARM
- case-244 (three_withdrawals): FALSE ALARM
- case-241 (three_withdrawals): FALSE ALARM

## Threshold sweep (accuracy vs latency trade-off)
| suppress | Accuracy | Precision | Recall | F1 | FPR | Delay median (s) | Delay p95 (s) |
|---|---|---|---|---|---|---|---|
| 1000 | 0.572 | 0.539 | 1.0 | 0.7 | 0.856 | 0.0 | 366.9 |
| 1500 | 0.9 | 0.833 | 1.0 | 0.909 | 0.2 | 110.4 | 625.7 |
| 2000 | 0.92 | 0.92 | 0.92 | 0.92 | 0.08 | 150.6 | 998.7 |
| 2500 | 0.916 | 0.919 | 0.912 | 0.916 | 0.08 | 185.5 | 1615.0 |
| 3000 | 0.92 | 1.0 | 0.84 | 0.913 | 0.0 | 231.8 | 1536.7 |
| 4000 | 0.748 | 1.0 | 0.496 | 0.663 | 0.0 | 303.7 | 510.2 |
| 6000 | 0.524 | 1.0 | 0.048 | 0.092 | 0.0 | 360.0 | 521.5 |

## Sensitivity to the ground-truth definition (accuracy only)
The labels come from our own rule (>=N changes in 15 min or >=N+1 in 90 min). Re-labelling with other N shows how much the score depends on that choice.
| N | positives | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|---|---|
| 3 | 140 | 0.94 | 1.0 | 0.893 | 0.943 | 0 | 15 |
| 4 | 125 | 0.92 | 0.92 | 0.92 | 0.92 | 10 | 10 |
| 5 | 89 | 0.856 | 0.712 | 1.0 | 0.832 | 36 | 0 |
| 6 | 64 | 0.756 | 0.512 | 1.0 | 0.677 | 61 | 0 |
