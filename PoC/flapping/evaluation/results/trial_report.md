# Route flapping: LIVE test
Capture: trial.jsonl; 1646 messages; watching ['193.0.0.0/8']; detector settings {'half_life': 900, 'suppress': 2000, 'reuse': 750, 'min_peers': 1}.

## Feed and pipeline latency (all messages)
- recorded for 5.0 min = 5.5 messages/s; 1877 withdrawals, 9270 announcements, 0 peer resets
- feed delay (our receive time - RIS timestamp), s: {'n': 1646, 'median': 2.9, 'mean': 2.934, 'p95': 3.821, 'min': 1.427, 'max': 13.999}
- detector compute per message, ms (replay on this machine): {'n': 1646, 'median': 0.0397, 'mean': 0.0735, 'p95': 0.1988, 'min': 0.0011, 'max': 8.3567}

## Network latency (live probes)
- set-up to ris-live.ripe.net: DNS 0.39 ms, TCP connect 144.69 ms (= 1 round trip), TLS 229.58 ms, WebSocket upgrade 663.81 ms (server 193.0.11.16)
- WebSocket ping round trip, ms: {'n': 29, 'median': 140.55, 'mean': 266.28, 'p95': 225.42, 'min': 137.32, 'max': 3569.08}
- network one-way delay estimate = RTT/2 = 70.3 ms median (assumes a symmetric path)
- PC clock vs NTP (pool.ntp.org): offset -0.083 s median over 1 samples (range -0.083 .. -0.083; positive = PC clock is behind). Added to every PC timestamp below.
- feed delay corrected for the clock offset, s: {'n': 1646, 'median': 2.817, 'mean': 2.851, 'p95': 3.738, 'min': 1.344, 'max': 13.916}
- split of the median corrected feed delay 2.817 s: network one-way ~0.070 s + RIS-side / other ~2.746 s (collector -> RIS Live server -> send, queueing, our read)

## Flap alerts: 388 raised in replay, 388 logged live
(if these differ, the live run and the replay saw a different clock for `tick`; the replay uses stream time)

| Latency (live) | n | median | mean | p95 | min | max |
|---|---|---|---|---|---|---|
| Detection delay (s) | 388 | 64.08 | 79.244 | 157.17 | 0.0 | 259.28 |
| Feed delay (s) | 388 | 2.908 | 2.885 | 3.617 | 1.72 | 13.999 |
| Compute (ms) | 388 | 1.078 | 1.791 | 5.338 | 0.045 | 5.338 |
| TOTAL time to detect (s) | 388 | 67.088 | 82.132 | 160.619 | 2.498 | 261.19 |
| Changes needed before alert | 388 | 5.0 | 4.577 | 5.0 | 2 | 5 |
| Feed delay, clock-corrected (s) | 388 | 2.825 | 2.802 | 3.534 | 1.637 | 13.916 |
| TOTAL time to detect, clock-corrected (s) | 388 | 67.005 | 82.049 | 160.536 | 2.415 | 261.107 |

Network share: one-way ~0.070 s of a median 67.0 s total = 0.10%. The rest is the flap itself unfolding (detection delay).

## Accuracy against the independent count rule (>=4 changes/15 min or >=5/90 min, resets excluded)
- routes with at least one change (population): 1810; flapping by the rule: 441; alerted by the detector: 388
- TP 340 | FP 48 | FN 101 | TN 1321
- precision 0.876 | recall 0.771 | F1 0.82 | accuracy 0.9177 (dominated by TN: most routes change once)
- for TPs, rule satisfied minus detector alert time, s (positive = detector fired first): {'n': 340, 'median': -0.5, 'mean': -10.5, 'p95': 0.0, 'min': -247.2, 'max': 33.0}

False-positive candidates (alerted, rule not satisfied):
- 193.105.156.0/24 via rrc00.ripe.net: 3 changes
- 193.105.156.0/24 via rrc00.ripe.net: 3 changes
- 193.239.180.0/23 via rrc00.ripe.net: 3 changes
- 193.239.180.0/23 via rrc00.ripe.net: 3 changes
- 193.58.168.0/23 via rrc00.ripe.net: 2 changes
- 193.58.168.0/23 via rrc00.ripe.net: 2 changes
- 193.58.168.0/23 via rrc00.ripe.net: 3 changes
- 193.58.168.0/23 via rrc00.ripe.net: 3 changes
- 193.58.168.0/24 via rrc00.ripe.net: 3 changes
- 193.58.168.0/24 via rrc00.ripe.net: 3 changes
- 194.156.96.0/23 via rrc00.ripe.net: 2 changes
- 194.156.96.0/23 via rrc00.ripe.net: 2 changes
- 194.156.96.0/23 via rrc00.ripe.net: 3 changes
- 194.156.96.0/23 via rrc00.ripe.net: 3 changes
- 45.134.252.0/23 via rrc00.ripe.net: 3 changes
- 45.134.252.0/23 via rrc00.ripe.net: 3 changes
- 45.135.32.0/23 via rrc00.ripe.net: 2 changes
- 45.135.32.0/23 via rrc00.ripe.net: 2 changes
- 45.135.32.0/23 via rrc00.ripe.net: 3 changes
- 45.135.32.0/23 via rrc00.ripe.net: 3 changes

Missed by the detector (rule satisfied):
- 103.114.43.0/24 via rrc00.ripe.net: 4 changes
- 103.114.43.0/24 via rrc00.ripe.net: 4 changes
- 103.139.48.0/24 via rrc00.ripe.net: 4 changes
- 103.139.48.0/24 via rrc00.ripe.net: 4 changes
- 138.124.67.0/24 via rrc00.ripe.net: 4 changes
- 138.124.79.0/24 via rrc00.ripe.net: 4 changes
- 144.31.14.0/24 via rrc00.ripe.net: 4 changes
- 144.31.14.0/24 via rrc00.ripe.net: 4 changes
- 144.31.158.0/24 via rrc00.ripe.net: 4 changes
- 144.31.158.0/24 via rrc00.ripe.net: 4 changes
- 144.31.203.0/24 via rrc00.ripe.net: 4 changes
- 144.31.203.0/24 via rrc00.ripe.net: 4 changes
- 144.31.207.0/24 via rrc00.ripe.net: 4 changes
- 144.31.207.0/24 via rrc00.ripe.net: 4 changes
- 144.31.224.0/24 via rrc00.ripe.net: 4 changes
- 144.31.224.0/24 via rrc00.ripe.net: 4 changes
- 144.31.234.0/24 via rrc00.ripe.net: 4 changes
- 144.31.234.0/24 via rrc00.ripe.net: 4 changes
- 144.31.30.0/24 via rrc00.ripe.net: 4 changes
- 144.31.30.0/24 via rrc00.ripe.net: 4 changes

## Manual verification: open trial_report_alerts.csv, fill `verdict` (TRUE/FALSE) per alert, then re-run analyze with --labels trial_report_alerts.csv

## Limits of this live test
- no ground truth: precision/recall are relative to our own counting rule, not to confirmed incidents
- recall is only meaningful for routes whose announcement we saw (RIS Live sends no initial table; withdrawals of unseen routes are ignored)
- flaps are rare: a short run may contain few or none; results are for this window, this prefix set and these collectors only
