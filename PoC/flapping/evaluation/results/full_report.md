# Route flapping: LIVE test
Capture: full_capture.jsonl; 369590 messages; watching rrc00; detector settings {'half_life': 900, 'suppress': 2000, 'reuse': 750, 'min_peers': 1}.

## Feed and pipeline latency (all messages)
- recorded for 45.0 min = 137.0 messages/s; 44115 withdrawals, 716717 announcements, 0 peer resets
- feed delay (our receive time - RIS timestamp), s: {'n': 369590, 'median': 15.28, 'mean': 18.395, 'p95': 42.096, 'min': 1.56, 'max': 73.661}
- detector compute per message, ms (replay on this machine): {'n': 369590, 'median': 4.6705, 'mean': 4.5742, 'p95': 10.6828, 'min': 0.0013, 'max': 711.9931}

## Network latency (live probes)
- set-up to ris-live.ripe.net: DNS 3.59 ms, TCP connect 202.46 ms (= 1 round trip), TLS 301.52 ms, WebSocket upgrade 1186.13 ms (server 193.0.11.16)
- WebSocket ping round trip, ms: {'n': 15, 'median': 5209.06, 'mean': 5361.63, 'p95': 12398.76, 'min': 446.77, 'max': 12711.76}
- network one-way delay estimate = RTT/2 = 2604.5 ms median (assumes a symmetric path)
- PC clock vs NTP (pool.ntp.org): offset +0.170 s median over 35 samples (range +0.123 .. +0.230; positive = PC clock is behind). Added to every PC timestamp below.
- feed delay corrected for the clock offset, s: {'n': 369590, 'median': 15.45, 'mean': 18.565, 'p95': 42.266, 'min': 1.73, 'max': 73.831}
- split of the median corrected feed delay 15.450 s: network one-way ~2.605 s + RIS-side / other ~12.846 s (collector -> RIS Live server -> send, queueing, our read)

## Flap alerts: 15624 raised in replay, 15628 logged live
(if these differ, the live run and the replay saw a different clock for `tick`; the replay uses stream time)

| Latency (live) | n | median | mean | p95 | min | max |
|---|---|---|---|---|---|---|
| Detection delay (s) | 15628 | 171.17 | 409.766 | 1679.186 | 0.0 | 2638.65 |
| Feed delay (s) | 15628 | 14.051 | 17.718 | 41.8 | 1.748 | 71.667 |
| Compute (ms) | 15628 | 15.776 | 79.207 | 490.811 | 0.034 | 565.215 |
| TOTAL time to detect (s) | 15628 | 184.094 | 427.565 | 1706.622 | 2.19 | 2684.359 |
| Changes needed before alert | 15628 | 5.0 | 4.937 | 7.0 | 2 | 11 |
| Feed delay, clock-corrected (s) | 15628 | 14.221 | 17.887 | 41.97 | 1.918 | 71.837 |
| TOTAL time to detect, clock-corrected (s) | 15628 | 184.264 | 427.735 | 1706.791 | 2.36 | 2684.529 |

Network share: one-way ~2.605 s of a median 184.3 s total = 1.41%. The rest is the flap itself unfolding (detection delay).

## Accuracy against the independent count rule (>=4 changes/15 min or >=5/90 min, resets excluded)
- routes with at least one change (population): 64667; flapping by the rule: 20900; alerted by the detector: 15455
- TP 14900 | FP 555 | FN 6000 | TN 43212
- precision 0.964 | recall 0.713 | F1 0.82 | accuracy 0.8986 (dominated by TN: most routes change once)
- for TPs, rule satisfied minus detector alert time, s (positive = detector fired first): {'n': 14900, 'median': -2.0, 'mean': -135.3, 'p95': 25.0, 'min': -2596.6, 'max': 2078.1}

False-positive candidates (alerted, rule not satisfied):
- 102.184.80.0/20 via rrc00.ripe.net: 3 changes
- 102.186.144.0/22 via rrc00.ripe.net: 3 changes
- 102.186.148.0/22 via rrc00.ripe.net: 3 changes
- 102.186.176.0/22 via rrc00.ripe.net: 3 changes
- 102.186.188.0/22 via rrc00.ripe.net: 3 changes
- 102.186.80.0/20 via rrc00.ripe.net: 3 changes
- 102.187.112.0/20 via rrc00.ripe.net: 3 changes
- 102.188.100.0/22 via rrc00.ripe.net: 3 changes
- 102.188.104.0/22 via rrc00.ripe.net: 3 changes
- 102.188.108.0/22 via rrc00.ripe.net: 3 changes
- 102.188.224.0/20 via rrc00.ripe.net: 3 changes
- 102.188.36.0/22 via rrc00.ripe.net: 3 changes
- 102.188.44.0/22 via rrc00.ripe.net: 3 changes
- 102.188.64.0/22 via rrc00.ripe.net: 3 changes
- 102.188.68.0/22 via rrc00.ripe.net: 3 changes
- 102.188.72.0/22 via rrc00.ripe.net: 3 changes
- 102.188.76.0/22 via rrc00.ripe.net: 3 changes
- 102.188.96.0/22 via rrc00.ripe.net: 3 changes
- 102.189.212.0/22 via rrc00.ripe.net: 3 changes
- 102.189.216.0/22 via rrc00.ripe.net: 3 changes

Missed by the detector (rule satisfied):
- 101.50.1.0/24 via rrc00.ripe.net: 4 changes
- 102.165.168.0/24 via rrc00.ripe.net: 4 changes
- 102.165.169.0/24 via rrc00.ripe.net: 4 changes
- 102.165.170.0/24 via rrc00.ripe.net: 4 changes
- 102.165.171.0/24 via rrc00.ripe.net: 4 changes
- 102.165.172.0/24 via rrc00.ripe.net: 4 changes
- 102.165.173.0/24 via rrc00.ripe.net: 4 changes
- 102.165.174.0/24 via rrc00.ripe.net: 4 changes
- 102.165.175.0/24 via rrc00.ripe.net: 4 changes
- 102.184.128.0/20 via rrc00.ripe.net: 4 changes
- 102.184.128.0/20 via rrc00.ripe.net: 4 changes
- 102.184.192.0/20 via rrc00.ripe.net: 4 changes
- 102.184.192.0/20 via rrc00.ripe.net: 4 changes
- 102.184.80.0/20 via rrc00.ripe.net: 4 changes
- 102.185.176.0/20 via rrc00.ripe.net: 4 changes
- 102.185.176.0/20 via rrc00.ripe.net: 4 changes
- 102.186.144.0/22 via rrc00.ripe.net: 4 changes
- 102.186.148.0/22 via rrc00.ripe.net: 4 changes
- 102.186.148.0/22 via rrc00.ripe.net: 4 changes
- 102.186.152.0/22 via rrc00.ripe.net: 4 changes

## Manual verification: open full_report_alerts.csv, fill `verdict` (TRUE/FALSE) per alert, then re-run analyze with --labels full_report_alerts.csv

## Limits of this live test
- no ground truth: precision/recall are relative to our own counting rule, not to confirmed incidents
- recall is only meaningful for routes whose announcement we saw (RIS Live sends no initial table; withdrawals of unseen routes are ignored)
- flaps are rare: a short run may contain few or none; results are for this window, this prefix set and these collectors only
