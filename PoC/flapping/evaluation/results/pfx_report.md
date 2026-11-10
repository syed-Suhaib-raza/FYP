# Route flapping: LIVE test
Capture: pfx_capture.jsonl; 39186 messages; watching ['193.0.0.0/8', '194.0.0.0/8', '195.0.0.0/8']; detector settings {'half_life': 900, 'suppress': 2000, 'reuse': 750, 'min_peers': 1}.

## Feed and pipeline latency (all messages)
- recorded for 45.0 min = 14.5 messages/s; 20807 withdrawals, 120716 announcements, 0 peer resets
- feed delay (our receive time - RIS timestamp), s: {'n': 39186, 'median': 2.75, 'mean': 4.374, 'p95': 5.251, 'min': 1.232, 'max': 173.98}
- detector compute per message, ms (replay on this machine): {'n': 39186, 'median': 0.5252, 'mean': 0.5047, 'p95': 0.7859, 'min': 0.0012, 'max': 10.3778}

## Network latency (live probes)
- set-up to ris-live.ripe.net: DNS 0.48 ms, TCP connect 132.77 ms (= 1 round trip), TLS 268.54 ms, WebSocket upgrade 757.99 ms (server 193.0.11.16)
- WebSocket ping round trip, ms: {'n': 257, 'median': 179.83, 'mean': 491.56, 'p95': 440.82, 'min': 129.3, 'max': 10476.4}
- network one-way delay estimate = RTT/2 = 89.9 ms median (assumes a symmetric path)
- PC clock vs NTP (pool.ntp.org): offset +0.467 s median over 9 samples (range +0.429 .. +0.504; positive = PC clock is behind). Added to every PC timestamp below.
- feed delay corrected for the clock offset, s: {'n': 39186, 'median': 3.218, 'mean': 4.841, 'p95': 5.718, 'min': 1.699, 'max': 174.447}
- split of the median corrected feed delay 3.218 s: network one-way ~0.090 s + RIS-side / other ~3.128 s (collector -> RIS Live server -> send, queueing, our read)

## Flap alerts: 2946 raised in replay, 2946 logged live
(if these differ, the live run and the replay saw a different clock for `tick`; the replay uses stream time)

| Latency (live) | n | median | mean | p95 | min | max |
|---|---|---|---|---|---|---|
| Detection delay (s) | 2946 | 309.81 | 376.843 | 1234.25 | 0.0 | 2449.47 |
| Feed delay (s) | 2946 | 2.817 | 3.868 | 4.047 | 1.354 | 153.299 |
| Compute (ms) | 2946 | 4.272 | 4.745 | 10.067 | 0.045 | 21.878 |
| TOTAL time to detect (s) | 2946 | 311.719 | 380.716 | 1237.586 | 1.842 | 2453.042 |
| Changes needed before alert | 2946 | 5.0 | 4.654 | 6.0 | 2 | 8 |
| Feed delay, clock-corrected (s) | 2946 | 3.284 | 4.335 | 4.514 | 1.821 | 153.766 |
| TOTAL time to detect, clock-corrected (s) | 2946 | 312.186 | 381.184 | 1238.053 | 2.309 | 2453.509 |

Network share: one-way ~0.090 s of a median 312.2 s total = 0.03%. The rest is the flap itself unfolding (detection delay).

## Accuracy against the independent count rule (>=4 changes/15 min or >=5/90 min, resets excluded)
- routes with at least one change (population): 9867; flapping by the rule: 3086; alerted by the detector: 2939
- TP 2814 | FP 125 | FN 272 | TN 6656
- precision 0.957 | recall 0.912 | F1 0.934 | accuracy 0.9598 (dominated by TN: most routes change once)
- for TPs, rule satisfied minus detector alert time, s (positive = detector fired first): {'n': 2814, 'median': -1.0, 'mean': -47.0, 'p95': 91.1, 'min': -1910.9, 'max': 1903.9}

False-positive candidates (alerted, rule not satisfied):
- 150.237.95.0/24 via rrc00.ripe.net: 3 changes
- 185.53.76.0/24 via rrc00.ripe.net: 3 changes
- 193.10.255.0/24 via rrc00.ripe.net: 3 changes
- 193.10.255.0/24 via rrc00.ripe.net: 4 changes
- 193.10.255.0/24 via rrc00.ripe.net: 4 changes
- 193.10.255.0/24 via rrc00.ripe.net: 4 changes
- 193.10.255.0/24 via rrc00.ripe.net: 3 changes
- 193.10.255.0/24 via rrc00.ripe.net: 4 changes
- 193.105.156.0/24 via rrc00.ripe.net: 3 changes
- 193.232.156.0/24 via rrc00.ripe.net: 4 changes
- 193.232.156.0/24 via rrc00.ripe.net: 4 changes
- 193.28.184.0/24 via rrc00.ripe.net: 3 changes
- 193.28.184.0/24 via rrc00.ripe.net: 3 changes
- 193.35.38.0/23 via rrc00.ripe.net: 3 changes
- 193.58.168.0/23 via rrc00.ripe.net: 3 changes
- 193.58.168.0/23 via rrc00.ripe.net: 4 changes
- 193.58.168.0/23 via rrc00.ripe.net: 4 changes
- 193.58.168.0/24 via rrc00.ripe.net: 3 changes
- 193.58.168.0/24 via rrc00.ripe.net: 3 changes
- 193.58.168.0/24 via rrc00.ripe.net: 4 changes

Missed by the detector (rule satisfied):
- 103.170.3.0/24 via rrc00.ripe.net: 6 changes
- 103.170.3.0/24 via rrc00.ripe.net: 8 changes
- 109.105.228.0/24 via rrc00.ripe.net: 5 changes
- 109.160.112.0/24 via rrc00.ripe.net: 4 changes
- 109.160.112.0/24 via rrc00.ripe.net: 4 changes
- 109.68.210.0/23 via rrc00.ripe.net: 4 changes
- 109.68.210.0/23 via rrc00.ripe.net: 4 changes
- 111.118.176.0/22 via rrc00.ripe.net: 5 changes
- 130.117.194.0/24 via rrc00.ripe.net: 5 changes
- 130.117.194.0/24 via rrc00.ripe.net: 5 changes
- 130.117.196.0/22 via rrc00.ripe.net: 5 changes
- 141.98.132.0/22 via rrc00.ripe.net: 4 changes
- 141.98.132.0/22 via rrc00.ripe.net: 4 changes
- 141.98.132.0/22 via rrc00.ripe.net: 4 changes
- 150.237.95.0/24 via rrc00.ripe.net: 4 changes
- 150.237.95.0/24 via rrc00.ripe.net: 4 changes
- 173.205.112.0/24 via rrc00.ripe.net: 4 changes
- 173.205.112.0/24 via rrc00.ripe.net: 4 changes
- 173.205.26.0/24 via rrc00.ripe.net: 5 changes
- 173.205.26.0/24 via rrc00.ripe.net: 6 changes

## Manual verification: open pfx_report_alerts.csv, fill `verdict` (TRUE/FALSE) per alert, then re-run analyze with --labels pfx_report_alerts.csv

## Limits of this live test
- no ground truth: precision/recall are relative to our own counting rule, not to confirmed incidents
- recall is only meaningful for routes whose announcement we saw (RIS Live sends no initial table; withdrawals of unseen routes are ignored)
- flaps are rare: a short run may contain few or none; results are for this window, this prefix set and these collectors only
