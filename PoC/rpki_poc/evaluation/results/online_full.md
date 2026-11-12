# RPKI Invalid PoC evaluation: online (config: full)

- run: 2026-11-10 16:10:22 UTC on vm (Linux x86_64, Python 3.13.18)
- dataset: `evaluation/labelled_updates.jsonl`: 200 lines, 206 checks, 19 scenarios (38 anomalous in scope, 166 benign, 2 out of scope); synthetic, labels by construction
- config `full`: MIN_PEERS=2, re-validate on VRP change=True. The labels assume the chosen design (`full`); ablation runs show what changes without it.
- wall time for the whole stream: 122.42 s
- transport: websocket, RIS Live protocol, built-in feed server ws://127.0.0.1:44575; send rate 20.0 msg/s; global order kept
- feed delay model: trace of 11401 measured delays (median 4194 ms, p95 102411 ms) from the RIS Live probe
- real RIS Live probe: 25330 messages in 20 s from rrc00; 11401 usable delay samples (median 4.19 s, p95 102.41 s); 13929 messages with timestamps older than 120 s (median 11.0 days: collector replay / table re-send) excluded

## 1. Alert decision (in-scope checks)

anomalous = an ACTIVE NOC alert exists for the (prefix, origin). A deterministic engine should score 1.0.

| metric | value |
|---|---|
| updates | 204 |
| accuracy (uncertain = wrong) | 1.0 |
| uncertain / no decision | 0 |
| accuracy on decided updates | 1.0 |
| precision (alert = anomalous or uncertain) | 1.0 |
| recall | 1.0 |
| F1 | 1.0 |
| false-positive rate | 0.0 |
| TP | 38 |
| FP | 0 |
| FN | 0 |
| TN | 166 |

| truth \ predicted | anomalous | benign |
|---|---|---|
| anomalous | 38 | 0 |
| benign | 0 | 166 |

### By category

| category | truth | n | correct | accuracy | predicted | mean decision latency (ms) |
|---|---|---|---|---|---|---|
| as0_roa | benign | 4 | 4 | 1.00 | {"benign": 2, "anomalous": 2} | 1.641 |
| as_set_origin | benign | 2 | 2 | 1.00 | {"benign": 1, "anomalous": 1} | 2.063 |
| customer_not_in_roa | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 1.494 |
| exact_prefix_hijack | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 1.420 |
| foreign_first_time | benign | 6 | 6 | 1.00 | {"benign": 3, "anomalous": 3} | 2.069 |
| foreign_in_space_no_roa | benign | 2 | 2 | 1.00 | {"benign": 1, "anomalous": 1} | 1.550 |
| invalid_not_cybernet | benign | 3 | 3 | 1.00 | {"benign": 3} | 0.569 |
| own_maxlength | benign | 10 | 10 | 1.00 | {"benign": 3, "anomalous": 7} | 1.444 |
| own_maxlength_ipv6 | benign | 4 | 4 | 1.00 | {"benign": 2, "anomalous": 2} | 1.372 |
| own_no_roa | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 1.951 |
| own_not_authorised | benign | 3 | 3 | 1.00 | {"benign": 1, "anomalous": 2} | 1.934 |
| own_valid | benign | 60 | 60 | 1.00 | {"benign": 60} | 0.519 |
| own_valid_ipv6 | benign | 23 | 23 | 1.00 | {"benign": 23} | 0.538 |
| roa_expired | benign | 4 | 4 | 1.00 | {"benign": 3, "anomalous": 1} | 3.477 |
| roa_tightened | benign | 30 | 30 | 1.00 | {"benign": 27, "anomalous": 3} | 1.322 |
| single_peer_noise | benign | 2 | 2 | 1.00 | {"benign": 2} | 1.835 |
| subprefix_hijack | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 1.631 |
| valid_not_cybernet | benign | 27 | 27 | 1.00 | {"benign": 27} | 0.504 |

## 2. RFC 6811 state and severity

- state correct: **204/204** in-scope checks
- severity correct (doc table) when an alert is raised: **38/38**
- ROA changes reported as MEDIUM: **2** (expected 2: maxLength reduced on 72.255.0.0/18, ROA for 203.0.113.0/24 removed)

| truth \ PoC state | VALID | NOT_FOUND | INVALID_AS | INVALID_ML | INVALID_AS_AND_ML |
|---|---|---|---|---|---|
| VALID | 140 | 0 | 0 | 0 | 0 |
| NOT_FOUND | 0 | 9 | 0 | 0 | 0 |
| INVALID_AS | 0 | 0 | 28 | 0 | 0 |
| INVALID_ML | 0 | 0 | 0 | 19 | 0 |
| INVALID_AS_AND_ML | 0 | 0 | 0 | 0 | 8 |

## 3. Time to decision

Processing per line, including SQLite writes. Triggering lines opened, re-opened or resolved an alert.

All values in milliseconds.

| stage | n | mean | p50 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| decision, all lines | 200 | 0.854 | 0.383 | 1.676 | 2.549 | 5.160 | 8.196 |
| decision, triggering lines | 23 | 1.817 | 1.264 | 3.703 | 5.064 | 7.526 | 8.196 |
| decision, other lines | 177 | 0.729 | 0.176 | 1.669 | 2.441 | 3.069 | 5.942 |
| feed delay (emit -> sent) | 200 | 25345.5 | 5221.7 | 81641.0 | 96461.4 | 107478.4 | 112247.2 |
| socket + queueing (sent -> read) | 200 | 0.624 | 0.551 | 0.694 | 0.791 | 2.630 | 5.585 |
| end-to-end (emit -> decision), all | 200 | 25347.0 | 5222.6 | 81643.4 | 96462.1 | 107480.1 | 112249.4 |
| end-to-end (emit -> decision), triggering | 23 | 13330.9 | 4250.6 | 5036.3 | 95536.8 | 110784.8 | 112249.4 |

## 4. Detection of anomalous episodes

From the first check where an alert should be active to the first check where the PoC has it.

| scenario | prefix | category | difficulty | detected | lines until detection | BGP time (s) | wall time (ms) |
|---|---|---|---|---|---|---|---|
| S02 | 72.255.0.0/19 | roa_tightened | hard | yes | 1 | 0 | 3465.2 |
| S03 | 72.255.40.0/24 | own_maxlength | easy | yes | 1 | 0 | 3547.4 |
| S04 | 72.255.0.0/18 | exact_prefix_hijack | easy | yes | 1 | 0 | 3935.8 |
| S05 | 72.255.8.0/24 | subprefix_hijack | easy | yes | 1 | 0 | 4098.8 |
| S06 | 72.255.48.0/20 | customer_not_in_roa | easy | yes | 1 | 0 | 4246.0 |
| S07 | 198.51.100.0/24 | own_not_authorised | easy | yes | 1 | 0 | 4485.6 |
| S08 | 192.0.2.0/24 | as0_roa | easy | yes | 1 | 0 | 4739.6 |
| S09 | 72.255.12.0/22 | as_set_origin | hard | yes | 1 | 0 | 4755.4 |
| S10 | 72.255.128.0/18 | own_no_roa | easy | yes | 1 | 0 | 4831.6 |
| S11b | 2001:db8:100:ff00::/56 | own_maxlength_ipv6 | easy | yes | 1 | 0 | 4935.3 |
| S16 | 72.255.160.0/20 | foreign_in_space_no_roa | hard | yes | 1 | 0 | 4771.8 |
| S17 | 203.0.113.0/24 | roa_expired | hard | yes | 1 | 0 | 3465.2 |
| S19 | 72.255.16.0/20 | foreign_first_time | easy | yes | 1 | 0 | 3494.6 |

Detected 13/13 anomalous episodes.

## 5. Out of scope (RPKI Valid by definition)

| category | n | PoC alerted |
|---|---|---|
| forged_origin_path_hijack | 2 | 0 |

## 6. Wrong checks

| seq | scenario | prefix | origin | truth | PoC | truth state | PoC state | truth sev | PoC sev |
|---|---|---|---|---|---|---|---|---|---|
| - | none | | | | | | | | |

## Notes

- The PoC is deterministic: the same stream always gives the same result. Latency varies with the machine.
- The forged-origin path hijack keeps the real origin, so it is RPKI Valid: covered by the AS-Path module.
- Agreement with Routinator is measured on live runs: `python evaluation/routinator_agreement.py --db rpki.db`.

## 7. Real RIS Live traffic (unlabelled, timing only)

20000 real messages (1000.0 msg/s); processing used 111.89% of the wall time.

| stage | n | mean | p50 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| RIS Live feed delay (arrival - collector timestamp) | 11401 | 26628.5 | 4194.1 | 91630.8 | 102410.9 | 117244.9 | 119244.2 |
| websocket round trip to RIS Live | 5 | 120.5 | 118.8 | 128.1 | 129.8 | 131.2 | 131.5 |
| decision, real updates | 20000 | 1.119 | 0.455 | 1.342 | 2.618 | 12.8 | 446.5 |

