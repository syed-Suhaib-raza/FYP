# RPKI Invalid PoC evaluation: offline (config: full)

- run: 2026-11-10 17:39:05 UTC on DESKTOP-JJSDSG4 (Windows AMD64, Python 3.14.3)
- dataset: `evaluation\labelled_updates.jsonl`: 200 lines, 206 checks, 19 scenarios (38 anomalous in scope, 166 benign, 2 out of scope); synthetic, labels by construction
- config `full`: MIN_PEERS=2, re-validate on VRP change=True. The labels assume the chosen design (`full`); ablation runs show what changes without it.
- wall time for the whole stream: 0.17 s

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
| as0_roa | benign | 4 | 4 | 1.00 | {"benign": 2, "anomalous": 2} | 1.687 |
| as_set_origin | benign | 2 | 2 | 1.00 | {"benign": 1, "anomalous": 1} | 2.128 |
| customer_not_in_roa | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 1.265 |
| exact_prefix_hijack | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 1.359 |
| foreign_first_time | benign | 6 | 6 | 1.00 | {"benign": 3, "anomalous": 3} | 1.716 |
| foreign_in_space_no_roa | benign | 2 | 2 | 1.00 | {"benign": 1, "anomalous": 1} | 2.080 |
| invalid_not_cybernet | benign | 3 | 3 | 1.00 | {"benign": 3} | 0.547 |
| own_maxlength | benign | 10 | 10 | 1.00 | {"benign": 3, "anomalous": 7} | 1.173 |
| own_maxlength_ipv6 | benign | 4 | 4 | 1.00 | {"benign": 2, "anomalous": 2} | 1.828 |
| own_no_roa | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 1.376 |
| own_not_authorised | benign | 3 | 3 | 1.00 | {"benign": 1, "anomalous": 2} | 1.814 |
| own_valid | benign | 60 | 60 | 1.00 | {"benign": 60} | 0.606 |
| own_valid_ipv6 | benign | 23 | 23 | 1.00 | {"benign": 23} | 0.508 |
| roa_expired | benign | 4 | 4 | 1.00 | {"benign": 3, "anomalous": 1} | 4.739 |
| roa_tightened | benign | 30 | 30 | 1.00 | {"benign": 27, "anomalous": 3} | 1.584 |
| single_peer_noise | benign | 2 | 2 | 1.00 | {"benign": 2} | 2.076 |
| subprefix_hijack | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 1.254 |
| valid_not_cybernet | benign | 27 | 27 | 1.00 | {"benign": 27} | 0.387 |

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
| decision, all lines | 200 | 0.802 | 0.248 | 1.314 | 3.038 | 5.105 | 10.4 |
| decision, triggering lines | 23 | 1.740 | 1.057 | 1.407 | 6.749 | 9.690 | 10.4 |
| decision, other lines | 177 | 0.680 | 0.195 | 1.297 | 3.019 | 3.626 | 5.082 |

## 4. Detection of anomalous episodes

From the first check where an alert should be active to the first check where the PoC has it.

| scenario | prefix | category | difficulty | detected | lines until detection | BGP time (s) | wall time (ms) |
|---|---|---|---|---|---|---|---|
| S02 | 72.255.0.0/19 | roa_tightened | hard | yes | 1 | 0 | 10.4 |
| S03 | 72.255.40.0/24 | own_maxlength | easy | yes | 1 | 0 | 1.056 |
| S04 | 72.255.0.0/18 | exact_prefix_hijack | easy | yes | 1 | 0 | 1.057 |
| S05 | 72.255.8.0/24 | subprefix_hijack | easy | yes | 1 | 0 | 0.958 |
| S06 | 72.255.48.0/20 | customer_not_in_roa | easy | yes | 1 | 0 | 1.112 |
| S07 | 198.51.100.0/24 | own_not_authorised | easy | yes | 1 | 0 | 1.177 |
| S08 | 192.0.2.0/24 | as0_roa | easy | yes | 1 | 0 | 1.117 |
| S09 | 72.255.12.0/22 | as_set_origin | hard | yes | 1 | 0 | 1.091 |
| S10 | 72.255.128.0/18 | own_no_roa | easy | yes | 1 | 0 | 1.091 |
| S11b | 2001:db8:100:ff00::/56 | own_maxlength_ipv6 | easy | yes | 1 | 0 | 1.099 |
| S16 | 72.255.160.0/20 | foreign_in_space_no_roa | hard | yes | 1 | 0 | 1.024 |
| S17 | 203.0.113.0/24 | roa_expired | hard | yes | 1 | 0 | 10.4 |
| S19 | 72.255.16.0/20 | foreign_first_time | easy | yes | 1 | 0 | 1.235 |

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
