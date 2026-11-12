# RPKI Invalid PoC evaluation: offline (config: no-revalidation)

- run: 2026-11-10 17:39:05 UTC on DESKTOP-JJSDSG4 (Windows AMD64, Python 3.14.3)
- dataset: `evaluation\labelled_updates.jsonl`: 200 lines, 206 checks, 19 scenarios (38 anomalous in scope, 166 benign, 2 out of scope); synthetic, labels by construction
- config `no-revalidation`: MIN_PEERS=2, re-validate on VRP change=False. The labels assume the chosen design (`full`); ablation runs show what changes without it.
- wall time for the whole stream: 0.25 s

## 1. Alert decision (in-scope checks)

anomalous = an ACTIVE NOC alert exists for the (prefix, origin). A deterministic engine should score 1.0.

| metric | value |
|---|---|
| updates | 204 |
| accuracy (uncertain = wrong) | 0.98 |
| uncertain / no decision | 0 |
| accuracy on decided updates | 0.98 |
| precision (alert = anomalous or uncertain) | 0.972 |
| recall | 0.921 |
| F1 | 0.946 |
| false-positive rate | 0.006 |
| TP | 35 |
| FP | 1 |
| FN | 3 |
| TN | 165 |

| truth \ predicted | anomalous | benign |
|---|---|---|
| anomalous | 35 | 3 |
| benign | 1 | 165 |

### By category

| category | truth | n | correct | accuracy | predicted | mean decision latency (ms) |
|---|---|---|---|---|---|---|
| as0_roa | benign | 4 | 4 | 1.00 | {"benign": 2, "anomalous": 2} | 2.524 |
| as_set_origin | benign | 2 | 2 | 1.00 | {"benign": 1, "anomalous": 1} | 2.708 |
| customer_not_in_roa | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 4.195 |
| exact_prefix_hijack | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 1.980 |
| foreign_first_time | benign | 6 | 6 | 1.00 | {"benign": 3, "anomalous": 3} | 2.359 |
| foreign_in_space_no_roa | benign | 2 | 2 | 1.00 | {"benign": 1, "anomalous": 1} | 2.711 |
| invalid_not_cybernet | benign | 3 | 3 | 1.00 | {"benign": 3} | 0.791 |
| own_maxlength | benign | 10 | 10 | 1.00 | {"benign": 3, "anomalous": 7} | 1.808 |
| own_maxlength_ipv6 | benign | 4 | 4 | 1.00 | {"benign": 2, "anomalous": 2} | 2.365 |
| own_no_roa | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 3.214 |
| own_not_authorised | benign | 3 | 3 | 1.00 | {"benign": 1, "anomalous": 2} | 1.967 |
| own_valid | benign | 60 | 60 | 1.00 | {"benign": 60} | 0.469 |
| own_valid_ipv6 | benign | 23 | 23 | 1.00 | {"benign": 23} | 0.761 |
| roa_expired | benign | 4 | 3 | 0.75 | {"benign": 4} | 3.530 |
| roa_tightened | benign | 30 | 27 | 0.90 | {"benign": 28, "anomalous": 2} | 1.266 |
| single_peer_noise | benign | 2 | 2 | 1.00 | {"benign": 2} | 2.271 |
| subprefix_hijack | benign | 6 | 6 | 1.00 | {"benign": 2, "anomalous": 4} | 2.102 |
| valid_not_cybernet | benign | 27 | 27 | 1.00 | {"benign": 27} | 0.573 |

## 2. RFC 6811 state and severity

- state correct: **204/204** in-scope checks
- severity correct (doc table) when an alert is raised: **35/35**
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
| decision, all lines | 200 | 1.146 | 0.593 | 2.738 | 3.932 | 6.202 | 11.4 |
| decision, triggering lines | 22 | 1.676 | 1.525 | 2.684 | 2.765 | 2.894 | 2.928 |
| decision, other lines | 178 | 1.080 | 0.283 | 2.677 | 4.304 | 7.312 | 11.4 |

## 4. Detection of anomalous episodes

From the first check where an alert should be active to the first check where the PoC has it.

| scenario | prefix | category | difficulty | detected | lines until detection | BGP time (s) | wall time (ms) |
|---|---|---|---|---|---|---|---|
| S02 | 72.255.0.0/19 | roa_tightened | hard | yes | 4 | 10 | 10.3 |
| S03 | 72.255.40.0/24 | own_maxlength | easy | yes | 1 | 0 | 1.041 |
| S04 | 72.255.0.0/18 | exact_prefix_hijack | easy | yes | 1 | 0 | 1.628 |
| S05 | 72.255.8.0/24 | subprefix_hijack | easy | yes | 1 | 0 | 1.882 |
| S06 | 72.255.48.0/20 | customer_not_in_roa | easy | yes | 1 | 0 | 2.767 |
| S07 | 198.51.100.0/24 | own_not_authorised | easy | yes | 1 | 0 | 1.231 |
| S08 | 192.0.2.0/24 | as0_roa | easy | yes | 1 | 0 | 1.422 |
| S09 | 72.255.12.0/22 | as_set_origin | hard | yes | 1 | 0 | 1.184 |
| S10 | 72.255.128.0/18 | own_no_roa | easy | yes | 1 | 0 | 1.611 |
| S11b | 2001:db8:100:ff00::/56 | own_maxlength_ipv6 | easy | yes | 1 | 0 | 2.233 |
| S16 | 72.255.160.0/20 | foreign_in_space_no_roa | hard | yes | 1 | 0 | 1.879 |
| S17 | 203.0.113.0/24 | roa_expired | hard | NO | - | - | - |
| S19 | 72.255.16.0/20 | foreign_first_time | easy | yes | 1 | 0 | 1.253 |

Detected 12/13 anomalous episodes.

## 5. Out of scope (RPKI Valid by definition)

| category | n | PoC alerted |
|---|---|---|
| forged_origin_path_hijack | 2 | 0 |

## 6. Wrong checks

| seq | scenario | prefix | origin | truth | PoC | truth state | PoC state | truth sev | PoC sev |
|---|---|---|---|---|---|---|---|---|---|
| 27 | S17 | 203.0.113.0/24 | 24440 | anomalous | benign | NOT_FOUND | NOT_FOUND | LOW | None |
| 27 | S02 | 72.255.0.0/19 | 9541 | anomalous | benign | INVALID_ML | INVALID_ML | HIGH | None |
| 27 | S02 | 72.255.32.0/20 | 9541 | anomalous | benign | INVALID_ML | INVALID_ML | HIGH | None |
| 31 | S02 | 72.255.32.0/20 | 9541 | benign | anomalous | VALID | VALID | None | HIGH |

## Notes

- The PoC is deterministic: the same stream always gives the same result. Latency varies with the machine.
- The forged-origin path hijack keeps the real origin, so it is RPKI Valid: covered by the AS-Path module.
- Agreement with Routinator is measured on live runs: `python evaluation/routinator_agreement.py --db rpki.db`.
