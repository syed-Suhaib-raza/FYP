# RPKI Invalid PoC evaluation: offline (config: min-peers-1)

- run: 2026-11-10 17:39:05 UTC on DESKTOP-JJSDSG4 (Windows AMD64, Python 3.14.3)
- dataset: `evaluation\labelled_updates.jsonl`: 200 lines, 206 checks, 19 scenarios (38 anomalous in scope, 166 benign, 2 out of scope); synthetic, labels by construction
- config `min-peers-1`: MIN_PEERS=1, re-validate on VRP change=True. The labels assume the chosen design (`full`); ablation runs show what changes without it.
- wall time for the whole stream: 0.22 s

## 1. Alert decision (in-scope checks)

anomalous = an ACTIVE NOC alert exists for the (prefix, origin). A deterministic engine should score 1.0.

| metric | value |
|---|---|
| updates | 204 |
| accuracy (uncertain = wrong) | 0.926 |
| uncertain / no decision | 0 |
| accuracy on decided updates | 0.926 |
| precision (alert = anomalous or uncertain) | 0.717 |
| recall | 1.0 |
| F1 | 0.835 |
| false-positive rate | 0.09 |
| TP | 38 |
| FP | 15 |
| FN | 0 |
| TN | 151 |

| truth \ predicted | anomalous | benign |
|---|---|---|
| anomalous | 38 | 0 |
| benign | 15 | 151 |

### By category

| category | truth | n | correct | accuracy | predicted | mean decision latency (ms) |
|---|---|---|---|---|---|---|
| as0_roa | benign | 4 | 3 | 0.75 | {"anomalous": 3, "benign": 1} | 1.719 |
| as_set_origin | benign | 2 | 1 | 0.50 | {"anomalous": 2} | 2.051 |
| customer_not_in_roa | benign | 6 | 5 | 0.83 | {"anomalous": 5, "benign": 1} | 1.546 |
| exact_prefix_hijack | benign | 6 | 5 | 0.83 | {"anomalous": 5, "benign": 1} | 1.660 |
| foreign_first_time | benign | 6 | 4 | 0.67 | {"anomalous": 5, "benign": 1} | 1.853 |
| foreign_in_space_no_roa | benign | 2 | 1 | 0.50 | {"anomalous": 2} | 2.223 |
| invalid_not_cybernet | benign | 3 | 3 | 1.00 | {"benign": 3} | 0.592 |
| own_maxlength | benign | 10 | 8 | 0.80 | {"anomalous": 9, "benign": 1} | 1.820 |
| own_maxlength_ipv6 | benign | 4 | 3 | 0.75 | {"anomalous": 3, "benign": 1} | 2.239 |
| own_no_roa | benign | 6 | 5 | 0.83 | {"anomalous": 5, "benign": 1} | 1.399 |
| own_not_authorised | benign | 3 | 2 | 0.67 | {"anomalous": 3} | 3.354 |
| own_valid | benign | 60 | 60 | 1.00 | {"benign": 60} | 0.724 |
| own_valid_ipv6 | benign | 23 | 23 | 1.00 | {"benign": 23} | 0.544 |
| roa_expired | benign | 4 | 4 | 1.00 | {"benign": 3, "anomalous": 1} | 6.491 |
| roa_tightened | benign | 30 | 30 | 1.00 | {"benign": 27, "anomalous": 3} | 2.155 |
| single_peer_noise | benign | 2 | 0 | 0.00 | {"anomalous": 2} | 2.483 |
| subprefix_hijack | benign | 6 | 5 | 0.83 | {"anomalous": 5, "benign": 1} | 1.642 |
| valid_not_cybernet | benign | 27 | 27 | 1.00 | {"benign": 27} | 0.811 |

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
| decision, all lines | 200 | 1.024 | 0.265 | 1.852 | 3.599 | 7.609 | 13.2 |
| decision, triggering lines | 24 | 3.625 | 3.051 | 6.826 | 10.5 | 12.7 | 13.2 |
| decision, other lines | 176 | 0.669 | 0.206 | 1.443 | 1.716 | 3.495 | 5.939 |

## 4. Detection of anomalous episodes

From the first check where an alert should be active to the first check where the PoC has it.

| scenario | prefix | category | difficulty | detected | lines until detection | BGP time (s) | wall time (ms) |
|---|---|---|---|---|---|---|---|
| S02 | 72.255.0.0/19 | roa_tightened | hard | yes | 1 | 0 | 13.2 |
| S03 | 72.255.40.0/24 | own_maxlength | easy | yes | 1 | 0 | 1.657 |
| S04 | 72.255.0.0/18 | exact_prefix_hijack | easy | yes | 1 | 0 | 1.071 |
| S05 | 72.255.8.0/24 | subprefix_hijack | easy | yes | 1 | 0 | 1.215 |
| S06 | 72.255.48.0/20 | customer_not_in_roa | easy | yes | 1 | 0 | 1.363 |
| S07 | 198.51.100.0/24 | own_not_authorised | easy | yes | 1 | 0 | 1.409 |
| S08 | 192.0.2.0/24 | as0_roa | easy | yes | 1 | 0 | 1.202 |
| S09 | 72.255.12.0/22 | as_set_origin | hard | yes | 1 | 0 | 0.985 |
| S10 | 72.255.128.0/18 | own_no_roa | easy | yes | 1 | 0 | 0.959 |
| S11b | 2001:db8:100:ff00::/56 | own_maxlength_ipv6 | easy | yes | 1 | 0 | 1.278 |
| S16 | 72.255.160.0/20 | foreign_in_space_no_roa | hard | yes | 1 | 0 | 1.462 |
| S17 | 203.0.113.0/24 | roa_expired | hard | yes | 1 | 0 | 13.2 |
| S19 | 72.255.16.0/20 | foreign_first_time | easy | yes | 1 | 0 | 1.137 |

Detected 13/13 anomalous episodes.

## 5. Out of scope (RPKI Valid by definition)

| category | n | PoC alerted |
|---|---|---|
| forged_origin_path_hijack | 2 | 0 |

## 6. Wrong checks

| seq | scenario | prefix | origin | truth | PoC | truth state | PoC state | truth sev | PoC sev |
|---|---|---|---|---|---|---|---|---|---|
| 23 | S19 | 72.255.16.0/20 | 64520 | benign | anomalous | INVALID_AS | INVALID_AS | None | CRITICAL |
| 32 | S03 | 72.255.40.0/24 | 9541 | benign | anomalous | INVALID_ML | INVALID_ML | None | HIGH |
| 40 | S03 | 72.255.40.0/24 | 9541 | benign | anomalous | INVALID_ML | INVALID_ML | None | HIGH |
| 49 | S04 | 72.255.0.0/18 | 64666 | benign | anomalous | INVALID_AS | INVALID_AS | None | CRITICAL |
| 55 | S05 | 72.255.8.0/24 | 64667 | benign | anomalous | INVALID_AS_AND_ML | INVALID_AS_AND_ML | None | CRITICAL |
| 61 | S06 | 72.255.48.0/20 | 64510 | benign | anomalous | INVALID_AS | INVALID_AS | None | HIGH |
| 64 | S07 | 198.51.100.0/24 | 9541 | benign | anomalous | INVALID_AS | INVALID_AS | None | HIGH |
| 67 | S08 | 192.0.2.0/24 | 64668 | benign | anomalous | INVALID_AS | INVALID_AS | None | CRITICAL |
| 71 | S09 | 72.255.12.0/22 | None | benign | anomalous | INVALID_AS_AND_ML | INVALID_AS_AND_ML | None | CRITICAL |
| 73 | S10 | 72.255.128.0/18 | 9541 | benign | anomalous | NOT_FOUND | NOT_FOUND | None | LOW |
| 76 | S16 | 72.255.160.0/20 | 64670 | benign | anomalous | NOT_FOUND | NOT_FOUND | None | LOW |
| 84 | S11b | 2001:db8:100:ff00::/56 | 9541 | benign | anomalous | INVALID_ML | INVALID_ML | None | HIGH |
| 86 | S12 | 72.255.60.0/24 | 9541 | benign | anomalous | INVALID_ML | INVALID_ML | None | HIGH |
| 89 | S19 | 72.255.16.0/20 | 64520 | benign | anomalous | INVALID_AS | INVALID_AS | None | HIGH |
| 93 | S12 | 72.255.60.0/24 | 9541 | benign | anomalous | INVALID_ML | INVALID_ML | None | HIGH |

## Notes

- The PoC is deterministic: the same stream always gives the same result. Latency varies with the machine.
- The forged-origin path hijack keeps the real origin, so it is RPKI Valid: covered by the AS-Path module.
- Agreement with Routinator is measured on live runs: `python evaluation/routinator_agreement.py --db rpki.db`.
