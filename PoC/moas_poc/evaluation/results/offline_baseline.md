# MOAS PoC evaluation: offline (backend: baseline)

- run: 2026-11-10 14:13:30 UTC on Suhaibs-Macbook.local (Darwin arm64, Python 3.13.1)
- dataset: `evaluation/labelled_updates.jsonl`: 202 updates, 39 scenarios (144 benign, 49 anomalous in scope, 9 anomalous out of scope); synthetic, labels by construction
- whitelist: `evaluation/eval_whitelist.json`, catalog window 3600 s
- wall time for the whole stream: 0.01 s
- backend `baseline` is the PoC's untuned additive rule set, not a model

## 1. Classification (in-scope updates)

| metric | value |
|---|---|
| updates | 193 |
| accuracy (uncertain = wrong) | 0.845 |
| uncertain / no decision | 22 |
| accuracy on decided updates | 0.953 |
| precision (alert = anomalous or uncertain) | 0.763 |
| recall | 0.918 |
| F1 | 0.833 |
| false-positive rate | 0.097 |
| TP | 45 |
| FP | 14 |
| FN | 4 |
| TN | 130 |

| truth \ predicted | anomalous | benign | uncertain |
|---|---|---|---|
| anomalous | 33 | 4 | 12 |
| benign | 4 | 130 | 10 |

### By category

| category | truth | n | correct | accuracy | predicted | mean decision latency (ms) |
|---|---|---|---|---|---|---|
| as_trans_origin | anomalous | 2 | 2 | 1.00 | {"anomalous": 2} | 0.299 |
| bogon_moas | anomalous | 3 | 3 | 1.00 | {"anomalous": 3} | 0.139 |
| exact_hijack_unwatched | anomalous | 12 | 0 | 0.00 | {"uncertain": 12} | 0.143 |
| exact_hijack_watched | anomalous | 13 | 13 | 1.00 | {"anomalous": 13} | 0.100 |
| exact_hijack_watched_private_asn | anomalous | 4 | 4 | 1.00 | {"anomalous": 4} | 0.126 |
| hijack_forged_adjacency | anomalous | 4 | 0 | 0.00 | {"benign": 4} | 0.118 |
| legit_origin_during_hijack | anomalous | 2 | 2 | 1.00 | {"anomalous": 2} | 0.003 |
| origin_added_to_planned_moas | anomalous | 3 | 3 | 1.00 | {"anomalous": 3} | 0.127 |
| private_asn_origin | anomalous | 6 | 6 | 1.00 | {"anomalous": 6} | 0.119 |
| after_hijack_aged_out | benign | 1 | 1 | 1.00 | {"benign": 1} | 0.446 |
| anycast_unwatched | benign | 6 | 1 | 0.17 | {"benign": 1, "uncertain": 5} | 0.105 |
| as_set_aggregate | benign | 4 | 4 | 1.00 | {"benign": 4} | 0.005 |
| ddos_scrubbing_diversion | benign | 4 | 0 | 0.00 | {"anomalous": 4} | 0.150 |
| moas_ended | benign | 1 | 1 | 1.00 | {"benign": 1} | 0.407 |
| origin_change_no_overlap | benign | 4 | 4 | 1.00 | {"benign": 4} | 0.007 |
| planned_multi_origin | benign | 8 | 8 | 1.00 | {"benign": 8} | 0.040 |
| planned_origin_migration | benign | 6 | 6 | 1.00 | {"benign": 6} | 0.061 |
| provider_aggregation | benign | 16 | 16 | 1.00 | {"benign": 16} | 0.096 |
| sibling_origins_unwatched | benign | 6 | 1 | 0.17 | {"benign": 1, "uncertain": 5} | 0.065 |
| steady_single_origin | benign | 43 | 43 | 1.00 | {"benign": 43} | 0.004 |
| steady_single_origin_unwatched | benign | 45 | 45 | 1.00 | {"benign": 45} | 0.004 |

## 2. Time to decision

Processing per update (catalog + AI layer). *Triggering* updates are those that opened, changed or closed a MOAS event and therefore caused an AI-layer verdict; every other update is decided by the catalog alone.

All values in milliseconds.

| stage | n | mean | p50 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| catalog (layer 1), all updates | 202 | 0.023 | 0.003 | 0.113 | 0.157 | 0.283 | 0.351 |
| AI layer (layer 2), triggering updates | 23 | 0.284 | 0.272 | 0.379 | 0.442 | 0.562 | 0.595 |
| decision, all updates | 202 | 0.056 | 0.003 | 0.314 | 0.444 | 0.648 | 0.764 |
| decision, triggering updates | 23 | 0.457 | 0.411 | 0.642 | 0.667 | 0.743 | 0.764 |
| decision, non-triggering updates | 179 | 0.004 | 0.003 | 0.006 | 0.009 | 0.019 | 0.021 |

## 3. Detection of anomalous episodes

From the first anomalous update of a scenario to the first update whose decision is `anomalous`. BGP time is measured on the update timestamps (0 = caught on the first anomalous update); wall time is ingest of that first update to the decision.

| scenario | prefix | category | difficulty | detected | flagged (anomalous or uncertain) | updates until detection | BGP time (s) | wall time (ms) |
|---|---|---|---|---|---|---|---|---|
| A01 | 1.1.1.0/24 | exact_hijack_watched | easy | yes | yes | 1 | 0 | 0.175 |
| A02 | 8.8.8.0/24 | exact_hijack_watched_private_asn | easy | yes | yes | 1 | 0 | 0.494 |
| A03 | 66.167.90.0/24 | exact_hijack_watched | easy | yes | yes | 1 | 0 | 0.764 |
| A04a | 102.130.48.0/24 | exact_hijack_unwatched | hard | NO | yes | - | - | - |
| A04b | 41.75.112.0/24 | exact_hijack_unwatched | hard | NO | yes | - | - | - |
| A04c | 196.49.4.0/24 | exact_hijack_unwatched | hard | NO | yes | - | - | - |
| A05a | 103.21.244.0/24 | private_asn_origin | easy | yes | yes | 1 | 0 | 0.382 |
| A05b | 180.92.160.0/24 | private_asn_origin | easy | yes | yes | 1 | 0 | 0.318 |
| A06 | 202.69.160.0/24 | as_trans_origin | easy | yes | yes | 1 | 0 | 0.593 |
| A07 | 100.64.12.0/24 | bogon_moas | easy | yes | yes | 1 | 0 | 0.411 |
| A10 | 104.16.0.0/24 | origin_added_to_planned_moas | easy | yes | yes | 1 | 0 | 0.373 |
| A11 | 46.19.36.0/24 | hijack_forged_adjacency | hard | NO | no | - | - | - |
| A13 | 45.223.12.0/24 | exact_hijack_watched | easy | yes | yes | 1 | 0 | 0.338 |

Detected 9/13 anomalous episodes; flagged for review 12/13.

## 4. Out-of-scope anomalies (not visible to an exact-prefix MOAS detector)

| category | n | PoC said anomalous |
|---|---|---|
| bogon_single_origin | 1 | 0 |
| forged_origin_path_hijack | 4 | 0 |
| subprefix_hijack | 4 | 0 |

## 5. Misclassified in-scope updates

| seq | scenario | prefix | origin | category | truth | predicted | score | reason |
|---|---|---|---|---|---|---|---|---|
| 52 | B10 | 199.83.128.0/24 | AS62571 | anycast_unwatched | benign | uncertain | 0.4 | no distinguishing evidence either way |
| 53 | B10 | 199.83.128.0/24 | AS19551 | anycast_unwatched | benign | uncertain | 0.4 | no distinguishing evidence either way |
| 54 | B10 | 199.83.128.0/24 | AS62571 | anycast_unwatched | benign | uncertain | 0.4 | no distinguishing evidence either way |
| 55 | B10 | 199.83.128.0/24 | AS19551 | anycast_unwatched | benign | uncertain | 0.4 | no distinguishing evidence either way |
| 56 | B10 | 199.83.128.0/24 | AS62571 | anycast_unwatched | benign | uncertain | 0.4 | no distinguishing evidence either way |
| 74 | A04a | 102.130.48.0/24 | AS328608 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 75 | A04a | 102.130.48.0/24 | AS328608 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 76 | A04a | 102.130.48.0/24 | AS328608 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 78 | A04a | 102.130.48.0/24 | AS328608 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 118 | A04b | 41.75.112.0/24 | AS199524 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 119 | A04b | 41.75.112.0/24 | AS199524 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 120 | A04b | 41.75.112.0/24 | AS199524 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 121 | A04b | 41.75.112.0/24 | AS199524 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 140 | B09 | 45.223.10.0/24 | AS32787 | ddos_scrubbing_diversion | benign | anomalous | 0.8 | origin(s) AS32787 not authorised for this watched prefix |
| 141 | B09 | 45.223.10.0/24 | AS32787 | ddos_scrubbing_diversion | benign | anomalous | 0.8 | origin(s) AS32787 not authorised for this watched prefix |
| 142 | B09 | 45.223.10.0/24 | AS32787 | ddos_scrubbing_diversion | benign | anomalous | 0.8 | origin(s) AS32787 not authorised for this watched prefix |
| 144 | B09 | 45.223.10.0/24 | AS32787 | ddos_scrubbing_diversion | benign | anomalous | 0.8 | origin(s) AS32787 not authorised for this watched prefix |
| 160 | A04c | 196.49.4.0/24 | AS263702 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 163 | A04c | 196.49.4.0/24 | AS263702 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 164 | A04c | 196.49.4.0/24 | AS263702 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 165 | A04c | 196.49.4.0/24 | AS263702 | exact_hijack_unwatched | anomalous | uncertain | 0.4 | no distinguishing evidence either way |
| 170 | B11 | 23.192.0.0/24 | AS16625 | sibling_origins_unwatched | benign | uncertain | 0.4 | no distinguishing evidence either way |
| 171 | B11 | 23.192.0.0/24 | AS20940 | sibling_origins_unwatched | benign | uncertain | 0.4 | no distinguishing evidence either way |
| 172 | B11 | 23.192.0.0/24 | AS16625 | sibling_origins_unwatched | benign | uncertain | 0.4 | no distinguishing evidence either way |
| 173 | B11 | 23.192.0.0/24 | AS20940 | sibling_origins_unwatched | benign | uncertain | 0.4 | no distinguishing evidence either way |
| 174 | A11 | 46.19.36.0/24 | AS211398 | hijack_forged_adjacency | anomalous | benign | 0.25 | origin AS39351 / AS211398 are in an upstream relation (often benign) |
| 175 | B11 | 23.192.0.0/24 | AS16625 | sibling_origins_unwatched | benign | uncertain | 0.4 | no distinguishing evidence either way |
| 176 | A11 | 46.19.36.0/24 | AS211398 | hijack_forged_adjacency | anomalous | benign | 0.25 | origin AS39351 / AS211398 are in an upstream relation (often benign) |
| 177 | A11 | 46.19.36.0/24 | AS211398 | hijack_forged_adjacency | anomalous | benign | 0.25 | origin AS39351 / AS211398 are in an upstream relation (often benign) |
| 178 | A11 | 46.19.36.0/24 | AS211398 | hijack_forged_adjacency | anomalous | benign | 0.25 | origin AS39351 / AS211398 are in an upstream relation (often benign) |

## Notes

- Label semantics: the decision the monitor should hold for the update's prefix right after the update (see `evaluation/make_dataset.py`). Accuracy counts `uncertain` as wrong; precision/recall count it as an alert.
- The AI layer is called right after each catalog change. In deployment `ai_layer.py --watch` polls every `--interval` seconds (default 5), which adds up to that interval to every triggering decision.
- Offline replays the file as fast as possible in one process, so its latency is pure processing time.
