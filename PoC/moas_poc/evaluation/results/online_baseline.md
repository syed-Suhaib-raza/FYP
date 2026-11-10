# MOAS PoC evaluation: online (backend: baseline)

- run: 2026-11-10 14:45:41 UTC on Suhaibs-Macbook.local (Darwin arm64, Python 3.13.1)
- dataset: `evaluation/labelled_updates.jsonl`: 202 updates, 39 scenarios (144 benign, 49 anomalous in scope, 9 anomalous out of scope); synthetic, labels by construction
- whitelist: `evaluation/eval_whitelist.json`, catalog window 3600 s
- wall time for the whole stream: 42.68 s
- transport: websocket, RIS Live protocol, built-in feed server ws://127.0.0.1:57792; send rate 20.0 msg/s
- feed delay model: trace of 15565 measured delays (median 17674 ms, p95 30413 ms) from the RIS Live probe
- real RIS Live probe: 62370 messages in 60 s from rrc00; 15565 usable delay samples (median 17.67 s, p95 30.41 s); 46805 messages with timestamps older than 120 s (median 12.5 days: collector replay / table re-send) excluded; NOTE: the feed itself was lagging during the probe (burst on the collector or limited bandwidth)
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
| as_trans_origin | anomalous | 2 | 2 | 1.00 | {"anomalous": 2} | 0.840 |
| bogon_moas | anomalous | 3 | 3 | 1.00 | {"anomalous": 3} | 0.613 |
| exact_hijack_unwatched | anomalous | 12 | 0 | 0.00 | {"uncertain": 12} | 0.480 |
| exact_hijack_watched | anomalous | 13 | 13 | 1.00 | {"anomalous": 13} | 0.573 |
| exact_hijack_watched_private_asn | anomalous | 4 | 4 | 1.00 | {"anomalous": 4} | 0.373 |
| hijack_forged_adjacency | anomalous | 4 | 0 | 0.00 | {"benign": 4} | 0.464 |
| legit_origin_during_hijack | anomalous | 2 | 2 | 1.00 | {"anomalous": 2} | 0.056 |
| origin_added_to_planned_moas | anomalous | 3 | 3 | 1.00 | {"anomalous": 3} | 0.664 |
| private_asn_origin | anomalous | 6 | 6 | 1.00 | {"anomalous": 6} | 0.636 |
| after_hijack_aged_out | benign | 1 | 1 | 1.00 | {"benign": 1} | 1.294 |
| anycast_unwatched | benign | 6 | 1 | 0.17 | {"benign": 1, "uncertain": 5} | 0.219 |
| as_set_aggregate | benign | 4 | 4 | 1.00 | {"benign": 4} | 0.082 |
| ddos_scrubbing_diversion | benign | 4 | 0 | 0.00 | {"anomalous": 4} | 0.533 |
| moas_ended | benign | 1 | 1 | 1.00 | {"benign": 1} | 1.661 |
| origin_change_no_overlap | benign | 4 | 4 | 1.00 | {"benign": 4} | 0.064 |
| planned_multi_origin | benign | 8 | 8 | 1.00 | {"benign": 8} | 0.322 |
| planned_origin_migration | benign | 6 | 6 | 1.00 | {"benign": 6} | 0.319 |
| provider_aggregation | benign | 16 | 16 | 1.00 | {"benign": 16} | 0.489 |
| sibling_origins_unwatched | benign | 6 | 1 | 0.17 | {"benign": 1, "uncertain": 5} | 0.344 |
| steady_single_origin | benign | 43 | 43 | 1.00 | {"benign": 43} | 0.060 |
| steady_single_origin_unwatched | benign | 45 | 45 | 1.00 | {"benign": 45} | 0.056 |

## 2. Time to decision

Processing per update (catalog + AI layer). *Triggering* updates are those that opened, changed or closed a MOAS event and therefore caused an AI-layer verdict; every other update is decided by the catalog alone.

All values in milliseconds.

| stage | n | mean | p50 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| catalog (layer 1), all updates | 202 | 0.147 | 0.065 | 0.642 | 0.828 | 1.013 | 1.176 |
| AI layer (layer 2), triggering updates | 23 | 1.005 | 0.868 | 1.006 | 2.234 | 3.043 | 3.233 |
| decision, all updates | 202 | 0.262 | 0.067 | 1.317 | 1.691 | 2.105 | 4.017 |
| decision, triggering updates | 23 | 1.829 | 1.689 | 2.065 | 3.279 | 3.883 | 4.017 |
| decision, non-triggering updates | 179 | 0.061 | 0.064 | 0.078 | 0.084 | 0.096 | 0.108 |
| feed delay incl. sender scheduling (emit -> sent) | 202 | 18055.2 | 17685.2 | 28917.1 | 30403.9 | 32105.9 | 32470.6 |
| socket + queueing (sent -> read) | 202 | 0.820 | 0.861 | 1.042 | 1.054 | 1.081 | 1.359 |
| end-to-end (emit -> decision), all | 202 | 18056.3 | 17687.0 | 28918.1 | 30405.0 | 32108.4 | 32471.7 |
| end-to-end (emit -> decision), triggering | 23 | 18713.9 | 18005.3 | 28579.6 | 29502.3 | 31553.3 | 32108.6 |

## 3. Detection of anomalous episodes

From the first anomalous update of a scenario to the first update whose decision is `anomalous`. BGP time is measured on the update timestamps (0 = caught on the first anomalous update); wall time is ingest of that first update to the decision (online: from its emit time).

| scenario | prefix | category | difficulty | detected | flagged (anomalous or uncertain) | updates until detection | BGP time (s) | wall time (ms) |
|---|---|---|---|---|---|---|---|---|
| A01 | 1.1.1.0/24 | exact_hijack_watched | easy | yes | yes | 1 | 0 | 8859.6 |
| A02 | 8.8.8.0/24 | exact_hijack_watched_private_asn | easy | yes | yes | 1 | 0 | 11401.6 |
| A03 | 66.167.90.0/24 | exact_hijack_watched | easy | yes | yes | 1 | 0 | 10495.7 |
| A04a | 102.130.48.0/24 | exact_hijack_unwatched | hard | NO | yes | - | - | - |
| A04b | 41.75.112.0/24 | exact_hijack_unwatched | hard | NO | yes | - | - | - |
| A04c | 196.49.4.0/24 | exact_hijack_unwatched | hard | NO | yes | - | - | - |
| A05a | 103.21.244.0/24 | private_asn_origin | easy | yes | yes | 1 | 0 | 15376.9 |
| A05b | 180.92.160.0/24 | private_asn_origin | easy | yes | yes | 1 | 0 | 26088.5 |
| A06 | 202.69.160.0/24 | as_trans_origin | easy | yes | yes | 1 | 0 | 18005.3 |
| A07 | 100.64.12.0/24 | bogon_moas | easy | yes | yes | 1 | 0 | 20277.0 |
| A10 | 104.16.0.0/24 | origin_added_to_planned_moas | easy | yes | yes | 1 | 0 | 12828.2 |
| A11 | 46.19.36.0/24 | hijack_forged_adjacency | hard | NO | no | - | - | - |
| A13 | 45.223.12.0/24 | exact_hijack_watched | easy | yes | yes | 1 | 0 | 29584.5 |

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
- Online streams the same updates through a websocket in RIS Live format, with the feed server on its own thread so it keeps sending on schedule while the PoC is busy (queueing shows up in `sent -> read`).

## 6. Real RIS Live traffic (unlabelled, timing only)

20000 real messages (333.3 msg/s observed); 17 triggered an AI verdict; processing used 0.16% of the wall time, i.e. the PoC keeps up with this feed: yes.

| stage | n | mean | p50 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| RIS Live feed delay (arrival - collector timestamp) | 15565 | 18117.1 | 17674.4 | 29352.0 | 30412.6 | 32462.8 | 33487.8 |
| websocket round trip to RIS Live | 5 | 79.7 | 77.8 | 85.5 | 88.1 | 90.2 | 90.7 |
| decision, all real updates | 20000 | 0.005 | 0.003 | 0.006 | 0.010 | 0.037 | 1.072 |
| decision, triggering real updates | 17 | 0.363 | 0.281 | 0.546 | 0.656 | 0.989 | 1.072 |

