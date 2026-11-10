# Unexpected Origin PoC evaluation: offline (model: MOCK)

> **MOCK model.** `llm.MockLLM` is a string-matching stand-in, not RouteLLM. The *pipeline* numbers below test the evaluation and the plumbing only; model accuracy and model latency must come from a run without `--mock` on the GPU machine.

- run: 2026-11-10 14:47:40 UTC on Suhaibs-Macbook.local (Darwin arm64, Python 3.13.1)
- dataset: `evaluation/labelled_updates.jsonl`: 200 updates (132 benign, 60 anomalous in scope, 8 anomalous out of scope); synthetic, labels by construction
- whitelist `evaluation/eval_whitelist.json`, AS relationships `evaluation/eval_asrel.txt`, cooldown 600 s, ownership evidence on, top-k 8
- model load time (excluded from latency): 0.00 s; warm-up calls: 1
- wall time for the whole stream: 0.03 s

## 1. Classification (in-scope updates)

| metric | rule only (candidate = alert) | rule + B2 (no CAIDA relationship) | **PoC pipeline (rule + model)** |
|---|---|---|---|
| updates | 192 | 192 | **192** |
| accuracy (uncertain = wrong) | 0.802 | 0.875 | **0.823** |
| uncertain | 0 | 0 | **0** |
| precision | 0.612 | 0.81 | **0.638** |
| recall | 1.0 | 0.783 | **1.0** |
| F1 | 0.759 | 0.797 | **0.779** |
| false-positive rate | 0.288 | 0.083 | **0.258** |
| TP | 60 | 47 | **60** |
| FP | 38 | 11 | **34** |
| FN | 0 | 13 | **0** |
| TN | 94 | 121 | **98** |

PoC pipeline confusion:

| truth \ predicted | anomalous | benign |
|---|---|---|
| anomalous | 60 | 0 |
| benign | 34 | 98 |

### Anomaly type (PoC pipeline)

| truth type \ predicted | unexpected_origin | unexpected_deaggregation | none |
|---|---|---|---|
| unexpected_origin | 30 | 0 | 0 |
| unexpected_deaggregation | 0 | 30 | 0 |
| none | 6 | 28 | 98 |

Type accuracy (benign = none): 158/192 = 0.823

### By category (PoC pipeline)

| category | truth | n | correct | accuracy | predicted | mean decision latency (ms) |
|---|---|---|---|---|---|---|
| exact_hijack_unrelated | anomalous | 15 | 15 | 1.00 | {"anomalous": 15} | 0.407 |
| hijack_by_related_as | anomalous | 10 | 10 | 1.00 | {"anomalous": 10} | 0.348 |
| hijack_repeat_in_cooldown | anomalous | 12 | 12 | 1.00 | {"anomalous": 12} | 0.009 |
| private_asn_origin | anomalous | 5 | 5 | 1.00 | {"anomalous": 5} | 0.345 |
| subprefix_hijack_unrelated | anomalous | 18 | 18 | 1.00 | {"anomalous": 18} | 0.373 |
| as_set_origin | benign | 4 | 4 | 1.00 | {"benign": 4} | 0.000 |
| ddos_scrubbing_diversion | benign | 5 | 0 | 0.00 | {"anomalous": 5} | 0.335 |
| expected_origin_exact | benign | 50 | 50 | 1.00 | {"benign": 50} | 0.009 |
| expected_origin_more_specific | benign | 15 | 15 | 1.00 | {"benign": 15} | 0.009 |
| legit_customer_exact | benign | 6 | 0 | 0.00 | {"anomalous": 6} | 0.311 |
| legit_customer_more_specific | benign | 10 | 0 | 0.00 | {"anomalous": 10} | 0.463 |
| legit_customer_of_customer_more_specific | benign | 6 | 0 | 0.00 | {"anomalous": 6} | 0.351 |
| legit_customer_repeat_in_cooldown | benign | 7 | 0 | 0.00 | {"anomalous": 7} | 0.010 |
| legit_sibling_exact | benign | 4 | 4 | 1.00 | {"benign": 4} | 0.276 |
| unwatched_prefix | benign | 25 | 25 | 1.00 | {"benign": 25} | 0.009 |

## 2. Time to decision

*Triggering* updates are candidates that went to the model; every other update is decided by the candidate filter alone (including repeats suppressed by the cooldown).

All values in milliseconds.

| stage | n | mean | p50 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| candidate filter, all updates | 200 | 0.010 | 0.010 | 0.012 | 0.014 | 0.019 | 0.106 |
| model generate (rounded to 10 ms by classify), triggering | 76 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| classify + store, triggering | 76 | 0.374 | 0.338 | 0.449 | 0.592 | 0.868 | 1.514 |
| decision, all updates | 200 | 0.152 | 0.010 | 0.359 | 0.408 | 0.620 | 1.525 |
| decision, triggering updates | 76 | 0.385 | 0.349 | 0.462 | 0.602 | 0.880 | 1.525 |
| decision, non-triggering updates | 124 | 0.009 | 0.008 | 0.010 | 0.013 | 0.028 | 0.106 |

## 3. Detection of hijack episodes

An episode is one hijack announcement plus its repeats from other vantage points. Wall time runs from the first anomalous update's ingest to the first `anomalous` decision.

| episode | prefix | origin | category | difficulty | rule alerted | pipeline detected | updates until detection | wall time (ms) |
|---|---|---|---|---|---|---|---|---|
| H126 | 45.223.8.0/22 | AS136907 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.619 |
| H127 | 45.223.8.0/22 | AS58224 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.319 |
| H128 | 104.16.0.0/22 | AS47065 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.343 |
| H129 | 66.167.90.0/24 | AS140224 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.365 |
| H130 | 45.223.8.0/22 | AS58224 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.322 |
| H131 | 104.16.0.0/22 | AS207656 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.359 |
| H132 | 104.16.0.0/22 | AS263702 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.482 |
| H133 | 1.1.1.0/24 | AS136907 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.359 |
| H134 | 45.223.8.0/22 | AS9009 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.336 |
| H135 | 1.1.1.0/24 | AS211398 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.369 |
| H136 | 8.8.8.0/24 | AS47065 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.537 |
| H137 | 45.223.8.0/22 | AS328608 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.363 |
| H138 | 66.167.90.0/24 | AS263702 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.343 |
| H139 | 8.8.8.0/24 | AS9009 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.665 |
| H140 | 8.8.8.0/24 | AS328608 | exact_hijack_unrelated | easy | yes | yes | 1 | 0.326 |
| H141 | 104.16.2.0/24 | AS45090 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.359 |
| H142 | 45.223.10.0/23 | AS207656 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.440 |
| H143 | 45.223.8.0/23 | AS328608 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.348 |
| H144 | 8.8.8.0/25 | AS136907 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.349 |
| H145 | 45.223.10.0/23 | AS140224 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.346 |
| H146 | 104.16.0.0/24 | AS263702 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.345 |
| H147 | 66.167.90.128/25 | AS140224 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.342 |
| H148 | 66.167.90.128/25 | AS58224 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.330 |
| H149 | 45.223.9.0/24 | AS47065 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.617 |
| H150 | 8.8.8.128/25 | AS199524 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.354 |
| H151 | 45.223.10.0/24 | AS9009 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.324 |
| H152 | 8.8.8.0/25 | AS263702 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.343 |
| H153 | 104.16.0.0/24 | AS328608 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.359 |
| H154 | 1.1.1.128/25 | AS9009 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.352 |
| H155 | 45.223.11.0/24 | AS263702 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.342 |
| H156 | 1.1.1.0/25 | AS9009 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.374 |
| H157 | 104.16.2.0/23 | AS45090 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.442 |
| H158 | 104.16.0.0/23 | AS51088 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 0.347 |
| H159 | 104.16.2.0/23 | AS1299 | hijack_by_related_as | hard | yes | yes | 1 | 0.345 |
| H160 | 66.167.90.0/24 | AS1299 | hijack_by_related_as | hard | yes | yes | 1 | 0.335 |
| H161 | 104.16.1.0/24 | AS174 | hijack_by_related_as | hard | yes | yes | 1 | 0.329 |
| H162 | 66.167.90.128/25 | AS174 | hijack_by_related_as | hard | yes | yes | 1 | 0.332 |
| H163 | 1.1.1.0/24 | AS174 | hijack_by_related_as | hard | yes | yes | 1 | 0.008 |
| H164 | 1.1.1.0/24 | AS174 | hijack_by_related_as | hard | yes | yes | 1 | 0.506 |
| H165 | 45.223.8.0/22 | AS3491 | hijack_by_related_as | hard | yes | yes | 1 | 0.340 |
| H166 | 8.8.8.0/24 | AS6939 | hijack_by_related_as | hard | yes | yes | 1 | 0.597 |
| H167 | 1.1.1.128/25 | AS174 | hijack_by_related_as | hard | yes | yes | 1 | 0.374 |
| H168 | 45.223.8.0/22 | AS3491 | hijack_by_related_as | hard | yes | yes | 1 | 0.311 |
| H169 | 66.167.90.0/25 | AS65530 | private_asn_origin | easy | yes | yes | 1 | 0.342 |
| H170 | 8.8.8.0/25 | AS64512 | private_asn_origin | easy | yes | yes | 1 | 0.366 |
| H171 | 45.223.11.0/24 | AS64512 | private_asn_origin | easy | yes | yes | 1 | 0.323 |
| H172 | 66.167.90.0/24 | AS64512 | private_asn_origin | easy | yes | yes | 1 | 0.340 |
| H173 | 66.167.90.0/24 | AS64512 | private_asn_origin | easy | yes | yes | 1 | 0.353 |

Pipeline detected 48/48 episodes; the rule layer alerted on 48/48.

## 4. Out-of-scope anomalies (origin is the expected one, so no candidate)

| category | n | PoC said anomalous |
|---|---|---|
| forged_origin_path_hijack | 5 | 0 |
| route_leak_valid_origin | 3 | 0 |

## 5. Misclassified in-scope updates (PoC pipeline)

| seq | episode | prefix | origin | category | truth | predicted | model label | raw output |
|---|---|---|---|---|---|---|---|---|
| 11 | L106 | 104.16.0.0/23 | AS23002 | legit_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 12 | L096 | 45.223.8.0/22 | AS135520 | legit_customer_exact | benign | anomalous | prefix hijack | prefix hijack |
| 17 | L119 | 66.167.90.128/25 | AS31500 | legit_customer_of_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 20 | L109 | 1.1.1.0/25 | AS23001 | legit_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 40 | L102 | 66.167.90.128/25 | AS31042 | legit_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 42 | L105 | 66.167.90.0/25 | AS31042 | legit_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 43 | L102 | 66.167.90.128/25 | AS31042 | legit_customer_repeat_in_cooldown | benign | anomalous | prefix hijack | prefix hijack |
| 45 | L103 | 45.223.9.0/24 | AS136525 | legit_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 46 | L122 | 45.223.8.0/24 | AS32787 | ddos_scrubbing_diversion | benign | anomalous | prefix hijack | prefix hijack |
| 47 | L124 | 45.223.10.0/23 | AS32787 | ddos_scrubbing_diversion | benign | anomalous | prefix hijack | prefix hijack |
| 48 | L103 | 45.223.9.0/24 | AS136525 | legit_customer_repeat_in_cooldown | benign | anomalous | prefix hijack | prefix hijack |
| 49 | L105 | 66.167.90.0/25 | AS31042 | legit_customer_repeat_in_cooldown | benign | anomalous | prefix hijack | prefix hijack |
| 59 | L115 | 8.8.8.0/25 | AS26911 | legit_customer_of_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 61 | L099 | 66.167.90.0/24 | AS31042 | legit_customer_exact | benign | anomalous | prefix hijack | prefix hijack |
| 65 | L095 | 104.16.0.0/22 | AS23002 | legit_customer_exact | benign | anomalous | prefix hijack | prefix hijack |
| 74 | L125 | 45.223.8.0/24 | AS32787 | ddos_scrubbing_diversion | benign | anomalous | prefix hijack | prefix hijack |
| 77 | L123 | 45.223.8.0/23 | AS32787 | ddos_scrubbing_diversion | benign | anomalous | prefix hijack | prefix hijack |
| 87 | L120 | 1.1.1.128/25 | AS23101 | legit_customer_of_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 88 | L107 | 45.223.8.0/24 | AS135520 | legit_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 100 | L108 | 104.16.1.0/24 | AS23002 | legit_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 105 | L108 | 104.16.1.0/24 | AS23002 | legit_customer_repeat_in_cooldown | benign | anomalous | prefix hijack | prefix hijack |
| 107 | L117 | 45.223.10.0/24 | AS138000 | legit_customer_of_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 111 | L118 | 8.8.8.0/25 | AS26911 | legit_customer_of_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 137 | L121 | 45.223.11.0/24 | AS32787 | ddos_scrubbing_diversion | benign | anomalous | prefix hijack | prefix hijack |
| 142 | L101 | 45.223.8.0/23 | AS135520 | legit_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 149 | L101 | 45.223.8.0/23 | AS135520 | legit_customer_repeat_in_cooldown | benign | anomalous | prefix hijack | prefix hijack |
| 153 | L110 | 1.1.1.0/25 | AS23001 | legit_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 161 | L098 | 45.223.8.0/22 | AS135520 | legit_customer_exact | benign | anomalous | prefix hijack | prefix hijack |
| 162 | L110 | 1.1.1.0/25 | AS23001 | legit_customer_repeat_in_cooldown | benign | anomalous | prefix hijack | prefix hijack |
| 163 | L100 | 66.167.90.0/24 | AS31042 | legit_customer_exact | benign | anomalous | prefix hijack | prefix hijack |
| 164 | L097 | 45.223.8.0/22 | AS135520 | legit_customer_exact | benign | anomalous | prefix hijack | prefix hijack |
| 194 | L116 | 45.223.8.0/23 | AS138000 | legit_customer_of_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 198 | L104 | 8.8.8.0/25 | AS26910 | legit_customer_more_specific | benign | anomalous | prefix hijack | prefix hijack |
| 199 | L104 | 8.8.8.0/25 | AS26910 | legit_customer_repeat_in_cooldown | benign | anomalous | prefix hijack | prefix hijack |

Model label counts: {"none": 3, "prefix hijack": 73}

## Notes

- Labels are synthetic and true by construction for the relationships in `evaluation/eval_asrel.txt`; with a real CAIDA file the evidence changes but the labels do not, so keep the evaluation file for scoring.
- Accuracy counts `uncertain` as wrong; precision/recall count `uncertain` as an alert (it goes to an operator).
- Offline replays the stream as fast as possible in one process: latency = processing only. Model load time is excluded.
