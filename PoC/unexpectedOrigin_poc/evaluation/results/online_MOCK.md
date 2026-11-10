# Unexpected Origin PoC evaluation: online (model: MOCK)

> **MOCK model.** `llm.MockLLM` is a string-matching stand-in, not RouteLLM. The *pipeline* numbers below test the evaluation and the plumbing only; model accuracy and model latency must come from a run without `--mock` on the GPU machine.

- run: 2026-11-10 14:47:40 UTC on Suhaibs-Macbook.local (Darwin arm64, Python 3.13.1)
- dataset: `evaluation/labelled_updates.jsonl`: 200 updates (132 benign, 60 anomalous in scope, 8 anomalous out of scope); synthetic, labels by construction
- whitelist `evaluation/eval_whitelist.json`, AS relationships `evaluation/eval_asrel.txt`, cooldown 600 s, ownership evidence on, top-k 8
- model load time (excluded from latency): 0.00 s; warm-up calls: 1
- wall time for the whole stream: 41.13 s
- transport: websocket, RIS Live protocol, built-in feed server ws://127.0.0.1:57798; send rate 20.0 msg/s
- feed delay model: trace of 19729 measured delays (median 16481 ms, p95 28709 ms) from the RIS Live probe
- real RIS Live probe: 68932 messages in 60 s from rrc00; 19729 usable delay samples (median 16.48 s, p95 28.71 s); 49203 messages with timestamps older than 120 s (median 12.5 days: collector replay / table re-send) excluded; NOTE: the feed itself was lagging during the probe (burst on the collector or limited bandwidth)

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
| exact_hijack_unrelated | anomalous | 15 | 15 | 1.00 | {"anomalous": 15} | 3.023 |
| hijack_by_related_as | anomalous | 10 | 10 | 1.00 | {"anomalous": 10} | 2.608 |
| hijack_repeat_in_cooldown | anomalous | 12 | 12 | 1.00 | {"anomalous": 12} | 0.176 |
| private_asn_origin | anomalous | 5 | 5 | 1.00 | {"anomalous": 5} | 3.068 |
| subprefix_hijack_unrelated | anomalous | 18 | 18 | 1.00 | {"anomalous": 18} | 2.891 |
| as_set_origin | benign | 4 | 4 | 1.00 | {"benign": 4} | 0.004 |
| ddos_scrubbing_diversion | benign | 5 | 0 | 0.00 | {"anomalous": 5} | 2.794 |
| expected_origin_exact | benign | 50 | 50 | 1.00 | {"benign": 50} | 0.165 |
| expected_origin_more_specific | benign | 15 | 15 | 1.00 | {"benign": 15} | 0.170 |
| legit_customer_exact | benign | 6 | 0 | 0.00 | {"anomalous": 6} | 2.550 |
| legit_customer_more_specific | benign | 10 | 0 | 0.00 | {"anomalous": 10} | 2.963 |
| legit_customer_of_customer_more_specific | benign | 6 | 0 | 0.00 | {"anomalous": 6} | 3.299 |
| legit_customer_repeat_in_cooldown | benign | 7 | 0 | 0.00 | {"anomalous": 7} | 0.160 |
| legit_sibling_exact | benign | 4 | 4 | 1.00 | {"benign": 4} | 2.539 |
| unwatched_prefix | benign | 25 | 25 | 1.00 | {"benign": 25} | 0.268 |

## 2. Time to decision

*Triggering* updates are candidates that went to the model; every other update is decided by the candidate filter alone (including repeats suppressed by the cooldown).

All values in milliseconds.

| stage | n | mean | p50 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| candidate filter, all updates | 200 | 0.191 | 0.185 | 0.257 | 0.264 | 0.279 | 3.139 |
| model generate (rounded to 10 ms by classify), triggering | 76 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| classify + store, triggering | 76 | 2.778 | 2.782 | 3.287 | 3.366 | 3.937 | 4.888 |
| decision, all updates | 200 | 1.248 | 0.198 | 3.247 | 3.517 | 3.725 | 5.084 |
| decision, triggering updates | 76 | 2.988 | 2.983 | 3.544 | 3.627 | 4.192 | 5.084 |
| decision, non-triggering updates | 124 | 0.181 | 0.175 | 0.207 | 0.220 | 0.240 | 3.140 |
| feed delay incl. sender scheduling (emit -> sent) | 200 | 16772.0 | 16471.2 | 25848.5 | 28617.9 | 29768.0 | 30973.7 |
| socket + queueing (sent -> read) | 200 | 0.858 | 0.900 | 1.036 | 1.089 | 1.430 | 3.190 |
| end-to-end (emit -> decision), all | 200 | 16774.1 | 16472.8 | 25849.7 | 28619.2 | 29768.5 | 30975.3 |
| end-to-end (emit -> decision), triggering | 76 | 16751.6 | 16240.0 | 26297.4 | 27967.2 | 29344.4 | 30144.2 |

## 3. Detection of hijack episodes

An episode is one hijack announcement plus its repeats from other vantage points. Wall time runs from the first anomalous update's emit to the first `anomalous` decision.

| episode | prefix | origin | category | difficulty | rule alerted | pipeline detected | updates until detection | wall time (ms) |
|---|---|---|---|---|---|---|---|---|
| H126 | 45.223.8.0/22 | AS136907 | exact_hijack_unrelated | easy | yes | yes | 1 | 8289.2 |
| H127 | 45.223.8.0/22 | AS58224 | exact_hijack_unrelated | easy | yes | yes | 1 | 11916.4 |
| H128 | 104.16.0.0/22 | AS47065 | exact_hijack_unrelated | easy | yes | yes | 1 | 19019.6 |
| H129 | 66.167.90.0/24 | AS140224 | exact_hijack_unrelated | easy | yes | yes | 1 | 19144.3 |
| H130 | 45.223.8.0/22 | AS58224 | exact_hijack_unrelated | easy | yes | yes | 1 | 8269.4 |
| H131 | 104.16.0.0/22 | AS207656 | exact_hijack_unrelated | easy | yes | yes | 1 | 25191.1 |
| H132 | 104.16.0.0/22 | AS263702 | exact_hijack_unrelated | easy | yes | yes | 1 | 4361.7 |
| H133 | 1.1.1.0/24 | AS136907 | exact_hijack_unrelated | easy | yes | yes | 1 | 13938.3 |
| H134 | 45.223.8.0/22 | AS9009 | exact_hijack_unrelated | easy | yes | yes | 1 | 11540.4 |
| H135 | 1.1.1.0/24 | AS211398 | exact_hijack_unrelated | easy | yes | yes | 1 | 25512.9 |
| H136 | 8.8.8.0/24 | AS47065 | exact_hijack_unrelated | easy | yes | yes | 1 | 3159.1 |
| H137 | 45.223.8.0/22 | AS328608 | exact_hijack_unrelated | easy | yes | yes | 1 | 12218.9 |
| H138 | 66.167.90.0/24 | AS263702 | exact_hijack_unrelated | easy | yes | yes | 1 | 19769.3 |
| H139 | 8.8.8.0/24 | AS9009 | exact_hijack_unrelated | easy | yes | yes | 1 | 26473.1 |
| H140 | 8.8.8.0/24 | AS328608 | exact_hijack_unrelated | easy | yes | yes | 1 | 14934.0 |
| H141 | 104.16.2.0/24 | AS45090 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 5597.2 |
| H142 | 45.223.10.0/23 | AS207656 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 3201.5 |
| H143 | 45.223.8.0/23 | AS328608 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 26388.9 |
| H144 | 8.8.8.0/25 | AS136907 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 22110.8 |
| H145 | 45.223.10.0/23 | AS140224 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 23815.9 |
| H146 | 104.16.0.0/24 | AS263702 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 28714.4 |
| H147 | 66.167.90.128/25 | AS140224 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 21519.1 |
| H148 | 66.167.90.128/25 | AS58224 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 12177.3 |
| H149 | 45.223.9.0/24 | AS47065 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 24727.0 |
| H150 | 8.8.8.128/25 | AS199524 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 5153.0 |
| H151 | 45.223.10.0/24 | AS9009 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 14999.6 |
| H152 | 8.8.8.0/25 | AS263702 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 23508.7 |
| H153 | 104.16.0.0/24 | AS328608 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 25166.6 |
| H154 | 1.1.1.128/25 | AS9009 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 26205.8 |
| H155 | 45.223.11.0/24 | AS263702 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 23571.9 |
| H156 | 1.1.1.0/25 | AS9009 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 19932.0 |
| H157 | 104.16.2.0/23 | AS45090 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 19234.8 |
| H158 | 104.16.0.0/23 | AS51088 | subprefix_hijack_unrelated | easy | yes | yes | 1 | 11781.1 |
| H159 | 104.16.2.0/23 | AS1299 | hijack_by_related_as | hard | yes | yes | 1 | 27564.6 |
| H160 | 66.167.90.0/24 | AS1299 | hijack_by_related_as | hard | yes | yes | 1 | 5445.4 |
| H161 | 104.16.1.0/24 | AS174 | hijack_by_related_as | hard | yes | yes | 1 | 7206.2 |
| H162 | 66.167.90.128/25 | AS174 | hijack_by_related_as | hard | yes | yes | 1 | 21553.7 |
| H163 | 1.1.1.0/24 | AS174 | hijack_by_related_as | hard | yes | yes | 1 | 21084.2 |
| H164 | 1.1.1.0/24 | AS174 | hijack_by_related_as | hard | yes | yes | 1 | 19263.6 |
| H165 | 45.223.8.0/22 | AS3491 | hijack_by_related_as | hard | yes | yes | 1 | 21738.1 |
| H166 | 8.8.8.0/24 | AS6939 | hijack_by_related_as | hard | yes | yes | 1 | 15103.0 |
| H167 | 1.1.1.128/25 | AS174 | hijack_by_related_as | hard | yes | yes | 1 | 29077.8 |
| H168 | 45.223.8.0/22 | AS3491 | hijack_by_related_as | hard | yes | yes | 1 | 15941.9 |
| H169 | 66.167.90.0/25 | AS65530 | private_asn_origin | easy | yes | yes | 1 | 27718.1 |
| H170 | 8.8.8.0/25 | AS64512 | private_asn_origin | easy | yes | yes | 1 | 24302.0 |
| H171 | 45.223.11.0/24 | AS64512 | private_asn_origin | easy | yes | yes | 1 | 15262.6 |
| H172 | 66.167.90.0/24 | AS64512 | private_asn_origin | easy | yes | yes | 1 | 21222.1 |
| H173 | 66.167.90.0/24 | AS64512 | private_asn_origin | easy | yes | yes | 1 | 23988.3 |

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
- Online streams the same updates over a websocket in RIS Live format. The feed server runs on its own thread, so while a slow model call blocks the PoC, later updates queue up (visible in `sent -> read` and end-to-end).

## 6. Real RIS Live traffic (unlabelled, timing only)

20000 real messages (333.3 msg/s); 0 were candidates for the watched prefixes; processing used 0.36% of the wall time.

| stage | n | mean | p50 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| RIS Live feed delay (arrival - collector timestamp) | 19729 | 16938.7 | 16480.9 | 26400.8 | 28708.6 | 30241.1 | 31101.1 |
| websocket round trip to RIS Live | 5 | 78.1 | 76.2 | 82.4 | 83.6 | 84.5 | 84.7 |
| decision, all real updates | 20000 | 0.011 | 0.006 | 0.017 | 0.030 | 0.066 | 1.915 |
| decision, triggering real updates | 0 | - | - | - | - | - | - |

