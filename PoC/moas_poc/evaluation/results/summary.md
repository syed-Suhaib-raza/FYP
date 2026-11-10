# MOAS PoC: evaluation summary

Latency in milliseconds. Accuracy counts `uncertain` as wrong; precision/recall count it as an alert.

| run | backend | updates | accuracy | precision | recall | F1 | FPR | uncertain | episodes detected | decision p50 | decision p95 | decision p95 (triggering) | network p50 | end-to-end p50 | end-to-end p95 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| offline | baseline | 202 | 0.845 | 0.763 | 0.918 | 0.833 | 0.097 | 22 | 9/13 | 0.003 | 0.444 | 0.667 | - | - | - |
| online | baseline | 202 | 0.845 | 0.763 | 0.918 | 0.833 | 0.097 | 22 | 9/13 | 0.067 | 1.691 | 3.279 | 17685.2 | 17687.0 | 30405.0 |

Online feed delay model per run: online/baseline: trace of 15565 measured delays (median 17674 ms, p95 30413 ms) from the RIS Live probe

