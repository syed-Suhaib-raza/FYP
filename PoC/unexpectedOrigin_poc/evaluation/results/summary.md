# Unexpected Origin PoC: evaluation summary

PoC pipeline decisions (rule + model). Latency in milliseconds. MOCK rows test the plumbing only, not RouteLLM.

| run | model | updates | accuracy | precision | recall | F1 | FPR | uncertain | type accuracy | episodes detected | decision p50 | decision p95 (triggering) | network p50 | end-to-end p50 | end-to-end p95 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| offline | MOCK | 200 | 0.823 | 0.638 | 1.0 | 0.779 | 0.258 | 0 | 0.823 | 48/48 | 0.010 | 0.602 | - | - | - |
| online | MOCK | 200 | 0.823 | 0.638 | 1.0 | 0.779 | 0.258 | 0 | 0.823 | 48/48 | 0.198 | 3.627 | 16471.2 | 16472.8 | 28619.2 |

Reference (same updates, no model): rule only accuracy 0.802, precision 0.612, recall 1.0; rule + B2 accuracy 0.875, precision 0.81, recall 0.783.

Online feed delay model per run: online/MOCK: trace of 19729 measured delays (median 16481 ms, p95 28709 ms) from the RIS Live probe

