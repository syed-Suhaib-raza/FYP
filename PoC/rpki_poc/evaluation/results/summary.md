# RPKI Invalid PoC: evaluation summary

Deterministic PoC: `full` is the chosen design and should be exact; the other configs are ablations. Latency in milliseconds.

| run | config | lines | checks | accuracy | precision | recall | F1 | FPR | state correct | severity correct | ROA changes (medium) | episodes detected | decision p50 | decision p95 | network p50 | end-to-end p50 | end-to-end p95 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| offline | full | 200 | 206 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 204/204 | 38/38 | 2 | 13/13 | 0.248 | 3.038 | - | - | - |
| offline | no-revalidation | 200 | 206 | 0.98 | 0.972 | 0.921 | 0.946 | 0.006 | 204/204 | 35/35 | 2 | 12/13 | 0.593 | 3.932 | - | - | - |
| offline | min-peers-1 | 200 | 206 | 0.926 | 0.717 | 1.0 | 0.835 | 0.09 | 204/204 | 38/38 | 2 | 13/13 | 0.265 | 3.599 | - | - | - |
| online | full | 200 | 206 | 1.0 | 1.0 | 1.0 | 1.0 | 0.0 | 204/204 | 38/38 | 2 | 13/13 | 0.383 | 2.549 | 5221.7 | 5222.6 | 96462.1 |

Online feed delay model: online/full: trace of 11401 measured delays (median 4194 ms, p95 102411 ms) from the RIS Live probe
