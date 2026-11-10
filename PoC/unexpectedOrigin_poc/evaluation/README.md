# Unexpected Origin PoC: latency + accuracy evaluation

Measures, for every update in a labelled stream, **how quickly the PoC reaches a decision** and **whether it is correct**
(anomalous or not, plus the anomaly type), offline (in-process replay) and online (over a websocket, with network/feed
latency). It sits next to `../eval.py`, which compares the model against baselines on independent cases. This one runs
the deployed stream path (`detector.OriginCandidates` with cooldown -> `pipeline.classify` -> SQLite) and times it.

| File | Purpose |
|---|---|
| `make_dataset.py` | Generates the labelled stream, whitelist and AS-relationship file (seeded, reproducible). |
| `labelled_updates.jsonl` | 200 RIS-Live-format updates: 132 benign, 60 anomalous in scope, 8 anomalous out of scope. Each line has a `truth` block (`label`, `type`, `category`, ...). |
| `eval_whitelist.json` | Watched prefixes + expected origins (superset of `../whitelist.json`). |
| `eval_asrel.txt` | Synthetic CAIDA-format relationships that make the labels true; the model's evidence comes from it. |
| `evaluate.py` | The evaluator (`--mode offline` / `--mode online`). |
| `netfeed.py`, `feed_server.py`, `evalcore.py` | Online plumbing and metrics (same as in the MOAS PoC). |
| `test_evaluation.py` | Tests (run with `python -m pytest -q`). |
| `results/` | `<mode>_<model>.md/.json/.csv` per run, `summary.md` across runs. |

## Run (from the `unexpectedOrigin_poc` folder)

    python evaluation/evaluate.py --mode offline --mock       # anywhere, no GPU (plumbing only)
    python evaluation/evaluate.py --mode online --mock
    python evaluation/evaluate.py --mode offline              # real RouteLLM on the CUDA machine (4-bit default)
    python evaluation/evaluate.py --mode online               # real RouteLLM + RIS Live probe

Model options are the PoC's own: `--base-model`, `--adapter`, `--quant`, `--top-k`, `--cooldown`, `--only-exact`,
`--no-ownership-evidence`. Model load time is excluded and `--warmup 1` makes one untimed call first.

## Decisions compared per update
- **rule only**: every candidate (watched prefix or more-specific, origin not expected) is an alert.
- **rule + B2**: a candidate is an alert only if its origin has no direct relationship with an expected origin.
- **PoC pipeline** (headline): model label is an anomaly -> `anomalous` (severity high); `none` -> `benign` (severity
  medium); unparsed/unknown -> `uncertain`. Predicted type = `pipeline.anomaly_type` when anomalous, else `none`.
A repeat that the detector suppresses (same prefix+origin inside `--cooldown`) keeps the earlier decision, as the
deployed system does. Accuracy counts `uncertain` as wrong; precision/recall count it as an alert.

Ground-truth categories: expected origin (exact and traffic-engineering more-specific), unwatched prefixes, AS_SET
aggregates, legitimate customer / sibling / customer-of-customer originations, DDoS-scrubbing diversion, cooldown
repeats (benign); unrelated exact and sub-prefix hijacks, hijacks by a peer/provider of the victim, private-ASN origins,
cooldown repeats (anomalous). Forged-origin path hijacks and route leaks keep the correct origin, so they are `in_scope:
false` and reported separately.

## Latency fields
`detector_ms` candidate filter; `model_ms` classify (evidence + model + parse) + SQLite write; `llm_ms` model generate
time as recorded by `pipeline.classify` (rounded to 10 ms); `decision_ms` total. Online adds `network_ms` (emit -> sent),
`queue_ms` (sent -> read, which includes waiting behind slow model calls) and `e2e_ms` (emit -> decision).

## Online mode
Same design as the MOAS evaluation (see `../../moas_poc/evaluation/README.md`): a probe of real RIS Live measures feed
delay and websocket RTT and times the PoC on real (unlabelled) traffic. The labelled stream is then served over a
websocket in RIS Live format with those measured delays. Same-prefix order is kept, and the server runs on its own
thread, so slow model calls build up a real backlog. RouteLLM takes seconds per call, so at `--rate 20` the backlog
dominates end-to-end latency; lower `--rate` to see the latency of an idle system. `--feed-url ws://<host>:8765` together
with `feed_server.py` on another machine adds a real network hop.

## Caveats
- `--mock` numbers are not results: `MockLLM` says `none` only when the evidence contains "are siblings".
- Labels assume `eval_asrel.txt`. With `--asrel <real CAIDA file>` the evidence changes but the labels do not.
- Synthetic stream; ASNs/prefixes are placeholders with fictional roles.
