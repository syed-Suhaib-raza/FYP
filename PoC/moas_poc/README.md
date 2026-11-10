# BGP MOAS Detection: FYP-I proof of concept (two layers)

Multiple Origin AS (MOAS) = one prefix announced with 2+ different origin ASes (last hop of the AS path).
Many MOAS events are benign (anycast, multi-homing), so detection is split in two:

| Layer | File | Job | Judges? |
|---|---|---|---|
| 1. Deterministic catalog | `moas.py` (+ `ris_live.py`, `replay.py`) | Record **every** instance of a prefix with multiple origins, with the evidence (who announced, who saw it, paths, timing). | No. No severity, no whitelist. |
| 2. AI layer | `ai_layer.py` | Read the catalog, flag the anomalous events. | Yes, writes verdicts. |

The layers only talk through the SQLite file, so either can be restarted or swapped on its own.

    RIS Live -> ris_live.py -> moas_events / moas_origins ->(poll)-> ai_layer.py -> verdicts -> dashboard.py

## Run
    pip install websockets streamlit pandas pytest
    python -m pytest -q                                              # unit tests (both layers)

    # offline demo, no internet
    python replay.py sample_updates.jsonl sample_updates_extra.jsonl --db demo.db
    python ai_layer.py --db demo.db --whitelist whitelist.json       # scores what was cataloged
    streamlit run dashboard.py -- --db demo.db

    # live
    python ris_live.py --whitelist whitelist.json                    # terminal 1: catalog (watches those prefixes)
    python ai_layer.py --whitelist whitelist.json --watch            # terminal 2: AI layer
    streamlit run dashboard.py                                       # terminal 3

`sample_updates_extra.jsonl` is synthetic: it adds a benign-looking upstream relation, an undecidable case and a
whitelist violation next to the original sample.

## Layer 1: catalog (`moas.py`)
An origin is *active* for `--window` seconds (default 3600) after it was last announced. When a prefix has 2+ active
origins an **event** opens; it closes when fewer than 2 remain. Tables:
- `moas_events`: id, prefix, first_seen, last_seen, status (open/closed), revision, origins.
  `revision` rises when a new origin joins and when the event closes, so layer 2 knows when to re-score.
- `moas_origins`: per (event, origin): first/last seen, update count, peer ASNs, collectors, up to 5 distinct AS paths.

The whitelist no longer influences the catalog; `ris_live.py` only uses it to choose which prefixes to subscribe to.
The old single-layer version (with severity) is kept in `_single_layer_backup/`.

## Layer 2: AI layer (`ai_layer.py`)
Builds a feature context per event (prefix facts, per-origin peer/collector counts and timing, special-purpose ASNs,
upstream relations between origins, and the whitelist as *prior knowledge*), then asks a backend for a verdict
`anomalous | benign | uncertain` + score + reason. Each (event, revision, backend) is scored once, so new origins and
closures trigger a re-score. A backend that errors (e.g. model server down) is retried on the next pass.

- `--backend baseline` (default): transparent additive rules. **Not a model**; weights in `WEIGHTS` are untuned placeholders.
  It is the reference to compare the model against.
- `--backend llm --llm-model NAME [--llm-url http://localhost:11434/v1]`: any OpenAI-compatible chat endpoint (Ollama,
  llama.cpp server, vLLM). `SYSTEM_PROMPT` and `llm_context()` define what the model sees; adapt them to the input
  format of whatever model/adapter you serve.
- `--backend both`: two verdicts per event, shown side by side in the dashboard's backend selector.

## Known limits (state these in the presentation)
- Update-driven and windowed: withdrawals are ignored, and a MOAS that was already stable before the monitor started is
  invisible (no RIB bootstrap), which also understates how long a conflict has lasted.
- Exact-prefix MOAS only: a more-specific announced by a different origin (sub-MOAS) is not cataloged.
- The baseline is a rule of thumb. The LLM backend is unit-tested with a stubbed endpoint only; it has not been
  run against a real model yet.
- No RPKI/IRR validation yet; the model decides from path/peer evidence plus the whitelist.
- The FYP-I experiments (precision, false positives, baseline vs model on labelled events) are still to be done.

## Latency + accuracy evaluation (`evaluation/`)
    python evaluation/evaluate.py --mode offline        # 202 labelled updates, in-process
    python evaluation/evaluate.py --mode online         # same stream over a websocket (RIS Live protocol) + real RIS Live delay probe
Per-update decision vs. ground truth, time to decision (catalog / AI layer / end-to-end), time-to-detect per anomalous
episode. Results in `evaluation/results/` (`summary.md` compares runs). Details: `evaluation/README.md`.
