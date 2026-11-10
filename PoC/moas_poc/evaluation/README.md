# MOAS PoC: latency + accuracy evaluation

Measures, for every update in a labelled stream, **how quickly the PoC reaches a decision** and **whether that decision
is correct**, offline (in-process replay) and online (over a websocket, with network/feed latency).

| File | Purpose |
|---|---|
| `make_dataset.py` | Generates the labelled stream (seeded, reproducible). |
| `labelled_updates.jsonl` | 202 RIS-Live-format updates, 39 scenarios: 144 benign, 49 anomalous in scope, 9 anomalous out of scope. Each line has a `truth` block the PoC never sees. |
| `eval_whitelist.json` | Watched prefixes + authorised origins used by the evaluation (superset of `../whitelist.json`). |
| `evaluate.py` | The evaluator (`--mode offline` / `--mode online`). |
| `netfeed.py` | Online plumbing: real RIS Live probe, RIS-Live-protocol feed server, client. |
| `feed_server.py` | Stand-alone feed server, to put a real LAN/WAN hop between the feed and the PoC. |
| `evalcore.py` | Metrics and report helpers. |
| `test_evaluation.py` | Tests (run with the PoC's `python -m pytest -q`). |
| `results/` | `<mode>_<backend>.md/.json/.csv` per run, `summary.md` across runs, `ris_probe_trace.json`. |

## Run (from the `moas_poc` folder)

    pip install websockets                       # online mode only
    python evaluation/evaluate.py --mode offline
    python evaluation/evaluate.py --mode online                          # probes RIS Live for 60 s first
    python evaluation/evaluate.py --mode offline --backend llm --llm-model <name> --llm-url http://<host>:11434/v1
    python evaluation/make_dataset.py --seed 7   # regenerate a different stream

## What counts as a decision, and the ground truth

The PoC is event-based: the catalog opens a MOAS event when a 2nd origin appears, and the AI layer scores each event
revision. After each update the evaluator reads the decision the PoC holds for that update's prefix: the latest verdict of
the open event (`anomalous` / `benign` / `uncertain`), or `benign` if there is no active multi-origin conflict. The
`truth.label` of each update is the decision that *should* be held at that moment (state semantics, see
`make_dataset.py`). Example: the legitimate origin re-announcing during a hijack is still `anomalous`; the first update
after the hijacker ages out of the window is `benign` again.

Scenarios cover steady single-origin traffic, planned anycast/multi-origin, provider aggregation, AS_SET aggregates,
planned migrations, DDoS-scrubbing diversion, unwatched anycast/siblings, exact-prefix hijacks (watched and unwatched),
private-ASN / AS_TRANS origins, bogon MOAS, an unauthorised origin joining a planned MOAS, and a forged-adjacency hijack.
Forged-origin path hijacks, sub-prefix hijacks and a single-origin bogon are marked `in_scope: false`: an exact-prefix
MOAS detector cannot see them, so they are reported in their own table instead of the headline metrics.

Metrics: accuracy counts `uncertain` as wrong; precision/recall/FPR count `uncertain` as an alert (it goes to an
operator). Per anomalous scenario the report also gives time-to-detect (updates, BGP time and wall time).

## Latency

| field | meaning |
|---|---|
| `catalog_ms` | `MoasCatalog.process()` (layer 1) |
| `ai_ms` | `ai_layer.run_once()` for the event(s) the update opened/changed/closed (layer 2, includes SQLite I/O) |
| `decision_ms` | catalog + AI: update in -> decision |
| `network_ms` | online: emit -> sent, the feed delay |
| `queue_ms` | online: sent -> read by the PoC (socket + waiting behind slower decisions) |
| `e2e_ms` | online: emit -> decision |

The AI layer is called immediately after each catalog change. A deployed `ai_layer.py --watch` polls every `--interval`
seconds (default 5), which adds up to that interval to each triggering decision.

## Online mode

1. **Probe** (`--delay-model auto`, the default): connects to `wss://ris-live.ripe.net`, listens to one collector
   (`--probe-host rrc00`) for `--probe-seconds`, and records arrival time minus collector timestamp for every real update,
   plus websocket round-trip times. The real messages are also run through the PoC (timing only, they have no labels) and
   the trace is saved to `results/ris_probe_trace.json`. If RIS Live is unreachable the run continues without a delay model
   and the report says so.
2. **Labelled stream over the network**: a feed server speaking the RIS Live protocol (`ris_subscribe` -> `ris_message`)
   streams the 202 labelled updates at `--rate` msg/s. Each update is held back by a delay from the measured trace. Updates
   of different prefixes may overtake each other, as they do on RIS Live; updates of the same prefix keep their order. The
   feed server runs on its own thread, so a slow decision makes later updates queue up as they would on a real socket.
   The PoC side connects, subscribes and processes messages as `ris_live.py` does.

Other delay models: `--delay-model none | fixed:0.8 | uniform:0.5,3 | trace:evaluation/results/ris_probe_trace.json`
(re-use an earlier probe without going online). To add a real network hop, run the feed on another machine:

    machine A:  python evaluation/feed_server.py --host 0.0.0.0 --port 8765 --delay-model trace:evaluation/results/ris_probe_trace.json
    machine B:  python evaluation/evaluate.py --mode online --feed-url ws://<A>:8765        # keep both clocks NTP-synced

## Caveats
- Synthetic stream with labels true by construction; ASNs/prefixes are placeholders with fictional roles. Real incidents can
  be appended as more lines in the same format.
- `baseline` is the PoC's untuned additive rule set, not a model. Its weak spots are visible by design: unwatched
  hijacks come out `uncertain`, scrubbing diversion is a false positive, and a forged-adjacency hijack looks like provider aggregation.
- Offline latency is pure processing time on this machine; online adds the feed delay and queueing.
