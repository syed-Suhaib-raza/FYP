# BGP Route Flapping Detection: FYP-I proof of concept

Detects route flapping (repeated withdrawals / path changes of the same route) from RIPE RIS Live. Deterministic rule
(the Anomaly Classification paper classifies flapping as deterministic): a penalty per (prefix, peer session) that grows
with each withdrawal / path change and decays over time raises an alert.

## Run
    pip install websockets streamlit pandas pytest
    python -m pytest -q                                                  # unit tests
    python replay.py sample_updates.jsonl --whitelist whitelist.json     # offline demo (no internet), writes demo.db
    python ris_live.py --whitelist whitelist.json                        # LIVE feed, watches whitelisted prefixes, writes flap.db
    streamlit run dashboard.py                                           # second terminal; reads flap.db (online alerts)
    streamlit run dashboard.py -- --db demo.db                           # dashboard of the offline demo

## All commands (run from the flap_poc folder; Windows PowerShell shown, Linux/macOS identical)
    # install
    pip install websockets streamlit pandas pytest

    # tests + offline demo (3 flap alerts and 3 clears, written to demo.db)
    python -m pytest -q
    python replay.py sample_updates.jsonl --whitelist whitelist.json

    # online: live RIPE RIS Live (no key); alerts go to flap.db. Ctrl+C stops it.
    python ris_live.py --whitelist whitelist.json
    python ris_live.py --prefix 1.1.1.0/24 --prefix 8.8.8.0/24
    python ris_live.py --prefix 193.0.0.0/8 --suppress 1000       # wider block + more sensitive: alerts sooner (volume untested)
    python ris_live.py --prefix 1.1.1.0/24 --no-more-specific     # only that exact prefix

    # dashboard (second terminal), open http://localhost:8501
    python -m streamlit run dashboard.py                          # online (flap.db)
    python -m streamlit run dashboard.py -- --db demo.db          # offline demo (demo.db)
    python -m streamlit run dashboard.py -- --refresh 120         # refresh interval in seconds (default 150)
    python -m streamlit run dashboard.py -- --no-refresh



    # typical online session: two terminals
    python ris_live.py --whitelist whitelist.json                 # terminal 1
    python -m streamlit run dashboard.py                          # terminal 2

## The rule (RFC 2439 penalty with decay, used only to detect)
One penalty per (prefix, peer session):
- route withdrawn: +1000
- route re-announced with a different AS path: +500 (same path again is free)
- penalty halves every 15 minutes (`--half-life 900`)
- penalty >= 2000 (`--suppress`): **FLAP alert**; penalty < 750 (`--reuse`): **CLEARED** (the gap stops alert chatter)
- capped at 12000; a peer session going down is NOT a flap (routes are forgotten, nothing is charged)
- `--min-peers N`: alert only when N sessions flap the same prefix (default 1)
So one blip never alerts, 2 to 3 withdrawals within minutes do, and slow flapping (one per 30 min) decays away.

## Severity
- high: the prefix is inside a whitelisted (monitored) prefix in `whitelist.json` (more-specifics count)
- medium: anything else (unknown, needs review)

