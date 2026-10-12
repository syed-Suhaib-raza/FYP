# BGP MOAS Detection: FYP-I proof of concept

Detects Multiple Origin AS (MOAS) conflicts from RIPE RIS Live. Deterministic rule: one prefix seen with
2+ different origin ASes (last hop of the AS path) within a time window raises an alert.

## Run
    pip install websockets streamlit pandas pytest
    python -m pytest -q                                   # unit tests
    python replay.py sample_updates.jsonl --whitelist whitelist.json   # offline demo (no internet)
    python ris_live.py --whitelist whitelist.json         # LIVE feed, watches whitelisted prefixes
    streamlit run dashboard.py                            # second terminal; reads moas.db

## Severity
- high: prefix is in the whitelist but a non-whitelisted origin appeared (hijack or misconfig candidate)
- medium: prefix is not in the whitelist (unknown; could be anycast / multi-homing)
- info: all origins are whitelisted (planned multi-origin)

## Files
moas.py (logic + SQLite) | ris_live.py (live client) | replay.py + sample_updates.jsonl (offline demo) |
dashboard.py | whitelist.json (edit to the monitored company's prefixes and ASNs)

## Known limits (state these in the presentation)
- Windowed, announcement-based: withdrawals are ignored; origins age out after --window seconds.
- No RPKI/IRR validation yet, so benign MOAS (anycast, CDNs) is separated only via the whitelist.
- The FYP-I experiments (precision, false positives, comparison against a model) are still to be done.
