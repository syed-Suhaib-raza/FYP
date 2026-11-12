# RPKI Invalid PoC (deterministic)

Detects BGP routes that touch Cybernet (AS9541 / AS24440) and are **RPKI Invalid** or have **no ROA**, using the
approach chosen in the RPKI_Invalid SOTA doc: **Routinator VRPs + RFC 6811 Route Origin Validation + cause and
severity rules**. No AI model: RPKI validity is an exact rule, so the same input always gives the same answer.

Pipeline: `RIPE RIS Live` -> `bgp_feed.py` -> route table + RFC 6811 (`engine.py`, `validator.py`) -> cause and
severity rules (`rules.py`) -> SQLite (`store.py`) -> `dashboard.py`. VRPs come from Routinator (`vrp_store.py`) and
are refreshed every 10 min; ROA changes for Cybernet are reported (`roa_watch.py`) and every held route is re-checked.

## Run (Windows PowerShell or Linux, from this folder, Python 3.10+)
```
pip install -r requirements.txt
python -m pytest -q                              # 51 tests, no internet needed
python main.py --demo                            # offline demo: every alert type, writes demo.db
python -m streamlit run dashboard.py -- --db demo.db
```
Live (needs Routinator with its HTTP server on 127.0.0.1:8323, e.g. `routinator server --http 127.0.0.1:8323`):
```
python main.py                                   # RIS Live + Routinator -> rpki.db
python -m streamlit run dashboard.py             # second window
python evaluation/routinator_agreement.py        # after a while: our verdicts vs Routinator /validity
```
Before going live, put Cybernet's real prefixes in `whitelist.json` (same format as the other PoCs:
`{"prefix": [expected origin ASNs]}`) and Cybernet's customer ASNs in `customers.json` (a JSON list).
Options: `--min-peers N` (default 2), `--no-cross-check`, `--no-revalidate` (ablation), `--db FILE`, `--delay S` (demo speed).

## What is detected (the doc's severity table)
| Case | State | Severity | cause |
|---|---|---|---|
| Foreign AS originates Cybernet space, first time, not in any ROA | INVALID_AS / INVALID_AS_AND_ML | CRITICAL | FOREIGN_NEW_ORIGIN |
| Same, but the origin announced this prefix before (history) | INVALID_* | HIGH | FOREIGN_KNOWN_ORIGIN |
| A Cybernet customer AS originates Cybernet space, ROA not updated | INVALID_* | HIGH | CUSTOMER_NOT_IN_ROA |
| Cybernet announces a more-specific than its ROA maxLength allows | INVALID_ML | HIGH | OWN_MAXLENGTH |
| Cybernet originates a prefix whose ROA names another AS (leased block) | INVALID_AS | HIGH | OWN_NOT_AUTHORISED |
| A Cybernet prefix with no ROA | NOT_FOUND | LOW | NO_ROA |
| A Cybernet ROA was removed / expires soon / its maxLength was reduced | (ROA change) | MEDIUM | roa_changes table |

Rules that keep alerts trustworthy:
* **Peer threshold:** an alert is PENDING until `MIN_PEERS` (2) RIS peers carry the route, then ACTIVE; it is RESOLVED
  only when no peer carries it any more (no on/off flapping). A route seen by one peer only never pages the NOC.
* **Re-validation on VRP change:** RIS only sends a message when a route changes. When a ROA is edited, expires or is
  removed, every route already held is re-checked, so a stable route that turns Invalid raises an alert with no BGP
  update at all (and a fixed ROA resolves it).
* **History:** `origin_history` remembers which origins announced which prefix, so a returning partner is HIGH, a
  never-seen origin CRITICAL.
* **AS0, AS_SET, IPv6** handled per RFC 6811 (an AS0 ROA never matches; an AS_SET origin is never Valid).
* **Routinator cross-check:** in live mode every alert that becomes ACTIVE also gets Routinator's own `/validity`
  verdict (second opinion, stored with the alert).
* **Peer sessions:** RIS_PEER_STATE "down" removes that peer's routes (a session reset is not a withdrawal storm).
* **Resubscribe:** when Cybernet's ROA prefix list changes, the RIS Live filters are rebuilt.
* **Stale VRPs:** a warning (terminal + dashboard) when VRPs have not loaded for 30 min.

## Evaluation (same framework as moas_poc / unexpectedOrigin_poc)
```
python evaluation/make_dataset.py                # labelled stream: 200 lines, 206 checks, 19 scenarios
python evaluation/evaluate.py --mode offline     # 3 configs: full + 2 ablations
python evaluation/evaluate.py --mode online      # websocket + real RIS Live delays (probes RIS Live 60 s first)
```
Results (`evaluation/results/summary.md`; the online row was measured from the build machine, re-run it on yours):

| run | config | accuracy | precision | recall | FPR | state correct | severity correct | episodes | decision p50 | end-to-end p50 |
|---|---|---|---|---|---|---|---|---|---|---|
| offline | **full** (chosen) | 1.0 | 1.0 | 1.0 | 0.0 | 204/204 | 38/38 | 13/13 | 0.08 ms | - |
| offline | no-revalidation | 0.98 | 0.972 | 0.921 | 0.006 | 204/204 | 35/35 | 12/13 | 0.06 ms | - |
| offline | min-peers-1 | 0.926 | 0.717 | 1.0 | 0.09 | 204/204 | 38/38 | 13/13 | 0.07 ms | - |
| online | **full** | 1.0 | 1.0 | 1.0 | 0.0 | 204/204 | 38/38 | 13/13 | 0.38 ms | 5.2 s |

How to read it: the PoC is deterministic, so `full` must be exact (any miss would be a bug, not a weak model). The
ablations show what each design choice buys: without re-validation the ROA-change episodes are missed; alerting on
the first RIS peer raises the false-positive rate from 0 to 9%. End-to-end time is dominated by the RIS Live feed
delay (median about 4 s in the probe), far inside the doc's target of < 60 s.

The dataset is synthetic (labels true by construction, written by hand from the doc's rules, not computed by the
PoC). Scenarios: own valid routes, ROA tightened and ROA expired (no BGP update), own too-specific (resolve and
reopen), exact-prefix and sub-prefix hijacks, customer not in ROA, leased block, AS0 ROA, AS_SET origin, Cybernet
prefix without ROA, foreign origin in uncovered Cybernet space, IPv6, a single-peer Invalid, invalid and valid routes
of other networks, peer sessions going down, a partner returning (history), and a forged-origin path hijack
(out of scope: RPKI Valid by definition, covered by the AS-Path PoC).

## Files
| File | Purpose |
|---|---|
| `main.py` | Entry point: `--demo` (replay) or live (Routinator + RIS Live) |
| `engine.py` | The detector: route table, alert lifecycle, peer threshold, history, VRP reload + re-validation |
| `validator.py` | RFC 6811 validation with the three Invalid classes (unchanged from the first version) |
| `rules.py` | When to alert, cause class and severity (the doc's table) |
| `roa_watch.py` | ROA added / removed / maxLength changed / expiring, for Cybernet |
| `vrp_store.py` | Loads VRPs from Routinator (`/jsonext` with expiry, falls back to `/json`) or a file |
| `bgp_feed.py` | RIS Live client (reconnect, ping, resubscribe, peer state) and file replay |
| `store.py` | SQLite: alerts, alert_events, origin_history, roa_changes, meta (+ `alerts.jsonl` log) |
| `dashboard.py` | Streamlit: active alerts, history, ROA changes, route states, alert detail |
| `config.py` | Every setting in one place |
| `whitelist.json`, `customers.json` | Cybernet prefixes and customer ASNs (live) |
| `demo_data/` | `make_demo.py` builds the demo VRPs, whitelist and replay |
| `test_validator.py`, `test_engine.py`, `test_parts.py`, `evaluation/test_evaluation.py` | 51 tests |
| `evaluation/` | Dataset, evaluator, results; `netfeed.py`, `evalcore.py`, `feed_server.py` copied from moas_poc |

## Limits (say these in the presentation)
* RPKI only checks the **origin**. A forged-origin path hijack (real origin kept at the end of a fake path) is
  Valid: that is the AS-Path PoC's job. RPKI does not stop IP spoofing either (a data-plane problem).
* Route Views is not used yet (it has no live stream; planned through BGPStream for history and confirmation).
* ROA expiry warnings need Routinator's `/jsonext` output; with plain `/json` there is no expiry date. Check that
  your Routinator version serves `/jsonext` (it falls back to `/json` automatically).
* The "seen before" history starts empty, so in the first days every foreign origin is CRITICAL.
* Cross-PoC correlation (linking an Invalid with an Unexpected Origin / Deaggregation alert) is not built yet.
* Model comparison from the doc (section 5: run RouteLLM on the same Invalid events and compare cause accuracy)
  is not run yet: it needs the GPU machine and the RouteLLM setup of the unexpectedOrigin PoC.
