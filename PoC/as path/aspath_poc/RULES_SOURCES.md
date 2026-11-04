# Where the AS-path rules come from (paste-ready for the report)

`python aspath.py rules` prints the same table from `detector.RULES`; the dashboard shows it next to every incident.
"Paper" = *The Surprising Effectiveness of LLMs in BGP Security* (ROUTE LLM, arXiv 2608.22812). "Proposal" = your FYP proposal.
The Cybernet requirements PDF was not among the files uploaded for this version, so rules are mapped to the proposal's FR numbers only.

## What the paper gives us
* Three categories (App. B.1, Fig. 10): prefix hijack, **path hijack** (path manipulated or fabricated while the origin can still look legitimate), **route leak** (route propagated against export policy such as valley-free).
  This PoC covers the two path categories. Prefix hijack = unexpectedOrigin PoC.
* Time-consistent evidence (R3, Sec. V-C, Fig. 4): facts known *before* the event: origins seen, AS links seen before / never or rarely seen before.
* Baseline features used by the Random-Forest comparison (Sec. VII): AS-path length, newly observed AS-path edges, prefix length, origin changes.
* BEAM (Sec. IV-A): AS routing roles from CAIDA relationships + abnormal AS-path changes.
* App. E.6, "why not rules alone": rules catch specific symptoms (valley violations) but noisy or incomplete evidence defeats them, so the model is used on top. This is why the rules are only a prefilter here.

## Rule table
| Rule | Primary? | Indicates | Paper | Proposal |
|---|---|---|---|---|
| `new_origin_upstream` | yes | path hijack | path-hijack definition (origin looks legitimate); Fig. 4 link next to the origin (AS7219-AS10990) rarely seen; DFOH [38]; Fig. 14 | 5b preferred peer; 5c path-shift vs expected preferred peer; FR1, FR4 |
| `new_as_link` | yes | path hijack | Fig. 4 link evidence; RF feature "newly observed edges"; knowledge base of adjacent AS pairs (App. E.4); BEAM path changes | 5b typical AS-path characteristics; 5c AS-path deviation; FR1, FR2, FR5 |
| `valley_violation` | yes | route leak | route-leak definition; App. E.6; BEAM routing roles | FR6 (transit-to-transit / transit-to-peer / peer-to-peer), RFC 7908 [10]; 5c |
| `path_length_deviation` | supporting only | (adds evidence) | RF feature AS-path length | 5b typical AS-path characteristics; FR2 |

`valley_violation` also reports the leak kind from FR6's wording: transit-to-transit, transit-to-peer, peer-to-transit (not listed in FR6, same rule), peer-to-peer.

## What is NOT from a paper (say so in the report)
* Thresholds: `--min-support` (1 = link never seen; 2 = never or rarely seen), `--len-delta` 3, `--cooldown` 600 s, learning window 600 s. All untuned.
* The valley-free walk itself is classic routing-policy background (Gao-Rexford style), implemented on CAIDA relationships as the paper's evidence also uses.
* Precedence when several primary rules fire: `new_origin_upstream` > `valley_violation` > `new_as_link` names the candidate. Our choice.
* AS links are treated as undirected and prepending is removed before comparing paths. Our choice.
* The baseline is whatever the learning window / history file contained, frozen afterwards. The paper's knowledge base is monthly snapshots over a year plus an 80% origin-regularity threshold; we do not reproduce that.
* The learning window is assumed clean: an attack inside it becomes "normal".

## Same as the unexpectedOrigin PoC
Candidate dict keys; ownership lines from the operator whitelist; CAIDA evidence via the same `ASRel.evidence()`; same system/user prompt and update text (a test compares them with strings
produced by that PoC's code); same label parser; type decided by code from the rule, never by the model; severity high = model flags an anomaly, medium = model says none/unreadable
(or no model); same cooldown idea (re-classify the same key only after N seconds); same `--no-ownership-evidence` switch.

## Different on purpose
* Extra evidence lines in the paper's Fig. 4 wording (baseline facts). `--no-history-evidence` removes them so you can measure their effect.
* Correlation (one incident per cause) and recovery tracking, because the proposal asks for them (FR10-FR12).
* Origin-unauthorised announcements are skipped (`deferred_origin`), not re-detected.

## How to defend the rules
They are explainable checks, each traced to a sentence in the paper or proposal, and none is validated on real incidents yet. The paper itself reports that rule-like
detectors generalise poorly (BEAM 57.67% event-level on its benchmark), so report: what the rules catch on replayed real incidents, what they miss, and what the model adds.
