# TEST 2 - live, two 45-minute runs back to back (about 95 minutes), rules + MODEL. Run from the aspath_poc folder:  .\run_live.ps1
# Keep the PC awake (power settings: never sleep) and the clock synced (w32tm /resync). Ctrl+C stops a run early and still analyses it.
# -Llm hf (default) = the real model. Each run first does a model self-test and REFUSES to start if the model does not answer.
param([string]$Llm = "hf")
$ErrorActionPreference = "Stop"
python preflight_live.py                         # CAIDA file, clock, websockets, disk, RIS Live reachable, rrc00 message rate
if ($LASTEXITCODE -ne 0) { Write-Host "Fix the preflight problems first."; exit 1 }

# Run A - whole collector rrc00: route-leak rule + model (model judges every alert, no cap)
python live_eval.py record --minutes 45 --host rrc00 --llm $Llm --capture full_capture.jsonl --alerts full_alerts.jsonl --out full_report
if ($LASTEXITCODE -ne 0) { Write-Host "Run A did not start/finish cleanly; stopping."; exit 1 }

# Run B (after A) - three /8 blocks: all rules + model, baseline learnt live
python live_eval.py record --minutes 45 --host rrc00 --llm $Llm --prefix 193.0.0.0/8 --prefix 194.0.0.0/8 --prefix 195.0.0.0/8 --capture pfx_capture.jsonl --alerts pfx_alerts.jsonl --out pfx_report
if ($LASTEXITCODE -ne 0) { Write-Host "Run B did not start/finish cleanly; stopping."; exit 1 }

# afterwards: clustering, then the workbook
python cluster_events.py full_alerts.jsonl full_events.csv
python cluster_events.py pfx_alerts.jsonl pfx_events.csv
python build_results.py
Write-Host "`nNext: open full_events.csv and pfx_events.csv, fill the verdict column for a sample, then re-run analyze with --labels (README_EVAL.md)."
