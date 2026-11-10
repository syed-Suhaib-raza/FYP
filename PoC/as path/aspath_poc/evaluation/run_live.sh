#!/usr/bin/env bash
# TEST 2 - live, two 45-minute runs back to back (about 95 minutes), rules + MODEL. Run from the aspath_poc folder:  bash run_live.sh [hf|llamacpp|mock]
set -euo pipefail
LLM="${1:-hf}"
python preflight_live.py
python live_eval.py record --minutes 45 --host rrc00 --llm "$LLM" --capture full_capture.jsonl --alerts full_alerts.jsonl --out full_report
python live_eval.py record --minutes 45 --host rrc00 --llm "$LLM" --prefix 193.0.0.0/8 --prefix 194.0.0.0/8 --prefix 195.0.0.0/8 --capture pfx_capture.jsonl --alerts pfx_alerts.jsonl --out pfx_report
python cluster_events.py full_alerts.jsonl full_events.csv
python cluster_events.py pfx_alerts.jsonl pfx_events.csv
python build_results.py
echo; echo "Next: fill the verdict column in full_events.csv / pfx_events.csv, then re-run analyze --labels (README_EVAL.md)."
