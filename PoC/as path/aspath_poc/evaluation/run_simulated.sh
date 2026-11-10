#!/usr/bin/env bash
# TEST 1 - simulated, 250 cases, rules + MODEL. Run from the aspath_poc folder:  bash run_simulated.sh [hf|llamacpp|mock]
set -euo pipefail
LLM="${1:-hf}"
python make_eval_set.py
python eval.py eval_set.jsonl --sweep --llm "$LLM" --llm-runs 2 --out results_sim
python -m pytest -q test_eval.py test_llm_eval.py
python build_results.py
echo; echo "Done: results_sim.md results_sim.csv results_sim.json results_and_calculations.xlsx"
[ "$LLM" = "mock" ] && echo "NOTE: mock model used: proves the harness only."
