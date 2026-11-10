# TEST 1 - simulated, 250 cases, rules + MODEL. Run from the aspath_poc folder:  .\run_simulated.ps1
# Use  -Llm mock  for a quick harness check with the fake model;  default is the real model (hf).  Add model-path flags after the script if your aspath.py needs them.
param([string]$Llm = "hf")
$ErrorActionPreference = "Stop"
python make_eval_set.py                                              # eval_set.jsonl + eval_as_rel.txt (250 cases, seed 42)
python eval.py eval_set.jsonl --sweep --llm $Llm --llm-runs 2 --out results_sim    # rules + model: results_sim.md / .json / .csv
python -m pytest -q test_eval.py test_llm_eval.py                    # harness tests (labels re-checked by an independent oracle; model scoring)
python build_results.py                                              # results_and_calculations.xlsx (incl. LLM sheet)
Write-Host "`nDone: results_sim.md  results_sim.csv  results_sim.json  results_and_calculations.xlsx"
if ($Llm -eq "mock") { Write-Host "NOTE: the mock model was used: the model section proves the harness only. Re-run without -Llm mock for the real model." }
