# AS-Path Anomaly PoC: test commands

This folder holds the test harness for the AS-path anomaly detector. Test outputs go in `results/`, and the written results are in `results/results.md`.

## Setup (once)

Copy this folder's files into the `aspath_poc` folder (next to `aspath.py`, `detector.py` and `llm.py`) and run everything from there with the virtual environment active.

```
pip install websockets openpyxl pytest
python aspath.py caida          # downloads the CAIDA AS-relationships file into ./data
w32tm /resync                   # Windows only: sync the clock (feed delay compares your clock with RIS)
python preflight_live.py        # checks CAIDA file, clock, websockets, disk, RIS Live and the rrc00 message rate
mkdir results                   # skip if it already exists
```

Without the CAIDA file the route-leak rule (`valley_violation`) stays silent.

## Test 1: simulated data (no internet)

```
python make_eval_set.py         # only to regenerate eval_set.jsonl; a copy is included
python eval.py eval_set.jsonl --sweep --llm llamacpp --llm-runs 1 --out results/results_sim
python eval.py eval_set.jsonl --llm none --out results/results_sim_rules_only
python -m pytest -q test_eval.py test_llm_eval.py
```

- `--llm none` is rules only. `--llm mock` is a fake model for a harness check only (its numbers say nothing about the real model).
- Outputs: `results/results_sim.md`, `.json` and `.csv`.

## Test 2: live data (internet needed, 2 x 45 minutes)

Keep the PC awake while these run. Ctrl+C stops a run early and still analyses what was recorded. Each run starts with a model self-test and refuses to start if the model does not answer.

Run A, whole collector rrc00 (route-leak rule + model):

```
python live_eval.py record --minutes 45 --host rrc00 --llm llamacpp --capture results/full_capture.jsonl --alerts results/full_alerts.jsonl --out results/full_report
```

Run B, three /8 blocks (all rules + model, baseline learned live for the first 600 s):

```
python live_eval.py record --minutes 45 --host rrc00 --llm llamacpp --prefix 193.0.0.0/8 --prefix 194.0.0.0/8 --prefix 195.0.0.0/8 --capture results/pfx_capture.jsonl --alerts results/pfx_alerts.jsonl --out results/pfx_report
```

A 5-minute trial first:

```
python live_eval.py record --minutes 5 --host rrc00 --capture results/trial.jsonl --alerts results/trial_alerts.jsonl --out results/trial_report
```

## After the live runs

```
python cluster_events.py results/full_alerts.jsonl results/full_events.csv
python cluster_events.py results/pfx_alerts.jsonl results/pfx_events.csv
python build_results.py --sim results/results_sim --run "Run A full rrc00=results/full_report,results/full_alerts.jsonl,results/full_events.csv" --run "Run B prefixes=results/pfx_report,results/pfx_alerts.jsonl,results/pfx_events.csv" --out results/results_and_calculations.xlsx
```

## Manual verification (live accuracy)

1. Open `results/full_events.csv` and `results/pfx_events.csv`.
2. For a sample of events, check the prefix, path and AS links on RIPEstat, bgp.tools or CAIDA AS-rank. Write `TRUE` (real hijack or leak) or `FALSE` in the `verdict` column and note how many you checked.
3. Re-run the analysis with the labels:

```
python live_eval.py analyze results/full_capture.jsonl --alerts results/full_alerts.jsonl --out results/full_report --labels results/full_events.csv
python live_eval.py analyze results/pfx_capture.jsonl --alerts results/pfx_alerts.jsonl --out results/pfx_report --labels results/pfx_events.csv
```

Report it as "X of N sampled events confirmed", not as recall.

## One-command scripts

`run_simulated.ps1` / `run_simulated.sh` run Test 1. `run_live.ps1` / `run_live.sh` run Test 2. They write to the current folder, so copy the outputs into `results/` afterwards. `README_EVAL.md` has the full detail, but it still mentions 250 cases and the `hf` model backend.

## Files

| File | Role |
| --- | --- |
| `make_eval_set.py` | builds the labelled simulated cases (`eval_set.jsonl`, `eval_as_rel.txt`) |
| `eval.py` | Test 1: accuracy, rule ablation, sweep, compute time |
| `live_eval.py` | Test 2: records live RIS data and measures latency |
| `cluster_events.py` | groups live alerts into events for manual checking |
| `build_results.py` | Excel workbook with every result and metric formula |
| `preflight_live.py` | pre-run checks for the live tests |
| `llm_eval.py` | scores the model's verdicts |
| `test_eval.py`, `test_llm_eval.py` | harness tests |
| `results/` | test outputs and `results.md` |
