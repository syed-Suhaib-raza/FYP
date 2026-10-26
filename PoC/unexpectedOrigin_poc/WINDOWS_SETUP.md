# Windows setup: Unexpected Origin PoC (RouteLLM)

Target layout (put the project anywhere, e.g. C:\Users\User\fyp\routellm_origin_poc):

    routellm_origin_poc\
      asrel.py  common.py  dashboard.py  detector.py  eval.py  live.py  llm.py  make_eval_set.py
      pipeline.py  prompt.py  replay.py  check_setup.py  test_poc.py
      whitelist.json  sample_updates.jsonl  sample_asrel.txt  requirements.txt  README.md
      data\                   <- create: put the CAIDA as-rel file here
      models\
        route-llm-llama3.1-8b-instruct-lora\   <- create: adapter_config.json + adapter_model.safetensors (+ README.md)
    (base model stays where it is: C:\Users\User\~\models\Meta-Llama-3.1-8B-Instruct)

## 1. Python
Use Python 3.10-3.12 (3.12 is safest for torch/bitsandbytes wheels). Check: `py -V`. Install from python.org if needed (tick "Add to PATH").

## 2. Project folder + virtual environment (PowerShell)
    cd C:\Users\User\fyp\routellm_origin_poc
    py -3.12 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    # if activation is blocked:  Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
    mkdir data, models\route-llm-llama3.1-8b-instruct-lora

## 3. Install PyTorch with CUDA FIRST, then the rest
    nvidia-smi                                   # confirm the driver sees the 4060 Ti
    pip install torch --index-url https://download.pytorch.org/whl/cu124
    pip install -r requirements.txt
(If cu124 fails for your driver/Python, pick the command at https://pytorch.org/get-started/locally/.)

## 4. Copy the adapter
Copy `adapter_config.json` and `adapter_model.safetensors` into `models\route-llm-llama3.1-8b-instruct-lora\`.

## 5. Get the CAIDA AS-relationship file
Open https://publicdata.caida.org/datasets/as-relationships/serial-2/ , download the newest `*.as-rel2.txt.bz2`
into `data\` (the code reads .bz2 directly; no need to unzip).

## 6. Set the paths once per PowerShell window
The base-model path contains a folder literally named "~", so always keep it in quotes:

    $env:ROUTE_LLM_BASE_MODEL = "C:\Users\User\~\models\Meta-Llama-3.1-8B-Instruct"
    $env:ROUTE_LLM_ADAPTER = "models\route-llm-llama3.1-8b-instruct-lora"
    $env:ROUTE_LLM_AS_RELATIONSHIPS = "data\<your-file>.as-rel2.txt.bz2"

(Every script reads these, so you can drop the --base-model/--adapter/--asrel flags below.)

## 7. Check the setup, then smoke-test the real model
    python check_setup.py
    python check_setup.py --load      # loads the model in 4-bit and classifies one made-up hijack; first load takes a few minutes
Healthy output: all [ OK ], GPU 4060 Ti ~16 GB, model loads, peak GPU memory around 6-7 GB, and a label for AS64666 on 1.1.1.0/24.

## 8. Run the PoC
    python -m pytest -q                                              # unit tests (no GPU)
    python replay.py sample_updates.jsonl --asrel sample_asrel.txt --db demo.db    # real model on the sample file (sample_asrel.txt is a tiny fake, use it only for this demo)
    python replay.py sample_updates.jsonl --db demo.db               # real model with the CAIDA file from step 6
    python live.py                                                   # live RIS feed -> origin.db  (edit whitelist.json first)
    streamlit run dashboard.py -- --db origin.db                     # second PowerShell window (activate the venv, no env vars needed)

Note: `--mock` swaps in a fake rule-based model for plumbing tests only. Leave it out for real runs.

## 9. Evaluation
    python make_eval_set.py --out eval_set.jsonl --n 12
    python eval.py eval_set.jsonl --out results            # writes results.md / .json / .csv

## Troubleshooting
- `CUDA available=False`: CPU torch got installed. `pip uninstall torch`, repeat step 3 (the cu124 command), then re-run check_setup.py.
- bitsandbytes error on Windows: `pip install -U bitsandbytes` (needs >= 0.43 for Windows).
- Out of memory: close other GPU apps (browsers, games); keep `--quant 4bit`.
- Path errors: keep the base-model path in quotes; use the env var in step 6.
- RIS Live connection errors: a firewall or university network may block WebSockets; try another network or a hotspot. The script retries every 5 seconds.
- `Torch not compiled with CUDA` or very slow generation: you are on CPU, see the first point.
