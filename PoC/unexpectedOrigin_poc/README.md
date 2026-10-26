# Unexpected Origin PoC (RouteLLM)  [separate from the MOAS PoC]

Pipeline: RIS Live -> candidate filter (watched prefix, origin not expected) -> CAIDA AS-relationship evidence
-> Llama-3.1-8B-Instruct + RouteLLM LoRA -> label (prefix hijack / path hijack / route leak / none) -> SQLite -> dashboard.

## Setup (on the machine with the RTX 4060 Ti 16GB; bitsandbytes needs CUDA, so not on a Mac)
    pip install torch transformers peft accelerate bitsandbytes websockets streamlit pandas pytest
    huggingface-cli login            # needs access to meta-llama/Meta-Llama-3.1-8B-Instruct
    # CAIDA AS relationships: https://publicdata.caida.org/datasets/as-relationships/serial-2/  (.bz2 is fine)
    # copy your adapter folder here as models/route-llm-llama3.1-8b-instruct-lora (adapter_config.json + adapter_model.safetensors)

## Run
    python -m pytest -q
    python replay.py sample_updates.jsonl --asrel sample_asrel.txt --mock --db demo.db     # pipeline test, NO real model
    python replay.py sample_updates.jsonl --asrel <caida file> --db demo.db                # real model, 4-bit
    python live.py --asrel <caida file>                                                    # live feed
    streamlit run dashboard.py -- --db origin.db
Options: --quant 4bit|8bit|bf16 (16GB: 4bit ~6GB, 8bit ~9GB; bf16 will not fit), --only-exact, --cooldown, --top-k.

## Caveats (say these in the presentation)
- Adapter was trained on the authors' Stage-1 fine-tuned model (not yet released); here it runs on stock Llama, so accuracy is not paper-level.
- Authors say a BGP-aware tokenizer is used, but the released README/inference use the standard Llama tokenizer; we use the standard one.
- The exact training format of the update/evidence text is unpublished; prompt.py follows the authors' system/user text.
- Only AS-relationship evidence is implemented (as in the public repo); RPKI/IRR/history evidence is future work.
- MOCK model output is not a result. Model output is advisory, not a verdict.

## Evaluation (model vs. baselines)
    python make_eval_set.py --asrel <caida file> --n 12 --out eval_set.jsonl     # synthetic labelled cases
    python eval.py eval_set.jsonl --asrel <caida file> --mock --out results_mock  # pipeline test only
    python eval.py eval_set.jsonl --asrel <caida file> --out results              # real model -> results.md / .json / .csv
Compares: B1 whitelist-only, B2 whitelist + "no CAIDA relationship", and the model (strict = prefix hijack only; any = any non-none label),
overall and split into easy / hard / real-incident cases.

Case kinds: legit_customer (easy), legit_cone2 (hard: customer-of-customer), hijack_random (easy), hijack_related (hard: peer/provider of the victim).
Labels are assumptions by construction, so say "synthetic" on slides. The B2 baseline is built from the same CAIDA data that supplies the model's evidence,
so on easy cases a good score is expected; the hard cases are where the model has to add value.

Add real incidents by appending lines to the eval file (one JSON per line):
    {"id":"inc-1","kind":"incident","label":"hijack","difficulty":"hard","source":"incident","data":{ RIS-Live-style UPDATE: type,timestamp,host,peer_asn,path,announcements:[{prefixes:[...]}] }}
Use label "legit" for known-good origin changes. Incident prefixes must be listed in whitelist.json (with the victim's expected origin) to be treated as candidates.
Use >= 30 cases per group before quoting percentages; report counts (TP/FP/FN/TN) alongside them.

## Unexpected Origin vs. Unexpected Deaggregation
The model's label set has no such split ("prefix hijack" covers both), so the type is decided in code (pipeline.anomaly_type):
- the announced prefix EQUALS a watched prefix and the origin is unexpected -> unexpected_origin
- the announced prefix is STRICTLY MORE SPECIFIC than a watched prefix and the origin is unexpected -> unexpected_deaggregation
- the model's verdict only decides whether it is anomalous (none -> "none"; unreadable output -> "review").
Because the type comes from prefix geometry, "type accuracy" is not a meaningful metric; evaluate each type's detection quality
instead (eval.py prints separate tables for exact-prefix and more-specific cases). Same-origin more-specifics (traffic engineering)
are never flagged. If one attack announces both forms, you get two alerts (one per type).


Windows users: follow WINDOWS_SETUP.md (venv, CUDA torch, env vars, check_setup.py).
