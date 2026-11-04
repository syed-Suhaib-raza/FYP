# BGP AS-path anomaly PoC (rules from the ROUTE LLM paper + proposal, ROUTE LLM model like the unexpectedOrigin PoC)

Pipeline (same stages as `unexpectedOrigin_poc`):
`RIS Live / jsonl` -> `detector.PathCandidates` (rules, `RULES`) -> `pipeline.classify` (ownership + baseline + CAIDA evidence -> Llama-3.1-8B + LoRA) -> verdict -> correlation -> SQLite -> `dashboard.py`.

* Rules (`python aspath.py rules`, details in `RULES_SOURCES.md`): `new_origin_upstream` and `new_as_link` -> **path hijack**; `valley_violation` -> **route leak** (with leak kind); `path_length_deviation` supports.
* Type = rule that fired. The model is a second opinion: severity **high** = model also flags an anomaly, **medium** = rule only / model says none. Alert != confirmed attack.
* Same model call as unexpectedOrigin: same prompt text, same evidence block, same parser (`--prompt repo`, default). `--prompt paper|infer` are options to compare.
* Origins that are not in the whitelist are left to the unexpectedOrigin PoC (`deferred_origin`). Same `whitelist.json` format as the other PoCs; `watch_asns.json` for ASN watching.


## Windows PowerShell, project in C:\aspath_poc
Use Python 3.10-3.12 (3.12 best; llama-cpp-python has no prebuilt wheel for 3.13+).
```
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
python -m pytest -q                      # 56 tests, no model needed
python aspath.py demo                    # rules only
python evaluate.py                       # synthetic labelled file: AC/PR/RC/F1/FPR/FNR + rule ablation
python aspath.py caida                   # real CAIDA AS relationships (public, ~2 MB) into ./data; needed for LIVE runs, not for the demo
```
### A) 
```
python cpu_setup.py --install-deps       # llama-cpp-python (prebuilt CPU wheel) + converter helpers
$env:HF_TOKEN="hf_xxx"                   # Read token; Meta access needed for the tokenizer/config files only
python cpu_setup.py                      # downloads 4.9 GB Q4_K_M base, tokenizer files, llama.cpp scripts; converts the adapter
python check_setup.py --llm llamacpp --load --compare     # close the browser first: needs ~7 GB free RAM
python aspath.py demo --llm llamacpp --no-history-evidence  # same prompt as the unexpectedOrigin PoC
python aspath.py demo --llm llamacpp                        # with the baseline evidence lines
python evaluate.py --llm llamacpp
python -m streamlit run dashboard.py     # second window
```
Tune speed with `--threads` (try 6, 4, 8). The prompt is rendered with the same Hugging Face chat template as the HF route, then llama.cpp generates greedily.
Differences to the unexpectedOrigin 4-bit run: Q4_K_M (llama.cpp) instead of NF4 (bitsandbytes), and the LoRA is applied on top of the 4-bit weights at run time, so outputs can differ slightly. The adapter was trained against full-precision weights.

### B) NVIDIA GPU: Hugging Face route, 4-bit 
```
$env:HF_TOKEN="hf_xxx"; python aspath.py download        # base model ~16 GB (resumable)
python check_setup.py --load --compare --quant 4bit      # files, adapter shapes, loads the model, runs 3 prompt styles, prints RAW output
python aspath.py demo --llm hf --quant 4bit
python evaluate.py --llm hf --quant 4bit
```
(CUDA build of torch + `pip install bitsandbytes` needed. Without a GPU and with < 20 GB RAM `--llm hf` stops early and points to route A.)

Live: `python aspath.py live --llm llamacpp --learn 900` (uses the newest CAIDA file in ./data automatically; without one it warns that it is on the synthetic demo relationships) (first 15 minutes only learn the baseline). Or build the baseline from earlier updates: `python aspath.py learn history.jsonl`, then `live`.
Watch list: `python aspath.py watch add 72.255.64.0/18 --origin 9541 | add-asn 15169 | remove ... | list`. Real relationships: `--as-rel <CAIDA as-rel .bz2>` (demo file is synthetic).
No model yet: `--llm mock` is a FAKE classifier to test the plumbing (rows tagged MOCK).

## Useful switches
`--min-support 2` (links seen once also count as new) | `--len-delta` | `--cooldown` | `--no-history-evidence` | `--no-ownership-evidence` | `--origin-policy any` | `--quant 4bit` (GPU only).


