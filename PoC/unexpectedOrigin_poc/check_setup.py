"""Verify the machine is ready.   python check_setup.py --base-model "C:\\Users\\User\\~\\models\\Meta-Llama-3.1-8B-Instruct" --adapter models\\route-llm-llama3.1-8b-instruct-lora --asrel data\\as-rel.txt
Add --load to also load the real model and classify one hand-made hijack update (takes a few minutes the first time)."""
import argparse, os, sys, importlib

p = argparse.ArgumentParser()
p.add_argument("--base-model", default=os.environ.get("ROUTE_LLM_BASE_MODEL", ""))
p.add_argument("--adapter", default=os.environ.get("ROUTE_LLM_ADAPTER", "models/route-llm-llama3.1-8b-instruct-lora"))
p.add_argument("--asrel", default=os.environ.get("ROUTE_LLM_AS_RELATIONSHIPS", ""))
p.add_argument("--quant", default="4bit"); p.add_argument("--load", action="store_true")
a = p.parse_args()
ok = True


def say(good, msg):
    global ok
    ok &= bool(good)
    print(("[ OK ] " if good else "[FAIL] ") + msg)


say(sys.version_info >= (3, 10), f"Python {sys.version.split()[0]} (3.10-3.12 recommended)")
for m in ["transformers", "peft", "accelerate", "bitsandbytes", "websockets", "streamlit", "pandas"]:
    try:
        mod = importlib.import_module(m); say(True, f"{m} {getattr(mod, '__version__', '')}")
    except Exception as e:
        say(False, f"{m} not importable: {str(e)[:100]}")
try:
    import torch
    say(torch.cuda.is_available(), f"torch {torch.__version__}, CUDA available={torch.cuda.is_available()}")
    if torch.cuda.is_available():
        pr = torch.cuda.get_device_properties(0)
        say(pr.total_memory / 2**30 > 7, f"GPU {pr.name}, {pr.total_memory / 2**30:.1f} GB")
    else:
        print("       -> you probably installed the CPU build of torch; see WINDOWS_SETUP.md step 3")
except Exception as e:
    say(False, f"torch: {e}")
b = a.base_model
say(b and os.path.isfile(os.path.join(b, "config.json")), f"base model config.json in {b!r}")
say(b and any(f.endswith(".safetensors") for f in (os.listdir(b) if os.path.isdir(b) else [])), "base model *.safetensors weights present")
say(b and os.path.isfile(os.path.join(b, "tokenizer.json")), "base model tokenizer.json present")
for f in ["adapter_config.json", "adapter_model.safetensors"]:
    say(os.path.isfile(os.path.join(a.adapter, f)), f"adapter {f} in {a.adapter!r}")
say(a.asrel and os.path.isfile(a.asrel), f"CAIDA as-rel file {a.asrel!r}")
if a.load and ok:
    from llm import RouteLLM
    from asrel import ASRel
    from pipeline import classify
    import time
    t = time.time(); llm = RouteLLM(a.base_model, a.adapter, a.quant); print(f"model loaded in {time.time() - t:.0f}s")
    cand = dict(ts=1760000000, prefix="1.1.1.0/24", watched="1.1.1.0/24", subtype="origin", origin=64666, expected=[13335],
                path=[6939, 64666], collector="rrc03", peer_asn="6939")
    r = classify(cand, ASRel(a.asrel), llm)
    print("evidence:", *r["evidence"], sep="\n  "); print("raw output:", repr(r["raw_output"]), "| label:", r["label"], "| type:", r["anomaly_type"], f"| {r['latency']}s")
    import torch; print(f"peak GPU memory: {torch.cuda.max_memory_allocated() / 2**30:.1f} GB")
print("\nALL CHECKS PASSED" if ok else "\nSome checks failed; fix the [FAIL] lines above.")
