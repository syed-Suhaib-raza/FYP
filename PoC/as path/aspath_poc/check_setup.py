"""Verify the machine is ready.   python check_setup.py                       (rules-only checks + Hugging Face route files)
                                   python check_setup.py --llm llamacpp        (4-bit CPU route: GGUF files, RAM, llama-cpp-python)
Add --load to also load the real model and classify two hand-made updates (minutes the first time);
add --compare to run all three prompt styles (repo / paper / infer) and print the raw outputs."""
import argparse, importlib, os, shutil, sys, time
from aspath import common

a = argparse.ArgumentParser(parents=[common()]); a.add_argument("--load", action="store_true"); a.add_argument("--compare", action="store_true")
a = a.parse_args(); ok = True; cpu = a.llm == "llamacpp"

def say(good, msg):
    global ok
    ok &= bool(good); print(("[ OK ] " if good else "[FAIL] ") + msg)

say(sys.version_info >= (3, 10), f"Python {sys.version.split()[0]} (3.10-3.12 recommended)")
if cpu:
    say(sys.version_info < (3, 13), "Python < 3.13 (llama-cpp-python wheels exist for 3.10-3.12)")
for m in (["transformers", "huggingface_hub", "websockets", "streamlit", "pandas"] if cpu else ["transformers", "peft", "accelerate", "huggingface_hub", "websockets", "streamlit", "pandas"]):
    try: say(True, f"{m} {getattr(importlib.import_module(m), '__version__', '')}")
    except Exception as e: say(False, f"{m} not importable: {str(e)[:90]}")
try:
    import torch
    print(f"[info] torch {torch.__version__}, CUDA={torch.cuda.is_available()}")
except Exception as e:
    say(False, f"torch: {e}")

try:
    import psutil; ram = psutil.virtual_memory(); free = ram.available / 2 ** 30
    if cpu: say(free >= 7, f"RAM {ram.total / 2 ** 30:.0f} GB total, {free:.1f} GB free (4-bit model needs ~7 GB free: close the browser/other apps if this fails)")
    else: say(ram.total / 2 ** 30 >= 15, f"RAM {ram.total / 2 ** 30:.0f} GB total, {free:.0f} GB free (bf16 8B needs ~16 GB; with a GPU use --quant 4bit)")
except Exception:
    print("[info] psutil missing (pip install psutil); cannot check RAM")

if cpu:
    try:
        import llama_cpp; say(True, f"llama-cpp-python {llama_cpp.__version__}")
    except Exception as e:
        say(False, f"llama-cpp-python not importable ({str(e)[:80]}): python cpu_setup.py --install-deps")
    g = os.path.isfile(a.gguf); sz = os.path.getsize(a.gguf) / 2 ** 30 if g else 0
    say(g and 4 < sz < 6, f"4-bit base GGUF {a.gguf!r} ({sz:.2f} GB, expected ~4.9 GB)  [python cpu_setup.py]")
    say(os.path.isfile(a.lora_gguf), f"adapter GGUF {a.lora_gguf!r}  [python cpu_setup.py]")
    for f in ["config.json", "tokenizer.json", "tokenizer_config.json"]:
        say(os.path.isfile(os.path.join(a.tokenizer_dir, f)), f"{f} in {a.tokenizer_dir!r}  (prompt is rendered with the HF chat template)")
    cfg = os.path.join(a.tokenizer_dir, "config.json")
    if os.path.isfile(cfg) and os.path.isfile(os.path.join(a.adapter, "adapter_model.safetensors")):
        from llm import adapter_fits_base
        good, msg = adapter_fits_base(a.adapter, cfg); say(good, msg)
else:
    b = a.base if os.path.isdir(a.base) else a.model_dir
    say(os.path.isfile(os.path.join(b, ".download_complete")) or os.path.isdir(a.base), f"base model downloaded in {b!r} (run: python aspath.py download)")
    say(os.path.isfile(os.path.join(b, "config.json")), "base model config.json"); say(os.path.isfile(os.path.join(b, "tokenizer.json")), "base model tokenizer.json")
    shards = [f for f in (os.listdir(b) if os.path.isdir(b) else []) if f.endswith(".safetensors")]
    size = sum(os.path.getsize(os.path.join(b, f)) for f in shards) / 2 ** 30
    say(len(shards) == 4 and 14.5 < size < 16.5, f"base model weights: {len(shards)} shards, {size:.1f} GB (expected 4 shards, ~15 GB bf16)")
    for f in ["adapter_config.json", "adapter_model.safetensors"]:
        say(os.path.isfile(os.path.join(a.adapter, f)), f"adapter {f} in {a.adapter!r}")
    if os.path.isfile(os.path.join(b, "config.json")) and os.path.isfile(os.path.join(a.adapter, "adapter_model.safetensors")):
        from llm import adapter_fits_base
        good, msg = adapter_fits_base(a.adapter, os.path.join(b, "config.json")); say(good, msg)
say(os.path.isfile(a.as_rel), f"AS-relationship file {a.as_rel!r} (demo file ok; use CAIDA for real runs)")
print(f"[info] free disk here: {shutil.disk_usage('.').free / 2**30:.0f} GB")

if a.load and ok:
    from llm import LlamaCpp, RouteLLM
    from pipeline import ownership_lines
    from prompt import STYLES, build_messages, parse_label
    t = time.time()
    m = LlamaCpp(a.gguf, a.lora_gguf, a.tokenizer_dir, a.threads, a.n_ctx) if cpu else RouteLLM(a.base, a.adapter, a.model_dir, a.hf_token, a.quant)
    print(f"model loaded in {time.time() - t:.0f}s")
    # two hand-made updates for 72.255.0.0/18 (expected origin AS9541): a path with an unseen link next to the origin, and the usual path
    base = dict(ts=1760001100, prefix="72.255.0.0/18", watched="72.255.0.0/18", expected=[9541], origin=9541, peer_asn="1299", peer_ip="192.0.2.49", origin_attr="igp")
    odd = dict(base, path=[1299, 64510, 9541])
    usual = dict(base, path=[1299, 3356, 17557, 9541])
    ev_odd = ownership_lines(odd) + ["AS9541 was observed as an origin of 72.255.0.0/18 before the event time.", "AS64510-AS9541 was never observed before event time.",
                                     "No known relationship between AS1299 and AS64510."]
    ev_usual = ownership_lines(usual) + ["AS17557-AS9541 was observed before.", "AS17557 is a provider of AS9541."]
    f_odd = dict(watched=odd["watched"], expected=[9541], origin=9541, links=[(1299, 64510, 0), (64510, 9541, 0)], rels=[])
    f_usual = dict(watched=usual["watched"], expected=[9541], origin=9541, links=[(1299, 3356, 3), (3356, 17557, 3), (17557, 9541, 3)], rels=[(17557, 9541, -1)])
    for style in (STYLES if a.compare else (a.prompt,)):
        for name, (u, ev, f) in {"odd-path": (odd, ev_odd, f_odd), "usual-path": (usual, ev_usual, f_usual)}.items():
            t = time.time(); raw = m.generate(build_messages(u, ev, style, f))
            print(f"[{style}] {name}: raw={raw!r} -> {parse_label(raw)} ({time.time() - t:.1f}s)")
print("\nALL CHECKS PASSED" if ok else "\nSome checks failed; fix the [FAIL] lines above.")
