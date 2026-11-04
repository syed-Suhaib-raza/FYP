"""One-time preparation of the 4-bit CPU route (no NVIDIA GPU, 16 GB RAM laptop).

    python cpu_setup.py --install-deps     # pip install llama-cpp-python (prebuilt CPU wheel) + converter helpers
    python cpu_setup.py                    # download base GGUF, tokenizer files, converter; convert the adapter
    python cpu_setup.py --dry-run          # only print what would happen

What it does (each step is skipped if its result already exists):
  1. base model, already 4-bit:  bartowski/Meta-Llama-3.1-8B-Instruct-GGUF  Q4_K_M (~4.9 GB)      -> models/gguf/
  2. tokenizer + config files of meta-llama/Llama-3.1-8B-Instruct (small; gated -> needs HF_TOKEN)  -> models/llama31-config/
  3. llama.cpp conversion scripts (git clone, or zip download if git is missing)                    -> tools/llama.cpp/
  4. adapter (PEFT LoRA) -> GGUF with llama.cpp's convert_lora_to_gguf.py; only the base *config* is needed, not its weights
Then:  python check_setup.py --llm llamacpp --load --compare     and     python aspath.py demo --llm llamacpp
"""
import argparse, os, re, shutil, subprocess, sys, urllib.request, zipfile

GGUF_REPO, GGUF_FILE = "bartowski/Meta-Llama-3.1-8B-Instruct-GGUF", "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"
CFG_REPO, CFG_FILES = "meta-llama/Llama-3.1-8B-Instruct", ["config.json", "generation_config.json", "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json"]
LLAMACPP_GIT, LLAMACPP_ZIP = "https://github.com/ggml-org/llama.cpp.git", "https://github.com/ggml-org/llama.cpp/archive/refs/heads/master.zip"
LLAMA_CPP_WHEELS = "https://abetlen.github.io/llama-cpp-python/whl/cpu"
CONVERTER_DEPS = ["numpy", "sentencepiece", "protobuf", "pyyaml", "tqdm", "safetensors"]
GATED_HELP = ("Hugging Face refused the download. Check: (1) Meta approved your access at huggingface.co/meta-llama/Llama-3.1-8B-Instruct; "
              "(2) the token is type Read and passed with --hf-token hf_xxx or $env:HF_TOKEN.")


def missing_module(stderr):
    """'ModuleNotFoundError: No module named 'x.y'' -> 'x' (None if the text has no such error)."""
    m = re.search(r"No module named '([\w\.]+)'", stderr or "")
    return m.group(1).split(".")[0] if m else None


def converter_cmd(llamacpp_dir, cfg_dir, adapter_dir, outfile):
    return [sys.executable, os.path.join(llamacpp_dir, "convert_lora_to_gguf.py"), "--base", cfg_dir, "--outtype", "f16", "--outfile", outfile, adapter_dir]


def run(cmd, dry, **kw):
    print("  $", " ".join(map(str, cmd)))
    return None if dry else subprocess.run(cmd, text=True, capture_output=True, **kw)


def step(n, text):
    print(f"\n[{n}] {text}")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--install-deps", action="store_true", help="pip install llama-cpp-python (CPU wheel) and the converter's helper packages, then stop")
    p.add_argument("--dry-run", action="store_true"); p.add_argument("--hf-token", default=None)
    p.add_argument("--adapter", default="models/route-llm-llama3.1-8b-instruct-lora")
    p.add_argument("--gguf-dir", default="models/gguf"); p.add_argument("--config-dir", default="models/llama31-config"); p.add_argument("--tools-dir", default="tools")
    p.add_argument("--lora-out", default=None, help="default: <gguf-dir>/route-llm-lora-F16.gguf")
    a = p.parse_args(argv); dry, token = a.dry_run, a.hf_token or os.environ.get("HF_TOKEN")
    base_gguf, lora_out = os.path.join(a.gguf_dir, GGUF_FILE), a.lora_out or os.path.join(a.gguf_dir, "route-llm-lora-F16.gguf")
    llamacpp = os.path.join(a.tools_dir, "llama.cpp")
    if sys.version_info >= (3, 13):
        print(f"WARNING: Python {sys.version.split()[0]}: llama-cpp-python has prebuilt wheels for 3.10-3.12 only. Use Python 3.12 (py -3.12 -m venv .venv).")

    if a.install_deps:
        step("deps", "llama-cpp-python (prebuilt CPU wheel, no compiler needed) + converter helpers")
        r1 = run([sys.executable, "-m", "pip", "install", "llama-cpp-python", "--extra-index-url", LLAMA_CPP_WHEELS], dry)
        r2 = run([sys.executable, "-m", "pip", "install", *CONVERTER_DEPS], dry)
        for r in (r1, r2):
            if r is not None and r.returncode:
                print(r.stderr[-1500:]); print("pip failed. Windows tips: use Python 3.12; enable long paths; set $env:TEMP='C:\\tmp' before pip."); return 1
        print("\nDone. Next:  python cpu_setup.py"); return 0

    step(1, f"base model, 4-bit: {GGUF_REPO}/{GGUF_FILE} (~4.9 GB)")
    if os.path.isfile(base_gguf) and os.path.getsize(base_gguf) > 4 * 2 ** 30:
        print("  already there:", base_gguf)
    elif dry:
        print("  would download to", base_gguf)
    else:
        from huggingface_hub import hf_hub_download
        os.makedirs(a.gguf_dir, exist_ok=True)
        try:
            hf_hub_download(GGUF_REPO, GGUF_FILE, local_dir=a.gguf_dir, token=token)
        except Exception as e:
            sys.exit(f"{type(e).__name__}: {e}")
        print("  saved:", base_gguf)

    step(2, f"tokenizer + config files of {CFG_REPO} (a few MB; used for the prompt template and for converting the adapter)")
    if all(os.path.isfile(os.path.join(a.config_dir, f)) for f in CFG_FILES[:4]):
        print("  already there:", a.config_dir)
    elif dry:
        print("  would download", CFG_FILES, "to", a.config_dir)
    else:
        from huggingface_hub import hf_hub_download
        os.makedirs(a.config_dir, exist_ok=True)
        for f in CFG_FILES:
            try:
                hf_hub_download(CFG_REPO, f, local_dir=a.config_dir, token=token)
            except Exception as e:
                if f == "special_tokens_map.json":                  # optional file
                    continue
                sys.exit(f"{type(e).__name__}: {e}\n{GATED_HELP}")
        print("  saved:", a.config_dir)

    step(3, "llama.cpp conversion scripts")
    if os.path.isfile(os.path.join(llamacpp, "convert_lora_to_gguf.py")):
        print("  already there:", llamacpp)
    elif dry:
        print("  would git clone (or download the zip) to", llamacpp)
    else:
        os.makedirs(a.tools_dir, exist_ok=True)
        r = subprocess.run(["git", "clone", "--depth", "1", LLAMACPP_GIT, llamacpp], text=True, capture_output=True) if shutil.which("git") else None
        if r is None or r.returncode:
            print("  git not available or failed; downloading the zip instead ...")
            zp = os.path.join(a.tools_dir, "llama.cpp.zip")
            urllib.request.urlretrieve(LLAMACPP_ZIP, zp)
            with zipfile.ZipFile(zp) as z:
                z.extractall(a.tools_dir)
            os.replace(os.path.join(a.tools_dir, "llama.cpp-master"), llamacpp); os.remove(zp)
        print("  saved:", llamacpp)

    step(4, f"convert the adapter {a.adapter} -> {lora_out}")
    if os.path.isfile(lora_out):
        print("  already there:", lora_out)
    else:
        if not dry:
            os.makedirs(os.path.dirname(lora_out) or ".", exist_ok=True)
        r = run(converter_cmd(llamacpp, a.config_dir, a.adapter, lora_out), dry)
        if r is not None and (r.returncode or not os.path.isfile(lora_out)):
            print((r.stderr or r.stdout)[-2000:])
            mod = missing_module(r.stderr)
            print(f"\nConversion failed. {'Missing Python package: ' + mod + '. Try:  pip install ' + mod + '   (or  python cpu_setup.py --install-deps) and run this script again.' if mod else 'See the error above.'}")
            return 1
        if r is not None:
            print("  saved:", lora_out, f"({os.path.getsize(lora_out) / 2 ** 20:.0f} MB)")

    print("\nNext:\n  python check_setup.py --llm llamacpp --load --compare\n  python aspath.py demo --llm llamacpp")
    return 0


if __name__ == "__main__":
    sys.exit(main())
