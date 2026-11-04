"""Model wrappers (same shape as the unexpectedOrigin PoC): RouteLLM = Llama-3.1-8B-Instruct + the released LoRA adapter,
MockLLM = NOT a model. The PoC can download the base model itself (resolve_base)."""
import json, os, re, struct, sys

GATED_HELP = ("\nDownload refused. Check: (1) Meta approved your access at huggingface.co/meta-llama/Llama-3.1-8B-Instruct "
              "(status: huggingface.co/settings/gated-repos); (2) your token is type Read and passed via --hf-token hf_xxx or the "
              "HF_TOKEN environment variable (or run `huggingface-cli login` once).")


def resolve_base(base, model_dir, token=None):
    """Local folder -> use it. Otherwise download the HF repo into model_dir once (resumable), then reuse it."""
    if os.path.isdir(base):
        return base
    marker = os.path.join(model_dir, ".download_complete")
    if os.path.exists(marker):
        return model_dir
    from huggingface_hub import snapshot_download
    print(f"Downloading {base} (~16 GB) into {model_dir} ... (resumes if interrupted)", flush=True)
    try:
        snapshot_download(repo_id=base, local_dir=model_dir, token=token or os.environ.get("HF_TOKEN"), ignore_patterns=["original/*"])
    except Exception as e:
        sys.exit(f"{type(e).__name__}: {e}" + (GATED_HELP if any(k in str(e).lower() for k in ("401", "403", "gated", "restricted")) else ""))
    open(marker, "w").write("ok")
    return model_dir


CPU_HELP = ("\nNo NVIDIA GPU detected, so the Hugging Face route (bitsandbytes 4-bit / bf16) cannot run here: bf16 needs ~16 GB for the weights alone.\n"
            "Use the 4-bit CPU route instead (about 6 GB RAM, no GPU):\n"
            "    python cpu_setup.py                      (one-time: downloads the 4-bit base GGUF, converts the adapter)\n"
            "    python aspath.py demo --llm llamacpp\n")


def _cpu_guard(quant):
    """On CPU the HF route only makes sense with plenty of RAM. With less than ~20 GB, stop early with a clear message instead of thrashing."""
    try:
        import psutil
        total = psutil.virtual_memory().total / 2 ** 30
    except Exception:
        return                                              # cannot tell: let it try
    if quant != "bf16" or total < 20:
        sys.exit(f"RAM {total:.0f} GB, no NVIDIA GPU, quant={quant}." + CPU_HELP)


class RouteLLM:
    name = "routellm-lora"

    def __init__(self, base="meta-llama/Llama-3.1-8B-Instruct", adapter="models/route-llm-llama3.1-8b-instruct-lora",
                 model_dir="models/llama31-8b-instruct", token=None, quant="bf16"):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from peft import PeftModel
        path = resolve_base(base, model_dir, token)
        self.tok = AutoTokenizer.from_pretrained(path)        # standard tokenizer, as in the released adapter's README
        kw = {"device_map": "auto", "low_cpu_mem_usage": True}
        if not torch.cuda.is_available():
            _cpu_guard(quant)
            quant = "bf16"
        if quant == "4bit":
            from transformers import BitsAndBytesConfig
            kw["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16)
        elif quant == "8bit":
            from transformers import BitsAndBytesConfig
            kw["quantization_config"] = BitsAndBytesConfig(load_in_8bit=True)
        else:
            kw["torch_dtype"] = torch.bfloat16
        self.model = PeftModel.from_pretrained(AutoModelForCausalLM.from_pretrained(path, **kw), adapter).eval()
        self.torch = torch
        print(f"RouteLLM ready: {path} + {adapter} on {self.model.device} ({quant})", flush=True)

    def generate(self, messages, max_new_tokens=64):   # 64: the training answer is JSON; a tiny limit would cut off anomaly_type
        ids = self.tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt").to(self.model.device)
        with self.torch.no_grad():
            out = self.model.generate(ids, max_new_tokens=max_new_tokens, do_sample=False, pad_token_id=self.tok.eos_token_id)
        return self.tok.decode(out[0][ids.shape[1]:], skip_special_tokens=True).strip()


class LlamaCpp:
    """4-bit CPU route (no NVIDIA GPU, ~6 GB RAM): Llama-3.1-8B-Instruct Q4_K_M GGUF + the LoRA adapter converted to GGUF, run by llama.cpp.
    Prompt text: rendered with the SAME Hugging Face chat template RouteLLM uses (tokenizer files in tokenizer_dir), then tokenised without an
    extra BOS and decoded greedily, so the model sees the same text as in the unexpectedOrigin PoC. If no tokenizer files are available it falls
    back to llama.cpp's own chat template. Prepare the files with:  python cpu_setup.py"""
    name = "routellm-lora-gguf-q4"
    STOP = ["<|eot_id|>", "<|end_of_text|>"]

    def __init__(self, gguf, lora_gguf, tokenizer_dir=None, threads=6, n_ctx=2048):
        for what, p in (("base GGUF", gguf), ("LoRA GGUF", lora_gguf)):
            if not p or not os.path.isfile(p):
                sys.exit(f"{what} not found: {p!r}\nRun the one-time preparation:  python cpu_setup.py")
        try:
            from llama_cpp import Llama
        except ImportError:
            sys.exit("llama-cpp-python is not installed. Run:  pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu"
                     "   (Python 3.10-3.12)")
        self.n_ctx = n_ctx
        self.m = Llama(model_path=gguf, lora_path=lora_gguf, n_ctx=n_ctx, n_threads=threads, n_batch=512, use_mmap=True, verbose=False)
        self.tok = None
        if tokenizer_dir and os.path.isfile(os.path.join(tokenizer_dir, "tokenizer.json")):
            try:
                from transformers import AutoTokenizer
                self.tok = AutoTokenizer.from_pretrained(tokenizer_dir)
            except Exception as e:
                print(f"WARNING: could not load the HF tokenizer from {tokenizer_dir!r} ({type(e).__name__}); using llama.cpp's chat template.", flush=True)
        print(f"RouteLLM ready (llama.cpp, 4-bit): {os.path.basename(gguf)} + {os.path.basename(lora_gguf)}, {threads} threads, "
              f"prompt via {'HF chat template' if self.tok else 'llama.cpp chat template'}", flush=True)

    def render(self, messages):
        return self.tok.apply_chat_template(messages, add_generation_prompt=True, tokenize=False)

    def generate(self, messages, max_new_tokens=64):
        if self.tok is None:
            r = self.m.create_chat_completion(messages=messages, max_tokens=max_new_tokens, temperature=0.0)
            return r["choices"][0]["message"]["content"].strip()
        ids = self.m.tokenize(self.render(messages).encode("utf-8"), add_bos=False, special=True)    # the template already contains <|begin_of_text|>
        if len(ids) + max_new_tokens > self.n_ctx:
            raise ValueError(f"prompt has {len(ids)} tokens, context is {self.n_ctx}: use --n-ctx {len(ids) + max_new_tokens + 256} or --top-k with a smaller value")
        r = self.m.create_completion(ids, max_tokens=max_new_tokens, temperature=0.0, stop=self.STOP)
        return r["choices"][0]["text"].strip()


class MockLLM:
    """NOT a real model. Rule-of-thumb stand-in so the pipeline/dashboard can be tested without the model. Rows are tagged model=MOCK."""
    name = "MOCK"

    def generate(self, messages, max_new_tokens=64):
        u = messages[-1]["content"]
        pfx = re.search(r"(?:ANNOUNCE: |PREFIX: |\"prefix\": \")(\S+?)[,\"\s]", u + " ")
        path = re.search(r"(?:ASPATH: |\"as_path\": \")([\d ]+)", u)
        n, plen = len(path.group(1).split()) if path else 0, int(pfx.group(1).split("/")[1]) if pfx else 0
        t = "prefix_hijack" if n == 2 and plen >= 24 else "route_leak" if n > 4 else "none"
        return '{"label": "normal", "anomaly_type": "none"}' if t == "none" else f'{{"label": "anomalous", "anomaly_type": "{t}"}}'


def make_llm(a):
    if a.llm == "hf":
        return RouteLLM(a.base, a.adapter, a.model_dir, a.hf_token, a.quant)
    if a.llm == "llamacpp":
        return LlamaCpp(a.gguf, a.lora_gguf, a.tokenizer_dir, a.threads, a.n_ctx)
    if a.llm == "mock":
        print("WARNING: --llm mock is a fake classifier for testing only, not the ROUTE LLM.", flush=True)
        return MockLLM()
    return None


def adapter_fits_base(adapter_dir, base_config):
    """Cheap compatibility check (no model load): every LoRA tensor shape in the adapter must match the base model's config.json.
    Returns (ok, message)."""
    cfg = json.load(open(base_config)); ac = json.load(open(os.path.join(adapter_dir, "adapter_config.json")))
    H, I, nh, nkv, L = cfg["hidden_size"], cfg["intermediate_size"], cfg["num_attention_heads"], cfg["num_key_value_heads"], cfg["num_hidden_layers"]
    hd, r = cfg.get("head_dim") or H // nh, ac["r"]
    want = {"q_proj": (H, nh * hd), "k_proj": (H, nkv * hd), "v_proj": (H, nkv * hd), "o_proj": (nh * hd, H),
            "gate_proj": (H, I), "up_proj": (H, I), "down_proj": (I, H)}          # (in_features, out_features)
    with open(os.path.join(adapter_dir, "adapter_model.safetensors"), "rb") as f:
        head = json.loads(f.read(struct.unpack("<Q", f.read(8))[0]))
    bad, layers = [], set()
    for k, v in head.items():
        m = re.search(r"layers\.(\d+)\..*?(\w+_proj)\.lora_([AB])\.weight", k)
        if not m: continue
        layers.add(int(m.group(1))); i, o = want[m.group(2)]
        exp = [r, i] if m.group(3) == "A" else [o, r]
        if v["shape"] != exp: bad.append(f"{k}: {v['shape']} != {exp}")
    ok = not bad and layers == set(range(L)) and ac["base_model_name_or_path"].lower().endswith("llama-3.1-8b-instruct")
    return ok, (f"adapter fits base: {len(layers)} layers, rank {r}, hidden {H}, kv-heads {nkv}, intermediate {I}" if ok else
                f"MISMATCH ({len(bad)} bad tensors, layers {len(layers)}/{L}): " + "; ".join(bad[:2]))
