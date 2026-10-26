"""Model wrappers. RouteLLM = Llama-3.1-8B-Instruct + the released LoRA adapter. torch/transformers imported lazily."""
import time


class RouteLLM:
    name = "routellm-lora"

    def __init__(self, base="meta-llama/Meta-Llama-3.1-8B-Instruct", adapter="models/route-llm-llama3.1-8b-instruct-lora",
                 quant="4bit"):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import PeftModel
        self.tok = AutoTokenizer.from_pretrained(base)       # standard tokenizer (see README caveat)
        kw = {"device_map": "auto"}
        if quant == "4bit":
            kw["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                                           bnb_4bit_compute_dtype=torch.bfloat16)
        elif quant == "8bit":
            kw["quantization_config"] = BitsAndBytesConfig(load_in_8bit=True)
        else:
            kw["torch_dtype"] = torch.bfloat16
        model = AutoModelForCausalLM.from_pretrained(base, **kw)
        self.model = PeftModel.from_pretrained(model, adapter).eval()
        self.torch = torch

    def generate(self, messages, max_new_tokens=32):
        ids = self.tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt").to(self.model.device)
        with self.torch.no_grad():
            out = self.model.generate(ids, max_new_tokens=max_new_tokens, do_sample=False,
                                      pad_token_id=self.tok.eos_token_id)
        return self.tok.decode(out[0][ids.shape[1]:], skip_special_tokens=True).strip()


class MockLLM:
    """NOT a real model. Rule-of-thumb stand-in so the pipeline can be tested without a GPU."""
    name = "MOCK"

    def generate(self, messages, max_new_tokens=32):
        u = messages[-1]["content"]
        return "none" if ("are siblings" in u or "is a provider of" in u.split("expected")[0]) and "No known relationship between AS" not in u.split("\n")[u.split("\n").index("Retrieved AS relationship knowledge:") + 1] else "prefix hijack"
