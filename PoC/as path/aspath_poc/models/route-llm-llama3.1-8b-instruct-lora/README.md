---
base_model: meta-llama/Meta-Llama-3.1-8B-Instruct
library_name: peft
pipeline_tag: text-generation
tags:
  - bgp
  - routing-security
  - lora
  - peft
---

# ROUTE LLM Llama 3.1 8B Instruct LoRA

This directory contains the PEFT/LoRA adapter released with ROUTE LLM, a
research prototype for classifying BGP routing updates as normal or anomalous.
It is designed to be loaded on top of
`meta-llama/Meta-Llama-3.1-8B-Instruct`; the base-model weights are not included.

## Intended use

The adapter is intended for research on BGP routing-security analysis,
including prefix hijacks, path or route hijacks, and route leaks. The repository
inference script can augment a BGP update with AS-relationship statements before
classification.

This model is not an autonomous routing-security authority. Do not trigger
filtering, mitigation, attribution, or operator notifications solely from its
output. Predictions require validation with routing telemetry and expert review.

## Files

- `adapter_model.safetensors`: LoRA adapter weights.
- `adapter_config.json`: PEFT adapter configuration and base-model identifier.
- `README.md`: this model card.

Training checkpoints, optimizer state, random-number-generator state, and other
resume-only artifacts are intentionally excluded.

## Loading the adapter

Install the repository dependencies, obtain access to the base model, and run:

```python
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

base_model_id = "meta-llama/Meta-Llama-3.1-8B-Instruct"
adapter_path = "models/route-llm-llama3.1-8b-instruct-lora"

tokenizer = AutoTokenizer.from_pretrained(base_model_id)
base_model = AutoModelForCausalLM.from_pretrained(
    base_model_id,
    torch_dtype="auto",
    device_map="auto",
)
model = PeftModel.from_pretrained(base_model, adapter_path)
model.eval()
```

For an end-to-end command-line example, see `inference/inference.py` and the
repository README.

## Adapter configuration

The released configuration uses LoRA rank 8, alpha 32, dropout 0.1, and targets
the attention projection layers plus the MLP gate, up, and down projection
layers. Refer to `adapter_config.json` for the machine-readable configuration.

## Training and evaluation context

The adapter was fine-tuned for BGP anomaly classification using processed
routing-update text and routing-domain instructions. The code for data
collection, preprocessing, and LoRA training is included in the repository.

The public package does not yet include a fully reproducible, licensed training
dataset or a standalone evaluation bundle. Consequently, users should not infer
production-level accuracy, coverage, or robustness from this release alone.

## Limitations

- Results depend on the quality and freshness of BGP evidence and retrieved
  AS-relationship data.
- Novel incidents, ambiguous paths, incomplete telemetry, and policy exceptions
  may lead to incorrect classifications.
- The current inference example retrieves AS-relationship statements; it does
  not reproduce every retrieval component explored in the accompanying work.
- Behavior inherits limitations and acceptable-use constraints from the Meta
  Llama 3.1 base model.

## License

The adapter files in this repository are released under Apache-2.0. The Meta
Llama 3.1 base model is not included and remains subject to Meta's separate
license and acceptable-use terms. See the repository `LICENSE` file.

## Citation

The final citation will be added when the accompanying paper's bibliographic
record is available.
