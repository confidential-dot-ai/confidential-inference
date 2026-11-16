"""Make exact-token transport inputs with the pinned model's reference encoder.

Install tokenizers==0.22.2 in the test environment. Supply tokenizer.json and
encoding/encoding.py from the model revision below. No model weights are used.
"""

import argparse
import hashlib
import json
import runpy
from pathlib import Path

from tokenizers import Tokenizer

MODEL = "deepseek-ai/DeepSeek-V4.1-Flash-1017"
REVISION = "1bae0e1088993b9b82de08f59de5be5a34e42170"
FILES = {
    "tokenizer.json": "c90dfa01249db1be4245780a052ede752e1361c612ac6d08e2bdada7d599476b",
    "tokenizer_config.json": "6ac8c8dc065ed118161d02dd532749ae3f52c243deac27872134fae2f50d8547",
    "encoding/encoding.py": "13231c592e958fb39e2af6001dae69d90e7a36b265702b9b390236fb387599e2",
}


def generate(directory, output, requests, context_tokens, output_tokens):
    for name, expected in FILES.items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != expected:
            raise ValueError("the tokenizer files do not match the model revision")
    encode = runpy.run_path(str(directory / "encoding/encoding.py"))["encode_messages"]
    tokenizer = Tokenizer.from_file(str(directory / "tokenizer.json"))
    target = context_tokens - output_tokens
    output.mkdir(parents=True, exist_ok=True)
    records = []
    for index in range(requests):
        prefix, unit = f"request-{index:04d}:", " hello"
        def count(content):
            prompt = encode([{"role": "user", "content": content}], thinking_mode="chat")
            return len(tokenizer.encode(prompt, add_special_tokens=False))
        repetitions = target - count(prefix + unit * 2) + 2
        content = prefix + unit * repetitions
        actual = count(content)
        if actual != target:
            raise ValueError(f"request {index} has {actual} input tokens, expected {target}")
        body = json.dumps({"model": "model-a", "stream": True, "max_tokens": output_tokens,
            "chat_template_kwargs": {"thinking": False}, "messages": [{"role": "user", "content": content}]},
            ensure_ascii=False, separators=(",", ":")).encode()
        name = f"request-{index:04d}.json"
        (output / name).write_bytes(body)
        records.append({"file": name, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
        if (index + 1) % 8 == 0:
            print(f"Verified {index + 1} inputs", flush=True)
    metadata = {"model": MODEL, "revision": REVISION, "tokenizer_files": FILES, "thinking_mode": "chat",
        "input_tokens": target, "output_token_budget": output_tokens, "context_tokens": context_tokens,
        "requests": records, "transport_only": True}
    (output / "corpus.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tokenizer-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--requests", type=int, default=64)
    parser.add_argument("--context-tokens", type=int, default=1048576)
    parser.add_argument("--output-tokens", type=int, default=20)
    args = parser.parse_args()
    if not 1 <= args.requests <= 1024 or not 0 < args.output_tokens < args.context_tokens:
        parser.error("invalid request count or token budget")
    generate(args.tokenizer_directory, args.output, args.requests, args.context_tokens, args.output_tokens)
