"""Check CPU staging on a digest-pinned worker image. Requires Docker.

The optional simulator mount tests an adapter before a release build. Run
again without that mount on the published image before signing the release.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import tempfile
import time
import uuid

BASE = "/opt/confidential-inference/sglang-simulator"
PYTHON = "/opt/dsv41/bin/python"
MODEL = "hf-internal-testing/tiny-random-LlamaForCausalLM"
PROBE = r'''
import json
import urllib.request

base = "http://127.0.0.1:18083"
model = "hf-internal-testing/tiny-random-LlamaForCausalLM"
with urllib.request.urlopen(base + "/v1/models", timeout=30) as response:
    catalog = json.load(response)
    assert any(item["id"] == model for item in catalog["data"]), catalog
print("Model catalog passed")
requests = [
    ("/v1/completions", {"prompt": "Hello"}),
    ("/v1/chat/completions", {"messages": [{"role": "user", "content": "Hello"}]}),
]
for route, body in requests:
    for stream in (False, True):
        payload = dict(body, model=model, max_tokens=4, temperature=0, stream=stream)
        request = urllib.request.Request(
            base + route, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read().decode()
        if stream:
            assert "data: [DONE]" in data, data
            chunks = [json.loads(line[6:]) for line in data.splitlines()
                      if line.startswith("data: ") and line != "data: [DONE]"]
            assert chunks and all(chunk["model"] == model for chunk in chunks), data
            choices = [choice for chunk in chunks for choice in chunk["choices"]]
            assert any(choice.get("finish_reason") in ("stop", "length")
                       for choice in choices), data
            assert any(choice.get("text") or choice.get("delta", {}).get("content")
                       for choice in choices), data
        else:
            result = json.loads(data)
            assert result["model"] == model and result["choices"], result
            assert result["usage"]["completion_tokens"] > 0, result
            choice = result["choices"][0]
            assert choice["finish_reason"] in ("stop", "length"), result
            assert choice.get("text") or choice.get("message", {}).get("content"), result
        print(route, "stream=" + str(stream), "passed")
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="worker image pinned by SHA-256")
    parser.add_argument("--simulator-source", type=pathlib.Path,
                        help="prepared simulator directory for an optional source test")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", args.image) is None:
        parser.error("image must be pinned by SHA-256")
    output = args.output or pathlib.Path(tempfile.mkdtemp(prefix="sglang-smoke-"))
    output.mkdir(parents=True, exist_ok=True)
    name = "sglang-smoke-" + uuid.uuid4().hex[:12]
    command = [
        "docker", "run", "-d", "--name", name, "--network", "none",
        "--cpus", "4", "--memory", "16g", "--shm-size", "1g", "--user", "1001:1001",
    ]
    if args.simulator_source:
        command += ["--mount", f"type=bind,src={args.simulator_source.resolve()},dst={BASE},readonly"]
    for value in (
        f"PYTHONPATH={BASE}/src", "SGLANG_USE_CPU_ENGINE=1", "CUDA_VISIBLE_DEVICES=",
        "HF_HUB_OFFLINE=1", "TRANSFORMERS_OFFLINE=1", "SGLANG_SIMULATOR_OUTPUT_MODE=BLOCKING",
    ):
        command += ["--env", value]
    command += [
        "--entrypoint", PYTHON, args.image, "-m",
        "sglang_simulator.simulation.sglang.launch_server",
        f"--model-path={BASE}/test/assets/qwen3-8b",
        f"--tokenizer-path={BASE}/examples/assets/tokenizer",
        f"--sim-config-path={BASE}/examples/sim_configs/replay.json",
        f"--served-model-name={MODEL}", "--chat-template=chatml",
        "--reasoning-parser=deepseek-v41", "--max-total-tokens=8192",
        "--max-running-requests=48", "--random-seed=0", "--enable-metrics",
        "--enable-cache-report", "--host=0.0.0.0", "--port=18083",
    ]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            running = subprocess.check_output(
                ["docker", "inspect", "--format", "{{.State.Running}}", name], text=True,
            ).strip()
            if running != "true":
                raise RuntimeError("Simulator exited during startup")
            check = subprocess.run(
                ["docker", "exec", name, PYTHON, "-c",
                 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:18083/health",timeout=2).read()'],
                capture_output=True, text=True,
            )
            if check.returncode == 0:
                break
            time.sleep(3)
        else:
            raise RuntimeError("Simulator startup timed out")
        print("CPU simulator healthy", flush=True)
        result = subprocess.run(
            ["docker", "exec", "-i", name, PYTHON, "-"], input=PROBE,
            text=True, capture_output=True, timeout=300,
        )
        print(result.stdout + result.stderr, flush=True)
        result.check_returncode()
        (output / "simulator-result.txt").write_text(
            f"Image: {args.image}\nSimulator mount: {args.simulator_source}\n" + result.stdout,
        )
    finally:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        (output / "simulator-runtime.log").write_text(logs.stdout + logs.stderr)
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, check=False)
        print("Evidence:", output, flush=True)


if __name__ == "__main__":
    main()
