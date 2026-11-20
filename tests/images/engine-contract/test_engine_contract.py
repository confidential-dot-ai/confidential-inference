#!/usr/bin/env python3
"""The contract of one SGLang engine image. Requires Docker, not a GPU.

Set ENGINE_IMAGE to an image reference pinned by SHA-256
(repository@sha256:<64 hex>). Without it, every test is skipped. The tests
run the image with no network, as uid 1001, on a read-only root filesystem
with a /tmp tmpfs, as the chart runs it. They check:

- the image config: user 1001 and HOME=/tmp;
- the root filesystem: uid 1001 can write nothing below /opt, and SGLang
  imports with a read-only root;
- the helpers: /usr/local/bin/wait-for-model, fetch-model and dcgm-exporter
  are executable files;
- the HTTP routes: the hardened app has the serving routes the gateway uses
  and no route outside the reviewed serving set (no admin, profiling,
  weight-update or documentation route);
- the refused settings: launch_server refuses each setting that logs or
  dumps request data (harden_http.REFUSED_SERVER_ARGS) before it starts;
- the FlashInfer kernels: each flashinfer_jit_cache provider for sm100a (B200)
  and sm103a (B300) carries jit_cache/sampling/sampling.so, so the first
  top-k/top-p request does not JIT-compile it;
- the supervisor: wait-for-model checks a model and runs a fake server
  that prints request text. Its stdout holds only events of the worker log
  policy (templates/_log-policy.tpl) with valid fields, and neither stdout
  nor stderr holds the server output;
- the CPU simulator: the worker command that the chart renders for
  inference.mode=simulator starts in the image, answers /health and
  completes one chat request.

confidential-dot-ai/confidential-sglang builds the image and tests its
helpers (`confidential/helpers`, `confidential/tests/helpers`) before it
publishes a release record; these tests check the result as this
repository's chart runs it.

Run:

    ENGINE_IMAGE=<repository>@sha256:<digest> \\
      python3 -m unittest discover -s tests/images/engine-contract -p 'test_*.py'

If the Docker daemon uses a different temporary directory, set
ENGINE_CONTRACT_TMPDIR to a directory shared by this process and the daemon.
"""
from __future__ import annotations

import functools
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]
IMAGE = os.environ.get("ENGINE_IMAGE", "")
PINNED = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
HELPERS = ("/usr/local/bin/wait-for-model", "/usr/local/bin/fetch-model", "/usr/local/bin/dcgm-exporter")
ARCHITECTURES = ("sm100a", "sm103a")
# The routes the gateway and the probes call. Each one must be present.
REQUIRED_ROUTES = {"/health", "/health_generate", "/v1/chat/completions", "/v1/completions", "/v1/models",
                   "/generate"}
MARKER = "ENGINE-CONTRACT-RESULT "
SECRET = "ENGINE-CONTRACT-PROMPT-TEXT"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The settings that log or dump request data. The image's build-time
# hardening (confidential-sglang confidential/helpers/harden_http.py,
# REFUSED_SERVER_ARGS) makes launch_server refuse each one.
REFUSED_SERVER_ARGS = (
    "log_requests", "log_requests_target", "crash_dump_folder",
    "export_metrics_to_file", "export_metrics_to_file_dir",
    "debug_tensor_dump_output_folder", "debug_tensor_dump_input_file",
    "msprobe_dump_config", "forward_hooks", "spec_trace_dir",
)
# The routes of http_server.py that the hardening keeps (confidential-sglang
# confidential/tests/helpers/test_http_policy.py SERVING_ROUTES).
SERVING_ROUTES = {
    "/", "/health", "/health_generate", "/model_info", "/get_model_info", "/server_info",
    "/get_server_info", "/generate", "/encode", "/classify",
    "/parse_function_call", "/separate_reasoning", "/v1/completions", "/v1/chat/completions",
    "/v1/embeddings", "/v1/classify", "/v1/tokenize", "/tokenize", "/v1/detokenize", "/detokenize",
    "/v1/audio/transcriptions", "/v1/realtime", "/v1/models", "/v1/models/{model:path}", "/v1/score",
    "/v1/responses", "/v1/responses/{response_id}", "/v1/responses/{response_id}/cancel",
    "/v1/rerank", "/api/chat", "/api/generate", "/api/tags", "/api/show", "/v1/messages",
    "/v1/messages/count_tokens", "/ping", "/invocations", "/vertex_generate",
}
# /v1/loads (v1_loads_router) and /metrics (--enable-metrics) are outside
# http_server.py; the pinned sources keep /get_load or /ready.
ALLOWED_ROUTES = SERVING_ROUTES | {"/get_load", "/ready", "/v1/loads", "/metrics"}
# Paths that must never be served, whatever the allowlist above says.
FORBIDDEN_ROUTE = re.compile(
    r"weight|profile|flush|memory_occupation|lora|expert_distribution|internal_state|abort|"
    r"configure_logging|dump|openapi|/docs|/redoc|admin|debug|freeze_gc|slow_down|pause|continue_generation")

PROBE = r'''
import importlib.util, json, pathlib, sys, types
result = {}
from sglang.srt.entrypoints import http_server
result["routes"] = sorted({route.path for route in http_server.app.routes if getattr(route, "path", None)})
refused = json.loads(sys.argv[1])
outcome = {}
def attempt(arguments):
    try:
        http_server.launch_server(types.SimpleNamespace(**arguments))
    except RuntimeError as error:
        return "refused" if "does not log or dump request data" in str(error) else "other"
    except Exception:
        return "other"
    return "started"
outcome[""] = attempt({name: None for name in refused})
for name in refused:
    outcome[name] = attempt({**{other: None for other in refused}, name: True})
result["refusal"] = outcome
spec = importlib.util.find_spec("flashinfer_jit_cache")
providers = {}
if spec is not None and spec.origin:
    root = pathlib.Path(spec.origin).parent / "providers"
    for architecture in json.loads(sys.argv[2]):
        library = root / architecture / "jit_cache/sampling/sampling.so"
        providers[architecture] = library.is_file() and library.stat().st_size > 0
result["flashinfer_jit_cache"] = spec is not None
result["providers"] = providers
print("ENGINE-CONTRACT-RESULT " + json.dumps(result), flush=True)
'''

FAKE_SERVER = r'''
import http.server, sys, threading
port = int(next(a for a in sys.argv[1:] if a.startswith("--port=")).split("=", 1)[1])
print("ENGINE-CONTRACT-PROMPT-TEXT on stdout", flush=True)
print("ENGINE-CONTRACT-PROMPT-TEXT on stderr", file=sys.stderr, flush=True)
done = threading.Event()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/health" else 404)
        self.end_headers()
        if self.path == "/health":
            threading.Timer(3.0, done.set).start()
    def log_message(self, *args):
        sys.stderr.write("ENGINE-CONTRACT-PROMPT-TEXT access log\n")
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
done.wait(120)
server.shutdown()
'''


# Runs the chart's simulator worker command (argv and env from the rendered
# StatefulSet) and sends it one health check and one chat request over
# loopback. Prints one result line; the server's own output is discarded.
SIMULATOR = r'''
import json, os, subprocess, sys, time, urllib.request
spec = json.loads(sys.argv[1])
server = subprocess.Popen(spec["argv"], env={**os.environ, **spec["env"]},
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
base = "http://127.0.0.1:%d" % spec["port"]
result = {"health": None, "chat": None}
deadline = time.monotonic() + spec["timeout"]
try:
    while time.monotonic() < deadline and server.poll() is None:
        try:
            with urllib.request.urlopen(base + "/health", timeout=5) as response:
                result["health"] = response.status
                break
        except Exception:
            time.sleep(2)
    if result["health"] == 200:
        body = json.dumps({"model": spec["model"], "max_tokens": 8, "temperature": 0,
                           "messages": [{"role": "user", "content": "Say hello."}]}).encode()
        request = urllib.request.Request(base + "/v1/chat/completions", data=body,
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=120) as response:
            reply = json.loads(response.read())
        result["chat"] = {"status": response.status, "choices": len(reply.get("choices") or []),
                          "content": isinstance(reply["choices"][0]["message"].get("content"), str)}
finally:
    result["exit"] = server.poll()
    server.terminate()
    try:
        _, stderr = server.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        server.kill()
        _, stderr = server.communicate()
    if result["chat"] is None:
        result["stderr"] = stderr.decode(errors="replace")[-4000:]
    print("ENGINE-CONTRACT-RESULT " + json.dumps(result), flush=True)
'''


def simulator_worker() -> dict:
    """The worker container that the chart renders for inference.mode=simulator, with this image."""
    rendered = subprocess.run(
        ["helm", "template", "contract", str(ROOT / "helm/confidential-inference"),
         "--set", "inference.mode=simulator", "--set", f"images.confidentialSglangEngine={IMAGE}"],
        text=True, capture_output=True, check=True).stdout
    for document in yaml.safe_load_all(rendered):
        if document and document.get("kind") == "StatefulSet" and document["metadata"]["name"] == "inference-worker":
            return next(container for container in document["spec"]["template"]["spec"]["containers"]
                        if container["name"] == "sglang")
    raise AssertionError("the chart renders no inference-worker StatefulSet")


def docker(*arguments: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *arguments], text=True, capture_output=True, timeout=timeout, check=False)


def run_args(*extra: str, read_only: bool = True) -> list[str]:
    """The `docker run` options of the chart's worker: no network, uid 1001, read-only root."""
    root = ["--read-only", "--tmpfs", "/tmp:rw,exec,size=1g"] if read_only else []
    return ["run", "--rm", "--network", "none", "--user", "1001:1001", *root,
            "--env", "CUDA_VISIBLE_DEVICES=", *extra]


@functools.lru_cache(maxsize=None)
def image_config() -> dict:
    result = docker("image", "inspect", "--format", "{{json .Config}}", IMAGE)
    if result.returncode:
        pulled = docker("pull", "--quiet", IMAGE, timeout=3600)
        if pulled.returncode:
            raise AssertionError(f"cannot pull {IMAGE}: {pulled.stderr.strip()}")
        result = docker("image", "inspect", "--format", "{{json .Config}}", IMAGE)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


@functools.lru_cache(maxsize=None)
def probe() -> dict:
    result = docker(*run_args("--entrypoint", "python3"), IMAGE, "-c", PROBE,
                    json.dumps(list(REFUSED_SERVER_ARGS)), json.dumps(ARCHITECTURES))
    lines = [line for line in result.stdout.splitlines() if line.startswith(MARKER)]
    if result.returncode or len(lines) != 1:
        raise AssertionError(f"the probe failed ({result.returncode}): {result.stderr[-4000:]}")
    return json.loads(lines[0].removeprefix(MARKER))


def worker_log_policy() -> dict:
    """The inference-worker entry of templates/_log-policy.tpl (pure YAML inside the define)."""
    text = (ROOT / "helm/confidential-inference/templates/_log-policy.tpl").read_text()
    body = text.split('{{- define "confidential-inference.logPolicy" -}}', 1)[1].split("{{- end -}}", 1)[0]
    return yaml.safe_load(body)["structured"]["inference-worker"]


def policy_violations(record: dict, policy: dict) -> list[str]:
    """The ways one record breaks the worker log policy: its event and each field."""
    problems = []
    if record.get("event") not in policy["events"]:
        problems.append(f"event {record.get('event')!r} is not in the policy")
    for name, value in record.items():
        if name == "event" or value is None:
            continue
        rule = policy["fields"].get(name)
        if rule is None:
            problems.append(f"field {name} is not in the policy")
        elif rule.get("int"):
            if not isinstance(value, int) or isinstance(value, bool):
                problems.append(f"field {name} is not an integer")
        elif not isinstance(value, str) or re.search(rule["string"], value) is None:
            problems.append(f"field {name} does not match its pattern")
    return problems


@unittest.skipUnless(IMAGE, "set ENGINE_IMAGE to an engine image pinned by digest")
class EngineContractTests(unittest.TestCase):
    def test_reference_is_pinned_by_digest(self) -> None:
        self.assertRegex(IMAGE, PINNED)

    def test_user_and_home(self) -> None:
        config = image_config()
        self.assertIn(config.get("User", ""), {"1001", "1001:1001"})
        env = dict(item.split("=", 1) for item in config.get("Env") or [])
        self.assertEqual(env.get("HOME"), "/tmp")

    def test_opt_is_not_writable_and_helpers_are_executable(self) -> None:
        script = ("find /opt -xdev -writable -print 2>/dev/null | head -20; "
                  + "".join(f"test -f {path} && test -x {path} || echo missing:{path}; " for path in HELPERS))
        # A read-only root hides write permission (EROFS), so this run has a
        # writable root: a file that uid 1001 owns or may write is found.
        result = docker(*run_args("--entrypoint", "/bin/sh", read_only=False), IMAGE, "-c", script)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.split()
        self.assertEqual([line for line in lines if line.startswith("missing:")], [], "helpers are missing")
        self.assertEqual([line for line in lines if not line.startswith("missing:")], [],
                         "uid 1001 can write below /opt")

    def test_routes_are_the_hardened_serving_set(self) -> None:
        routes = set(probe()["routes"])
        self.assertEqual(REQUIRED_ROUTES - routes, set(), "required routes are missing")
        self.assertEqual(sorted(routes - ALLOWED_ROUTES), [], "routes outside the serving set")
        self.assertEqual(sorted(route for route in routes if FORBIDDEN_ROUTE.search(route)), [])

    def test_logging_settings_refuse_startup(self) -> None:
        outcome = probe()["refusal"]
        # With every setting off, the guard passes and the namespace fails later.
        self.assertEqual(outcome.pop(""), "other")
        self.assertEqual({name: value for name, value in outcome.items() if value != "refused"}, {},
                         "launch_server accepts a setting that logs or dumps request data")

    def test_flashinfer_sampling_kernels_are_prebuilt(self) -> None:
        result = probe()
        self.assertTrue(result["flashinfer_jit_cache"], "flashinfer_jit_cache is not installed")
        self.assertEqual({arch: ok for arch, ok in result["providers"].items() if not ok}, {},
                         "a provider has no jit_cache/sampling/sampling.so")

    def test_supervisor_writes_only_policy_events(self) -> None:
        revision = "0" * 39 + "1"
        repository = "example/contract-model"
        with tempfile.TemporaryDirectory(dir=os.environ.get("ENGINE_CONTRACT_TMPDIR")) as directory:
            model = Path(directory) / "model"
            model.mkdir()
            files = {"config.json": b"{}\n", "tokenizer_config.json": b"{}\n", "model.safetensors": b"weights\n"}
            for name, data in files.items():
                (model / name).write_bytes(data)
            manifest = {
                "canonical_local_manifest_sha256": "a" * 64, "classification": "verified_local_snapshot_bytes",
                "files": [{"content_sha256": hashlib.sha256(data).hexdigest(), "path": name, "size": len(data)}
                          for name, data in sorted(files.items())],
                "immutable_ref": f"{repository}@{revision}", "immutable_revision": revision,
                "repository": repository, "schema": "confidential-benchmark/local-model-byte-manifest/v1",
                "source_remote_inventory_sha256": "b" * 64,
            }
            metadata = ".model-lock-local-manifest.json"
            (model / metadata).write_text(json.dumps(manifest))
            os.chmod(directory, 0o755)
            os.chmod(model, 0o755)
            for path in model.iterdir():
                os.chmod(path, 0o644)
            pins = [f"--expected-file={name}={hashlib.sha256((model / name).read_bytes()).hexdigest()}"
                    for name in (metadata, "config.json", "tokenizer_config.json")]
            mount = "/mnt/c8s-data/models/contract"
            result = docker(*run_args("--mount", f"type=bind,src={model},dst={mount},readonly",
                                      "--entrypoint", "/usr/local/bin/wait-for-model"), IMAGE,
                            f"--path={mount}", "--plain-cache", "--timeout-seconds=30", "--poll-seconds=1",
                            f"--expected-repository={repository}", f"--expected-revision={revision}",
                            f"--revision-metadata={metadata}", *pins,
                            "--", "python3", "-c", FAKE_SERVER, "--port=18090", timeout=300)
        self.assertNotIn(SECRET, result.stdout)
        self.assertNotIn(SECRET, result.stderr)
        records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        policy = worker_log_policy()
        for record in records:
            self.assertEqual(policy_violations(record, policy), [], record)
        events = [record["event"] for record in records]
        self.assertIn("worker_ready", events, result.stderr[-2000:])
        self.assertEqual(records[-1], {"event": "worker_exit", "exit_code": 0, "signal": None})
        self.assertEqual(result.returncode, 0)


    def test_simulator_mode_serves_a_chat_request(self) -> None:
        worker = simulator_worker()
        self.assertEqual(worker["image"], IMAGE)
        argv = [*worker.get("command", []), *worker.get("args", [])]
        env = {item["name"]: item["value"] for item in worker.get("env", []) if "value" in item}
        port = next(int(arg.split("=", 1)[1]) for arg in argv if arg.startswith("--port="))
        model = next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--served-model-name="))
        spec = {"argv": argv, "env": env, "port": port, "model": model, "timeout": 600}
        # The worker's root filesystem is writable (no readOnlyRootFilesystem);
        # /dev/shm is a memory emptyDir.
        result = docker(*run_args("--shm-size", "1g", "--entrypoint", "python3", read_only=False), IMAGE,
                        "-c", SIMULATOR, json.dumps(spec), timeout=900)
        lines = [line for line in result.stdout.splitlines() if line.startswith(MARKER)]
        self.assertEqual(len(lines), 1, result.stderr[-4000:])
        outcome = json.loads(lines[0].removeprefix(MARKER))
        self.assertEqual(outcome["health"], 200, outcome)
        self.assertEqual(outcome["chat"], {"status": 200, "choices": 1, "content": True}, outcome)


class PolicyCheckTests(unittest.TestCase):
    """The checks of this file, without Docker."""

    def test_policy_violations(self) -> None:
        policy = worker_log_policy()
        self.assertEqual(policy_violations({"event": "worker_exit", "exit_code": 0, "signal": None}, policy), [])
        self.assertTrue(policy_violations({"event": "worker_log", "message": "x"}, policy))
        self.assertTrue(policy_violations({"event": "worker_ready", "model_revision": "main"}, policy))
        self.assertTrue(policy_violations({"event": "worker_exit", "exit_code": "0"}, policy))

    def test_route_sets(self) -> None:
        self.assertLessEqual(REQUIRED_ROUTES, ALLOWED_ROUTES)
        self.assertFalse([route for route in ALLOWED_ROUTES if FORBIDDEN_ROUTE.search(route)])
        for route in ("/update_weights_from_disk", "/start_profile", "/flush_cache", "/openapi.json",
                      "/release_memory_occupation", "/load_lora_adapter", "/abort_request"):
            self.assertRegex(route, FORBIDDEN_ROUTE)


class PinnedEngineTests(unittest.TestCase):
    """pinned_engine.py finds the spec pin and skips a placeholder."""

    def test_find(self) -> None:
        pinned = load("pinned_engine", Path(__file__).with_name("pinned_engine.py"))
        digest = "sha256:" + "1" * 64
        self.assertEqual(pinned.find({"images": {"gateway": "g@" + digest, "engine": "e@" + digest}}), "e@" + digest)
        self.assertEqual(pinned.find({"confidentialSglang": {"engineImage": {"reference": "e", "digest": digest}}}),
                         "e@" + digest)
        self.assertIsNone(pinned.find({"images": {"engine": "e"}}))
        with tempfile.TemporaryDirectory() as directory:
            spec = Path(directory) / "spec.yaml"
            spec.write_text(yaml.safe_dump({"images": {"engine": "e@sha256:" + "0" * 64}}))
            result = subprocess.run(["python3", str(Path(__file__).with_name("pinned_engine.py")), str(spec)],
                                    text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout, "")
            spec.write_text(yaml.safe_dump({"confidentialSglang": {"record": "images-000000000000"}}))
            result = subprocess.run(["python3", str(Path(__file__).with_name("pinned_engine.py")), str(spec)],
                                    text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout, "")
            inputs = Path(directory) / "inputs"
            inputs.mkdir()
            # A record in confidential-sglang's format, checked by scripts/confidential_sglang_release.py.
            fixture = Path(__file__).resolve().parents[2] / "release-v1/fixtures/confidential-sglang/images-0123456789ab.json"
            (inputs / "images-0123456789ab.json").write_bytes(fixture.read_bytes())
            spec.write_text(yaml.safe_dump({"confidentialSglang": {"record": "images-0123456789ab"}}))
            result = subprocess.run(["python3", str(Path(__file__).with_name("pinned_engine.py")), str(spec),
                                     str(inputs)], text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout.strip(),
                             "ghcr.io/confidential-dot-ai/confidential-sglang/engine@sha256:" + "e" * 64)


if __name__ == "__main__":
    unittest.main()
