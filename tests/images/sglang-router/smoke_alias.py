#!/usr/bin/env python3
"""Test a built PD router image against workers that reject public aliases.

No GPU or source mount is used. Both workers must receive the backend model
for chat and text completions, with and without streaming.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OLD = "deepseek-ai/DeepSeek-V4-Flash-0731"
NEW = "deepseek-ai/DeepSeek-V4.1-Flash"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--image")
    source.add_argument("--binary", help="Local test binary; never used for deployment")
    parser.add_argument("--pairs", action="store_true", help="Check two fixed pairs and a failed decode worker")
    parser.add_argument("--policy", choices=("round_robin", "manual"), default="round_robin")
    parser.add_argument("--private-errors", action="store_true", help="Check private values in worker error bodies and headers")
    args = parser.parse_args()
    received: list[tuple[str, str, str, bool, str]] = []

    class Worker(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            pass

        def reply(self, value: object, status: int = 200) -> None:
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path in ("/health", "/health_generate") and not self.server.healthy:
                self.reply({"status": "unavailable"}, 503)
                return
            if self.path in ("/model_info", "/get_model_info"):
                self.reply({"model_path": NEW, "served_model_name": NEW,
                            "is_generation": True, "architectures": ["DeepseekV4ForCausalLM"]})
            elif self.path in ("/server_info", "/get_server_info"):
                self.reply({"model_path": NEW, "served_model_name": NEW,
                            "dp_size": 1, "tp_size": 1,
                            "internal_states": [{"waiting_queue_size": 0,
                                                 "running_queue_size": 0}]})
            elif self.path == "/v1/models":
                self.reply({"object": "list", "data": [{"id": NEW, "object": "model"}]})
            else:
                self.reply({"status": "ok"})

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            role = self.server.role
            received.append((role, self.path, body.get("model"), bool(body.get("stream")), self.server.pair))
            if body.get("model") != NEW:
                self.reply({"error": "backend model required"}, 400)
                return
            prompt = body.get("prompt", "")
            if isinstance(prompt, str):
                prefill_error = "test-prefill-error" in prompt or "test-prefill-late-error" in prompt
                if prefill_error and role == "prefill":
                    if "test-prefill-late-error" in prompt:
                        time.sleep(0.15)
                    self.reply({"error": {"message": prompt}}, 400)
                    return
                if prefill_error and role == "decode" and "test-prefill-late-error" not in prompt:
                    time.sleep(0.15)
                if "test-decode-error" in prompt and role == "decode":
                    raw = prompt.encode()
                    self.send_response(400)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
            usage = {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}
            if body.get("stream"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                choice = ({"delta": {"content": "ok"}, "finish_reason": "stop", "index": 0}
                          if "chat" in self.path else
                          {"text": "ok", "finish_reason": "stop", "index": 0})
                chunk = {"id": "smoke", "model": NEW, "choices": [choice], "usage": usage}
                self.wfile.write(("data: " + json.dumps(chunk) + "\n\ndata: [DONE]\n\n").encode())
            else:
                choice = ({"message": {"role": "assistant", "content": "ok"},
                           "finish_reason": "stop", "index": 0} if "chat" in self.path else
                          {"text": "ok", "finish_reason": "stop", "index": 0})
                self.reply({"id": "smoke", "model": NEW, "choices": [choice], "usage": usage})

    workers = []
    for pair, role in [(pair, role) for pair in (("a", "b") if args.pairs else ("a",))
                       for role in ("prefill", "decode")]:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Worker)
        server.role = role
        server.pair = pair
        server.healthy = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        workers.append(server)
    # Reserve a free router port. Docker uses the host network for the mocks.
    import socket
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        metrics_port = reservation.getsockname()[1]
    routes = json.dumps({"schemaVersion": 1, "routes": {OLD: [NEW], NEW: [NEW]}})
    name = f"ci-pd-alias-smoke-{port}"
    process = None
    log_file = tempfile.NamedTemporaryFile(prefix="ci-pd-alias-", suffix=".log", delete=False)
    try:
        launch = ["--pd-disaggregation", "--prefill",
                        f"http://127.0.0.1:{workers[0].server_port}", "8998", "--decode",
                        f"http://127.0.0.1:{workers[1].server_port}",
                        "--host", "127.0.0.1", "--port", str(port),
                        "--prometheus-port", str(metrics_port), "--disable-retries",
                        "--worker-startup-timeout-secs", "30"]
        pairs = {}
        if args.pairs:
            launch[launch.index("--host"):launch.index("--host")] = [
                "--prefill", f"http://127.0.0.1:{workers[2].server_port}", "8999",
                "--decode", f"http://127.0.0.1:{workers[3].server_port}"]
            launch += ["--prefill-policy", args.policy, "--decode-policy", args.policy,
                       "--health-check-interval-secs", "1", "--health-failure-threshold", "1"]
            if args.policy == "manual":
                launch += ["--assignment-mode", "min_group"]
            pairs = {f"http://127.0.0.1:{workers[i].server_port}":
                     f"http://127.0.0.1:{workers[i+1].server_port}" for i in (0, 2)}
        environment = {"CI_ROUTER_MODEL_ROUTES": routes}
        if pairs:
            environment["CI_ROUTER_PD_PAIRS"] = json.dumps(pairs)
        if args.binary:
            process = subprocess.Popen([args.binary, *launch],
                                       env={**os.environ, **environment},
                                       stdout=log_file, stderr=subprocess.STDOUT)
        else:
            subprocess.run(["docker", "run", "--detach", "--name", name, "--network", "host",
                            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                            *[item for key, value in environment.items() for item in ("--env", key + "=" + value)],
                            args.image, *launch],
                           check=True, capture_output=True)
        origin = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 60
        while True:
            try:
                with urllib.request.urlopen(origin + "/readiness", timeout=2) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.HTTPError):
                pass
            if time.monotonic() > deadline:
                raise AssertionError("PD router did not become ready")
            time.sleep(0.2)
        received.clear()
        for model in (NEW, OLD):
            for route in ("/v1/chat/completions", "/v1/completions"):
                for stream in (False, True):
                    body = {"model": model, "max_tokens": 1, "stream": stream}
                    body.update({"messages": [{"role": "user", "content": "hi"}]}
                                if "chat" in route else {"prompt": "hi"})
                    request = urllib.request.Request(origin + route, data=json.dumps(body).encode(),
                                                     headers={"Content-Type": "application/json",
                                                              "X-SMG-Routing-Key": "synthetic-pair"})
                    before = len(received)
                    with urllib.request.urlopen(request, timeout=10) as response:
                        result = response.read().decode()
                    if stream:
                        assert "data: [DONE]" in result, result
                        chunks = [json.loads(line[5:]) for line in result.splitlines()
                                  if line.startswith("data:") and "[DONE]" not in line]
                        assert chunks and all(chunk["model"] == NEW for chunk in chunks)
                    else:
                        assert json.loads(result)["model"] == NEW, result
                    sent = received[before:]
                    assert len(sent) == 2 and {row[0] for row in sent} == {"prefill", "decode"}, sent
                    assert all(row[2] == NEW for row in sent), sent
                    assert len({row[4] for row in sent}) == 1, sent
        if args.pairs:
            initial_pairs = {row[4] for row in received}
            if args.policy == "manual":
                assert len(initial_pairs) == 1, received
                failed_pair = next(iter(initial_pairs))
            else:
                assert initial_pairs == {"a", "b"}, received
                failed_pair = "a"
            failed_worker = workers[1 if failed_pair == "a" else 3]
            surviving_pair = "b" if failed_pair == "a" else "a"
            failed_worker.healthy = False
            time.sleep(4)
            for _ in range(8):
                before = len(received)
                body = {"model": NEW, "prompt": "synthetic", "max_tokens": 1}
                request = urllib.request.Request(origin + "/v1/completions", data=json.dumps(body).encode(),
                                                 headers={"Content-Type": "application/json",
                                                          "X-SMG-Routing-Key": "synthetic-pair"})
                with urllib.request.urlopen(request, timeout=10) as response:
                    assert response.status == 200
                    response.read()
                sent = received[before:]
                assert len(sent) == 2 and {row[4] for row in sent} == {surviving_pair}, sent
            failed_worker.healthy = True
            time.sleep(4)
            recovered = set()
            for _ in range(8):
                before = len(received)
                with urllib.request.urlopen(request, timeout=10) as response:
                    response.read()
                sent = received[before:]
                assert len(sent) == 2 and len({row[4] for row in sent}) == 1, sent
                recovered.add(sent[0][4])
            # ManualPolicy keeps the original candidate first. It restores
            # that key's original pair when the failed candidate is healthy.
            assert recovered == ({failed_pair} if args.policy == "manual" else {"a", "b"}), recovered
            print("PASS: requests stay in each pair; a failed decode removes its whole pair; routing recovers", args.policy)
        if args.private_errors:
            assert args.image, "private log checks require the built image"
            canary = "PRIVATE_ROUTER_CANARY_" + uuid.uuid4().hex
            for mode in ("test-prefill-error", "test-prefill-late-error", "test-decode-error"):
                for stream in (False, True):
                    body = {"model": NEW, "prompt": canary + " " + mode,
                            "max_tokens": 1, "stream": stream}
                    request = urllib.request.Request(origin + "/v1/completions", data=json.dumps(body).encode(),
                        headers={"Content-Type": "application/json", "Authorization": "Bearer " + canary,
                                 "X-Request-Id": canary, "X-SMG-Routing-Key": canary})
                    try:
                        with urllib.request.urlopen(request, timeout=10) as response:
                            assert response.status == 200
                            response.read()
                    except urllib.error.HTTPError as error:
                        assert error.code == 400, error.code
                        error.read()
            time.sleep(0.3)
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True, check=True)
            assert canary not in logs.stdout + logs.stderr, "private value reached router logs"
            rows = [json.loads(line) for line in logs.stdout.splitlines() if line.startswith("{")]
            assert any(row.get("event") == "worker_http_error" for row in rows), "reviewed error event is missing"
            for row in rows:
                assert set(row) <= {"timestamp", "source_revision", "event", "role", "status", "code"}, "unreviewed log field"
            print("PASS: worker error bodies, request IDs, routing keys and authorization values stay out of logs")
        print("PASS: both model names, chat/text, streaming/nonstream; both PD workers receive V4.1")
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        elif args.image:
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
            log_file.write((logs.stdout + logs.stderr).encode())
            subprocess.run(["docker", "rm", "--force", name], capture_output=True)
        log_file.close()
        print("Router log:", log_file.name)
        for server in workers:
            server.shutdown()


if __name__ == "__main__":
    main()
