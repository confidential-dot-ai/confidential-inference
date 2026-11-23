#!/usr/bin/env python3
"""Run the node log agent and the telemetry collector with the rendered pipelines.

The test writes container log files in the kubelet layout
(/var/log/pods/<namespace>_<pod>_<uid>/<container>/0.log, CRI lines) for every
source: gateway, router, worker, C8s, the collector and an unlisted pod. The
lines carry a canary marker in prompts, messages, unreviewed fields and
pattern-failing values, plus a client address, a user agent and a Bearer
token. The agent reads them and sends to a local collector, whose relay
exporters are replaced by file exporters (tests/telemetry/test_collector.py).

It checks that the reviewed events of every source leave with their identity,
that the marker, the address, the user agent and the token leave nowhere
(logs or metric labels), and that dropped records are counted.

Needs a container runtime (CONTAINER_RUNTIME, default docker) and the pinned
image.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_collector as collector  # noqa: E402

RUNTIME = collector.RUNTIME
NAMESPACE = "default"
MARK = "CANARY-9d7e1c"
CLIENT = "198.51.100.77"
AGENT = "Mozilla/5.0 (CanaryBrowser)"
TOKEN = "sk-canary-token-77"
REVISION = "0123456789abcdef0123456789abcdef01234567"


def agent_config() -> tuple[str, dict]:
    documents = collector.rendered_documents()
    agent = next(item for item in documents if item["kind"] == "DaemonSet"
                 and item["metadata"]["name"] == "node-log-agent")
    container = agent["spec"]["template"]["spec"]["containers"][0]
    (argument,) = container["args"]
    return container["image"], json.loads(argument.removeprefix("--config=yaml:"))


def local_agent(config: dict) -> dict:
    config = json.loads(json.dumps(config))
    config["exporters"]["otlphttp/collector"]["endpoint"] = "http://127.0.0.1:14318"
    config["extensions"]["health_check"]["endpoint"] = "127.0.0.1:14134"
    config["service"]["telemetry"]["metrics"]["readers"][0]["pull"]["exporter"]["prometheus"]["port"] = 18889
    job = config["receivers"]["prometheus/self"]["config"]["scrape_configs"][0]
    job["static_configs"][0]["targets"] = ["127.0.0.1:18889"]
    job["scrape_interval"] = "1s"
    return config


def cri(stream: str, line: str) -> str:
    return f"2026-11-16T10:00:00.123456789Z {stream} F {line}\n"


def j(**fields) -> str:
    return json.dumps(fields, separators=(",", ":"))


# A pod UID, as the kubelet writes it in the path (the container parser requires one).
UID = "0b5f3c9e-7a1d-4e2b-9c8f-00000000000"
AUDIT = ('{"event":"gateway_request_completed","key_ref":null,'
         '"request_id":"c0ffee00-cafe-4000-8000-deadbeef0009","route":"/v1/chat/completions","status":200}')
FILES = {
    (f"{NAMESPACE}_gateway-6d8f-abcde_{UID}1", "gateway"): [
        j(timestamp="t", level="INFO", message="the gateway is ready", listen="0.0.0.0:9443"),
        j(timestamp="t", level="INFO", message=AUDIT),
        j(timestamp="t", level="INFO", message=AUDIT.replace("null", f'"{MARK}"')),
        j(timestamp="t", level="ERROR", message=f"upstream said {MARK}"),
        j(level="INFO", message="the gateway is ready", client=CLIENT, user_agent=AGENT),
        f"plain text {MARK} from {CLIENT}",
    ],
    (f"{NAMESPACE}_sglang-router-7c9-xyz12_{UID}2", "sglang-router"): [
        j(timestamp="2026-11-16T10:00:00+00:00", source_revision="unknown", event="router_started", role="router"),
        j(event="worker_http_error", role="router", status=502, url=f"http://x/{MARK}", request_id=MARK),
        j(event=f"router_{MARK}", role="router"),
    ],
    # A replica's PD router: the router's reviewed events, nothing else.
    (f"{NAMESPACE}_pd-router-0-5d4c-k9j8h_{UID}7", "pd-router"): [
        j(event="paired_decode_cancelled", role="decode", status=503, url=f"http://x/{MARK}"),
        j(event=f"pair_{MARK}", role="prefill"),
    ],
    (f"{NAMESPACE}_inference-worker-0_{UID}3", "sglang"): [
        j(event="worker_ready", model_revision=REVISION, gpus=1, load_seconds=42),
        j(event="request_failed", error_class="invalid_request", http_status=400, phase="http",
          input_tokens_bucket="unknown", duration_ms=None, exception=None, location=None),
        j(event="worker_error", error_class="unclassified", exception="KeyError",
          location="sglang/srt/managers/scheduler.py:1234"),
        j(event="worker_error", error_class=f"x {MARK}", exception=f"{MARK} Error", location=f"{MARK}:1"),
        j(event="worker_exit", exit_code=None, signal="SIGKILL", prompt=MARK),
        j(event="jit_compile", cache="flashinfer", files=2),
        j(event="jit_compile", cache=f"/tmp/.cache/{MARK}", files=1, path=f"/tmp/{MARK}.so"),
        j(event="jit_compile", cache="triton", files=3, kernels="_fwd_kernel,fused_gdn_gating"),
        j(event="jit_compile", cache="triton", files=1, kernels=f"/tmp/{MARK}/x.cubin"),
        f"[2026-11-16 10:00:00 TP0] Prefill batch. prompt={MARK} Authorization: Bearer {TOKEN}",
    ],
    (f"{NAMESPACE}_inference-worker-0_{UID}3", "c8s-cert"): [
        f'time=2026-11-16T10:00:00Z level=INFO msg="certificate issued to {CLIENT}" workload={MARK}',
    ],
    (f"c8s-router_router-5f6-q1w2e_{UID}4", "router"): [
        j(time="t", level="WARN", msg=f"upstream {CLIENT} slow; Authorization: Bearer {TOKEN}", path=f"/{MARK}"),
        f'{CLIENT} - - [16/Nov/2026:10:00:00 +0000] "POST /v1/chat/completions?q={MARK} HTTP/1.1" 200 5 "-" "{AGENT}"',
    ],
    (f"{NAMESPACE}_telemetry-collector-5b7-abc12_{UID}5", "otelcol"): [
        j(level="warn", ts=1.0, caller="x.go:1", msg="Exporting failed. Will retry the request after interval.",
          error=f"Post {MARK}"),
    ],
    (f"kube-system_coredns-n-1-2-3-4_{UID}6", "coredns"): [
        f"[INFO] {CLIENT}:53 - 1 \"A IN {MARK}.example. udp\" NOERROR",
    ],
}
# The events that must leave, by source.
EXPECTED = {
    "gateway": [{"event": "the gateway is ready", "level": "info"},
                {**json.loads(AUDIT), "level": "info"},
                {"event": "the gateway is ready", "level": "info"}],
    "sglang-router": [{"event": "router_started", "role": "router", "source_revision": "unknown",
                       "timestamp": "2026-11-16T10:00:00+00:00"},
                      {"event": "worker_http_error", "role": "router", "status": 502},
                      {"event": "paired_decode_cancelled", "role": "decode", "status": 503}],
    "inference-worker": [{"event": "worker_ready", "model_revision": REVISION, "gpus": 1, "load_seconds": 42},
                         {"event": "request_failed", "error_class": "invalid_request", "http_status": 400,
                          "phase": "http", "input_tokens_bucket": "unknown", "duration_ms": None,
                          "exception": None, "location": None},
                         {"event": "worker_error", "error_class": "unclassified", "exception": "KeyError",
                          "location": "sglang/srt/managers/scheduler.py:1234"},
                         {"event": "worker_error"},
                         {"event": "worker_exit", "exit_code": None, "signal": "SIGKILL"},
                         {"event": "jit_compile", "cache": "flashinfer", "files": 2},
                         {"event": "jit_compile", "files": 1},
                         # Kernel names are identifiers; anything else (a path) is dropped.
                         {"event": "jit_compile", "cache": "triton", "files": 3,
                          "kernels": "_fwd_kernel,fused_gdn_gating"},
                         {"event": "jit_compile", "cache": "triton", "files": 1}],
    "c8s": [{"msg": "certificate issued to [ip]", "level": "info"},
            {"msg": "upstream [ip] slow; Authorization=[REDACTED]", "level": "warn"}],
    "telemetry-collector": [{"msg": "Exporting failed. Will retry the request after interval.", "level": "warn"}],
}
IDENTITY = {"environment": "example", "deployment": "staging-0123456789ab", "framework_release": "v0.0.0",
            "node": "n-10-0-0-5"}


class NodeLogAgentTests(unittest.TestCase):
    def test_only_reviewed_events_leave_and_the_rest_is_counted(self) -> None:
        collector_image, collector_config = collector.render()
        image, config = agent_config()
        self.assertEqual(image, collector_image)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            pods, state, secrets, out = base / "pods", base / "state", base / "secrets", base / "out"
            for path in (pods, state, secrets, out):
                path.mkdir()
            state.chmod(0o777)
            out.chmod(0o777)
            for name in ("entra-client-secret", "loki-password"):
                (secrets / name).write_text("test")
            for (pod, container), lines in FILES.items():
                folder = pods / pod / container
                folder.mkdir(parents=True)
                stream = "stderr" if container == "otelcol" else "stdout"
                (folder / "0.log").write_text("".join(cri(stream, line) for line in lines))
            names = [f"node-log-agent-test-{os.getpid()}", f"node-log-collector-test-{os.getpid()}"]
            mounts = ["-v", f"{secrets}:/mnt/c8s-data/telemetry-relay:ro", "-v", f"{out}:/out"]
            local = collector.local_pipeline(collector_config, "127.0.0.1:1")
            subprocess.run([RUNTIME, "run", "-d", "--name", names[1], "--network", "host", *mounts, image,
                            "--config=yaml:" + json.dumps(local)], check=True, capture_output=True)
            try:
                for _ in range(60):
                    try:
                        urllib.request.urlopen("http://127.0.0.1:14133/", timeout=1)
                        break
                    except OSError:
                        time.sleep(0.5)
                subprocess.run([RUNTIME, "run", "-d", "--name", names[0], "--network", "host",
                                "-e", "NODE_NAME=n-10-0-0-5", "-v", f"{pods}:/var/log/pods:ro",
                                "-v", f"{state}:/var/lib/node-log-agent", image,
                                "--config=yaml:" + json.dumps(local_agent(config))],
                               check=True, capture_output=True)
                time.sleep(12)
            finally:
                logs = "".join(subprocess.run([RUNTIME, "logs", name], text=True, capture_output=True).stderr
                               for name in names)
                for name in names:
                    subprocess.run([RUNTIME, "rm", "-f", name], capture_output=True)
            outputs = {path.name: path.read_text() for path in out.iterdir()}
            self.assertIn("logs.json", outputs, logs)
            for name, text in outputs.items():
                for value in (MARK, CLIENT, AGENT, TOKEN):
                    self.assertNotIn(value, text, f"{name} carries {value}")
            self.check_logs(outputs["logs.json"])
            self.check_counts(outputs.get("metrics.json", ""))

    def check_logs(self, text: str) -> None:
        bodies: dict[str, list[dict]] = {}
        for line in text.splitlines():
            for resource in json.loads(line)["resourceLogs"]:
                attributes = {item["key"]: item["value"]["stringValue"]
                              for item in resource["resource"]["attributes"]}
                self.assertEqual(attributes["k8s.cluster.name"], "staging-0123456789ab")
                self.assertEqual(attributes["deployment.environment"], "example")
                for scope in resource["scopeLogs"]:
                    for record in scope["logRecords"]:
                        self.assertFalse(record.get("attributes"), record)
                        body = json.loads(record["body"]["stringValue"])
                        bodies.setdefault(attributes["service.name"], []).append(body)
        self.assertEqual(set(bodies), set(EXPECTED))
        for source, events in EXPECTED.items():
            got = bodies[source]
            for body in got:
                self.assertLessEqual(IDENTITY.items(), body.items(), body)
                self.assertEqual(body["service"], source)
                for key in ("namespace", "pod", "container"):
                    self.assertIn(key, body)
            identity_keys = set(IDENTITY) | {"service", "namespace", "pod", "container"}
            stripped = [{key: value for key, value in body.items() if key not in identity_keys} for body in got]
            # Records of one file keep their order; files are read in any order.
            order = lambda body: json.dumps(body, sort_keys=True)  # noqa: E731
            self.assertEqual(sorted(stripped, key=order), sorted(events, key=order), source)

    def check_counts(self, text: str) -> None:
        counts: dict[tuple[str, bool], int] = {}
        for line in text.splitlines():
            try:
                document = json.loads(line)
            except json.JSONDecodeError:  # the last line, cut when the collector stops
                continue
            for resource in document.get("resourceMetrics", []):
                for scope in resource["scopeMetrics"]:
                    for metric in scope["metrics"]:
                        if metric["name"] != "node_log_agent.records":
                            continue
                        for point in metric["sum"]["dataPoints"]:
                            labels = {item["key"]: next(iter(item["value"].values()))
                                      for item in point["attributes"]}
                            self.assertLessEqual(set(labels), {"source", "kept", "node"})
                            key = (labels["source"], labels["kept"])
                            counts[key] = max(counts.get(key, 0), int(point["asInt"]))
        self.assertGreaterEqual(counts.get(("unlisted", False), 0), 1, counts)
        self.assertGreaterEqual(counts.get(("gateway", False), 0), 3, counts)
        self.assertGreaterEqual(counts.get(("gateway", True), 0), 3, counts)


if __name__ == "__main__":
    unittest.main()
