#!/usr/bin/env python3
"""Run the stock telemetry collector with the rendered pipeline and check what leaves.

The test renders the chart, validates the exact collector argument with the
pinned image, then runs the same pipeline with the two relay exporters
replaced by file exporters. A local target serves metrics with an extra label;
OTLP inputs carry a prompt attribute, a request id, a span event, and a
Bearer token. None of them may reach the output.

Needs a container runtime (CONTAINER_RUNTIME, default docker) and network
access to pull the pinned image.
"""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "helm/confidential-inference"
RUNTIME = os.environ.get("CONTAINER_RUNTIME", "docker")
VALUES = {
    "inference.mode": "simulator",
    "telemetry.enabled": "true",
    "telemetry.traces.enabled": "true",
    "telemetry.kubeStateMetrics.enabled": "true",
    "telemetry.deployment": "test-deployment",
    "telemetry.relay.serverName": "relay.example.com",
    "telemetry.relay.address": "203.0.113.7",
    "telemetry.metrics.tenantId": "00000000-0000-0000-0000-000000000001",
    "telemetry.metrics.clientId": "00000000-0000-0000-0000-000000000002",
    "telemetry.metrics.dataCollectionRule": "dcr-" + "0" * 32,
}
SECRET = "do-not-leak-7f3a"
METRICS = (
    "# TYPE gateway_requests counter\n"
    'gateway_requests{model="m",key_id="k1",status="200",prompt="%s"} 3\n' % SECRET
)


def render() -> tuple[str, dict]:
    arguments = [item for key, value in VALUES.items() for item in ("--set", f"{key}={value}")]
    output = subprocess.run(["helm", "template", "example", str(CHART), *arguments],
                            check=True, text=True, capture_output=True).stdout
    collector = next(item for item in yaml.safe_load_all(output) if item
                     and item["kind"] == "Deployment" and item["metadata"]["name"] == "telemetry-collector")
    container = collector["spec"]["template"]["spec"]["containers"][0]
    (argument,) = container["args"]
    return container["image"], json.loads(argument.removeprefix("--config=yaml:"))


def local_pipeline(config: dict, target: str) -> dict:
    """The rendered pipeline with local targets and file exporters instead of the relay."""
    config = json.loads(json.dumps(config))
    for job in config["receivers"]["prometheus"]["config"]["scrape_configs"]:
        job.pop("dns_sd_configs", None)
        labels = (job.get("static_configs") or [{}])[0].get("labels", {})
        job["static_configs"] = [{"targets": [target], "labels": labels}]
        job["scrape_interval"] = "1s"
    config["receivers"]["otlp"]["protocols"] = {"http": {"endpoint": "127.0.0.1:14318"}}
    config["extensions"]["health_check"]["endpoint"] = "127.0.0.1:14133"
    for name in ("oauth2client", "basicauth/loki"):
        config["extensions"].pop(name)
    config["service"]["extensions"] = ["health_check"]
    config["connectors"]["spanmetrics"]["metrics_flush_interval"] = "1s"
    config["exporters"] = {
        "file/metrics": {"path": "/out/metrics.json"},
        "file/logs": {"path": "/out/logs.json"},
        "file/spans": {"path": "/out/spans.json"},
    }
    pipelines = config["service"]["pipelines"]
    pipelines["metrics"]["exporters"] = ["file/metrics"]
    pipelines["metrics/spans"]["exporters"] = ["file/metrics"]
    pipelines["logs"]["exporters"] = ["file/logs"]
    pipelines["traces"]["exporters"] = ["spanmetrics", "file/spans"]
    for pipeline in pipelines.values():
        pipeline["processors"] = [item for item in pipeline["processors"] if item != "batch"]
    return config


class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = METRICS.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        pass


def post(path: str, document: dict) -> None:
    request = urllib.request.Request("http://127.0.0.1:14318" + path, data=json.dumps(document).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 200, response.status


def attribute(key: str, value: str) -> dict:
    return {"key": key, "value": {"stringValue": value}}


class CollectorTests(unittest.TestCase):
    def test_only_the_pinned_labels_and_attributes_leave(self) -> None:
        image, config = render()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            secrets, out = base / "secrets", base / "out"
            secrets.mkdir()
            out.mkdir()
            out.chmod(0o777)
            for name in ("entra-client-secret", "loki-password"):
                (secrets / name).write_text("test")
            mounts = ["-v", f"{secrets}:/mnt/c8s-data/telemetry-relay:ro", "-v", f"{out}:/out"]
            subprocess.run([RUNTIME, "run", "--rm", "--network", "host", *mounts, image, "validate",
                            "--config=yaml:" + json.dumps(config)], check=True)

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            local = local_pipeline(config, f"127.0.0.1:{server.server_port}")
            name = f"telemetry-collector-test-{os.getpid()}"
            subprocess.run([RUNTIME, "run", "-d", "--name", name, "--network", "host", *mounts, image,
                            "--config=yaml:" + json.dumps(local)], check=True, capture_output=True)
            try:
                for _ in range(60):
                    try:
                        urllib.request.urlopen("http://127.0.0.1:14133/", timeout=1)
                        break
                    except OSError:
                        time.sleep(0.5)
                now = str(time.time_ns())
                resource = {"attributes": [attribute("service.name", "sglang"), attribute("host.name", SECRET)]}
                post("/v1/traces", {"resourceSpans": [{"resource": resource, "scopeSpans": [{"spans": [{
                    "traceId": "0" * 31 + "1", "spanId": "0" * 15 + "1", "name": "request",
                    "startTimeUnixNano": now, "endTimeUnixNano": now,
                    "attributes": [attribute("prompt", SECRET), attribute("gen_ai.request.id", SECRET),
                                   {"key": "gen_ai.usage.prompt_tokens", "value": {"intValue": "7"}}],
                    "events": [{"timeUnixNano": now, "name": "abort", "attributes": [attribute("matched", SECRET)]}],
                }]}]}]})
                post("/v1/logs", {"resourceLogs": [{"resource": resource, "scopeLogs": [{"logRecords": [{
                    "timeUnixNano": now, "severityText": "INFO",
                    "body": {"stringValue": f"auth Bearer {SECRET} done"},
                    "attributes": [attribute("prompt", SECRET)],
                }]}]}]})
                time.sleep(8)
            finally:
                logs = subprocess.run([RUNTIME, "logs", name], text=True, capture_output=True)
                subprocess.run([RUNTIME, "rm", "-f", name], capture_output=True)
                server.shutdown()
                server.server_close()
            outputs = {path.name: path.read_text() for path in out.iterdir()}
            self.assertEqual(set(outputs), {"metrics.json", "logs.json", "spans.json"}, logs.stdout + logs.stderr)
            for name, text in outputs.items():
                self.assertFalse(SECRET in text, f"{name} carries the secret")
            for name, expected in (("metrics.json", "gateway_requests"), ("metrics.json", '"key_id"'),
                                   ("metrics.json", "traces.span.metrics.duration"),
                                   ("spans.json", "gen_ai.usage.prompt_tokens"), ("logs.json", "Bearer [REDACTED]")):
                self.assertTrue(expected in outputs[name], f"{expected} missing from {name}")


if __name__ == "__main__":
    unittest.main()
