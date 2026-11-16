"""Socket tests for both maintenance implementations, without secrets."""

import asyncio
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import aiohttp
from support import PYTHON_ROOT, raw_request


class MaintenanceContract(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="maintenance-test-")
        self.log = open(Path(self.directory.name) / "stdout", "wb")
        self.kind = os.environ.get("GATEWAY_TEST_IMPLEMENTATION", "python")
        command = ([os.environ.get("RUST_MAINTENANCE_BINARY", "/tmp/gateway-rust-baseline-target/release/maintenance-gateway")]
            if self.kind == "rust" else [sys.executable, "-m", "gateway.maintenance"])
        self.container = None
        image = os.environ.get("MAINTENANCE_GATEWAY_TEST_IMAGE")
        if self.kind == "python" and os.environ.get("GATEWAY_TEST_IMAGE") and not image:
            raise RuntimeError("container tests need MAINTENANCE_GATEWAY_TEST_IMAGE")
        if self.kind == "python" and image:
            self.container = Path(self.directory.name).name
            command = ["docker", "run", "--rm", "--name", self.container, "--network", "host",
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "32",
                "--env", "MAINTENANCE_GATEWAY_LISTEN=127.0.0.1:9443",
                "--entrypoint", "python", image, "-m", "gateway.maintenance"]
        self.process = subprocess.Popen(command, env={**os.environ, "PYTHONPATH": str(PYTHON_ROOT),
            "MAINTENANCE_GATEWAY_LISTEN": "127.0.0.1:9443"}, stdout=self.log, stderr=subprocess.STDOUT)
        self.client = aiohttp.ClientSession()
        async with asyncio.timeout(10):
            while True:
                if self.process.poll() is not None:
                    raise RuntimeError("maintenance exited before readiness")
                try:
                    async with self.client.get("http://127.0.0.1:9443/health") as result:
                        if result.status == 200:
                            break
                except aiohttp.ClientError:
                    pass
                await asyncio.sleep(.02)

    async def asyncTearDown(self):
        # The Rust baseline handles SIGINT; the replacement handles both.
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT if self.kind == "rust" else signal.SIGTERM)
            try:
                async with asyncio.timeout(12):
                    while self.process.poll() is None:
                        await asyncio.sleep(.02)
            except TimeoutError:
                if self.container:
                    await asyncio.to_thread(subprocess.run, ["docker", "rm", "--force", self.container],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                self.process.kill()
                self.process.wait()
        await self.client.close()
        self.log.close()
        self.directory.cleanup()

    async def send(self, path, method="GET", **options):
        async with self.client.request(method, "http://127.0.0.1:9443" + path, **options) as result:
            self.assertEqual(result.headers["Cache-Control"], "no-store")
            self.assertEqual(result.headers["X-Content-Type-Options"], "nosniff")
            return result.status, result.headers.copy(), await result.json()

    async def test_catalog_status_and_attestation(self):
        status, _, body = await self.send("/v1/models")
        self.assertEqual(status, 200)
        self.assertEqual(body["data"], [{"id": "deepseek-ai/DeepSeek-V4-Flash-0731", "object": "model", "owned_by": "confidential.ai"}])
        for path, state in (("/health", "live"), ("/readiness", "ready")):
            status, _, body = await self.send(path)
            self.assertEqual(status, 200)
            self.assertEqual(body, {"status": state, "mode": "maintenance", "inferenceAvailable": False})
        status, _, body = await self.send("/attestation")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"mode": "maintenance", "inferenceAvailable": False, "inferenceWorkloads": [],
            "attestationType": "outage-status", "statement": "This maintenance gateway runs no inference workload."})

    async def test_http_parser_errors_do_not_quote_caller_bytes(self):
        for invalid in (b"private-parser-canary\r\n", b"Content-Length: private-parser-canary\r\n"):
            raw = await raw_request(b"GET /health HTTP/1.1\r\nHost: test\r\n" + invalid + b"\r\n")
            self.assertEqual(raw.split(b" ", 2)[1], b"400")
            self.assertNotIn(b"private-parser-canary", raw)
        self.log.flush()
        self.assertNotIn("private-parser-canary", (Path(self.directory.name) / "stdout").read_text())

    async def test_all_inference_routes_refuse_without_credentials(self):
        for path in ("/v1/completions", "/v1/chat/completions", "/v1/responses"):
            status, headers, body = await self.send(path, "POST", data=b'{"prompt":"private-canary"}')
            self.assertEqual(status, 429)
            self.assertEqual(headers["Retry-After"], "60")
            self.assertEqual(body, {"error": {"code": "inference_unavailable", "type": "service_unavailable",
                "param": None, "message": "Inference is temporarily unavailable."}})
        status, _, body = await self.send("/unknown")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")

    async def test_body_bound_and_forwarding_headers(self):
        self.assertEqual((await self.send("/v1/responses", "POST", data=b"x" * 65536))[0], 429)
        status, _, body = await self.send("/v1/responses", "POST", data=b"x" * 65537)
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "request_body_too_large")
        for headers in ({"Forwarded": "for=192.0.2.1"}, {"X-Forwarded-For": "192.0.2.1"}):
            status, _, body = await self.send("/health", headers=headers)
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], "invalid_forwarding_headers")

    async def test_slow_upload_deadline_and_address_rate(self):
        async def slow():
            yield b"x"
            await asyncio.sleep(6)
            yield b"y"
        status, _, body = await self.send("/v1/responses", "POST", data=slow())
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "request_body_too_large")
        # A fresh one-second window permits exactly 30 requests from this peer.
        await asyncio.sleep(1.05)
        codes = [(await self.send("/health"))[0] for _ in range(31)]
        self.assertEqual(codes, [200] * 30 + [429])
