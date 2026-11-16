"""The same socket-level contract checks target Rust and Python.

GATEWAY_TEST_IMPLEMENTATION=rust python -m unittest discover -s tests/gateway
"""

import asyncio
import base64
import hashlib
import hmac
import os
import unittest
from datetime import UTC

import aiohttp
import orjson
from aiohttp import web
from support import (
    ADMIN_KEY,
    API_KEY,
    MODEL,
    ROOT,
    AdminPeer,
    Gateway,
    raw_request,
    snapshot,
)


class GatewayContract(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.received = []
        self.reply = None

        async def upstream(request):
            value = await request.json()
            self.received.append((request.path, value, dict(request.headers)))
            if self.reply:
                return await self.reply(request, value)
            if not value.get("stream"):
                response = web.json_response(
                    {
                        "id": "result",
                        "model": "backend",
                        "choices": [
                            {"message": {"content": "hello"}, "finish_reason": "stop"}
                        ],
                        "usage": {"prompt_tokens": 8, "completion_tokens": 2},
                    }
                )
                response.enable_compression()
                return response
            raw = (
                b": heartbeat\r\n\r\ndata: "
                + orjson.dumps(
                    {"model": "backend", "choices": [{"delta": {"content": "日"}}]}
                )
                + b"\r\n\r\ndata: [DONE]\n\n"
            )
            split = raw.index("日".encode())
            response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
            await response.prepare(request)
            try:
                for chunk in (
                    raw[: split + 1],
                    raw[split + 1 : split + 2],
                    raw[split + 2 :],
                ):
                    await response.write(chunk)
                    await asyncio.sleep(0.01)
            except ConnectionError:
                pass
            return response

        app = web.Application(client_max_size=0)
        for route in ("/v1/chat/completions", "/v1/completions", "/v1/responses"):
            app.router.add_post(route, upstream)
        self.runner = web.AppRunner(app, access_log=None, handler_cancellation=True)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.upstream = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        self.client = aiohttp.ClientSession()
        self.gateway = None
        self.admin_peer = None

    async def asyncTearDown(self):
        if self.gateway:
            await self.gateway.close()
        if self.admin_peer:
            await self.admin_peer.close()
        await self.client.close()
        await self.runner.cleanup()

    async def start(self, settings=None, apply=True, **credentials):
        self.gateway = Gateway(
            os.environ.get("GATEWAY_TEST_IMPLEMENTATION", "python"),
            self.upstream,
            settings,
        )
        await self.gateway.start(apply_snapshot=apply, **credentials)

    async def send(
        self,
        path="/v1/chat/completions",
        body=None,
        token=API_KEY,
        method="POST",
        headers=None,
    ):
        supplied = {"Authorization": "Bearer " + token, **(headers or {})}
        if isinstance(body, bytes):
            options = {"data": body}
        elif body is not None:
            options = {"json": body}
        else:
            options = {}
        async with self.client.request(
            method, "http://127.0.0.1:9443" + path, headers=supplied, **options
        ) as response:
            return response.status, response.headers.copy(), await response.read()

    async def push(self, value):
        return await self.send("/admin/v1/api-keys/snapshot", value, ADMIN_KEY, "PUT")

    async def start_with_admin(self, usage=False):
        self.admin_peer = AdminPeer()
        await self.admin_peer.start()
        await self.start(
            {
                "SSL_CERT_FILE": str(self.admin_peer.ca_file),
                "GATEWAY_ADMIN_ENDPOINT": self.admin_peer.endpoint,
                "GATEWAY_USAGE_ENABLED": str(usage).lower(),
                "GATEWAY_USAGE_MODELS": orjson.dumps(
                    {
                        MODEL: {
                            "served_model": "backend",
                            "model_revision": "test-revision",
                        }
                    }
                ).decode(),
            },
            apply=False,
        )
        async with asyncio.timeout(10):
            while (await self.send("/ready", method="GET"))[0] != 200:
                await asyncio.sleep(0.05)

    async def test_https_admin_pull_usage_retry_and_local_budget(self):
        """K1/B1/T1/L3: trusted pulls and usage retries retain identities and token charges."""
        await self.start_with_admin(usage=True)
        self.assertGreaterEqual(self.admin_peer.gets, 1)
        self.admin_peer.fail_usage = 1
        value = snapshot(2)
        value["keys"][0]["tokenBudget"] = {"tokens": 10, "window": "day"}
        self.assertEqual((await self.push(value))[0], 200)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 429)
        async with asyncio.timeout(25):
            while not self.admin_peer.events:
                await asyncio.sleep(0.1)
        self.assertGreaterEqual(len(self.admin_peer.batches), 2)
        self.assertEqual(self.admin_peer.batches[0], self.admin_peer.batches[1])
        self.assertEqual(len(self.admin_peer.events), 1)
        event = self.admin_peer.events[0]
        self.assertEqual(event["key_id"], "key_test")
        self.assertEqual(event["requested_model"], MODEL)
        self.assertEqual(event["outcome"], "completed")
        self.assertTrue(event["final_usage"])
        self.assertEqual((event["input_tokens"], event["output_tokens"]), (8, 2))
        self.assertEqual(
            set(event),
            {
                "request_id",
                "key_id",
                "requested_model",
                "outcome",
                "final_usage",
                "input_tokens",
                "output_tokens",
                "cached_input_tokens",
                "reasoning_tokens",
                "ended_at_ms",
                "producer_instance",
            },
        )
        self.assertTrue(
            all(
                value == "Bearer " + "t" * 32
                for value in self.admin_peer.authorizations
            )
        )

    async def test_admin_outage_keeps_last_keys_after_failed_refresh(self):
        """K6: a failed scheduled HTTPS refresh leaves cached keys available."""
        await self.start_with_admin()
        self.admin_peer.unavailable = True
        gets = self.admin_peer.gets
        async with asyncio.timeout(35):
            while self.admin_peer.gets == gets:
                await asyncio.sleep(0.1)
        self.assertEqual((await self.send("/ready", method="GET"))[0], 200)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_empty_snapshot_is_ready_but_authorizes_no_key(self):
        """K1/K3: a valid empty set replaces the old set without granting access."""
        await self.start()
        empty = snapshot(2)
        empty["keys"] = []
        self.assertEqual((await self.push(empty))[0], 200)
        self.assertEqual((await self.send("/ready", method="GET"))[0], 200)
        status, _, body = await self.send(body={"model": MODEL})
        self.assertEqual(status, 401)
        self.assertEqual(orjson.loads(body)["error"]["code"], "invalid_api_key")
        self.assertEqual(self.received, [])

    async def test_startup_rejects_invalid_admin_tokens(self):
        """K1: a missing, mistyped or invalid outbound token prevents startup."""
        for token in (None, 17, "short", "startup-secret-canary-" + "x" * 32 + "\n"):
            with self.subTest(token_type=type(token).__name__):
                try:
                    with self.assertRaises(RuntimeError):
                        await self.start(admin_token=token)
                    self.assertNotIn("startup-secret-canary", self.gateway.logs())
                finally:
                    await self.gateway.close()
                    self.gateway = None

    async def test_startup_rejects_invalid_settings(self):
        """K1: invalid limits, schema or admin transport cannot start a listener."""
        for settings in (
            {"GATEWAY_MAXIMUM_BODY_BYTES": "0"},
            {"GATEWAY_FIRST_TOKEN_TIMEOUT_SECONDS": "0"},
            {"GATEWAY_ADMIN_ENDPOINT": "http://127.0.0.1:1/api/usage/ingest"},
            {"GATEWAY_ADMIN_ENDPOINT": "https://127.0.0.1:99999/api/usage/ingest"},
            {
                "GATEWAY_RUNTIME_CONFIG": '{"schemaVersion":1,"catalogModelIds":["model-a"],"inferenceModelIds":["model-a"]}'
            },
        ):
            with self.subTest(settings=list(settings)):
                try:
                    with self.assertRaises(RuntimeError):
                        await self.start(settings)
                finally:
                    await self.gateway.close()
                    self.gateway = None

    async def test_projected_credentials_work_and_unsafe_files_fail_startup(self):
        """K1: projected files work; unsafe mounts fail without blocking startup."""
        for layout in ("empty", "outside", "fifo"):
            with self.subTest(layout=layout):
                try:
                    with self.assertRaises(RuntimeError):
                        await self.start(pepper_layout=layout, startup_timeout=2)
                    self.assertIsNotNone(
                        self.gateway.process.poll(),
                        "unsafe credentials must cause process exit",
                    )
                finally:
                    await self.gateway.close()
                    self.gateway = None
        await self.start(pepper_layout="projected")
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_cold_readiness_catalog_and_snapshot(self):
        """K1/K6/I1: a real listener waits for a snapshot but keeps its catalog."""
        await self.start(apply=False)
        status, _, body = await self.send("/ready", method="GET")
        self.assertEqual(status, 503)
        self.assertEqual(orjson.loads(body)["status"], "key_registry_not_ready")
        self.assertEqual((await self.send("/v1/models", method="GET"))[0], 200)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 503)
        self.assertEqual((await self.push(snapshot()))[0], 200)
        self.assertEqual((await self.send("/ready", method="GET"))[0], 200)

    async def test_private_metrics_and_log_privacy(self):
        """T2/T3/F1: metrics stay private; reviewed logs exclude caller data."""
        from prometheus_client.parser import text_string_to_metric_families

        await self.start({"GATEWAY_INSTANCE_ID": "gateway-test", "RUST_LOG": "trace"})
        canary = "private-prompt-canary-839212"
        status, headers, _ = await self.send(
            body={"model": MODEL, "messages": [{"role": "user", "content": canary}]},
            headers={
                "x-request-id": "caller-log-canary",
                "X-Confidential-Gateway": "caller-instance-canary",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-confidential-gateway"], "gateway-test")
        self.assertIn((await self.send("/metrics", method="GET"))[0], (401, 404))
        await asyncio.sleep(0.05)
        async with self.client.get("http://127.0.0.1:9090/metrics") as result:
            self.assertEqual(result.status, 200)
            raw = await result.text()
        samples = [
            sample
            for family in text_string_to_metric_families(raw)
            for sample in family.samples
        ]
        values = (ROOT / "helm/confidential-inference/values.yaml").read_text()
        # Read the two flat default allowlists without adding a YAML dependency.
        allowed_labels = set()
        for prefix in ("  commonLabels: [", "    gateway: ["):
            allowed_labels.update(
                label.strip()
                for label in values.split(prefix, 1)[1].split("]", 1)[0].split(",")
            )
        for sample in samples:
            self.assertLessEqual(set(sample.labels), allowed_labels, sample.name)

        def metric(name, **labels):
            return next(
                sample.value
                for sample in samples
                if sample.name == name
                and all(
                    sample.labels.get(key) == value for key, value in labels.items()
                )
            )

        self.assertEqual(metric("gateway_key_registry_revision"), 1)
        self.assertEqual(metric("gateway_inference_active"), 0)
        self.assertEqual(metric("gateway_router_requests_active"), 0)
        self.assertEqual(metric("gen_ai_client_token_usage_total", type="input"), 8)
        self.assertGreater(metric("process_resident_memory_bytes"), 0)
        self.assertGreaterEqual(metric("process_cpu_seconds_total"), 0)
        self.assertIn("gateway_request_completed", self.gateway.logs())
        for private in (
            canary,
            API_KEY,
            ADMIN_KEY,
            "caller-log-canary",
            "caller-instance-canary",
        ):
            self.assertNotIn(private, raw)
            self.assertNotIn(private, self.gateway.logs())
        import re

        policy = (
            ROOT / "helm/confidential-inference/templates/_log-policy.tpl"
        ).read_text()
        listed = policy.split("gatewayMessages:", 1)[1].split("auditRecord:", 1)[0]
        allowed = {
            orjson.loads(line.strip()[2:])
            for line in listed.splitlines()
            if line.strip().startswith('- "')
        }
        audit = policy.split("auditRecord: '", 1)[1].split("'", 1)[0]
        for line in self.gateway.logs().splitlines():
            record = orjson.loads(line)
            # The old Rust filter permits this library's startup diagnostics.
            # The collector drops them. Python permits only reviewed records.
            if (
                self.gateway.kind == "rust"
                and record.get("log.target", "").startswith(
                    "rustls_platform_verifier::"
                )
                and record["level"] in ("DEBUG", "TRACE")
            ):
                continue
            self.assertIn(record["level"], ("INFO", "WARN", "ERROR"), record)
            self.assertTrue(
                record["message"] in allowed or re.fullmatch(audit, record["message"]),
                record["message"],
            )

    async def test_cumulative_usage_is_replaced_and_flushed_once(self):
        """B1/B2: cumulative frames replace totals; shutdown flushes one event."""
        from uuid import UUID

        await self.start_with_admin(usage=True)

        async def reply(request, value):
            frames = [
                {
                    "model": "backend",
                    "choices": [{"delta": {"content": "x"}}],
                    "usage": {"prompt_tokens": count, "completion_tokens": 2},
                }
                for count in (3, 6)
            ]
            frames.append(
                {
                    "model": "backend",
                    "choices": [],
                    "usage": {"prompt_tokens": 8, "completion_tokens": 2},
                }
            )
            return web.Response(
                body=b"".join(
                    b"data: " + orjson.dumps(frame) + b"\n\n" for frame in frames
                )
                + b"data: [DONE]\n\n",
                content_type="text/event-stream",
            )

        self.reply = reply
        self.assertEqual(
            (await self.send(body={"model": MODEL, "stream": True}))[0], 200
        )
        await self.gateway.close()
        self.gateway = None
        self.assertEqual(len(self.admin_peer.events), 1)
        event = self.admin_peer.events[0]
        self.assertEqual((event["input_tokens"], event["output_tokens"]), (8, 2))
        self.assertTrue(event["final_usage"])
        self.assertEqual(event["outcome"], "completed")
        self.assertEqual(UUID(event["request_id"]).version, 4)
        self.assertGreater(event["ended_at_ms"], 0)
        self.assertTrue(event["producer_instance"])

    async def test_responses_terminal_events_and_usage_binding(self):
        """I2/I5/T1: all terminal Responses events finish and report approved usage."""
        await self.start_with_admin(usage=True)
        state = {"status": "completed", "model": "backend"}

        async def reply(request, value):
            terminal = {
                "type": "response." + state["status"],
                "response": {
                    "model": state["model"],
                    "status": state["status"],
                    "usage": {
                        "input_tokens": 8,
                        "output_tokens": 2,
                        "input_tokens_details": {"cached_tokens": 3},
                        "output_tokens_details": {"reasoning_tokens": 1},
                    },
                },
            }
            return web.Response(
                body=b"event: response.created\ndata: "
                + orjson.dumps({"type": "response.created"})
                + b"\n\nevent: "
                + terminal["type"].encode()
                + b"\ndata: "
                + orjson.dumps(terminal)
                + b"\n\n",
                content_type="text/event-stream",
            )

        self.reply = reply
        for terminal in ("completed", "incomplete", "failed"):
            state["status"] = terminal
            status, _, raw = await self.send(
                "/v1/responses", {"model": MODEL, "input": "hello", "stream": True}
            )
            self.assertEqual(status, 200)
            self.assertIn(b'"model":"model-a"', raw)
            self.assertNotIn(b"[DONE]", raw)
            self.assertFalse(self.received[-1][1]["store"])
        state.update(status="completed", model="wrong-backend")
        self.assertEqual(
            (
                await self.send(
                    "/v1/responses", {"model": MODEL, "input": "hello", "stream": True}
                )
            )[0],
            200,
        )
        async with asyncio.timeout(10):
            while len(self.admin_peer.events) < 4:
                await asyncio.sleep(0.05)
        self.assertEqual(
            [event["outcome"] for event in self.admin_peer.events],
            ["completed", "completed", "failed", "completed"],
        )
        for event in self.admin_peer.events[:3]:
            self.assertEqual(
                (
                    event["input_tokens"],
                    event["output_tokens"],
                    event["cached_input_tokens"],
                    event["reasoning_tokens"],
                ),
                (8, 2, 3, 1),
            )
            self.assertTrue(event["final_usage"])
        mismatch = self.admin_peer.events[3]
        self.assertIsNone(mismatch["input_tokens"])
        self.assertIsNone(mismatch["output_tokens"])
        self.assertFalse(mismatch["final_usage"])

    async def test_internal_stream_usage_is_hidden_only_when_not_requested(self):
        """T1/I3: request backend usage without adding an unsolicited public frame."""
        await self.start_with_admin(usage=True)

        async def reply(request, value):
            self.assertTrue(value["stream_options"]["include_usage"])
            raw = b"data: " + orjson.dumps(
                {
                    "model": "backend",
                    "choices": [{"delta": {"content": "hi"}, "finish_reason": "stop"}],
                }
            )
            raw += b"\n\ndata: " + orjson.dumps(
                {
                    "model": "backend",
                    "choices": [],
                    "usage": {"prompt_tokens": 8, "completion_tokens": 2},
                }
            )
            return web.Response(
                body=raw + b"\n\ndata: [DONE]\n\n", content_type="text/event-stream"
            )

        self.reply = reply
        for included in (False, True):
            value = {
                "model": MODEL,
                "stream": True,
                "messages": [{"role": "user", "content": "hi"}],
            }
            if included:
                value["stream_options"] = {"include_usage": True}
            status, _, body = await self.send(body=value)
            self.assertEqual(status, 200)
            self.assertEqual(b"prompt_tokens" in body, included)
            self.assertTrue(body.endswith(b"data: [DONE]\n\n"))
        async with asyncio.timeout(10):
            while len(self.admin_peer.events) < 2:
                await asyncio.sleep(0.05)
        for event in self.admin_peer.events:
            self.assertEqual(
                (
                    event["input_tokens"],
                    event["output_tokens"],
                    event["outcome"],
                    event["final_usage"],
                ),
                (8, 2, "completed", True),
            )

    async def test_plain_peppered_and_revoked_keys(self):
        """K2/K4: both digest algorithms authenticate; revocation denies both."""
        await self.start()
        value = snapshot(2)
        row = value["keys"][0].copy()
        row["id"] = "key_hmac"
        row.pop("hashAlgorithm")
        row["pepperFingerprint"] = hashlib.sha256(
            b"confidential.ai/gateway-pepper-fingerprint/v1" + b"test-pepper" * 4
        ).hexdigest()
        row["keyHash"] = (
            base64.urlsafe_b64encode(
                hmac.digest(b"test-pepper" * 4, (API_KEY + "-hmac").encode(), "sha256")
            )
            .decode()
            .rstrip("=")
        )
        value["keys"].append(row)
        self.assertEqual((await self.push(value))[0], 200)
        for key in (API_KEY, API_KEY + "-hmac"):
            self.assertEqual(
                (await self.send(body={"model": MODEL}, token=key))[0], 200
            )
        value["revision"] = 3
        for row in value["keys"]:
            row["revokedAt"] = "2026-01-02T00:00:00Z"
        self.assertEqual((await self.push(value))[0], 200)
        for key in (API_KEY, API_KEY + "-hmac", "invalid"):
            status, _, body = await self.send(body={"model": MODEL}, token=key)
            self.assertEqual(status, 401)
            self.assertEqual(orjson.loads(body)["error"]["code"], "invalid_api_key")

    async def test_pepper_mismatch_rows_and_envelopes(self):
        """K4: skip mismatched HMAC rows, reject mismatched envelopes and plain rows."""
        import copy

        await self.start()
        value = snapshot(2)
        hmac_row = copy.deepcopy(value["keys"][0])
        hmac_row.update(
            id="key_wrong_pepper",
            hashAlgorithm="hmac-sha256",
            pepperFingerprint="0" * 64,
        )
        value["keys"].append(hmac_row)
        status, _, body = await self.push(value)
        self.assertEqual(status, 200)
        self.assertEqual(orjson.loads(body)["skippedPepperMismatch"], 1)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)
        value = snapshot(3)
        value["pepperFingerprint"] = "0" * 64
        self.assertEqual((await self.push(value))[0], 409)
        value["pepperFingerprint"] = ""
        value["keys"][0]["pepperFingerprint"] = "0" * 64
        self.assertEqual((await self.push(value))[0], 400)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_cors_and_public_input_bounds(self):
        """I6/L1: CORS preflight needs no key; URI, headers and forwarding stay bounded."""
        await self.start()
        status, headers, _ = await self.send(
            method="OPTIONS",
            token="",
            headers={
                "Origin": "https://client.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Access-Control-Allow-Origin"], "*")
        self.assertEqual(
            {
                value.strip().lower()
                for value in headers["Access-Control-Allow-Headers"].split(",")
            },
            {"authorization", "content-type", "accept", "x-smg-routing-key"},
        )
        self.assertEqual(
            (await self.send("/health?" + "x" * 2100, method="GET"))[0], 414
        )
        self.assertEqual(
            (
                await self.send(
                    "/health",
                    method="GET",
                    headers={f"X-Fill-{index}": "x" * 8000 for index in range(3)},
                )
            )[0],
            431,
        )
        self.assertEqual(
            (
                await self.send(
                    "/health", method="GET", headers={"Forwarded": "for=192.0.2.1"}
                )
            )[0],
            400,
        )
        self.assertEqual(self.received, [])

    async def test_execution_queue_is_bounded_and_releases_waiters(self):
        """L2: one queued request waits; overflow is refused without forwarding."""
        await self.start(
            {
                "GATEWAY_INFERENCE_CONCURRENCY": "1",
                "GATEWAY_INFERENCE_QUEUE": "1",
                "GATEWAY_QUEUE_TIMEOUT_SECONDS": "2",
            }
        )
        entered, release = asyncio.Event(), asyncio.Event()

        async def reply(request, value):
            entered.set()
            await release.wait()
            return web.json_response({"model": "backend", "choices": []})

        self.reply = reply
        first = asyncio.create_task(self.send(body={"model": MODEL}))
        second = None
        try:
            async with asyncio.timeout(2):
                await entered.wait()
            second = asyncio.create_task(self.send(body={"model": MODEL}))
            async with asyncio.timeout(2):
                while True:
                    async with self.client.get(
                        "http://127.0.0.1:9090/metrics"
                    ) as response:
                        metrics = await response.text()
                    if 'gateway_inference_queue_depth{env="test"} 1' in metrics:
                        break
                    await asyncio.sleep(0.01)
            self.assertFalse(second.done())
            status, headers, raw = await self.send(body={"model": MODEL})
            self.assertEqual(status, 429)
            self.assertIn("Retry-After", headers)
            self.assertEqual(orjson.loads(raw)["error"]["code"], "inference_capacity")
            self.assertEqual(len(self.received), 1)
        finally:
            release.set()
            results = await asyncio.gather(first, *([second] if second else []))
        self.assertEqual([result[0] for result in results], [200, 200])
        self.assertEqual(len(self.received), 2)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_execution_queue_timeout_does_not_leak_capacity(self):
        """L2: an expired waiter cannot reach the router or retain a permit."""
        await self.start(
            {
                "GATEWAY_INFERENCE_CONCURRENCY": "1",
                "GATEWAY_INFERENCE_QUEUE": "1",
                "GATEWAY_QUEUE_TIMEOUT_SECONDS": "1",
            }
        )
        entered, release = asyncio.Event(), asyncio.Event()

        async def reply(request, value):
            entered.set()
            await release.wait()
            return web.json_response({"model": "backend", "choices": []})

        self.reply = reply
        first = asyncio.create_task(self.send(body={"model": MODEL}))
        try:
            async with asyncio.timeout(2):
                await entered.wait()
                status, _, raw = await self.send(body={"model": MODEL})
            self.assertEqual(status, 429)
            self.assertEqual(orjson.loads(raw)["error"]["code"], "inference_capacity")
            self.assertEqual(len(self.received), 1)
        finally:
            release.set()
            await first
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_public_capacity_is_held_during_upload_and_released(self):
        """L1: global and address capacity independently bound incomplete uploads."""
        cases = [
            ({"GATEWAY_GLOBAL_REQUEST_CONCURRENCY": "1"}, 503, "request_capacity"),
            ({"GATEWAY_PER_ADDRESS_CONCURRENCY": "1"}, 429, "address_capacity"),
        ]
        for settings, expected_status, expected_code in cases:
            await self.start(settings)
            release = asyncio.Event()

            async def slow():
                yield b'{"model":'
                await release.wait()
                yield b'"model-a"}'

            upload = asyncio.ensure_future(
                self.client.post(
                    "http://127.0.0.1:9443/v1/chat/completions",
                    data=slow(),
                    headers={"Authorization": "Bearer " + API_KEY},
                )
            )
            try:
                async with asyncio.timeout(2):
                    while True:
                        status, _, raw = await self.send("/health", method="GET")
                        if status != 200:
                            break
                        await asyncio.sleep(0.01)
                self.assertEqual(status, expected_status)
                self.assertEqual(orjson.loads(raw)["error"]["code"], expected_code)
                self.assertEqual(self.received, [])
            finally:
                release.set()
                response = await upload
                await response.read()
                response.close()
                await self.gateway.close()
                self.gateway = None
            self.assertEqual(response.status, 200)
            self.received.clear()

    async def test_trusted_proxy_addresses_have_separate_rate_limits(self):
        """L1: trusted single addresses select a bucket; malformed chains fail."""
        await self.start(
            {
                "GATEWAY_TRUSTED_PROXY_CIDRS": "127.0.0.0/8",
                "GATEWAY_REQUESTS_PER_ADDRESS_PER_SECOND": "2",
            }
        )
        headers = {"X-Forwarded-For": "192.0.2.1", "X-Real-IP": "192.0.2.1"}
        for _ in range(2):
            self.assertEqual(
                (await self.send(body={"model": MODEL}, headers=headers))[0], 200
            )
        status, _, raw = await self.send(body={"model": MODEL}, headers=headers)
        self.assertEqual(status, 429)
        self.assertEqual(orjson.loads(raw)["error"]["code"], "address_rate_limited")
        self.assertEqual(
            (
                await self.send(
                    body={"model": MODEL}, headers={"X-Forwarded-For": "192.0.2.2"}
                )
            )[0],
            200,
        )
        for value in ("192.0.2.3, 192.0.2.4", "not-an-address"):
            status, _, raw = await self.send(
                body={"model": MODEL}, headers={"X-Forwarded-For": value}
            )
            self.assertEqual(status, 400)
            self.assertEqual(
                orjson.loads(raw)["error"]["code"], "invalid_forwarding_headers"
            )
        self.assertEqual(
            (
                await self.send(
                    body={"model": MODEL},
                    headers={"X-Forwarded-For": "192.0.2.3", "X-Real-IP": "192.0.2.4"},
                )
            )[0],
            400,
        )
        self.assertEqual(len(self.received), 3)

    async def test_monthly_budget_and_rate_refill(self):
        """L3: one token bucket refills over time and completed tokens exhaust a monthly budget."""
        await self.start_with_admin(usage=True)
        value = snapshot(2)
        value["keys"][0].update(
            rateLimit={"requestsPerMinute": 60, "burst": 1},
            tokenBudget={"tokens": 20, "window": "month"},
        )
        self.assertEqual((await self.push(value))[0], 200)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)
        status, _, raw = await self.send(body={"model": MODEL})
        self.assertEqual(status, 429)
        self.assertEqual(orjson.loads(raw)["error"]["code"], "rate_limit_exceeded")
        await asyncio.sleep(1.05)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)
        status, _, raw = await self.send(body={"model": MODEL})
        self.assertEqual(status, 429)
        self.assertEqual(orjson.loads(raw)["error"]["code"], "insufficient_quota")

    @unittest.skipUnless(
        os.environ.get("GATEWAY_LONG_TESTS") == "1",
        "100001-request usage queue acceptance",
    )
    async def test_full_usage_queue_drops_only_the_oldest_event(self):
        """B1/B2: a full queue keeps the latest 100000 events and bounded batches."""
        from prometheus_client.parser import text_string_to_metric_families

        asyncio.get_running_loop().set_debug(False)
        await self.start_with_admin(usage=True)
        self.admin_peer.unavailable = True
        counter = 0

        async def reply(request, value):
            nonlocal counter
            counter += 1
            return web.json_response(
                {
                    "model": "backend",
                    "choices": [],
                    "usage": {"prompt_tokens": counter, "completion_tokens": 1},
                }
            )

        self.reply = reply

        async def complete():
            self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

        await complete()
        # The first event must be saved before any later request starts.
        async with asyncio.timeout(2):
            while True:
                async with self.client.get("http://127.0.0.1:9090/metrics") as response:
                    raw = await response.text()
                if 'gateway_usage_events_pending{env="test"} 1' in raw:
                    break
                await asyncio.sleep(0.01)
        for _ in range(3125):
            await asyncio.gather(*(complete() for _ in range(32)))
        async with self.client.get("http://127.0.0.1:9090/metrics") as response:
            samples = [
                sample
                for family in text_string_to_metric_families(await response.text())
                for sample in family.samples
            ]
        for name, expected in (
            ("gateway_usage_events_pending", 100000),
            ("gateway_usage_events_dropped_total", 1),
        ):
            self.assertEqual(
                next(sample.value for sample in samples if sample.name == name),
                expected,
            )
        self.admin_peer.unavailable = False
        await self.gateway.close(timeout=25)
        self.gateway = None
        events = self.admin_peer.events
        self.assertEqual(len(events), 100000)
        self.assertEqual(
            sorted(event["input_tokens"] for event in events), list(range(2, 100002))
        )
        self.assertEqual(len({event["request_id"] for event in events}), 100000)
        self.assertTrue(
            all(
                event["outcome"] == "completed"
                and event["final_usage"]
                and event["output_tokens"] == 1
                for event in events
            )
        )
        self.assertTrue(
            all(1 <= len(batch) <= 500 for batch in self.admin_peer.batches)
        )
        print(
            "Queue acceptance: 100000 unique retained events; duplicate deliveries:",
            self.admin_peer.duplicate_deliveries,
            flush=True,
        )

    async def test_usage_batch_splitting_drops_only_the_refused_event(self):
        """B2: retain accepted usage when the admin permanently refuses one event."""
        await self.start_with_admin(usage=True)
        self.admin_peer.reject_input_tokens = 99
        state = {"input": 8}

        async def reply(request, value):
            return web.json_response(
                {
                    "model": "backend",
                    "choices": [],
                    "usage": {"prompt_tokens": state["input"], "completion_tokens": 2},
                }
            )

        self.reply = reply
        for amount in (8, 99, 10):
            state["input"] = amount
            self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)
        async with asyncio.timeout(10):
            while len(self.admin_peer.events) < 2:
                await asyncio.sleep(0.05)
        self.assertEqual(
            [event["input_tokens"] for event in self.admin_peer.events], [8, 10]
        )
        self.assertEqual(
            len({event["request_id"] for event in self.admin_peer.events}), 2
        )
        self.assertGreater(len(self.admin_peer.batches), 1)

    async def test_snapshot_revision_and_environment(self):
        """K3: equal revisions acknowledge; rollback/wrong environment do not replace."""
        await self.start()
        self.assertEqual((await self.push(snapshot(2)))[0], 200)
        equal = snapshot(2)
        equal["keys"] = []
        status, _, body = await self.push(equal)
        self.assertEqual(status, 200)
        self.assertFalse(orjson.loads(body)["applied"])
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

        self.assertEqual((await self.push(snapshot(1)))[0], 409)
        wrong = snapshot(3)
        wrong["environment"] = "different"
        self.assertEqual((await self.push(wrong))[0], 400)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_malformed_snapshot_leaves_cached_keys_unchanged(self):
        """K3/F1: malformed typed snapshots never replace an accepted registry."""
        import copy

        await self.start()
        invalid = [
            [],
            "invalid",
            {**snapshot(2), "revision": True},
            {**snapshot(2), "tokenUsage": []},
        ]
        for field, value in (("rateLimit", []), ("tokenBudget", [])):
            candidate = copy.deepcopy(snapshot(2))
            candidate["keys"][0][field] = value
            invalid.append(candidate)
        for candidate in invalid:
            with self.subTest(value=candidate):
                # Rust's JSON extractor uses 422 for typed schema errors.
                # F1 permits framework-specific parser envelopes and statuses.
                self.assertIn((await self.push(candidate))[0], (400, 422))
                self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_upstream_errors_are_sanitized_and_redirects_are_not_followed(self):
        """I3/F1: preserve status with fixed errors, bounded retry, and no redirect."""
        await self.start()
        state = {"status": 400, "retry": "999999"}

        async def reply(request, value):
            return web.Response(
                status=state["status"],
                text="private-upstream-error-canary",
                headers={
                    "Location": self.upstream + "/do-not-follow",
                    "Retry-After": state["retry"],
                },
            )

        self.reply = reply
        for status in (400, 404, 408, 413, 422, 429, 500, 503, 307):
            state["status"] = status
            received, headers, raw = await self.send(body={"model": MODEL})
            self.assertEqual(received, status)
            self.assertNotIn(b"private-upstream-error-canary", raw)
            self.assertNotIn("Location", headers)
            self.assertIn("error", orjson.loads(raw))
            if status == 503:
                self.assertEqual(headers["Retry-After"], "30")
            else:
                self.assertNotIn("Retry-After", headers)
        state.update(status=429, retry="17")
        self.assertEqual(
            (await self.send(body={"model": MODEL}))[1]["Retry-After"], "17"
        )

    async def test_fields_ids_and_public_model(self):
        """I3/I4/I5: preserve tool input, replace model, keep caller credentials out."""
        await self.start()
        value = {
            "model": MODEL,
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": 0.7,
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "test", "parameters": {"type": "object"}},
                }
            ],
        }
        status, headers, body = await self.send(
            body=value,
            headers={
                "x-request-id": "caller-canary",
                "X-SMG-Routing-Key": "routing-canary",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(orjson.loads(body)["model"], MODEL)
        _, observed, sent = self.received[-1]
        self.assertEqual(observed, value)
        sent = {k.lower(): v for k, v in sent.items()}
        self.assertNotIn("authorization", sent)
        self.assertNotEqual(sent["x-request-id"], "caller-canary")
        self.assertEqual(headers["x-ci-request-id"], sent["x-request-id"])
        self.assertNotEqual(sent["x-smg-routing-key"], "routing-canary")

    async def test_fragmented_stream_rewrites_model_and_preserves_content(self):
        """I5: single UTF-8 bytes across writes do not corrupt output or markers."""
        await self.start()
        status, _, body = await self.send(
            body={
                "model": MODEL,
                "stream": True,
                "messages": [{"role": "user", "content": "hi"}],
            }
        )
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertIn("日", text)
        self.assertIn(": heartbeat\r\n", text)
        self.assertIn('"model":"model-a"', text)
        self.assertTrue(text.endswith("data: [DONE]\n\n"))

    async def test_streamed_tool_arguments_and_sampling_fields_are_preserved(self):
        """I3/I5: tool deltas survive split JSON lines and partial arguments."""
        await self.start()
        frames = [
            {
                "id": "tool-result",
                "model": "backend",
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call-1",
                                    "type": "function",
                                    "function": {
                                        "name": "lookup",
                                        "arguments": '{"city":"',
                                    },
                                }
                            ]
                        },
                    }
                ],
            },
            {
                "id": "tool-result",
                "model": "backend",
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {"index": 0, "function": {"arguments": '東京"}'}}
                            ]
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
            },
        ]

        async def reply(request, value):
            response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
            await response.prepare(request)
            for value in frames:
                encoded = b"data: " + orjson.dumps(value) + b"\n\n"
                for start in range(0, len(encoded), 7):
                    await response.write(encoded[start : start + 7])
                    await asyncio.sleep(0)
            await response.write(b"data: [DONE]\n\n")
            return response

        self.reply = reply
        value = {
            "model": MODEL,
            "stream": True,
            "messages": [{"role": "user", "content": "lookup"}],
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "lookup", "parameters": {"type": "object"}},
                }
            ],
            "tool_choice": "auto",
            "parallel_tool_calls": True,
            "temperature": 0.2,
            "top_p": 0.9,
            "max_tokens": 512,
            "stop": ["END"],
        }
        status, _, raw = await self.send(body=value)
        self.assertEqual(status, 200)
        self.assertEqual(self.received[-1][1], value)
        observed = [
            orjson.loads(line[5:])
            for line in raw.splitlines()
            if line.startswith(b"data:") and b"[DONE]" not in line
        ]
        self.assertEqual(observed, [{**frame, "model": MODEL} for frame in frames])
        self.assertTrue(raw.endswith(b"data: [DONE]\n\n"))

    async def test_affinity_is_stable_and_separates_key_records(self):
        """I4: inline and worker parsing use one process secret and isolate keys."""
        import copy

        await self.start()
        value = snapshot(2)
        second = copy.deepcopy(value["keys"][0])
        second.update(
            id="key_second",
            keyHash=base64.urlsafe_b64encode(
                hashlib.sha256((API_KEY + "-second").encode()).digest()
            )
            .decode()
            .rstrip("="),
        )
        value["keys"].append(second)
        self.assertEqual((await self.push(value))[0], 200)
        body = {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": "system"},
                {"role": "user", "content": "opening"},
            ],
        }

        async def affinity(body, token=API_KEY, tag=None):
            self.assertEqual(
                (
                    await self.send(
                        body=body,
                        token=token,
                        headers={"X-SMG-Routing-Key": tag} if tag else None,
                    )
                )[0],
                200,
            )
            return next(
                value
                for key, value in self.received[-1][2].items()
                if key.lower() == "x-smg-routing-key"
            )

        first = await affinity(body)
        large = copy.deepcopy(body)
        large["padding"] = "x" * 65536
        large["messages"].append({"role": "assistant", "content": "later"})
        self.assertEqual(await affinity(large), first)
        self.assertNotEqual(await affinity(body, API_KEY + "-second"), first)
        explicit = await affinity(body, tag="customer-conversation")
        self.assertEqual(await affinity(large, tag="customer-conversation"), explicit)
        self.assertNotEqual(
            await affinity(body, API_KEY + "-second", "customer-conversation"), explicit
        )
        self.assertNotEqual(explicit, "customer-conversation")

    async def test_body_boundary_and_responses_state_refusal(self):
        """L1/I2/F1: exact body limit succeeds; excess/stateful input never forwards."""
        await self.start({"GATEWAY_MAXIMUM_BODY_BYTES": "1024"})
        prefix, suffix = b'{"model":"model-a","padding":"', b'"}'
        value = prefix + b"x" * (1024 - len(prefix) - len(suffix)) + suffix
        self.assertEqual((await self.send(body=value))[0], 200)
        self.assertEqual((await self.send(body=value + b" "))[0], 413)
        count = len(self.received)
        status, _, body = await self.send(
            "/v1/responses", {"model": MODEL, "input": "hi", "store": True}
        )
        self.assertEqual(status, 400)
        self.assertEqual(
            orjson.loads(body)["error"]["code"], "stateful_responses_not_supported"
        )
        self.assertEqual(len(self.received), count)

    async def test_encoded_bodies_are_not_expanded_before_admission(self):
        """L1/P1: body bytes and memory reservations use the wire representation."""
        import gzip

        await self.start({"GATEWAY_MAXIMUM_BODY_BYTES": "1024"})
        encoded = gzip.compress(orjson.dumps({"model": MODEL, "padding": "x" * 200000}))
        self.assertLess(len(encoded), 1024)
        status, _, body = await self.send(
            body=encoded, headers={"Content-Encoding": "gzip"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(orjson.loads(body)["error"]["code"], "invalid_json")
        self.assertEqual(self.received, [])
        # A header alone does not change the body that the baseline parses.
        self.assertEqual(
            (
                await self.send(
                    body=orjson.dumps({"model": MODEL}),
                    headers={"Content-Encoding": "gzip"},
                )
            )[0],
            200,
        )

    async def test_disconnect_releases_execution_and_upstream_connection(self):
        """L2/V2: hold a key permit through a stream; release it on disconnect."""
        await self.start(
            {"GATEWAY_INFERENCE_CONCURRENCY": "2", "GATEWAY_PER_KEY_CONCURRENCY": "1"}
        )
        stopped = asyncio.Event()

        async def reply(request, value):
            response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
            await response.prepare(request)
            try:
                await response.write(
                    b'data: {"model":"backend","choices":[{"delta":{"content":"hi"}}]}\n\n'
                )
                await asyncio.Event().wait()
            finally:
                stopped.set()
            return response

        self.reply = reply
        response = await self.client.post(
            "http://127.0.0.1:9443/v1/chat/completions",
            json={"model": MODEL, "stream": True},
            headers={"Authorization": "Bearer " + API_KEY},
        )
        try:
            self.assertEqual(response.status, 200)
            self.assertTrue((await response.content.readline()).startswith(b"data:"))
            before = len(self.received)
            status, _, body = await self.send(body={"model": MODEL})
            self.assertEqual(status, 429)
            self.assertEqual(orjson.loads(body)["error"]["code"], "inference_capacity")
            self.assertEqual(len(self.received), before)
        finally:
            response.close()
        async with asyncio.timeout(1):
            await stopped.wait()
        self.reply = None
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_slow_reader_bounds_memory_and_does_not_block_another_request(self):
        """I5/L2/V2: a blocked reader holds bounded buffers and releases on close."""
        from prometheus_client.parser import text_string_to_metric_families

        await self.start(
            {"GATEWAY_INFERENCE_CONCURRENCY": "2", "GATEWAY_PER_KEY_CONCURRENCY": "2"}
        )

        async def resident():
            async with self.client.get("http://127.0.0.1:9090/metrics") as response:
                return next(
                    sample.value
                    for family in text_string_to_metric_families(await response.text())
                    for sample in family.samples
                    if sample.name == "process_resident_memory_bytes"
                )

        baseline = await resident()
        stopped = asyncio.Event()
        written = 0
        payload = (
            b"data: "
            + orjson.dumps(
                {"model": "backend", "choices": [{"delta": {"content": "x" * 16384}}]}
            )
            + b"\n\n"
        )

        async def reply(request, value):
            nonlocal written
            if not value.get("slow_reader"):
                return web.json_response({"model": "backend", "choices": []})
            response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
            await response.prepare(request)
            try:
                while written < 128 * 1024**2:
                    await response.write(payload)
                    written += len(payload)
                    await asyncio.sleep(0)
            except ConnectionError:
                pass
            finally:
                stopped.set()
            return response

        self.reply = reply
        response = await self.client.post(
            "http://127.0.0.1:9443/v1/chat/completions",
            json={"model": MODEL, "stream": True, "slow_reader": True},
            headers={"Authorization": "Bearer " + API_KEY},
        )
        try:
            self.assertEqual(response.status, 200)
            async with asyncio.timeout(4):
                while True:
                    before = written
                    await asyncio.sleep(0.1)
                    if written == before and written > 65536:
                        break
            self.assertLess(written, 128 * 1024**2)
            self.assertFalse(stopped.is_set())
            self.assertLess(await resident() - baseline, 64 * 1024**2)
            async with asyncio.timeout(1):
                self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)
        finally:
            response.close()
        async with asyncio.timeout(1):
            await stopped.wait()
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_graceful_shutdown_keeps_an_admitted_stream(self):
        """V2: SIGTERM stops the gateway after an admitted response finishes."""
        await self.start(
            {
                "GATEWAY_SHUTDOWN_GRACE_SECONDS": "8",
                "GATEWAY_UPSTREAM_TIMEOUT_SECONDS": "3",
                "GATEWAY_BODY_TIMEOUT_SECONDS": "1",
                "GATEWAY_QUEUE_TIMEOUT_SECONDS": "1",
                "GATEWAY_FIRST_TOKEN_TIMEOUT_SECONDS": "1",
                "GATEWAY_STREAM_IDLE_TIMEOUT_SECONDS": "1",
            }
        )

        async def reply(request, value):
            response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
            await response.prepare(request)
            await response.write(b": heartbeat\n\n")
            for _ in range(10):
                await asyncio.sleep(0.2)
                await response.write(b": heartbeat\n\n")
            await response.write(b"data: [DONE]\n\n")
            return response

        self.reply = reply
        async with self.client.post(
            "http://127.0.0.1:9443/v1/chat/completions",
            json={"model": MODEL, "stream": True},
            headers={"Authorization": "Bearer " + API_KEY},
        ) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(await response.content.readline(), b": heartbeat\n")
            self.gateway.process.terminate()
            self.assertTrue((await response.read()).endswith(b"data: [DONE]\n\n"))
        async with asyncio.timeout(6):
            while self.gateway.process.poll() is None:
                await asyncio.sleep(0.02)
        self.assertEqual(self.gateway.process.returncode, 0)

    async def test_body_timeout_does_not_retain_execution_capacity(self):
        """L1/L2: a stalled upload times out before it can reach inference."""
        await self.start(
            {"GATEWAY_BODY_TIMEOUT_SECONDS": "1", "GATEWAY_INFERENCE_CONCURRENCY": "1"}
        )

        async def slow():
            yield b'{"model":'
            await asyncio.sleep(2)
            yield b'"model-a"}'

        async with self.client.post(
            "http://127.0.0.1:9443/v1/chat/completions",
            data=slow(),
            headers={"Authorization": "Bearer " + API_KEY},
        ) as response:
            self.assertEqual(response.status, 408)
            self.assertEqual(
                (await response.json())["error"]["code"], "request_body_timeout"
            )
        self.assertEqual(self.received, [])
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_header_deadline_does_not_end_an_active_stream(self):
        """L1/I5: incomplete headers time out; the header timer excludes a stream."""
        await self.start({"GATEWAY_HEADER_TIMEOUT_SECONDS": "1"})
        reader, writer = await asyncio.open_connection("127.0.0.1", 9443)
        try:
            writer.write(
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nX-Partial: "
            )
            await writer.drain()
            async with asyncio.timeout(2):
                self.assertEqual(await reader.read(), b"")
        finally:
            writer.close()
            await writer.wait_closed()

        async def reply(request, value):
            response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
            await response.prepare(request)
            await response.write(b": heartbeat\n\n")
            await asyncio.sleep(1.2)
            await response.write(b"data: [DONE]\n\n")
            return response

        self.reply = reply
        status, _, body = await self.send(body={"model": MODEL, "stream": True})
        self.assertEqual(status, 200)
        self.assertTrue(body.endswith(b"data: [DONE]\n\n"))

    async def test_http_parser_errors_do_not_quote_caller_bytes(self):
        """F1/T1: errors before application dispatch also use fixed text."""
        await self.start({"RUST_LOG": "trace"})
        for port in (9443, 9090):
            for invalid in (
                b"private-parser-canary\r\n",
                b"Content-Length: private-parser-canary\r\n",
            ):
                raw = await raw_request(
                    b"GET /health HTTP/1.1\r\nHost: test\r\n" + invalid + b"\r\n", port
                )
                self.assertEqual(raw.split(b" ", 2)[1], b"400")
                self.assertNotIn(b"private-parser-canary", raw)
        self.assertNotIn("private-parser-canary", self.gateway.logs())

    async def test_oversized_upstream_json_and_sse_lines_release_capacity(self):
        """I5/F1: oversized pending responses close without retaining a permit."""
        await self.start({"GATEWAY_INFERENCE_CONCURRENCY": "1"})
        for stream in (False, True):
            stopped = asyncio.Event()

            async def reply(request, value):
                response = web.StreamResponse(
                    headers={
                        "Content-Type": "text/event-stream"
                        if stream
                        else "application/json"
                    }
                )
                await response.prepare(request)
                try:
                    await response.write(b'data: "' if stream else b'"')
                    for _ in range(17 * 16):
                        await response.write(b"x" * 65536)
                        await asyncio.sleep(0)
                except ConnectionError:
                    pass
                finally:
                    stopped.set()
                return response

            self.reply = reply
            async with asyncio.timeout(5):
                with self.assertRaises(aiohttp.ClientPayloadError):
                    await self.send(body={"model": MODEL, "stream": stream})
                await stopped.wait()
            self.reply = None
            self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_first_chunk_and_idle_deadlines_abort_stream(self):
        """P1/I5: first-byte and later idle deadlines both close the upstream."""
        await self.start(
            {
                "GATEWAY_FIRST_TOKEN_TIMEOUT_SECONDS": "1",
                "GATEWAY_STREAM_IDLE_TIMEOUT_SECONDS": "1",
                "GATEWAY_UPSTREAM_TIMEOUT_SECONDS": "5",
            }
        )
        for first in (True, False):
            stopped = asyncio.Event()

            async def reply(request, value):
                response = web.StreamResponse(
                    headers={"Content-Type": "text/event-stream"}
                )
                await response.prepare(request)
                try:
                    if not first:
                        await response.write(b": heartbeat\n\n")
                    await asyncio.Event().wait()
                finally:
                    stopped.set()
                return response

            self.reply = reply
            async with asyncio.timeout(2):
                with self.assertRaises(aiohttp.ClientPayloadError):
                    await self.send(body={"model": MODEL, "stream": True})
                await stopped.wait()

    async def test_dense_json_pays_for_objects_before_materialization(self):
        """P1: valid small text fits; many tiny objects exceed the same budget."""
        await self.start(
            {
                "GATEWAY_MAXIMUM_BODY_BYTES": str(1024**2),
                "GATEWAY_BODY_MEMORY_BYTES": str(13 * 1024**2),
            }
        )
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)
        dense = b'{"model":"model-a","values":[' + b"{}," * 300_000 + b"{}]}"
        before = len(self.received)
        status, _, body = await self.send(body=dense)
        self.assertEqual(status, 413)
        self.assertEqual(orjson.loads(body)["error"]["code"], "request_too_large")
        self.assertEqual(len(self.received), before)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_admin_signature_and_replay(self):
        """K5: exact signed bytes authenticate once; a bearer takes precedence."""
        import time

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        await self.start()
        path = "/admin/v1/api-keys/source"
        stamp, nonce = str(int(time.time())), "abcdef0123456789" * 2
        digest = hashlib.sha256(b"").hexdigest()
        canonical = f"v1\n{stamp}\n{nonce}\nGET\n{path}\n{digest}\n".encode()
        signature = self.gateway.signer.sign(canonical, ec.ECDSA(hashes.SHA256()))
        headers = {
            "X-Admin-Signature-Version": "v1",
            "X-Admin-Timestamp": stamp,
            "X-Admin-Nonce": nonce,
            "X-Admin-Body-SHA256": digest,
            "X-Admin-Signature": base64.urlsafe_b64encode(signature)
            .decode()
            .rstrip("="),
        }
        async with self.client.get(
            "http://127.0.0.1:9443" + path, headers=headers
        ) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual((await response.json())["cachedRevision"], 1)
        async with self.client.get(
            "http://127.0.0.1:9443" + path, headers=headers
        ) as response:
            self.assertEqual(response.status, 401)
            self.assertEqual((await response.json())["code"], "replayed_signature")
        async with self.client.get(
            "http://127.0.0.1:9443" + path,
            headers={**headers, "Authorization": "Bearer invalid"},
        ) as response:
            self.assertEqual(response.status, 401)
            self.assertEqual((await response.json())["code"], "invalid_api_key")
        async with self.client.get(
            "http://127.0.0.1:9443" + path,
            headers={**headers, "X-Admin-Timestamp": "9" * 5000},
        ) as response:
            self.assertEqual(response.status, 401)
            self.assertEqual((await response.json())["code"], "invalid_timestamp")
        # A leading plus and zeros are valid u64 syntax in the Rust baseline.
        for prefix in ("", "+"):
            padded, fresh_nonce = prefix + "0" * 5000 + stamp, os.urandom(16).hex()
            canonical = f"v1\n{padded}\n{fresh_nonce}\nGET\n{path}\n{digest}\n".encode()
            signature = self.gateway.signer.sign(canonical, ec.ECDSA(hashes.SHA256()))
            async with self.client.get(
                "http://127.0.0.1:9443" + path,
                headers={
                    **headers,
                    "X-Admin-Timestamp": padded,
                    "X-Admin-Nonce": fresh_nonce,
                    "X-Admin-Signature": base64.urlsafe_b64encode(signature)
                    .decode()
                    .rstrip("="),
                },
            ) as response:
                self.assertEqual(response.status, 200)
        raw = await raw_request(
            b"GET /admin/v1/api-keys/source HTTP/1.1\r\nHost: test\r\nConnection: close\r\nAuthorization: Bearer private-admin-canary\xff\r\n\r\n"
        )
        self.assertEqual(raw.split(b" ", 2)[1], b"401")
        self.assertNotIn(b"private-admin-canary", raw)

    async def test_signed_snapshot_binds_body_path_and_timestamp(self):
        """K5: signed writes reject tampering and leave the accepted cache intact."""
        import time

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        await self.start()
        path = "/admin/v1/api-keys/snapshot"
        raw = orjson.dumps(snapshot(2))

        def signed(body=raw, route=path, age=0):
            stamp = str(int(time.time()) - age)
            nonce = os.urandom(16).hex()
            digest = hashlib.sha256(body).hexdigest()
            canonical = f"v1\n{stamp}\n{nonce}\nPUT\n{route}\n{digest}\n".encode()
            signature = self.gateway.signer.sign(canonical, ec.ECDSA(hashes.SHA256()))
            return {
                "Content-Type": "application/json",
                "X-Admin-Signature-Version": "v1",
                "X-Admin-Timestamp": stamp,
                "X-Admin-Nonce": nonce,
                "X-Admin-Body-SHA256": digest,
                "X-Admin-Signature": base64.urlsafe_b64encode(signature)
                .decode()
                .rstrip("="),
            }

        cases = [
            (signed(body=raw + b" "), "body_hash_mismatch"),
            (signed(route="/admin/v1/api-keys/source"), "invalid_signature"),
            (signed(age=120), "stale_signature"),
        ]
        duplicate = list(signed().items())
        duplicate.append(("X-Admin-Nonce", "0" * 32))
        cases.append((duplicate, "duplicate_signature_header"))
        for headers, code in cases:
            async with self.client.put(
                "http://127.0.0.1:9443" + path, data=raw, headers=headers
            ) as response:
                self.assertEqual(response.status, 401, code)
                self.assertEqual((await response.json())["code"], code)
            status, _, value = await self.send(
                "/admin/v1/api-keys/source", token=ADMIN_KEY, method="GET"
            )
            self.assertEqual(status, 200)
            self.assertEqual(orjson.loads(value)["cachedRevision"], 1)
        async with self.client.put(
            "http://127.0.0.1:9443" + path, data=raw, headers=signed()
        ) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual((await response.json())["cachedRevision"], 2)

    async def test_key_rate_bucket_is_not_refilled_by_a_snapshot(self):
        """L3: per-key rate refusal happens before forwarding and survives refresh."""
        await self.start()
        value = snapshot(2)
        value["keys"][0]["rateLimit"] = {"requestsPerMinute": 1, "burst": 1}
        self.assertEqual((await self.push(value))[0], 200)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)
        before = len(self.received)
        status, headers, body = await self.send(body={"model": MODEL})
        self.assertEqual(status, 429)
        self.assertEqual(orjson.loads(body)["error"]["code"], "rate_limit_exceeded")
        self.assertTrue(1 <= int(headers["Retry-After"]) <= 60)
        value["revision"] = 3
        self.assertEqual((await self.push(value))[0], 200)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 429)
        self.assertEqual(len(self.received), before)

    async def test_equal_revision_can_refresh_budget_spend(self):
        """L3/K3: newer totals on the same revision deny subsequent requests."""
        from datetime import datetime

        await self.start()
        value = snapshot(2)
        value["keys"][0]["tokenBudget"] = {"tokens": 10, "window": "day"}
        self.assertEqual((await self.push(value))[0], 200)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)
        now = datetime.now(UTC)
        value["tokenUsage"] = {
            "asOf": now.isoformat(),
            "keys": [
                {
                    "id": "key_test",
                    "windowStart": now.replace(
                        hour=0, minute=0, second=0, microsecond=0
                    ).isoformat(),
                    "tokens": 10,
                }
            ],
        }
        status, _, body = await self.push(value)
        self.assertEqual(status, 200)
        self.assertFalse(orjson.loads(body)["applied"])
        status, headers, body = await self.send(body={"model": MODEL})
        self.assertEqual(status, 429)
        self.assertEqual(orjson.loads(body)["error"]["code"], "insufficient_quota")
        self.assertGreater(int(headers["Retry-After"]), 0)

    async def test_duplicate_json_fields_keep_last_value(self):
        """I2/I3: large JSON follows the baseline's last-field-wins behavior."""
        await self.start()
        value = (
            b'{"model":"not-authorized","model":"model-a","padding":"'
            + b"x" * 65536
            + b'"}'
        )
        self.assertEqual((await self.send(body=value))[0], 200)
        self.assertEqual(self.received[-1][1]["model"], MODEL)
        reversed_value = (
            b'{"model":"model-a","model":"not-authorized","padding":"'
            + b"x" * 65536
            + b'"}'
        )
        self.assertEqual((await self.send(body=reversed_value))[0], 401)

    async def test_large_json_preserves_uninterpreted_numeric_fields(self):
        """I3: valid metadata outside integer64 is still passed to the backend."""
        await self.start()
        value = (
            b'{"model":"model-a","metadata":{"number":18446744073709551616},"padding":"'
            + b"x" * 65536
            + b'"}'
        )
        status, _, _ = await self.send(body=value)
        self.assertEqual(status, 200)
        self.assertEqual(
            self.received[-1][1]["metadata"]["number"], 18446744073709551616
        )

    @unittest.skipIf(
        os.environ.get("GATEWAY_TEST_IMPLEMENTATION") == "rust",
        "Python parser process recovery",
    )
    async def test_failed_parser_processes_are_replaced(self):
        """V2: a failed parse can fail one request, but later work recovers."""
        import subprocess
        import sys

        await self.start()
        command = [sys.executable, "-c"]
        if self.gateway.container:
            command = ["docker", "exec", self.gateway.container, "python", "-c"]
        script = """
import os, signal, sys
from pathlib import Path
pid = sys.argv[1]
children = (Path('/proc') / pid / 'task' / pid / 'children').read_text().split()
workers = [int(child) for child in children if b'multiprocessing.spawn' in (Path('/proc') / child / 'cmdline').read_bytes()]
for worker in workers:
    os.kill(worker, signal.SIGKILL)
print(len(workers))
"""
        count = int(
            await asyncio.to_thread(
                subprocess.check_output,
                [
                    *command,
                    script,
                    "1" if self.gateway.container else str(self.gateway.process.pid),
                ],
            )
        )
        self.assertGreater(count, 0)
        body = orjson.dumps(
            {"model": MODEL, "messages": [{"role": "user", "content": "x" * 1024**2}]}
        )
        statuses = []
        for _ in range(2 * count):
            status, _, raw = await self.send(body=body)
            self.assertIn(status, (200, 500))
            if status == 500:
                self.assertEqual(orjson.loads(raw)["error"]["code"], "internal_error")
            statuses.append(status)
        self.assertEqual(statuses[-count:], [200] * count)
        self.assertEqual((await self.send(body={"model": MODEL}))[0], 200)

    async def test_wide_metadata_preserves_fields_without_unbounded_lookup_work(self):
        """I3/P1: wide objects remain valid and do not stall a parser worker."""
        await self.start()
        value = {
            "model": MODEL,
            "metadata": {f"field_{index}": index for index in range(40000)},
        }
        async with asyncio.timeout(3):
            self.assertEqual((await self.send(body=value))[0], 200)
        self.assertEqual(self.received[-1][1], value)
