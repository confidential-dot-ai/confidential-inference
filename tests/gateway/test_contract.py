"""The same socket-level contract checks target Rust and Python.

GATEWAY_TEST_IMPLEMENTATION=rust python -m unittest discover -s tests/gateway
"""

import asyncio
import base64
import hashlib
import hmac
import os
import unittest

import aiohttp
import orjson
from aiohttp import web

from support import ADMIN_KEY, API_KEY, MODEL, Gateway, snapshot


class GatewayContract(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.received = []
        async def upstream(request):
            value = await request.json()
            self.received.append((request.path, value, dict(request.headers)))
            if not value.get("stream"):
                return web.json_response({"id": "result", "model": "backend", "choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 8, "completion_tokens": 2}})
            raw = b': heartbeat\r\n\r\ndata: ' + orjson.dumps({"model": "backend", "choices": [{"delta": {"content": "日"}}]}) + b'\r\n\r\ndata: [DONE]\n\n'
            split = raw.index("日".encode())
            response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
            await response.prepare(request)
            try:
                for chunk in (raw[:split + 1], raw[split + 1:split + 2], raw[split + 2:]):
                    await response.write(chunk)
                    await asyncio.sleep(.01)
            except ConnectionError:
                pass
            return response
        app = web.Application(client_max_size=0)
        for route in ("/v1/chat/completions", "/v1/completions", "/v1/responses"):
            app.router.add_post(route, upstream)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.upstream = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        self.client = aiohttp.ClientSession()
        self.gateway = None

    async def asyncTearDown(self):
        if self.gateway:
            await self.gateway.close()
        await self.client.close()
        await self.runner.cleanup()

    async def start(self, settings=None, apply=True):
        self.gateway = Gateway(os.environ.get("GATEWAY_TEST_IMPLEMENTATION", "python"), self.upstream, settings)
        await self.gateway.start(apply_snapshot=apply)

    async def send(self, path="/v1/chat/completions", body=None, token=API_KEY, method="POST", headers=None):
        supplied = {"Authorization": "Bearer " + token, **(headers or {})}
        if isinstance(body, bytes):
            options = {"data": body}
        elif body is not None:
            options = {"json": body}
        else:
            options = {}
        async with self.client.request(method, "http://127.0.0.1:9443" + path, headers=supplied, **options) as response:
            return response.status, response.headers.copy(), await response.read()

    async def push(self, value):
        return await self.send("/admin/v1/api-keys/snapshot", value, ADMIN_KEY, "PUT")

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

    async def test_plain_peppered_and_revoked_keys(self):
        """K2/K4: both digest algorithms authenticate; revocation denies both."""
        await self.start()
        value = snapshot(2)
        row = value["keys"][0].copy()
        row["id"] = "key_hmac"
        row.pop("hashAlgorithm")
        row["pepperFingerprint"] = hashlib.sha256(b"confidential.ai/gateway-pepper-fingerprint/v1" + b"test-pepper" * 4).hexdigest()
        row["keyHash"] = base64.urlsafe_b64encode(hmac.digest(b"test-pepper" * 4, (API_KEY + "-hmac").encode(), "sha256")).decode().rstrip("=")
        value["keys"].append(row)
        self.assertEqual((await self.push(value))[0], 200)
        for key in (API_KEY, API_KEY + "-hmac"):
            self.assertEqual((await self.send(body={"model": MODEL}, token=key))[0], 200)
        value["revision"] = 3
        for row in value["keys"]:
            row["revokedAt"] = "2026-01-02T00:00:00Z"
        self.assertEqual((await self.push(value))[0], 200)
        for key in (API_KEY, API_KEY + "-hmac", "invalid"):
            status, _, body = await self.send(body={"model": MODEL}, token=key)
            self.assertEqual(status, 401)
            self.assertEqual(orjson.loads(body)["error"]["code"], "invalid_api_key")

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

    async def test_fields_ids_and_public_model(self):
        """I3/I4/I5: preserve tool input, replace model, keep caller credentials out."""
        await self.start()
        value = {"model": MODEL, "messages": [{"role": "user", "content": "hello"}], "temperature": .7,
                 "tools": [{"type": "function", "function": {"name": "test", "parameters": {"type": "object"}}}]}
        status, headers, body = await self.send(body=value, headers={"x-request-id": "caller-canary", "X-SMG-Routing-Key": "routing-canary"})
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
        status, _, body = await self.send(body={"model": MODEL, "stream": True, "messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertIn("日", text)
        self.assertIn(": heartbeat\r\n", text)
        self.assertIn('"model":"model-a"', text)
        self.assertTrue(text.endswith("data: [DONE]\n\n"))

    async def test_body_boundary_and_responses_state_refusal(self):
        """L1/I2/F1: exact body limit succeeds; excess/stateful input never forwards."""
        await self.start({"GATEWAY_MAXIMUM_BODY_BYTES": "1024"})
        prefix, suffix = b'{"model":"model-a","padding":"', b'"}'
        value = prefix + b"x" * (1024 - len(prefix) - len(suffix)) + suffix
        self.assertEqual((await self.send(body=value))[0], 200)
        self.assertEqual((await self.send(body=value + b" "))[0], 413)
        count = len(self.received)
        status, _, body = await self.send("/v1/responses", {"model": MODEL, "input": "hi", "store": True})
        self.assertEqual(status, 400)
        self.assertEqual(orjson.loads(body)["error"]["code"], "stateful_responses_not_supported")
        self.assertEqual(len(self.received), count)
