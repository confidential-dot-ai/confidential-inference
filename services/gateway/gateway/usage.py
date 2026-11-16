"""Authenticated admin synchronization and bounded per-request usage events."""

import asyncio
import time
import uuid
from collections import deque
from itertools import islice
from urllib.parse import urlsplit, urlunsplit

import aiohttp
import orjson

from .limits import Rejected
from .telemetry import log


class AdminClient:
    def __init__(self, config, token, client):
        origin = urlsplit(config.admin_endpoint)
        if origin.scheme != "https" or not origin.hostname or origin.username or origin.password or origin.query or origin.fragment:
            raise ValueError("invalid admin endpoint")
        if not 32 <= len(token) <= 256 or any(not c.isascii() or not (c.isalnum() or c in "_-") for c in token):
            raise ValueError("invalid admin token")
        self.endpoint = config.admin_endpoint
        self.snapshot_endpoint = urlunsplit((origin.scheme, origin.netloc, "/api/gateway/key-snapshot", "", ""))
        self.headers = {"Authorization": "Bearer " + token}
        self.client = client

    async def request(self, method, url, maximum, **options):
        async with self.client.request(method, url, headers=self.headers, allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=20, sock_connect=10), **options) as response:
            status, body = response.status, bytearray()
            if response.content_length is not None and response.content_length > maximum:
                raise ValueError("body_too_large")
            async for chunk in response.content.iter_chunked(65536):
                if len(body) + len(chunk) > maximum:
                    raise ValueError("body_too_large")
                body.extend(chunk)
            return status, body

    async def synchronize(self, keys, metrics):
        while True:
            try:
                status, body = await self.request("GET", self.snapshot_endpoint, 4 * 1024**2)
                if status != 200:
                    raise ValueError("http_status")
                try:
                    keys.apply(orjson.loads(body))
                except Rejected:
                    log("refused the pulled key snapshot", "ERROR")
            except (aiohttp.ClientError, OSError, TimeoutError, ValueError) as error:
                reason = str(error) if type(error) is ValueError and str(error) in ("body_too_large", "http_status") else "unreachable"
                metrics.inc("gateway_key_registry_fetch_failed_total", reason=reason)
                log("the key snapshot pull failed", "WARN")
            if keys.updated is not None:
                metrics.set("gateway_key_registry_stale_seconds", max(0, int(time.time()) - keys.updated))
            await asyncio.sleep(30 if keys.revision is not None else 5)


class Recorder:
    def __init__(self, config, keys, metrics):
        self.models, self.keys, self.metrics = config.usage_models, keys, metrics
        self.instance = "gateway-" + uuid.uuid4().hex
        self.events, self.sequence = deque(), 0
        self.sending = asyncio.Lock()

    def begin(self, key, model):
        if model not in self.models:
            raise Rejected(429, "usage_capacity", 1)
        return RequestUsage(self, key, model, self.models[model]["served_model"])

    def append(self, event):
        if len(self.events) >= 100_000:
            self.events.popleft()
            self.metrics.inc("gateway_usage_events_dropped_total")
            log("the usage queue is full; dropped the oldest event", "ERROR")
        self.events.append((self.sequence, event))
        self.sequence += 1
        self.metrics.set("gateway_usage_events_pending", len(self.events))

    async def send_pending(self, admin):
        async with self.sending:
            limit = 500
            while self.events:
                batch = list(islice(self.events, limit))
                try:
                    status, _ = await admin.request("POST", admin.endpoint, 65536, json={"events": [event for _, event in batch]})
                except (aiohttp.ClientError, OSError, TimeoutError, ValueError):
                    self.metrics.inc("gateway_usage_send_failed_total", reason="unreachable")
                    return False
                if status in (400, 413, 422):
                    if len(batch) > 1:
                        limit = len(batch) // 2
                        continue
                    self.metrics.inc("gateway_usage_events_rejected_total", status=status)
                    log("the admin refused a usage event; dropped it", "ERROR")
                elif not 200 <= status < 300:
                    self.metrics.inc("gateway_usage_send_failed_total", reason="http_status")
                    return False
                acknowledged = batch[-1][0]
                while self.events and self.events[0][0] <= acknowledged:
                    self.events.popleft()
                self.metrics.set("gateway_usage_events_pending", len(self.events))
                limit = 500
            return True

    async def deliver(self, admin):
        delay = 5
        while True:
            await asyncio.sleep(delay)
            delivered = await self.send_pending(admin)
            delay = 5 if delivered else min(60, delay * 2)
            if not delivered:
                log("usage delivery delayed", "WARN")

    async def flush(self, admin):
        try:
            async with asyncio.timeout(20):
                while self.events:
                    if await self.send_pending(admin):
                        return
                    await asyncio.sleep(1)
        except TimeoutError:
            log("usage events were not delivered before shutdown", "ERROR")


class RequestUsage:
    def __init__(self, recorder, key, model, expected):
        self.recorder, self.key, self.model, self.expected = recorder, key, model, expected
        self.observation, self.outcome, self.ended = {}, "cancelled", None
        self.saved = False

    def finish(self, outcome):
        self.outcome, self.ended = outcome, int(time.time() * 1000)

    def save(self):
        if self.saved:
            return
        self.saved = True
        value = self.observation
        self.recorder.keys.limits.record(self.key, (value.get("input_tokens") or 0) + (value.get("output_tokens") or 0))
        event = {"request_id": str(uuid.uuid4()), "key_id": self.key, "requested_model": self.model,
                 "outcome": self.outcome, "final_usage": value.get("final_usage", False),
                 "ended_at_ms": self.ended if self.ended is not None else int(time.time() * 1000), "producer_instance": self.recorder.instance}
        event.update({field: value.get(field) for field in ("input_tokens", "output_tokens", "cached_input_tokens", "reasoning_tokens")})
        self.recorder.append(event)
