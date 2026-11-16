"""Stateless outage responses. This entry point reads no gateway secrets."""

import argparse
import asyncio
import ipaddress
import logging
import os
import signal

import orjson
import uvloop
from aiohttp import web

from .config import Config
from .http import AppRunner
from .limits import Public, Rejected

MODEL = "deepseek-ai/DeepSeek-V4-Flash-0731"


def response(value, status=200, retry=None):
    headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
    if retry is not None:
        headers["Retry-After"] = str(retry)
    return web.Response(body=orjson.dumps(value), status=status, content_type="application/json", headers=headers)


@web.middleware
async def limits(request, handler):
    release = None
    try:
        # Maintenance rejects forwarding metadata from an untrusted peer.
        if "X-Forwarded-For" in request.headers:
            peer = ipaddress.ip_address(request.remote or "0.0.0.0")
            if not any(peer in network for network in request.app["public"].trusted):
                raise Rejected(400, "invalid_forwarding_headers")
        release = request.app["public"].enter(request)
        size = 0
        try:
            async with asyncio.timeout(5):
                async for chunk in request.content.iter_chunked(65536):
                    size += len(chunk)
                    if size > 65536:
                        raise Rejected(413, "request_body_too_large")
        except TimeoutError as error:
            raise Rejected(413, "request_body_too_large") from error
        return await handler(request)
    except Rejected as error:
        return response({"error": {"code": error.code}}, 429 if error.status == 503 else error.status, error.retry)
    except web.HTTPException as error:
        return response({"error": {"code": "not_found", "type": "invalid_request_error",
            "param": None, "message": "Route not found."}}, error.status)
    finally:
        if release:
            release()


async def handle(request):
    path = request.path
    if path == "/v1/models":
        return response({"object": "list", "data": [{"id": MODEL, "object": "model", "owned_by": "confidential.ai"}]})
    if path in ("/health", "/readiness"):
        return response({"status": "live" if path == "/health" else "ready", "mode": "maintenance", "inferenceAvailable": False})
    if path == "/attestation":
        return response({"mode": "maintenance", "inferenceAvailable": False, "inferenceWorkloads": [],
            "attestationType": "outage-status", "statement": "This maintenance gateway runs no inference workload."})
    return response({"error": {"message": "Inference is temporarily unavailable.",
        "type": "service_unavailable", "param": None, "code": "inference_unavailable"}}, 429, 60)


def create_app(trusted):
    config = Config(public_capacity=128, trusted_proxies=trusted)
    app = web.Application(middlewares=[limits], client_max_size=65536)
    app["public"] = Public(config)
    for path in ("/v1/models", "/health", "/readiness", "/attestation"):
        app.router.add_get(path, handle)
    for path in ("/v1/chat/completions", "/v1/completions", "/v1/responses"):
        app.router.add_post(path, handle)
    return app


async def serve(listen, trusted):
    runner = AppRunner(create_app(trusted), access_log=None, handler_cancellation=True,
        shutdown_timeout=10, max_field_size=16384, keepalive_timeout=5, max_headers=64)
    await runner.setup()
    host, port = listen.rsplit(":", 1)
    try:
        await web.TCPSite(runner, host.strip("[]"), int(port)).start()
        stop = asyncio.Event()
        for number in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_running_loop().add_signal_handler(number, stop.set)
        await stop.wait()
    finally:
        await runner.cleanup()


def main():
    logging.disable(logging.CRITICAL)
    parser = argparse.ArgumentParser(prog="maintenance-gateway")
    parser.add_argument("--listen", default=os.environ.get("MAINTENANCE_GATEWAY_LISTEN", "0.0.0.0:9443"))
    parser.add_argument("--trusted-proxy-cidrs", default=os.environ.get("MAINTENANCE_GATEWAY_TRUSTED_PROXY_CIDRS", ""))
    args = parser.parse_args()
    host, port = args.listen.rsplit(":", 1)
    ipaddress.ip_address(host.strip("[]"))
    if int(port) != 9443:
        raise ValueError("the maintenance gateway must listen on port 9443")
    trusted = list(filter(None, args.trusted_proxy_cidrs.split(",")))
    for value in trusted:
        ipaddress.ip_network(value)
    uvloop.run(serve(args.listen, trusted))


if __name__ == "__main__":
    main()
