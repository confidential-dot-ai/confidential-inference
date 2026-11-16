"""Gateway startup, listeners, and signal-controlled drain."""

import asyncio
import logging
import signal
from pathlib import Path

import orjson
import uvloop
from aiohttp import web

from .app import create_app
from .config import Config
from .http import AppRunner
from .keys import AdminAuth, Keys
from .telemetry import log


async def bounded_file(path, maximum, wait=0):
    deadline = asyncio.get_running_loop().time() + wait
    while True:
        try:
            with open(path, "rb") as file:
                value = file.read(maximum + 1)
            if not value or len(value) > maximum:
                raise ValueError("invalid credential size")
            return value
        except FileNotFoundError:
            if asyncio.get_running_loop().time() >= deadline:
                raise
            await asyncio.sleep(0.1)


async def serve(config):
    pepper = await bounded_file(config.pepper_file, 4096, config.secret_wait)
    secret = orjson.loads(
        await bounded_file(config.admin_file, 65536, config.secret_wait)
    )
    certificate = await bounded_file(config.signer_file, 256 * 1024)
    hashes = []
    if Path(config.hashes_file).exists():
        text = (await bounded_file(config.hashes_file, 1024)).decode()
        hashes = [line.strip() for line in text.splitlines() if line.strip()]
        if not hashes:
            raise ValueError("empty admin hashes")
    else:
        log("no admin API key file; admin requests need the v1 signature")
    keys = Keys(pepper, config.environment)
    app = create_app(config, keys, AdminAuth(certificate, hashes), secret["token"])
    runner = AppRunner(
        app,
        access_log=None,
        handler_cancellation=True,
        shutdown_timeout=config.shutdown_grace,
        keepalive_timeout=config.header_timeout,
        max_headers=config.maximum_headers,
        max_field_size=config.maximum_header_bytes,
        max_line_size=max(8192, config.maximum_uri + 32),
    )
    await runner.setup()
    private = web.Application()

    async def metrics(request):
        return web.Response(
            body=app["metrics"].render(),
            headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
        )

    private.router.add_get("/metrics", metrics)
    metrics_runner = AppRunner(private, access_log=None)
    await metrics_runner.setup()

    def address(value):
        host, port = value.rsplit(":", 1)
        return host.strip("[]"), int(port)

    try:
        await web.TCPSite(metrics_runner, *address(config.metrics_listen)).start()
        await web.TCPSite(runner, *address(config.listen)).start()
        log("the gateway is ready")
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for number in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(number, stop.set)
        await stop.wait()
        log("the gateway started endpoint drain")
        await asyncio.sleep(config.endpoint_drain)
        log("the gateway started graceful shutdown")
    finally:
        await runner.cleanup()
        await metrics_runner.cleanup()


def main():
    # Only explicitly reviewed records are written. HTTP/exception loggers
    # cannot reveal caller headers or request content at any verbosity.
    logging.disable(logging.CRITICAL)
    config = Config.from_env()
    log("gateway configuration validated")
    uvloop.run(serve(config))


if __name__ == "__main__":
    main()
