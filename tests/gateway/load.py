"""Measure large uploads alongside active streams through either gateway.

Run from the repo: python tests/gateway/load.py --gateway python --body-mib 32
This is a transport test, not a GPU or tokenizer capacity claim.
"""

import argparse
import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

import aiohttp
import orjson
import psutil
from aiohttp import web

from support import API_KEY, MODEL, Gateway


def percentile(values, fraction):
    return sorted(values)[min(len(values) - 1, int((len(values) - 1) * fraction))] if values else None


async def fixture():
    async def upstream(request):
        length = 0
        async for chunk in request.content.iter_chunked(262_144):
            length += len(chunk)
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        try:
            for index in range(150 if length < 1024**2 else 20):
                value = {"model": MODEL, "choices": [{"delta": {"content": "x"}, "finish_reason": None}], "_sent_ns": time.monotonic_ns()}
                await response.write(b"data: " + orjson.dumps(value) + b"\n\n")
                await asyncio.sleep(.02)
            await response.write(b"data: [DONE]\n\n")
        except ConnectionError:
            pass
        return response
    app = web.Application(client_max_size=0)
    app.router.add_post("/v1/chat/completions", upstream)
    runner = web.AppRunner(app, access_log=None, handler_cancellation=True)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    print(port, flush=True)
    await asyncio.Event().wait()


async def measure(args):
    peer = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--fixture"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Fixture readiness is one small line, not a timing assumption.
    line = await asyncio.to_thread(peer.stdout.readline)
    if not line:
        raise RuntimeError("upstream fixture failed")
    upstream = "http://127.0.0.1:" + line.decode().strip()
    gateway = Gateway(args.gateway, upstream)
    sampler = None
    try:
        await gateway.start()
        process = psutil.Process(gateway.process.pid)
        rss, cpu, sampling = [], [], True
        initial_cpu = process.cpu_times()
        initial_time = time.monotonic()
        async def sample():
            while sampling:
                rss.append(sum(p.memory_info().rss for p in [process, *process.children(recursive=True)] if p.is_running()))
                await asyncio.sleep(.01)
        sampler = asyncio.create_task(sample())
        gaps, firsts, durations, errors, delays, processing = [], [], [], [], [], []
        upload_finished = {}
        active, peak = 0, 0
        headers = {"Authorization": "Bearer " + API_KEY, "Content-Type": "application/json"}
        prefix = b'{"model":"model-a","stream":true,"messages":[{"role":"user","content":"'
        suffix = b'"}]}'
        size = args.body_mib * 1024**2
        slab = b"x" * 262_144
        async def body(identifier):
            yield prefix
            remaining = size - len(prefix) - len(suffix)
            while remaining:
                count = min(remaining, len(slab))
                yield slab[:count]
                remaining -= count
            yield suffix
            upload_finished[identifier] = time.monotonic()
        timeout = aiohttp.ClientTimeout(total=180)
        connector = aiohttp.TCPConnector(limit=0)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as client:
            async def request(large=False, slow=False, cancel=False):
                nonlocal active, peak
                active += 1
                peak = max(peak, active)
                started, previous, first, done = time.monotonic(), None, None, False
                identifier = id(asyncio.current_task())
                try:
                    options = {"data": body(identifier), "headers": {**headers, "Content-Length": str(size)}} if large else {"json": {"model": MODEL, "stream": True, "messages": [{"role": "user", "content": "hello"}]}, "headers": headers}
                    async with client.post("http://127.0.0.1:9443/v1/chat/completions", **options) as response:
                        if response.status != 200:
                            errors.append({"status": response.status, "body": (await response.text())[:200]})
                            return
                        async for line in response.content:
                            if not line.startswith(b"data:"):
                                continue
                            now = time.monotonic()
                            if previous is not None and not large:
                                gaps.append(now - previous)
                            previous = now
                            if not slow and not large and b"[DONE]" not in line:
                                value = orjson.loads(line[5:])
                                delays.append((time.monotonic_ns() - value["_sent_ns"]) / 1e9)
                            if first is None:
                                first = now
                                if large:
                                    firsts.append(now - started)
                                    if identifier in upload_finished:
                                        processing.append(now - upload_finished[identifier])
                            if b"[DONE]" in line:
                                done = True
                            if cancel:
                                return
                            if slow:
                                await asyncio.sleep(.04)
                        if not done:
                            errors.append({"error": "missing terminal marker"})
                    if large:
                        durations.append(time.monotonic() - started)
                except Exception as error:
                    errors.append({"error": type(error).__name__})
                finally:
                    active -= 1
            background = [asyncio.create_task(request(slow=(i == 0), cancel=(i == 1))) for i in range(args.background)]
            await asyncio.sleep(.2)
            started = time.monotonic()
            await asyncio.gather(*(request(large=True) for _ in range(args.requests)))
            elapsed = time.monotonic() - started
            await asyncio.gather(*background)
        sampling = False
        await sampler
        final_cpu = process.cpu_times()
        child_cpu = sum(p.cpu_times().user + p.cpu_times().system for p in process.children(recursive=True) if p.is_running())
        result = {"gateway": args.gateway, "requests": args.requests, "body_bytes": size, "background": args.background,
                  "peak_client_concurrency": peak, "completed_large": len(durations), "errors": errors,
                  "large_elapsed_seconds": elapsed, "input_mib_per_second": args.requests * args.body_mib / elapsed,
                  "large_first_chunk_p95_seconds": percentile(firsts, .95),
                  "post_upload_first_chunk_p95_seconds": percentile(processing, .95),
                  "post_upload_first_chunk_p99_seconds": percentile(processing, .99),
                  "stream_gap_p50_seconds": percentile(gaps, .5), "stream_gap_p95_seconds": percentile(gaps, .95),
                  "stream_gap_p99_seconds": percentile(gaps, .99), "stream_gap_max_seconds": max(gaps, default=None),
                  "chunk_delay_p95_seconds": percentile(delays, .95), "chunk_delay_p99_seconds": percentile(delays, .99),
                  "chunk_delay_max_seconds": max(delays, default=None), "peak_rss_mib": max(rss, default=0) / 1024**2,
                  "cpu_seconds": final_cpu.user + final_cpu.system - initial_cpu.user - initial_cpu.system + child_cpu,
                  "sample_elapsed_seconds": time.monotonic() - initial_time, "transport_only": True}
        print(json.dumps(result, indent=2))
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
        if errors or len(durations) != args.requests:
            raise SystemExit(1)
    finally:
        if sampler and not sampler.done():
            sampler.cancel()
        await gateway.close()
        peer.terminate()
        try:
            await asyncio.to_thread(peer.wait, 3)
        except subprocess.TimeoutExpired:
            peer.kill()
            peer.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway", choices=["rust", "python"], default="python")
    parser.add_argument("--requests", type=int, default=64)
    parser.add_argument("--body-mib", type=int, default=32)
    parser.add_argument("--background", type=int, default=16)
    parser.add_argument("--output")
    parser.add_argument("--fixture", action="store_true")
    args = parser.parse_args()
    asyncio.run(fixture() if args.fixture else measure(args))
