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
from prometheus_client.parser import text_string_to_metric_families
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
            for index in range(500 if length < 1024**2 else 20):
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
        pid = gateway.process.pid
        if gateway.container:
            pid = int(await asyncio.to_thread(subprocess.check_output,
                ["docker", "inspect", "--format", "{{.State.Pid}}", gateway.container]))
        process = psutil.Process(pid)
        rss, sampling = [], True
        initial_cpu = process.cpu_times()
        initial_children_cpu = sum(p.cpu_times().user + p.cpu_times().system for p in process.children(recursive=True) if p.is_running())
        initial_time = time.monotonic()
        async def sample():
            while sampling:
                rss.append(sum(p.memory_info().rss for p in [process, *process.children(recursive=True)] if p.is_running()))
                await asyncio.sleep(.01)
        sampler = asyncio.create_task(sample())
        gaps, firsts, durations, errors, delays, processing = [], [], [], [], [], []
        upload_finished = {}
        upload_start, upload_end = None, None
        probes = []
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
            async def request(large=False, slow=False, cancel=False, probe=False):
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
                            if previous is not None and not large and not slow and upload_start is not None and (upload_end is None or now <= upload_end):
                                gaps.append(now - previous)
                            previous = now
                            if not slow and not large and b"[DONE]" not in line and upload_start is not None and (upload_end is None or now <= upload_end):
                                value = orjson.loads(line[5:])
                                delays.append((time.monotonic_ns() - value["_sent_ns"]) / 1e9)
                            if first is None:
                                first = now
                                if probe:
                                    probes.append(now - started)
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
            async def small_requests():
                while upload_end is None:
                    await request(cancel=True, probe=True)
                    await asyncio.sleep(.1)
            elapsed, settled_rss = 0, []
            for _ in range(args.batches):
                upload_start = upload_end = None
                background = [asyncio.create_task(request(slow=(i == 0), cancel=(i == 1))) for i in range(args.background)]
                await asyncio.sleep(.2)
                probe_task = asyncio.create_task(small_requests())
                started = upload_start = time.monotonic()
                await asyncio.gather(*(request(large=True) for _ in range(args.requests)))
                upload_end = time.monotonic()
                elapsed += upload_end - started
                await probe_task
                for task in background:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*background, return_exceptions=True)
                await asyncio.sleep(.25)
                settled_rss.append(sum(p.memory_info().rss for p in [process, *process.children(recursive=True)] if p.is_running()) / 1024**2)
            async with client.get("http://127.0.0.1:9090/metrics") as response:
                metrics = await response.text()
            processing_bounds = {}
            forwarding_bound = None
            for family in text_string_to_metric_families(metrics):
                if family.name == "gateway_stream_forward_seconds":
                    count = next(sample.value for sample in family.samples if sample.name.endswith("_count"))
                    forwarding_bound = min(float(sample.labels["le"]) for sample in family.samples
                        if sample.name.endswith("_bucket") and sample.value >= .99 * count)
                if family.name == "gateway_request_processing_seconds":
                    for sample in family.samples:
                        if sample.name.endswith("_count"):
                            count = sample.value
                            size_class = sample.labels["size"]
                            bounds = [float(bucket.labels["le"]) for bucket in family.samples
                                if bucket.name.endswith("_bucket") and bucket.labels["size"] == size_class and bucket.value >= .99 * count]
                            processing_bounds[size_class] = min(bounds)
        sampling = False
        await sampler
        final_cpu = process.cpu_times()
        child_cpu = sum(p.cpu_times().user + p.cpu_times().system for p in process.children(recursive=True) if p.is_running())
        result = {"gateway": args.gateway, "requests": args.requests, "batches": args.batches, "body_bytes": size, "background": args.background, "body_memory_budget_bytes": 32 * 1024**3,
                  "peak_client_concurrency": peak, "completed_large": len(durations), "errors": errors,
                  "large_elapsed_seconds": elapsed, "input_mib_per_second": args.requests * args.batches * args.body_mib / elapsed,
                  "settled_rss_mib_by_batch": settled_rss,
                  "settled_rss_growth_fraction": settled_rss[-1] / settled_rss[0] - 1,
                  "large_first_chunk_p95_seconds": percentile(firsts, .95),
                  "post_upload_first_chunk_p95_seconds": percentile(processing, .95),
                  "post_upload_first_chunk_p99_seconds": percentile(processing, .99),
                  "server_body_complete_to_submission_p99_upper_seconds": processing_bounds,
                  "server_chunk_receive_to_write_p99_upper_seconds": forwarding_bound,
                  "stream_gap_p50_seconds": percentile(gaps, .5), "stream_gap_p95_seconds": percentile(gaps, .95),
                  "stream_gap_p99_seconds": percentile(gaps, .99), "stream_gap_max_seconds": max(gaps, default=None),
                  "small_probe_first_chunk_p95_seconds": percentile(probes, .95),
                  "small_probe_first_chunk_p99_seconds": percentile(probes, .99),
                  "chunk_delay_p95_seconds": percentile(delays, .95), "chunk_delay_p99_seconds": percentile(delays, .99),
                  "chunk_delay_max_seconds": max(delays, default=None), "peak_rss_mib": max(rss, default=0) / 1024**2,
                  "cpu_seconds": final_cpu.user + final_cpu.system - initial_cpu.user - initial_cpu.system + child_cpu - initial_children_cpu,
                  "sample_elapsed_seconds": time.monotonic() - initial_time, "transport_only": True}
        print(json.dumps(result, indent=2))
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
        if errors or len(durations) != args.requests * args.batches:
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
    parser.add_argument("--batches", type=int, default=1)
    parser.add_argument("--output")
    parser.add_argument("--fixture", action="store_true")
    args = parser.parse_args()
    asyncio.run(fixture() if args.fixture else measure(args))
