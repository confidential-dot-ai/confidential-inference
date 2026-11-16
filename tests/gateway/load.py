"""Measure large uploads alongside active streams through either gateway.

Run from the repo: python tests/gateway/load.py --gateway python --body-mib 32
This is a transport test, not a GPU or tokenizer capacity claim.
"""

import argparse
import asyncio
import hashlib
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
from support import API_KEY, MODEL, AdminPeer, Gateway


def percentile(values, fraction):
    return (
        sorted(values)[min(len(values) - 1, int((len(values) - 1) * fraction))]
        if values
        else None
    )


async def fixture(args):
    large_active, large_peak, arrived = 0, 0, 0
    group_ready = asyncio.Event()

    async def upstream(request):
        nonlocal large_active, large_peak, arrived, group_ready
        length = 0
        digest = hashlib.sha256()
        async for chunk in request.content.iter_chunked(262_144):
            length += len(chunk)
            digest.update(chunk)
        large = length >= 1024**2
        if large:
            large_active += 1
            large_peak = max(large_peak, large_active)
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        try:
            if large and args.large_barrier:
                ready = group_ready
                arrived += 1
                if arrived == args.requests:
                    arrived, group_ready = 0, asyncio.Event()
                    ready.set()
                await ready.wait()
            await response.prepare(request)
            for index in range(500 if length < 1024**2 else 20):
                value = {
                    "model": MODEL,
                    "choices": [{"delta": {"content": "x"}, "finish_reason": None}],
                    "_sent_ns": time.monotonic_ns(),
                }
                if index == 0:
                    value["_request_sha256"] = digest.hexdigest()
                    value["_upstream_peak_large"] = large_peak
                await response.write(b"data: " + orjson.dumps(value) + b"\n\n")
                await asyncio.sleep(0.02)
            if args.usage:
                await response.write(
                    b"data: "
                    + orjson.dumps(
                        {
                            "model": MODEL,
                            "choices": [],
                            "usage": {
                                "prompt_tokens": args.fixture_input_tokens
                                if length >= 1024**2
                                else 5,
                                "completion_tokens": 20,
                            },
                        }
                    )
                    + b"\n\n"
                )
            await response.write(b"data: [DONE]\n\n")
        except ConnectionError:
            pass
        finally:
            if large:
                large_active -= 1
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
    corpus, corpus_metadata = [], None
    if args.corpus:
        directory = Path(args.corpus)
        corpus_metadata = json.loads((directory / "corpus.json").read_bytes())
        for entry in corpus_metadata["requests"]:
            data = (directory / entry["file"]).read_bytes()
            if (
                len(data) != entry["bytes"]
                or hashlib.sha256(data).hexdigest() != entry["sha256"]
            ):
                raise ValueError("the corpus does not match its manifest")
            corpus.append(data)
        if len(corpus) != args.requests:
            raise ValueError("the corpus must contain exactly --requests bodies")
    command = [sys.executable, str(Path(__file__).resolve()), "--fixture"]
    if args.large_barrier:
        command += ["--large-barrier", "--requests", str(args.requests)]
    if args.usage:
        command += [
            "--usage",
            "--fixture-input-tokens",
            str(corpus_metadata["input_tokens"] if corpus_metadata else 1000),
        ]
    peer = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Fixture readiness is one small line, not a timing assumption.
    line = await asyncio.to_thread(peer.stdout.readline)
    if not line:
        raise RuntimeError("upstream fixture failed")
    upstream = "http://127.0.0.1:" + line.decode().strip()
    admin, settings = None, {}
    if args.usage:
        admin = AdminPeer()
        await admin.start()
        settings = {
            "SSL_CERT_FILE": str(admin.ca_file),
            "GATEWAY_ADMIN_ENDPOINT": admin.endpoint,
            "GATEWAY_USAGE_ENABLED": "true",
            "GATEWAY_USAGE_MODELS": json.dumps(
                {MODEL: {"served_model": MODEL, "model_revision": "transport-fixture"}}
            ),
        }
    gateway = Gateway(args.gateway, upstream, settings)
    gateway_closed = False
    sampler = None
    try:
        await gateway.start()
        pid = gateway.process.pid
        if gateway.container:
            pid = int(
                await asyncio.to_thread(
                    subprocess.check_output,
                    [
                        "docker",
                        "inspect",
                        "--format",
                        "{{.State.Pid}}",
                        gateway.container,
                    ],
                )
            )
        process = psutil.Process(pid)
        rss, sampling = [], True
        initial_cpu = process.cpu_times()
        initial_children_cpu = sum(
            p.cpu_times().user + p.cpu_times().system
            for p in process.children(recursive=True)
            if p.is_running()
        )
        initial_time = time.monotonic()

        async def sample():
            while sampling:
                rss.append(
                    sum(
                        p.memory_info().rss
                        for p in [process, *process.children(recursive=True)]
                        if p.is_running()
                    )
                )
                await asyncio.sleep(0.01)

        sampler = asyncio.create_task(sample())
        gaps, firsts, durations, errors, delays, processing, peer_peaks = (
            [],
            [],
            [],
            [],
            [],
            [],
            [],
        )
        upload_finished = {}
        upload_start, upload_end = None, None
        probes = []
        active, peak = 0, 0
        headers = {
            "Authorization": "Bearer " + API_KEY,
            "Content-Type": "application/json",
        }
        prefix = (
            b'{"model":"model-a","stream":true,"messages":[{"role":"user","content":"'
        )
        suffix = b'"}]}'
        if args.small_body_bytes < len(prefix) + len(suffix):
            raise ValueError("--small-body-bytes is too small for the request envelope")
        small_body = (
            prefix + b"x" * (args.small_body_bytes - len(prefix) - len(suffix)) + suffix
        )
        size = args.body_mib * 1024**2
        slab = b"x" * 262_144
        if corpus:
            sizes = [len(data) for data in corpus]
            expected_inputs = corpus
        else:
            sizes = [size] * args.requests
            expected_inputs = [
                prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix
            ]
        expected_digests = []
        for data in expected_inputs:
            if args.usage:
                value = orjson.loads(data)
                value["stream_options"] = {"include_usage": True}
                # Object key order is not part of the forwarding contract.
                variants = (
                    orjson.dumps(value),
                    orjson.dumps(value, option=orjson.OPT_SORT_KEYS),
                )
            else:
                variants = (data,)
            expected_digests.append(
                {hashlib.sha256(value).hexdigest() for value in variants}
            )
        if not corpus:
            expected_digests *= args.requests
        large_index = 0

        async def body(identifier, data=None):
            if data is not None:
                for start in range(0, len(data), 262_144):
                    yield data[start : start + 262_144]
                upload_finished[identifier] = time.monotonic()
                return
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
        async with aiohttp.ClientSession(
            timeout=timeout, connector=connector
        ) as client:

            async def request(large=False, slow=False, cancel=False, probe=False):
                nonlocal active, peak, large_index
                active += 1
                peak = max(peak, active)
                started, previous, first, done = time.monotonic(), None, None, False
                identifier = id(asyncio.current_task())
                try:
                    if large:
                        slot = large_index % args.requests
                        large_index += 1
                        options = {
                            "data": body(identifier, corpus[slot] if corpus else None),
                            "headers": {**headers, "Content-Length": str(sizes[slot])},
                        }
                    else:
                        options = {"data": small_body, "headers": headers}
                    async with client.post(
                        "http://127.0.0.1:9443/v1/chat/completions", **options
                    ) as response:
                        if response.status != 200:
                            errors.append(
                                {
                                    "status": response.status,
                                    "body": (await response.text())[:200],
                                }
                            )
                            return
                        async for line in response.content:
                            if not line.startswith(b"data:"):
                                continue
                            now = time.monotonic()
                            if (
                                previous is not None
                                and not large
                                and not slow
                                and upload_start is not None
                                and (upload_end is None or now <= upload_end)
                            ):
                                gaps.append(now - previous)
                            previous = now
                            if (
                                not slow
                                and not large
                                and b"[DONE]" not in line
                                and upload_start is not None
                                and (upload_end is None or now <= upload_end)
                            ):
                                value = orjson.loads(line[5:])
                                delays.append(
                                    (time.monotonic_ns() - value["_sent_ns"]) / 1e9
                                )
                            if first is None:
                                first = now
                                if probe:
                                    probes.append(now - started)
                                if large:
                                    value = orjson.loads(line[5:])
                                    observed = value["_request_sha256"]
                                    peer_peaks.append(value["_upstream_peak_large"])
                                    if observed not in expected_digests[slot]:
                                        raise ValueError(
                                            "the upstream received a different body"
                                        )
                                    firsts.append(now - started)
                                    if identifier in upload_finished:
                                        processing.append(
                                            now - upload_finished[identifier]
                                        )
                            if b"[DONE]" in line:
                                done = True
                            if cancel:
                                return
                            if slow:
                                await asyncio.sleep(0.04)
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
                    await asyncio.sleep(0.1)

            elapsed, settled_rss, batches = 0, [], 0
            soak_started = time.monotonic()
            while (
                batches < args.batches
                or time.monotonic() - soak_started < args.duration_seconds
            ):
                upload_start = upload_end = None
                background = [
                    asyncio.create_task(request(slow=(i == 0), cancel=(i == 1)))
                    for i in range(args.background)
                ]
                await asyncio.sleep(0.2)
                probe_task = asyncio.create_task(small_requests())
                started = upload_start = time.monotonic()
                await asyncio.gather(
                    *(request(large=True) for _ in range(args.requests))
                )
                upload_end = time.monotonic()
                elapsed += upload_end - started
                await probe_task
                for task in background:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*background, return_exceptions=True)
                await asyncio.sleep(0.25)
                settled_rss.append(
                    sum(
                        p.memory_info().rss
                        for p in [process, *process.children(recursive=True)]
                        if p.is_running()
                    )
                    / 1024**2
                )
                batches += 1
                if args.output:
                    progress = {
                        "batches": batches,
                        "completed_large": len(durations),
                        "errors": errors,
                        "elapsed_seconds": time.monotonic() - soak_started,
                        "settled_rss_mib": settled_rss[-1],
                    }
                    Path(args.output + ".progress.json").write_text(
                        json.dumps(progress) + "\n"
                    )
            async with client.get("http://127.0.0.1:9090/metrics") as response:
                metrics = await response.text()
            processing_bounds = {}
            forwarding_bound = None
            for family in text_string_to_metric_families(metrics):
                if family.name == "gateway_stream_forward_seconds":
                    count = next(
                        sample.value
                        for sample in family.samples
                        if sample.name.endswith("_count")
                    )
                    forwarding_bound = min(
                        float(sample.labels["le"])
                        for sample in family.samples
                        if sample.name.endswith("_bucket")
                        and sample.value >= 0.99 * count
                    )
                if family.name in (
                    "gateway_small_request_processing_seconds",
                    "gateway_large_request_processing_seconds",
                ):
                    for sample in family.samples:
                        if sample.name.endswith("_count"):
                            count = sample.value
                            size_class = family.name.split("_")[1]
                            bounds = [
                                float(bucket.labels["le"])
                                for bucket in family.samples
                                if bucket.name.endswith("_bucket")
                                and bucket.value >= 0.99 * count
                            ]
                            processing_bounds[size_class] = min(bounds)
        sampling = False
        await sampler
        final_cpu = process.cpu_times()
        child_cpu = sum(
            p.cpu_times().user + p.cpu_times().system
            for p in process.children(recursive=True)
            if p.is_running()
        )
        result = {
            "gateway": args.gateway,
            "requests": args.requests,
            "batches": batches,
            "body_bytes": max(sizes),
            "background": args.background,
            "body_memory_budget_bytes": 32 * 1024**3,
            "soak_elapsed_seconds": time.monotonic() - soak_started,
            "usage_enabled": args.usage,
            "large_barrier": args.large_barrier,
            "upstream_peak_large": max(peer_peaks, default=0),
            "small_body_bytes": len(small_body),
            "peak_client_concurrency": peak,
            "completed_large": len(durations),
            "errors": errors,
            "large_elapsed_seconds": elapsed,
            "input_mib_per_second": sum(sizes) * batches / 1024**2 / elapsed,
            "body_bytes_by_request": sizes,
            "corpus": corpus_metadata,
            "settled_rss_mib_by_batch": settled_rss,
            "settled_rss_growth_fraction": settled_rss[-1] / settled_rss[0] - 1,
            "large_first_chunk_p95_seconds": percentile(firsts, 0.95),
            "post_upload_first_chunk_p95_seconds": percentile(processing, 0.95),
            "post_upload_first_chunk_p99_seconds": percentile(processing, 0.99),
            "server_body_complete_to_submission_p99_upper_seconds": processing_bounds,
            "server_chunk_receive_to_write_p99_upper_seconds": forwarding_bound,
            "stream_gap_p50_seconds": percentile(gaps, 0.5),
            "stream_gap_p95_seconds": percentile(gaps, 0.95),
            "stream_gap_p99_seconds": percentile(gaps, 0.99),
            "stream_gap_max_seconds": max(gaps, default=None),
            "small_probe_first_chunk_p95_seconds": percentile(probes, 0.95),
            "small_probe_first_chunk_p99_seconds": percentile(probes, 0.99),
            "chunk_delay_p95_seconds": percentile(delays, 0.95),
            "chunk_delay_p99_seconds": percentile(delays, 0.99),
            "chunk_delay_max_seconds": max(delays, default=None),
            "peak_rss_mib": max(rss, default=0) / 1024**2,
            "cpu_seconds": final_cpu.user
            + final_cpu.system
            - initial_cpu.user
            - initial_cpu.system
            + child_cpu
            - initial_children_cpu,
            "main_cpu_seconds": final_cpu.user
            + final_cpu.system
            - initial_cpu.user
            - initial_cpu.system,
            "worker_cpu_seconds": child_cpu - initial_children_cpu,
            "sample_elapsed_seconds": time.monotonic() - initial_time,
            "transport_only": True,
        }
        if admin:
            await gateway.close()
            gateway_closed = True
            input_tokens = corpus_metadata["input_tokens"] if corpus_metadata else 1000
            completed = [
                event
                for event in admin.events
                if event["outcome"] == "completed"
                and event["input_tokens"] == input_tokens
            ]
            result["completed_large_usage_events"] = len(completed)
            result["usage_events_received"] = len(admin.events)
            if len(completed) != args.requests * batches or any(
                not event["final_usage"] or event["output_tokens"] != 20
                for event in completed
            ):
                errors.append({"error": "incomplete usage accounting"})
        if args.large_barrier and max(peer_peaks, default=0) < args.requests:
            errors.append(
                {"error": "the upstream did not hold the full concurrent batch"}
            )
        summary = {
            key: value
            for key, value in result.items()
            if key not in ("corpus", "body_bytes_by_request")
        }
        if corpus_metadata:
            summary["corpus"] = {
                key: value
                for key, value in corpus_metadata.items()
                if key != "requests"
            }
        print(json.dumps(summary, indent=2))
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
        if errors or len(durations) != args.requests * batches:
            raise SystemExit(1)
    finally:
        if sampler and not sampler.done():
            sampler.cancel()
        if not gateway_closed:
            await gateway.close()
        if admin:
            await admin.close()
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
    parser.add_argument("--small-body-bytes", type=int, default=65536)
    parser.add_argument("--background", type=int, default=16)
    parser.add_argument("--batches", type=int, default=1)
    parser.add_argument(
        "--duration-seconds",
        type=int,
        default=0,
        help="Repeat full batches for at least this duration",
    )
    parser.add_argument("--corpus", help="Directory made by tests/gateway/context.py")
    parser.add_argument("--output")
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument(
        "--usage",
        action="store_true",
        help="Exercise HTTPS key pulls and usage delivery",
    )
    parser.add_argument(
        "--large-barrier",
        action="store_true",
        help="Hold every large request open upstream before responding",
    )
    parser.add_argument(
        "--fixture-input-tokens", type=int, default=1000, help=argparse.SUPPRESS
    )
    args = parser.parse_args()
    asyncio.run(fixture(args) if args.fixture else measure(args))
