"""Measure a local gateway against an external OpenAI-compatible backend.

Use an isolated test backend. This tool does not flush caches, change a worker,
or verify hardware. Record those facts in --profile and inspect their evidence
before treating a run as GPU acceptance. Use the same cache state for Rust and
Python; repeated prompts can otherwise make the second run much faster.
"""

import argparse
import asyncio
import hashlib
import json
import math
import os
import ssl
import statistics
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
import orjson
import psutil
from support import API_KEY, AdminPeer, Gateway


def quantiles(values):
    ordered = sorted(values)
    result = {}
    for name, fraction in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99)):
        if not ordered:
            result[name] = None
            continue
        position = (len(ordered) - 1) * fraction
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        result[name] = ordered[lower] + (ordered[upper] - ordered[lower]) * (
            position - lower
        )
    return result


def inputs(args):
    origin = urlsplit(args.upstream)
    if (
        origin.scheme not in ("http", "https")
        or not origin.hostname
        or origin.username
        or origin.password
        or origin.query
        or origin.fragment
        or origin.path not in ("", "/")
    ):
        raise ValueError("the upstream must be a plain HTTP or HTTPS origin")
    profile = json.loads(args.profile.read_bytes())
    allowed = {
        "model",
        "served_model",
        "model_revision",
        "tokenizer_revision",
        "context_length",
        "gpu_model",
        "gpu_count",
        "worker_image_digest",
        "worker_concurrency",
        "cache_policy",
    }
    if not isinstance(profile, dict) or set(profile) != allowed:
        raise ValueError(
            "the backend profile must contain exactly the documented fields"
        )
    if any(
        not isinstance(profile[name], str) or not profile[name]
        for name in (
            "model",
            "served_model",
            "model_revision",
            "tokenizer_revision",
            "gpu_model",
            "worker_image_digest",
        )
    ):
        raise ValueError("invalid backend profile strings")
    if profile["cache_policy"] not in ("disabled", "cold", "warm") or any(
        type(profile[name]) is not int or profile[name] < 0
        for name in ("gpu_count", "context_length", "worker_concurrency")
    ):
        raise ValueError("invalid backend profile limits or cache policy")
    if args.backend_kind == "gpu" and (
        profile["gpu_count"] < 1 or profile["worker_concurrency"] < 1
    ):
        raise ValueError("GPU runs require GPU count and worker concurrency")
    metadata = json.loads((args.corpus / "corpus.json").read_bytes())
    if (
        metadata["revision"] != profile["tokenizer_revision"]
        or metadata["context_tokens"] > profile["context_length"]
    ):
        raise ValueError(
            "the corpus does not match the declared tokenizer or context limit"
        )
    bodies, records = [], []
    for entry in metadata["requests"]:
        name = entry["file"]
        if Path(name).name != name or not (args.corpus / name).resolve().is_relative_to(
            args.corpus.resolve()
        ):
            raise ValueError("invalid corpus path")
        raw = (args.corpus / name).read_bytes()
        if (
            len(raw) != entry["bytes"]
            or hashlib.sha256(raw).hexdigest() != entry["sha256"]
        ):
            raise ValueError("a corpus body does not match its manifest")
        value = orjson.loads(raw)
        if (
            value.get("max_tokens") != metadata["output_token_budget"]
            or value.get("stream") is not True
        ):
            raise ValueError("invalid corpus output budget or streaming mode")
        value.update(
            model=profile["model"],
            temperature=0,
            seed=42,
            stream_options={"include_usage": True},
        )
        body = orjson.dumps(value)
        bodies.append(body)
        records.append(
            {
                "file": name,
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )
    if len(bodies) != args.requests:
        raise ValueError("the corpus must contain exactly --requests bodies")
    return profile, metadata, bodies, records


async def measure(args):
    profile, corpus, bodies, records = inputs(args)
    if (
        args.backend_kind == "gpu"
        and args.gateway == "python"
        and not os.environ.get("GATEWAY_TEST_IMAGE")
    ):
        raise ValueError("GPU acceptance must use the built Python container")
    admin = AdminPeer()
    await admin.start()
    # Keep the test admin CA and the normal public roots in one trust bundle.
    bundle = Path(admin.directory.name) / "bundle.pem"
    roots = ssl.get_default_verify_paths().cafile
    bundle.write_bytes(
        (Path(roots).read_bytes() if roots else b"")
        + b"\n"
        + admin.ca_file.read_bytes()
    )
    settings = {
        "SSL_CERT_FILE": str(bundle),
        "GATEWAY_ADMIN_ENDPOINT": admin.endpoint,
        "GATEWAY_MODEL": profile["model"],
        "GATEWAY_USAGE_ENABLED": "true",
        "GATEWAY_USAGE_MODELS": json.dumps(
            {
                profile["model"]: {
                    "served_model": profile["served_model"],
                    "model_revision": profile["model_revision"],
                }
            }
        ),
        "GATEWAY_UPSTREAM_TIMEOUT_SECONDS": str(args.timeout),
        "GATEWAY_FIRST_TOKEN_TIMEOUT_SECONDS": str(min(args.timeout, 3600)),
        "GATEWAY_SHUTDOWN_GRACE_SECONDS": str(args.timeout),
    }
    gateway = Gateway(args.gateway, args.upstream, settings)
    samples, results, errors = [], [], []
    sampler = None
    closed = False
    try:
        await gateway.start()
        pid = gateway.process.pid
        runtime_artifact = None
        if gateway.container:
            runtime_artifact = json.loads(
                await asyncio.to_thread(
                    subprocess.check_output,
                    [
                        "docker",
                        "inspect",
                        "--format",
                        '{"pid":{{.State.Pid}},"id":{{json .Image}},"source_revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}}}',
                        gateway.container,
                    ],
                )
            )
            pid = runtime_artifact.pop("pid")
        elif args.gateway == "rust":
            runtime_artifact = {
                "sha256": hashlib.sha256(Path(gateway.rust).read_bytes()).hexdigest()
            }
        process = psutil.Process(pid)

        def processes():
            return [
                item
                for item in [process, *process.children(recursive=True)]
                if item.is_running()
            ]

        def cpu():
            return sum(
                item.cpu_times().user + item.cpu_times().system for item in processes()
            )

        initial_cpu = cpu()

        async def sample():
            while True:
                samples.append(sum(item.memory_info().rss for item in processes()))
                await asyncio.sleep(0.02)

        sampler = asyncio.create_task(sample())
        headers = {
            "Authorization": "Bearer " + API_KEY,
            "Content-Type": "application/json",
        }
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=args.timeout + 120),
            connector=aiohttp.TCPConnector(limit=0),
        ) as client:

            async def request(index, body):
                started, first, previous = time.monotonic(), None, None
                intervals, usage, done = [], None, False
                failure = "network_or_event_error"

                async def chunks():
                    for start in range(0, len(body), 262144):
                        yield body[start : start + 262144]
                        await asyncio.sleep(0)

                try:
                    async with client.post(
                        "http://127.0.0.1:9443/v1/chat/completions",
                        data=chunks(),
                        headers={**headers, "Content-Length": str(len(body))},
                    ) as response:
                        if response.status != 200:
                            errors.append({"request": index, "status": response.status})
                            return
                        async for line in response.content:
                            if not line.startswith(b"data:"):
                                continue
                            payload = line[5:].strip()
                            if payload == b"[DONE]":
                                done = True
                                continue
                            value = orjson.loads(payload)
                            if isinstance(value.get("usage"), dict):
                                usage = value["usage"]
                            content = False
                            for choice in value.get("choices", []):
                                delta = choice.get("delta", {})
                                content |= bool(
                                    delta.get("content")
                                    or delta.get("reasoning_content")
                                    or delta.get("tool_calls")
                                )
                            if content:
                                now = time.monotonic()
                                if first is None:
                                    first = now - started
                                if previous is not None:
                                    intervals.append(now - previous)
                                previous = now
                    if not done or first is None or usage is None:
                        failure = "missing_content_marker_or_usage"
                        raise ValueError("missing content, final marker or usage")
                    incoming, outgoing = (
                        usage.get("prompt_tokens"),
                        usage.get("completion_tokens"),
                    )
                    if (
                        incoming != corpus["input_tokens"]
                        or type(outgoing) is not int
                        or not 1 <= outgoing <= corpus["output_token_budget"]
                    ):
                        failure = "context_token_count_mismatch"
                        errors.append(
                            {
                                "request": index,
                                "error_code": failure,
                                "observed_input_tokens": incoming
                                if type(incoming) is int
                                else None,
                                "observed_output_tokens": outgoing
                                if type(outgoing) is int
                                else None,
                            }
                        )
                        return
                    detail = usage.get("prompt_tokens_details")
                    cached = (
                        detail.get("cached_tokens")
                        if isinstance(detail, dict)
                        else usage.get("cache_read_input_tokens")
                    )
                    if "prompt_tokens_details" in usage and detail is None:
                        cached = 0
                    if cached is not None and (
                        type(cached) is not int or not 0 <= cached <= incoming
                    ):
                        failure = "invalid_cache_count"
                        raise ValueError("invalid backend cache count")
                    results.append(
                        {
                            "request": index,
                            "ttft_seconds": first,
                            "elapsed_seconds": time.monotonic() - started,
                            "output_delivery_intervals_seconds": intervals,
                            "input_tokens": incoming,
                            "output_tokens": outgoing,
                            "cached_input_tokens": cached,
                        }
                    )
                except Exception as error:
                    errors.append(
                        {
                            "request": index,
                            "error_type": type(error).__name__,
                            "error_code": failure,
                        }
                    )

            started = time.monotonic()
            await asyncio.gather(
                *(request(index, body) for index, body in enumerate(bodies))
            )
            elapsed, used_cpu = time.monotonic() - started, cpu() - initial_cpu
        sampler.cancel()
        await asyncio.gather(sampler, return_exceptions=True)
        await gateway.close(timeout=25)
        closed = True
        events = [
            event
            for event in admin.events
            if event["outcome"] == "completed"
            and event["input_tokens"] == corpus["input_tokens"]
        ]
        if len(events) != len(results) or sum(
            event["output_tokens"] or 0 for event in events
        ) != sum(row["output_tokens"] for row in results):
            errors.append({"error_type": "usage_delivery_mismatch"})
        result = {
            "gateway": args.gateway,
            "backend_kind_declared": args.backend_kind,
            "profile": profile,
            "profile_verified_by_runner": False,
            "frontdoor_and_rollout_verified": False,
            "upstream_origin": args.upstream,
            "source_revision": subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                cwd=Path(__file__).resolve().parents[2],
                text=True,
            ).strip(),
            "harness_dirty": bool(
                subprocess.check_output(
                    ["git", "status", "--porcelain", "--", "tests/gateway"],
                    cwd=Path(__file__).resolve().parents[2],
                    text=True,
                ).strip()
            ),
            "corpus": corpus,
            "actual_request_bodies": records,
            "completed": len(results),
            "errors": errors,
            "batch_elapsed_seconds": elapsed,
            "output_tokens_per_second": sum(row["output_tokens"] for row in results)
            / elapsed,
            "ttft_seconds": quantiles([row["ttft_seconds"] for row in results]),
            "output_delivery_interval_seconds": quantiles(
                [
                    interval
                    for row in results
                    for interval in row["output_delivery_intervals_seconds"]
                ]
            ),
            "quantile_method": "linear interpolation",
            "cpu_seconds": used_cpu,
            "peak_rss_mib": max(samples, default=0) / 1024**2,
            "completed_usage_events": len(events),
            "requests": sorted(results, key=lambda row: row["request"]),
        }
        result["runtime_artifact"] = runtime_artifact or {
            "source_revision": result["source_revision"]
        }
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(
            json.dumps(
                {
                    key: result[key]
                    for key in (
                        "gateway",
                        "backend_kind_declared",
                        "completed",
                        "errors",
                        "batch_elapsed_seconds",
                        "output_tokens_per_second",
                        "ttft_seconds",
                        "peak_rss_mib",
                    )
                },
                indent=2,
            )
        )
        if errors or len(results) != args.requests:
            raise SystemExit(1)
    finally:
        if sampler and not sampler.done():
            sampler.cancel()
            await asyncio.gather(sampler, return_exceptions=True)
        if not closed:
            await gateway.close()
        await admin.close()


def compare(rust_files, python_files, output):
    pairs, issues = [], []
    eligible = True
    seen_runs = set()
    reference = None
    artifacts = {}
    for index, (rust_path, python_path) in enumerate(
        zip(rust_files, python_files, strict=True), 1
    ):
        rust, python = (
            json.loads(path.read_bytes()) for path in (rust_path, python_path)
        )
        pair_issues = []
        for kind, value in (("rust", rust), ("python", python)):
            identity = hashlib.sha256(
                json.dumps(value, sort_keys=True).encode()
            ).hexdigest()
            if identity in seen_runs:
                pair_issues.append("duplicate run evidence")
            seen_runs.add(identity)
            settings = {
                name: value[name]
                for name in (
                    "profile",
                    "upstream_origin",
                    "actual_request_bodies",
                    "source_revision",
                    "corpus",
                    "backend_kind_declared",
                )
            }
            if reference is None:
                reference = settings
            elif settings != reference:
                pair_issues.append("different workload or harness across runs")
            if kind in artifacts and artifacts[kind] != value["runtime_artifact"]:
                pair_issues.append(kind + " runtime changed across runs")
            artifacts[kind] = value["runtime_artifact"]
            rows = value["requests"]
            if (
                value["gateway"] != kind
                or not rows
                or value["errors"]
                or value["completed"] != len(rows)
                or value["completed_usage_events"] != len(rows)
            ):
                pair_issues.append(kind + " has missing or failed work")
            if value["harness_dirty"]:
                pair_issues.append(kind + " used an uncommitted harness")
            if [row["request"] for row in rows] != list(range(len(rows))):
                pair_issues.append(
                    kind + " has duplicate or missing request identities"
                )
            if any(row["cached_input_tokens"] is None for row in rows):
                pair_issues.append(kind + " lacks backend cache observations")
            eligible &= (
                value["backend_kind_declared"] == "gpu"
                and value["completed"] == 64
                and value["corpus"]["context_tokens"] == 1048576
            )
        for field in ("profile", "upstream_origin", "actual_request_bodies"):
            if rust[field] != python[field]:
                pair_issues.append("different " + field)
        for field in ("input_tokens", "output_tokens", "cached_input_tokens"):
            if [row[field] for row in rust["requests"]] != [
                row[field] for row in python["requests"]
            ]:
                pair_issues.append("different per-request " + field)
        for value in (rust, python):
            for metric in (
                value["output_tokens_per_second"],
                value["ttft_seconds"]["p95"],
                value["output_delivery_interval_seconds"]["p95"],
            ):
                if (
                    type(metric) not in (int, float)
                    or not math.isfinite(metric)
                    or metric <= 0
                ):
                    pair_issues.append("missing or invalid rate or latency samples")
        if pair_issues:
            issues.append({"pair": index, "issues": pair_issues})
            continue
        throughput = (
            python["output_tokens_per_second"] / rust["output_tokens_per_second"]
        )
        ttft = python["ttft_seconds"]["p95"] / rust["ttft_seconds"]["p95"]
        interval = (
            python["output_delivery_interval_seconds"]["p95"]
            / rust["output_delivery_interval_seconds"]["p95"]
        )
        pairs.append(
            {
                "pair": index,
                "rust_file": str(rust_path),
                "python_file": str(python_path),
                "throughput_ratio": throughput,
                "p95_ttft_ratio": ttft,
                "p95_output_delivery_interval_ratio": interval,
                "thresholds_pass": throughput >= 0.95
                and ttft <= 1.05
                and interval <= 1.05,
            }
        )
    result = {
        "pairs": pairs,
        "comparability_issues": issues,
        "declared_gpu_workload_matches_target": bool(eligible),
        "thresholds_pass_every_pair": len(pairs) == 3
        and not issues
        and all(pair["thresholds_pass"] for pair in pairs),
        "median_throughput_ratio": statistics.median(
            pair["throughput_ratio"] for pair in pairs
        )
        if pairs
        else None,
        "hardware_profile_and_full_path_verified_by_comparator": False,
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if issues:
        raise SystemExit(2)
    if not result["thresholds_pass_every_pair"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="Measure one complete external-backend batch")
    run.add_argument("--gateway", choices=("rust", "python"), required=True)
    run.add_argument("--upstream", required=True)
    run.add_argument(
        "--profile",
        type=Path,
        required=True,
        help="JSON fields: model, served_model, model_revision, tokenizer_revision, context_length, gpu_model, gpu_count, worker_image_digest, worker_concurrency, cache_policy",
    )
    run.add_argument("--corpus", type=Path, required=True)
    run.add_argument("--backend-kind", choices=("controlled", "gpu"), default="gpu")
    run.add_argument("--requests", type=int, default=64)
    run.add_argument("--timeout", type=int, default=14400)
    run.add_argument("--output", type=Path, required=True)
    comparison = commands.add_parser(
        "compare",
        help="Check three paired runs with matching work and cache observations",
    )
    comparison.add_argument("--rust", type=Path, nargs=3, required=True)
    comparison.add_argument("--python", type=Path, nargs=3, required=True)
    comparison.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "run":
        if not 1 <= args.requests <= 128 or not 60 <= args.timeout <= 86400:
            parser.error("invalid request count or timeout")
        asyncio.run(measure(args))
    else:
        compare(args.rust, args.python, args.output)
