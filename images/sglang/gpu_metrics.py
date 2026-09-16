#!/usr/bin/env python3
"""Expose bounded NVIDIA GPU metrics for one SGLang worker container."""

from __future__ import annotations

import argparse
import csv
import http.server
import io
import re
import subprocess
from dataclasses import dataclass


QUERY_FIELDS = (
    "index",
    "utilization.gpu",
    "memory.used",
    "memory.total",
    "temperature.gpu",
    "ecc.errors.corrected.volatile.total",
    "ecc.errors.uncorrected.volatile.total",
)
WORKER_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")


class GpuMetricsError(ValueError):
    """The NVIDIA metrics response is not valid."""


@dataclass(frozen=True)
class GpuSample:
    index: int
    utilization_ratio: float
    memory_used_bytes: int
    memory_total_bytes: int
    temperature_celsius: float
    corrected_ecc_errors: int | None
    uncorrected_ecc_errors: int | None


def _number(value: str, name: str) -> float:
    try:
        result = float(value.strip())
    except ValueError as error:
        raise GpuMetricsError(f"invalid {name}") from error
    if result < 0:
        raise GpuMetricsError(f"invalid {name}")
    return result


def _optional_integer(value: str, name: str) -> int | None:
    if value.strip().lower() in {"n/a", "[not supported]", "not supported"}:
        return None
    result = _number(value, name)
    if not result.is_integer():
        raise GpuMetricsError(f"invalid {name}")
    return int(result)


def parse_nvidia_smi(text: str) -> list[GpuSample]:
    samples: list[GpuSample] = []
    indexes: set[int] = set()
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        if len(row) != len(QUERY_FIELDS):
            raise GpuMetricsError("invalid NVIDIA metrics field count")
        index_value = _number(row[0], "GPU index")
        if not index_value.is_integer():
            raise GpuMetricsError("invalid GPU index")
        index = int(index_value)
        if index in indexes:
            raise GpuMetricsError("duplicate GPU index")
        indexes.add(index)
        utilization = _number(row[1], "GPU utilization")
        if utilization > 100:
            raise GpuMetricsError("invalid GPU utilization")
        memory_used = _number(row[2], "used GPU memory")
        memory_total = _number(row[3], "total GPU memory")
        if memory_used > memory_total or memory_total <= 0:
            raise GpuMetricsError("invalid GPU memory")
        samples.append(
            GpuSample(
                index=index,
                utilization_ratio=utilization / 100.0,
                memory_used_bytes=int(memory_used * 1024 * 1024),
                memory_total_bytes=int(memory_total * 1024 * 1024),
                temperature_celsius=_number(row[4], "GPU temperature"),
                corrected_ecc_errors=_optional_integer(row[5], "corrected ECC errors"),
                uncorrected_ecc_errors=_optional_integer(row[6], "uncorrected ECC errors"),
            )
        )
    if not samples:
        raise GpuMetricsError("NVIDIA metrics returned no GPUs")
    return sorted(samples, key=lambda sample: sample.index)


def query_nvidia_smi() -> list[GpuSample]:
    command = [
        "nvidia-smi",
        f"--query-gpu={','.join(QUERY_FIELDS)}",
        "--format=csv,noheader,nounits",
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if completed.returncode != 0:
        raise GpuMetricsError("nvidia-smi failed")
    return parse_nvidia_smi(completed.stdout)


def render_metrics(worker: str, samples: list[GpuSample], *, success: bool = True) -> bytes:
    if not WORKER_PATTERN.fullmatch(worker):
        raise GpuMetricsError("invalid worker label")
    lines = [
        "# HELP confidential_inference_gpu_metrics_scrape_success Whether the local NVIDIA query succeeded.",
        "# TYPE confidential_inference_gpu_metrics_scrape_success gauge",
        f'confidential_inference_gpu_metrics_scrape_success{{worker="{worker}"}} {1 if success else 0}',
    ]
    families = (
        ("confidential_inference_gpu_utilization_ratio", "gauge", "GPU execution use as a ratio from zero to one."),
        ("confidential_inference_gpu_memory_used_bytes", "gauge", "GPU memory in use."),
        ("confidential_inference_gpu_memory_total_bytes", "gauge", "Total GPU memory."),
        ("confidential_inference_gpu_temperature_celsius", "gauge", "GPU temperature in degrees Celsius."),
        ("confidential_inference_gpu_ecc_corrected_errors_total", "counter", "Volatile corrected GPU ECC errors."),
        ("confidential_inference_gpu_ecc_uncorrected_errors_total", "counter", "Volatile uncorrected GPU ECC errors."),
    )
    for name, metric_type, help_text in families:
        lines.extend((f"# HELP {name} {help_text}", f"# TYPE {name} {metric_type}"))
    for sample in samples:
        labels = f'worker="{worker}",gpu="{sample.index}"'
        lines.extend(
            (
                f"confidential_inference_gpu_utilization_ratio{{{labels}}} {sample.utilization_ratio:.6f}",
                f"confidential_inference_gpu_memory_used_bytes{{{labels}}} {sample.memory_used_bytes}",
                f"confidential_inference_gpu_memory_total_bytes{{{labels}}} {sample.memory_total_bytes}",
                f"confidential_inference_gpu_temperature_celsius{{{labels}}} {sample.temperature_celsius:g}",
            )
        )
        if sample.corrected_ecc_errors is not None:
            lines.append(
                f"confidential_inference_gpu_ecc_corrected_errors_total{{{labels}}} {sample.corrected_ecc_errors}"
            )
        if sample.uncorrected_ecc_errors is not None:
            lines.append(
                f"confidential_inference_gpu_ecc_uncorrected_errors_total{{{labels}}} {sample.uncorrected_ecc_errors}"
            )
    return ("\n".join(lines) + "\n").encode("ascii")


def handler(worker: str) -> type[http.server.BaseHTTPRequestHandler]:
    class MetricsHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
                return
            if self.path != "/metrics":
                self.send_error(404)
                return
            try:
                body = render_metrics(worker, query_nvidia_smi())
            except (GpuMetricsError, OSError, subprocess.SubprocessError):
                body = render_metrics(worker, [], success=False)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    return MetricsHandler


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--worker", required=True)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("the port must be between 1024 and 65535")
    if not WORKER_PATTERN.fullmatch(args.worker):
        parser.error("the worker label is invalid")
    return args


def main() -> int:
    args = parse_args()
    server = http.server.ThreadingHTTPServer((args.host, args.port), handler(args.worker))
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
