"""Reviewed stdout records and the existing Prometheus wire contract."""

import hmac
import math
import os
import re
import resource
import sys
from datetime import UTC, datetime
from pathlib import Path

import orjson
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    disable_created_metrics,
    generate_latest,
)
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

LATENCY_BUCKETS = (.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30)
TOKEN_BUCKETS = (1, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768)
RATE_BUCKETS = (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000)
MESSAGES = frozenset((
    "gateway configuration validated", "no admin API key file; admin requests need the v1 signature",
    "the metrics listener stopped", "the gateway is ready", "the gateway started endpoint drain",
    "the gateway started graceful shutdown", "the gateway panicked; the panic message is not logged",
    "no routing key secret: the router routes requests at random", "refused the pulled key snapshot",
    "the key snapshot pull failed", "applied a key registry snapshot",
    "refused a key registry snapshot: the pepper does not match",
    "usage model identity did not match its approved binding", "the usage queue is full; dropped the oldest event",
    "the admin refused a usage event; dropped it", "usage delivery delayed",
    "usage events were not delivered before shutdown",
))


def log(message, level="INFO"):
    if message not in MESSAGES:
        raise ValueError("unreviewed log message")
    write_log(message, level)


def write_log(message, level):
    record = {"timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"), "level": level, "message": message}
    try:
        sys.stdout.write(orjson.dumps(record).decode() + "\n")
        sys.stdout.flush()
    except OSError:
        pass


class Audit:
    def __init__(self, pepper):
        self.secret = hmac.digest(pepper, b"confidential.ai/gateway-log-key-pseudonym/v1", "sha256")

    def record(self, identifier, route, status, key=None):
        value = {"event": "gateway_request_completed", "key_ref": None if key is None else "kp_" + hmac.digest(self.secret, key.encode(), "sha256")[:12].hex(),
                 "request_id": identifier, "route": route, "status": status}
        write_log(orjson.dumps(value, option=orjson.OPT_SORT_KEYS).decode(), "INFO")


class Metrics:
    def __init__(self, environment):
        disable_created_metrics()
        self.environment = environment
        self.registry = CollectorRegistry()
        self.registry.register(ProcessMetrics(environment))
        self.values, self.dimensions, self.renames = {}, {}, []
        counters = {
            "gateway_requests": ("model", "key_id", "status"), "gateway_rejections": ("reason", "key_id"),
            "gen_ai_client_token_usage": ("model", "key_id", "type"), "gen_ai_usage_cache_read_input_tokens": ("model", "key_id"),
            "gen_ai_response_finish_reasons": ("model", "reason"), "gateway_key_registry_push_rejected_total": ("reason",),
            "gateway_key_registry_fetch_failed_total": ("reason",), "gateway_usage_events_dropped_total": (),
            "gateway_usage_send_failed_total": ("reason",), "gateway_usage_events_rejected_total": ("status",),
        }
        gauges = {name: () for name in ("gateway_upstream_reachable", "gateway_inference_active", "gateway_inference_queue_depth",
            "gateway_key_registry_stale_seconds", "gateway_key_registry_revision", "gateway_key_registry_pepper_mismatch_rows",
            "gateway_key_registry_pepper_mismatch", "gateway_usage_events_pending", "confidential_gateway_process_configured")}
        gauges["gateway_router_requests_active"] = ("router",)
        histograms = {
            "gateway_small_request_processing_seconds": (),
            "gateway_large_request_processing_seconds": (),
            "gateway_stream_forward_seconds": (),
            "gateway_queue_duration": (), "gateway_request_duration": ("model", "status"),
            "gen_ai_server_time_to_first_token": ("model", "key_id"),
            "gateway_time_to_first_token_seconds": ("model", "key_id", "cache_status"),
            "gen_ai_server_time_per_output_token": ("model", "key_id"),
            "gateway_tokens_per_second": ("model", "key_id"),
            "gateway_input_tokens_per_request": ("model", "key_id"), "gateway_output_tokens_per_request": ("model", "key_id"),
        }
        for definitions, kind in ((counters, Counter), (gauges, Gauge), (histograms, Histogram)):
            for name, dimensions in definitions.items():
                options = {}
                if kind is Histogram:
                    options["buckets"] = TOKEN_BUCKETS if "tokens_per_request" in name else RATE_BUCKETS if name == "gateway_tokens_per_second" else LATENCY_BUCKETS
                    if name.endswith("_request_processing_seconds"):
                        options["buckets"] = sorted((*LATENCY_BUCKETS, 2))
                self.values[name] = kind(name, name.replace("_", " "), ("env", *dimensions), registry=self.registry, **options)
                self.dimensions[name] = dimensions
                if kind is Counter and not name.endswith("_total"):
                    self.renames.append(name)
                if not dimensions:
                    self.metric(name)
        self.metric("confidential_gateway_process_configured").set(1)

    def metric(self, name, **labels):
        return self.values[name].labels(self.environment, *(str(labels.get(key, "")) for key in self.dimensions[name]))

    def inc(self, name, amount=1, **labels):
        self.metric(name, **labels).inc(amount)

    def set(self, name, value, **labels):
        self.metric(name, **labels).set(value)

    def observe(self, name, value, **labels):
        if value is not None and math.isfinite(value) and value >= 0:
            self.metric(name, **labels).observe(value)

    def render(self):
        text = generate_latest(self.registry).decode()
        # Rust published these counter names without the conventional suffix.
        # Restrict substitution to family/sample names, never label values.
        for name in self.renames:
            text = re.sub(rf"(?m)^(# (?:HELP|TYPE) )?{name}_total(?=[ {{])", lambda match: (match[1] or "") + name, text)
        return text.encode()


class ProcessMetrics:
    """Include parser children in process CPU and memory accounting."""

    def __init__(self, environment):
        self.environment = environment
        self.ticks = os.sysconf("SC_CLK_TCK")
        self.page = os.sysconf("SC_PAGE_SIZE")
        self.boot = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))

    def collect(self):
        root = Path("/proc/self")
        children = (root / f"task/{os.getpid()}/children").read_text().split()
        cpu, resident, virtual, descriptors = 0, 0, 0, 0
        started = None
        for process in [root, *(Path("/proc") / child for child in children)]:
            try:
                fields = (process / "stat").read_text().rsplit(")", 1)[1].split()
                cpu += (int(fields[11]) + int(fields[12])) / self.ticks
                resident += int(fields[21]) * self.page
                virtual += int(fields[20])
                descriptors += len(list((process / "fd").iterdir()))
                if process == root:
                    started = self.boot + int(fields[19]) / self.ticks
            except (OSError, ValueError, IndexError):
                continue
        exited = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu += exited.ru_utime + exited.ru_stime
        metric = CounterMetricFamily("process_cpu_seconds", "CPU seconds of the gateway and its parser processes", labels=["env"])
        metric.add_metric([self.environment], cpu)
        yield metric
        for name, value in (("resident_memory_bytes", resident), ("virtual_memory_bytes", virtual),
                            ("open_fds", descriptors), ("max_fds", resource.getrlimit(resource.RLIMIT_NOFILE)[0]),
                            ("start_time_seconds", started)):
            if value is not None:
                metric = GaugeMetricFamily("process_" + name, name.replace("_", " "), labels=["env"])
                metric.add_metric([self.environment], value)
                yield metric


class StreamTiming:
    def __init__(self, metrics, model, key, started):
        self.metrics, self.model, self.key, self.started = metrics, model, key, started
        self.first = self.last = None

    def value(self, value, now):
        choices = value.get("choices")
        output = False
        for choice in choices if isinstance(choices, list) else ():
            delta = choice.get("delta") if isinstance(choice, dict) else None
            if isinstance(delta, dict) and any(delta.get(field) for field in ("content", "reasoning_content", "tool_calls", "function_call")):
                output = True
        output |= value.get("type") in ("response.output_text.delta", "response.reasoning_text.delta", "response.function_call_arguments.delta") and bool(value.get("delta"))
        if output:
            labels = {"model": self.model, "key_id": self.key}
            if self.first is None:
                self.first = now
                self.metrics.observe("gen_ai_server_time_to_first_token", now - self.started, **labels)
            else:
                self.metrics.observe("gen_ai_server_time_per_output_token", now - self.last, **labels)
            self.last = now

    def finish(self, observation):
        labels = {"model": self.model, "key_id": self.key}
        if self.first is not None and observation.get("cached_input_tokens") is not None:
            self.metrics.observe("gateway_time_to_first_token_seconds", self.first - self.started,
                                 cache_status="cached" if observation["cached_input_tokens"] > 0 else "cold", **labels)
        output = observation.get("output_tokens")
        if output is not None and output > 1 and self.last is not None and self.last > self.first:
            self.metrics.observe("gateway_tokens_per_second", (output - 1) / (self.last - self.first), **labels)
