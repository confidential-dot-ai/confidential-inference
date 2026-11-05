#!/usr/bin/env python3
"""Run the PD router with an allowlist of error fields on container stdout."""
import json
import os
import resource
import re
import signal
import subprocess
import sys
import threading
import time

from private_log_sink import LogSink, NonblockingStdout, consume_child_output
from safe_events import envelope

LOG_SINK = None
LOG_STDOUT = None
SOURCE_REVISION = os.environ.get("CI_DIAGNOSTIC_SOURCE_REVISION", "")
if not re.fullmatch(r"[0-9a-f]{40}", SOURCE_REVISION):
    SOURCE_REVISION = "unknown"

EVENTS = {
    "worker_response_read_failed", "worker_proxy_failed", "pair_selection_failed",
    "request_serialization_failed", "worker_error_body_invalid_json",
    "worker_request_prepare_failed", "paired_decode_cancelled", "worker_http_error",
    "worker_request_failed", "response_serialization_failed",
}
BLOCKED_FLAGS = {"--log-dir", "--enable-trace", "--otlp-traces-endpoint"}


def reviewed_event(record):
    if type(record) is not dict:
        return None
    event = record.get("ci_event")
    role = record.get("role", "router")
    if type(event) is not str or event not in EVENTS:
        return None
    if type(role) is not str or role not in {"prefill", "decode", "router"}:
        return None
    result = {"event": event, "role": role}
    if "status" in record:
        status = record["status"]
        if type(status) is not int or not 100 <= status <= 599:
            return None
        result["status"] = status
    # Do not copy messages, request spans, request IDs, URLs, or log metadata.
    return result


def emit(event, **fields):
    own = {"router_config_rejected", "router_exit", "router_failed", "router_diagnostic_delivery_failed", "router_started", "router_log_records_rejected"}
    if type(event) is not str:
        raise ValueError("invalid diagnostic event")
    if event in own:
        if fields.get("role") != "router" or fields.keys() - {"role", "code", "count", "exported", "dropped", "pending", "failures"}:
            raise ValueError("invalid diagnostic fields")
        if any(type(value) is not int or not -(2**63) < value < 2**63 for key, value in fields.items() if key != "role"):
            raise ValueError("invalid diagnostic fields")
        value = {"event": event, **fields}
    else:
        value = reviewed_event({"ci_event": event, **fields})
        if value is None:
            raise ValueError("invalid diagnostic fields")
    record = envelope({"timestamp_ns": time.time_ns(),
                       "source_revision": SOURCE_REVISION, **value})
    if record is None:
        raise ValueError("invalid diagnostic record")
    try:
        if LOG_STDOUT is None:
            print(json.dumps(record, separators=(",", ":")), flush=True)
        else:
            LOG_STDOUT.write(record)
    except Exception:
        pass  # Never report an exception from a failed log sink.
    if LOG_SINK is not None:
        try:
            LOG_SINK.submit(record)
        except Exception:
            pass  # No raw fallback from delivery errors.



def main():
    global LOG_SINK, LOG_STDOUT
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    LOG_STDOUT = NonblockingStdout()
    LOG_SINK = LogSink.from_environment()
    for argument in sys.argv[1:]:
        flag = argument.split("=", 1)[0].replace("_", "-")
        # argparse accepts abbreviated flags. Reject those too.
        if flag.startswith("--") and any(blocked.startswith(flag) for blocked in BLOCKED_FLAGS):
            emit("router_config_rejected", role="router")
            return 2
    environment = os.environ.copy()
    environment["RUST_LOG"] = "smg::routers::http::pd_router=warn"
    environment.pop("RUST_BACKTRACE", None)
    environment.pop("PYTHONFAULTHANDLER", None)
    command = [sys.executable, "-m", "sglang_router.launch_router", *sys.argv[1:],
               "--json-log", "--log-level", "warn"]
    child = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True)
    emit("router_started", role="router")
    timer = None

    def kill_group():
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def stop(signum, _frame):
        nonlocal timer
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass
        if timer is None:
            timer = threading.Timer(30, kill_group)
            timer.daemon = True
            timer.start()

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGQUIT):
        signal.signal(sig, stop)
    try:
        def accept(raw):
            value = reviewed_event(json.loads(raw))
            if value is None:
                return False
            emit(**value)
            return True
        code, rejected = consume_child_output(child, accept)
        if rejected:
            emit("router_log_records_rejected", role="router", count=rejected)
        if code != 0:
            emit("router_exit", role="router", code=code)
        return code if code >= 0 else 128 - code
    finally:
        if timer is not None:
            timer.cancel()
        kill_group()
        if LOG_SINK is not None:
            delivery = LOG_SINK.close(timeout=1)
            LOG_SINK = None
            if delivery["dropped"] or delivery["pending"] or delivery["failures"]:
                emit("router_diagnostic_delivery_failed", role="router", **delivery)


if __name__ == "__main__":
    try:
        result = main()
    except Exception:
        emit("router_failed", role="router")
        result = 1
    raise SystemExit(result)
