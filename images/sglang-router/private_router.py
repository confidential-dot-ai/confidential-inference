#!/usr/bin/env python3
"""Run the SGLang router and write only reviewed fixed events to stdout.

Each stdout line is one JSON object. Its keys are a subset of timestamp,
source_revision, event, role, status and code. timestamp is the ISO-8601 UTC
time of the record. source_revision is the 40-hex image source revision, or
"unknown". The node log agent ships stdout. This program sends nothing else.
"""
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import resource
import re
import signal
import subprocess
import sys
import threading

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
# Events of this launcher. Each has role "router" and an optional int code.
OWN_EVENTS = {"router_config_rejected", "router_exit", "router_failed", "router_started"}
ROLES = {"prefill", "decode", "router"}
RECORD_KEYS = {"timestamp", "source_revision", "event", "role", "status", "code"}
BLOCKED_FLAGS = {"--log-dir", "--enable-trace", "--otlp-traces-endpoint"}


class NonblockingStdout:
    """Write one bounded record to a container pipe without waiting for readers.

    The caller must review the schema. This is not a content filter. A full
    pipe drops that record.
    """
    def __init__(self, fd=1):
        self.fd = fd
        os.set_blocking(fd, False)

    def write(self, record):
        payload = (json.dumps(record, separators=(",", ":")) + "\n").encode()
        # Linux pipe writes at or below PIPE_BUF are atomic. A full pipe must
        # never leave half a JSON line or block the failure/restart path.
        if len(payload) > 4096:
            return False
        try:
            return os.write(self.fd, payload) == len(payload)
        except OSError:
            return False


def reviewed_event(record):
    if type(record) is not dict:
        return None
    event = record.get("ci_event")
    role = record.get("role", "router")
    if type(event) is not str or event not in EVENTS:
        return None
    if type(role) is not str or role not in ROLES:
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
    if type(event) is not str:
        raise ValueError("invalid diagnostic event")
    if event in OWN_EVENTS:
        if fields.get("role") != "router" or fields.keys() - {"role", "code"}:
            raise ValueError("invalid diagnostic fields")
        code = fields.get("code", 0)
        if type(code) is not int or not -(2**63) < code < 2**63:
            raise ValueError("invalid diagnostic fields")
        value = {"event": event, **fields}
    else:
        value = reviewed_event({"ci_event": event, **fields})
        if value is None or fields.keys() - {"role", "status"}:
            raise ValueError("invalid diagnostic fields")
    record = {"timestamp": datetime.now(timezone.utc).isoformat(),
              "source_revision": SOURCE_REVISION, **value}
    assert record.keys() <= RECORD_KEYS
    if LOG_STDOUT is None:
        print(json.dumps(record, separators=(",", ":")), flush=True)
    else:
        LOG_STDOUT.write(record)


def supports_json_log():
    """Return True when the installed launch_router accepts --json-log.

    PyPI sglang-router 0.3.2 (the engine image) does not have the flag; the
    router image build (source a7fd2e1) does. This reads the source text and
    does not import the package. Without the flag the child writes text
    lines, which the parser drops.
    """
    try:
        spec = importlib.util.find_spec("sglang_router")
        locations = spec.submodule_search_locations if spec else None
        for location in locations or ():
            path = Path(location) / "router_args.py"
            if path.is_file():
                return "--{prefix}json-log" in path.read_text(encoding="utf-8")
    except (ImportError, OSError, UnicodeError, ValueError):
        pass
    return False


def main():
    global LOG_STDOUT
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    LOG_STDOUT = NonblockingStdout()
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
    command = [sys.executable, "-m", "sglang_router.launch_router", *sys.argv[1:]]
    if supports_json_log():
        command.append("--json-log")
    command += ["--log-level", "warn"]
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
        assert child.stdout is not None
        while True:
            line = child.stdout.readline(8193)
            if not line:
                break
            if len(line) > 8192:
                while line and not line.endswith(b"\n"):
                    line = child.stdout.readline(8193)
                continue
            try:
                value = reviewed_event(json.loads(line))
            except (ValueError, UnicodeError):
                continue
            if value is not None:
                emit(**value)
        code = child.wait()
        if code != 0:
            emit("router_exit", role="router", code=code)
        return code if code >= 0 else 128 - code
    finally:
        if timer is not None:
            timer.cancel()
        kill_group()


if __name__ == "__main__":
    try:
        result = main()
    except Exception:
        emit("router_failed", role="router")
        result = 1
    raise SystemExit(result)
