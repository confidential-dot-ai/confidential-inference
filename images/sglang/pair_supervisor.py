#!/usr/bin/env python3
"""Run one prefill/decode pair. Emit only fixed, reviewed error records.

The workers keep separate HTTP/metrics ports. Their raw stdout and stderr
are discarded, including native-library output. Reviewed events arrive on a
local datagram socket and pass a strict schema before reaching container logs.
The status handler reads cached state only; it never calls CUDA or a worker.
"""

from __future__ import annotations

import argparse
import ctypes
import http.client
import json
import math
import os
from pathlib import Path
import resource
import secrets
import re
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pair_diagnostics import SNAPSHOT_SECONDS, StackSnapshots
from private_log_sink import LogSink, NonblockingStdout


ROLES = {"prefill", "decode"}
EVENTS = {
    "rank_failed", "watchdog_timeout", "communicator_abort_timeout",
    "child_exit", "progress_stale", "startup_timeout", "shutdown_timeout",
    "supervisor_failed", "cuda_error", "nccl_error", "diagnostic_failed",
    "kv_transfer_failed",
    "status_request_failed", "rank_progress_failed",
    "stack_frame", "stack_dump_complete", "stack_dump_unavailable",
    "communicator_abort_started", "communicator_abort_finished",
    "communicator_abort_failed", "fatal_exit_deadline",
    "nccl_collective", "nccl_snapshot", "nccl_snapshot_unavailable",
    "scheduler_snapshot", "scheduler_snapshot_unavailable",
    "gpu_event_query_failed",
    "diagnostic_delivery_failed",
    "flashinfer_prewarm_finished", "flashinfer_prewarm_failed",
}
NUMBER_FIELDS = {"rank", "code", "count", "bytes", "queue_depth", "sequence", "duration_ms",
                 "age_ms", "gpu_pending_ms", "thread", "frame", "line", "rejected",
                 "created_ns", "started_ns", "completed_ns", "timeout_ms",
                 "stage_code", "batch_size", "input_tokens", "output_tokens",
                 "step_age_ms", "last_step_ms", "exported", "dropped", "pending", "failures", "group_id"}
COLLECTIVES = {"all_reduce", "broadcast", "reduce", "all_gather", "reduce_scatter",
               "all_to_all", "send", "recv", "barrier"}
CODE_LOCATIONS = set()
RUN_ID = secrets.token_hex(16)
SOURCE_REVISION = os.environ.get("CI_DIAGNOSTIC_SOURCE_REVISION", "")
if not re.fullmatch(r"[0-9a-f]{40}", SOURCE_REVISION):
    SOURCE_REVISION = "unknown"
LOG_SINK = None
LOG_STDOUT = None
LOG_LOCK = threading.Lock()
INHERITED_ENV = {"PATH", "LD_LIBRARY_PATH", "HOME", "LANG", "LC_ALL", "TZ", "VIRTUAL_ENV",
                 "PYTHONDONTWRITEBYTECODE", "NVIDIA_VISIBLE_DEVICES", "NVIDIA_DRIVER_CAPABILITIES",
                 "NVIDIA_REQUIRE_CUDA"}
# Worker settings that decide where and for what the FlashInfer JIT compiles.
PREWARM_ENV = {"FLASHINFER_WORKSPACE_BASE", "FLASHINFER_CUDA_ARCH_LIST", "CUDA_CACHE_PATH",
               "TORCH_CUDA_ARCH_LIST", "CUDA_HOME", "PATH", "LD_LIBRARY_PATH", "HOME", "TMPDIR"}
PREWARM_COMMAND = [sys.executable, "-I", "-B", "/usr/local/bin/prewarm-flashinfer"]


def new_generation(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    previous = sorted((path for path in directory.glob("generation-*")
                       if not path.is_symlink() and path.is_dir()),
                      key=lambda path: path.stat().st_mtime_ns, reverse=True)
    # The run volume is small. Keep the last generation for diagnosis, plus
    # the new generation, so repeated restarts cannot fill it with old files.
    for path in previous[1:]:
        shutil.rmtree(path)
    return Path(tempfile.mkdtemp(prefix="generation-", dir=directory))


def reviewed_event(value: object) -> dict | None:
    """Reject whole records, rather than try to remove sensitive substrings."""
    if type(value) is not dict or not {"event", "role"} <= value.keys():
        return None
    if value.keys() - ({"event", "role", "location", "op", "state"} | NUMBER_FIELDS):
        return None
    if type(value["event"]) is not str or type(value["role"]) is not str:
        return None
    if value["event"] not in EVENTS or value["role"] not in ROLES | {"pair"}:
        return None
    if "location" in value:
        if value["event"] != "stack_frame" or type(value["location"]) is not str or value["location"] not in CODE_LOCATIONS:
            return None
    elif value["event"] == "stack_frame":
        return None
    if "op" in value or "state" in value or value["event"] == "nccl_collective":
        if value["event"] != "nccl_collective" or type(value.get("op")) is not str or value["op"] not in COLLECTIVES:
            return None
        if type(value.get("state")) is not str or value["state"] not in {"scheduled", "started", "completed"}:
            return None
        if not {"rank", "sequence", "count"} <= value.keys():
            return None
    for name in value.keys() & NUMBER_FIELDS:
        if type(value[name]) is not int or not -(2**63) < value[name] < 2**63:
            return None
    if "line" in value and not 1 <= value["line"] <= 1000000:
        return None
    return value


def emit(event: str, role: str = "pair", **fields) -> None:
    value = reviewed_event({"event": event, "role": role, **fields})
    if value is None:
        raise ValueError("invalid diagnostic record")
    # A generated timestamp is the only field added outside the fixed schema.
    record = {"timestamp_ns": time.time_ns(), "run_id": RUN_ID,
              "source_revision": SOURCE_REVISION, **value}
    with LOG_LOCK:
        if LOG_STDOUT is None:
            print(json.dumps(record, separators=(",", ":")), flush=True)
        else:
            LOG_STDOUT.write(record)
        if LOG_SINK is not None:
            LOG_SINK.submit(record)


class PrivateStatusServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # The base server prints an exception and peer address to stderr.
        emit("status_request_failed")


def assigned_gpus() -> list[str]:
    """Enumerate only CUDA-visible devices; do not use host physical indices."""
    driver = ctypes.CDLL("libcuda.so.1")
    count = ctypes.c_int()
    if driver.cuInit(0) or driver.cuDeviceGetCount(ctypes.byref(count)):
        raise RuntimeError("CUDA enumeration failed")
    devices = []
    for ordinal in range(count.value):
        device = ctypes.c_int()
        uuid = (ctypes.c_ubyte * 16)()
        if driver.cuDeviceGet(ctypes.byref(device), ordinal) or driver.cuDeviceGetUuid_v2(ctypes.byref(uuid), device):
            raise RuntimeError("CUDA device identity failed")
        raw = bytes(uuid).hex()
        devices.append("GPU-" + "-".join((raw[:8], raw[8:12], raw[12:16], raw[16:20], raw[20:])))
    return devices


def validate_config(config: dict) -> None:
    if set(config) != {"workers", "modelGate", "statusPort", "progressTimeoutSeconds", "startupTimeoutSeconds", "shutdownTimeoutSeconds"}:
        raise ValueError("invalid pair configuration")
    if not config["modelGate"] or any(type(v) is not str for v in config["modelGate"]):
        raise ValueError("model verification command is required")
    workers = config["workers"]
    if len(workers) != 2 or {w["role"] for w in workers} != ROLES:
        raise ValueError("one worker of each role is required")
    ports = {config["statusPort"]}
    for w in workers:
        if set(w) != {"role", "gpus", "ranks", "port", "command", "env"}:
            raise ValueError("invalid worker configuration")
        if type(w["gpus"]) is not int or not 1 <= w["gpus"] <= 8 or w["ranks"] != w["gpus"]:
            raise ValueError("unsupported worker ranks")
        if w["port"] in ports or type(w["port"]) is not int or not 1024 <= w["port"] <= 65534:
            raise ValueError("invalid worker port")
        ports.add(w["port"])
        if not w["command"] or any(type(v) is not str for v in w["command"]):
            raise ValueError("invalid worker command")
        unsafe_flags = {"--log-requests", "--log-requests-target", "--enable-trace",
                        "--crash-dump-folder", "--debug-tensor-dump-output-folder"}
        for argument in w["command"]:
            flag = argument.split("=", 1)[0].replace("_", "-")
            if flag.startswith("--") and any(blocked.startswith(flag) for blocked in unsafe_flags):
                raise ValueError("unreviewed diagnostic output is disabled")
        if type(w["env"]) is not dict or any(type(v) is not str for v in w["env"].values()):
            raise ValueError("invalid worker environment")
        if any(k.startswith("SGLANG_PAIR_") or k in {"CUDA_VISIBLE_DEVICES", "SGLANG_HOST_IP"} for k in w["env"]):
            raise ValueError("worker overrides pair controls")
        if any(any(part in k for part in ("DUMP", "TRACE", "PROFILER", "LOG_REQUEST", "DEBUG_INFO",
                                          "REPRO", "SAVE_ARGS", "LOGGING_CONFIG"))
               or k in {"NCCL_DEBUG_FILE", "TORCH_COMPILE_DEBUG", "TORCH_LOGS", "TORCH_LOGS_OUT",
                        "PYTHONFAULTHANDLER"} for k in w["env"]):
            raise ValueError("unreviewed diagnostic artifacts are disabled")
    if type(config["statusPort"]) is not int or not 1024 <= config["statusPort"] <= 65534:
        raise ValueError("invalid status port")
    for key in ("progressTimeoutSeconds", "startupTimeoutSeconds", "shutdownTimeoutSeconds"):
        if type(config[key]) is not int or not 1 <= config[key] <= 86400:
            raise ValueError("invalid timeout")


def rank_status(path: Path, now: float, timeout: float, known_pid: int | None) -> tuple[str, int | None]:
    """Only scheduler-owned progress counts. A live HTTP frontend is insufficient."""
    try:
        if path.stat().st_size > 1024:
            return "failed", known_pid
        record = json.loads(path.read_text())
        if set(record) != {"pid", "state", "updated", "completed", "pending_since"}:
            return "failed", known_pid
        pid = record["pid"]
        if type(pid) is not int or pid <= 0 or (known_pid is not None and pid != known_pid):
            return "failed", known_pid
        os.kill(pid, 0)
        for key in ("updated", "completed", "pending_since"):
            value = record[key]
            if type(value) not in {int, float} or not math.isfinite(value) or value < 0 or value > now + 1:
                return "failed", pid
        state = record["state"]
        if state not in {"starting", "idle", "busy", "failed"}:
            return "failed", pid
        if state == "failed":
            return "failed", pid
        if state == "starting":
            return "starting", pid
        if now - record["updated"] > timeout:
            return "failed", pid
        if state == "busy" and (not record["pending_since"] or now - record["pending_since"] > timeout):
            return "failed", pid
        return "ready", pid
    except (FileNotFoundError, ProcessLookupError):
        return ("starting" if known_pid is None else "failed"), known_pid
    except (OSError, ValueError, TypeError, KeyError):
        return "failed", known_pid


def rank_failure_details(path: Path, now: float, timeout: float) -> dict:
    # Codes: 1 missing/invalid record, 2 CPU heartbeat stale, 3 GPU completion
    # stale, 4 process gone, 5 worker reported failure, 6 identity/state failure.
    try:
        if path.stat().st_size > 1024:
            return {"code": 1}
        record = json.loads(path.read_text())
        if set(record) != {"pid", "state", "updated", "completed", "pending_since"}:
            return {"code": 1}
        for key in ("updated", "pending_since"):
            number = record[key]
            if type(number) not in {int, float} or not math.isfinite(number) or not 0 <= number <= now + 1:
                return {"code": 1}
        details = {"code": 6, "age_ms": min(2**63 - 1, max(0, int((now - record["updated"]) * 1000)))}
        if record["pending_since"]:
            details["gpu_pending_ms"] = min(2**63 - 1, max(0, int((now - record["pending_since"]) * 1000)))
        if type(record["pid"]) is not int or record["pid"] <= 0:
            return {"code": 1}
        try:
            os.kill(record["pid"], 0)
        except ProcessLookupError:
            details["code"] = 4
            return details
        if record["state"] == "failed":
            details["code"] = 5
        elif now - record["updated"] > timeout:
            details["code"] = 2
        elif record["state"] == "busy" and record["pending_since"] and now - record["pending_since"] > timeout:
            details["code"] = 3
        return details
    except (OSError, ValueError, TypeError, KeyError):
        return {"code": 1}


class Supervisor:
    def __init__(self, config: dict, directory: Path, devices: list[str]):
        validate_config(config)
        if len(devices) != sum(w["gpus"] for w in config["workers"]) or len(set(devices)) != len(devices):
            raise ValueError("the pair requires its exact assigned GPUs")
        self.config, self.directory, self.devices = config, directory, devices
        self.children: dict[str, subprocess.Popen] = {}
        self.rank_pids: dict[tuple[str, int], int] = {}
        self.http_state: dict[str, tuple[float, bool, int, bool]] = {}
        self.stop = threading.Event()
        self.started = time.monotonic()
        self.snapshot = ("starting", self.started)
        self.failed = False
        self.server = None
        self.events = None
        self.diagnostics = None

    def serve(self) -> None:
        supervisor = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                state, updated = supervisor.snapshot
                fresh = time.monotonic() - updated < 5
                if self.path not in {"/livez", "/readyz", "/startupz"}:
                    code = 404
                else:
                    code = 200 if fresh and state == "ready" else 503
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass  # Paths, headers and client addresses never enter logs.

        self.server = PrivateStatusServer(("0.0.0.0", self.config["statusPort"]), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def collect_events(self) -> None:
        assert self.events is not None
        while not self.stop.is_set():
            try:
                data = self.events.recv(4096)
                if len(data) >= 4096:
                    continue
                value = reviewed_event(json.loads(data))
                if value is not None:
                    emit(**value)
                    if value["event"] in {"nccl_snapshot", "nccl_snapshot_unavailable"} and self.diagnostics is not None:
                        self.diagnostics.acknowledge(value["role"], value.get("rank"))
                    if value["event"] in {"watchdog_timeout", "rank_failed", "communicator_abort_started"} and self.diagnostics is not None:
                        self.diagnostics.request(self.rank_pids)
            except socket.timeout:
                continue
            except (ValueError, TypeError):
                continue
            except OSError:
                return

    def start(self) -> None:
        # Container restarts retain emptyDir data. A new generation must never
        # accept progress or socket files from the previous supervisor.
        self.directory = new_generation(self.directory)
        ranks = [(worker["role"], rank) for worker in self.config["workers"]
                 for rank in range(worker["ranks"])]
        self.diagnostics = StackSnapshots(self.directory, ranks, emit)
        CODE_LOCATIONS.update(self.diagnostics.catalog.values())
        self.events = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.events.bind(str(self.directory / "events.sock"))
        self.events.settimeout(0.5)
        threading.Thread(target=self.collect_events, daemon=True).start()
        self.serve()
        # Model verification and the resident Engram holder belong to the same
        # application container. Its marker is private to this generation.
        ready_file = self.directory / "engram.ready"
        gate_command = [arg.replace("/run/dsv41/engram.ready", str(ready_file))
                        for arg in self.config["modelGate"]]
        gate_env = {k: v for k, v in os.environ.items() if k in INHERITED_ENV}
        self.children["model"] = subprocess.Popen(gate_command, env=gate_env, stdin=subprocess.DEVNULL,
                                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                                   start_new_session=True)
        while not self.stop.wait(0.2):
            if self.children["model"].poll() is not None:
                emit("child_exit", code=self.children["model"].returncode)
                self.failed = True
                self.stop.set()
                return
            if ready_file.is_file() and ready_file.stat().st_size:
                break
            if time.monotonic() - self.started > self.config["startupTimeoutSeconds"]:
                emit("startup_timeout")
                self.failed = True
                self.stop.set()
                return
        if not self.prewarm_flashinfer():
            self.failed = True
            self.stop.set()
            return
        offset = 0
        for worker in sorted(self.config["workers"], key=lambda w: w["role"] != "prefill"):
            if self.stop.is_set():
                break
            role = worker["role"]
            env = {k: v for k, v in os.environ.items() if k in INHERITED_ENV}
            env.update(worker["env"])
            # Disable raw native diagnostic artifacts as well as raw log streams.
            # Reviewed exporters can be added after their privacy test passes.
            for key in tuple(env):
                if key.startswith(("CUDA_COREDUMP", "CUDA_ENABLE_COREDUMP", "CUDA_ENABLE_USER_TRIGGERED_COREDUMP",
                                   "TORCH_FR_DUMP", "TORCH_NCCL_DUMP", "NCCL_DEBUG_FILE")):
                    env.pop(key)
            env.update(CUDA_VISIBLE_DEVICES=",".join(self.devices[offset:offset + worker["gpus"]]),
                       SGLANG_HOST_IP="127.0.0.1", SGLANG_PAIR_ROLE=role,
                       SGLANG_PAIR_RUN_DIR=str(self.directory),
                       TORCH_NCCL_TRACE_BUFFER_SIZE="256", TORCH_NCCL_DUMP_ON_TIMEOUT="0",
                       TORCH_NCCL_TRACE_CPP_STACK="0", TORCH_NCCL_ENABLE_TIMING="0")
            offset += worker["gpus"]
            self.children[role] = subprocess.Popen(worker["command"], env=env, stdin=subprocess.DEVNULL,
                                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                                  start_new_session=True)
            # Load and warm one worker before the next, preserving the existing
            # launch order and avoiding concurrent cold-build memory spikes.
            while not self.stop.wait(0.2):
                if self.children["model"].poll() is not None:
                    emit("child_exit", code=self.children["model"].returncode)
                    self.failed = True
                    self.stop.set()
                    break
                # A previously started worker must not sit failed throughout
                # the next worker's long compilation and warmup.
                if any(self.worker_state(previous) == "failed" for previous in self.config["workers"]
                       if previous["role"] != role and previous["role"] in self.children):
                    emit("rank_failed")
                    self.failed = True
                    self.stop.set()
                    break
                state = self.worker_state(worker)
                if state == "ready":
                    break
                if state == "failed" or time.monotonic() - self.started > self.config["startupTimeoutSeconds"]:
                    emit("rank_failed" if state == "failed" else "startup_timeout", role)
                    self.failed = True
                    self.stop.set()
                    break
            if self.stop.is_set():
                break

    def prewarm_flashinfer(self) -> bool:
        """Compile FlashInfer sampling kernels into each worker cache before any worker starts."""
        caches = {}
        for worker in self.config["workers"]:
            env = {k: v for k, v in os.environ.items() if k in INHERITED_ENV}
            env.update({k: v for k, v in worker["env"].items() if k in PREWARM_ENV})
            caches.setdefault(env.get("FLASHINFER_WORKSPACE_BASE"), env)
        for env in caches.values():
            env.update(CUDA_VISIBLE_DEVICES=self.devices[0])
            started = time.monotonic()
            child = subprocess.Popen(PREWARM_COMMAND, env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     start_new_session=True)
            self.children["prewarm"] = child
            while child.poll() is None:
                if self.stop.wait(0.2):
                    return False
                if time.monotonic() - self.started > self.config["startupTimeoutSeconds"]:
                    emit("startup_timeout")
                    return False
            del self.children["prewarm"]
            duration_ms = int((time.monotonic() - started) * 1000)
            if child.returncode:
                emit("flashinfer_prewarm_failed", code=child.returncode, duration_ms=duration_ms)
                return False
            emit("flashinfer_prewarm_finished", duration_ms=duration_ms)
        return True

    def worker_state(self, worker: dict) -> str:
        role = worker["role"]
        child = self.children.get(role)
        if child is None:
            return "starting"
        code = child.poll()
        if code is not None:
            emit("child_exit", role, code=code)
            return "failed"
        states = []
        now = time.monotonic()
        checked, available, failures, ever_ready = self.http_state.get(role, (0.0, False, 0, False))
        progress_budget = (self.config["progressTimeoutSeconds"] if ever_ready
                           else self.config["startupTimeoutSeconds"])
        for rank in range(worker["ranks"]):
            key = (role, rank)
            state, pid = rank_status(self.directory / f"{role}-{rank}.json", now,
                                     progress_budget, self.rank_pids.get(key))
            if pid is not None:
                self.rank_pids[key] = pid
            if state == "failed":
                details = rank_failure_details(self.directory / f"{role}-{rank}.json", now, progress_budget)
                emit("rank_progress_failed", role, rank=rank, **details)
            states.append(state)
        if "failed" in states:
            return "failed"
        if "starting" in states:
            return "starting"
        # HTTP availability is necessary, but never sufficient. This poll is
        # outside the status handler and has a short, bounded socket timeout.
        if now - checked >= 2:
            # Startup must include SGLang's warmup, not merely HTTP startup.
            # Once proven, fast frontend availability plus rank progress is
            # sufficient; do not generate inference in each liveness request.
            connection = http.client.HTTPConnection("127.0.0.1", worker["port"],
                                                    timeout=0.5 if ever_ready else 3)
            try:
                connection.request("GET", "/v1/models" if ever_ready else "/health")
                available = connection.getresponse().status == 200
            except (OSError, http.client.HTTPException):
                available = False
            finally:
                connection.close()
            failures = 0 if available else failures + 1
            ever_ready |= available
            self.http_state[role] = (now, available, failures, ever_ready)
        if available:
            return "ready"
        return "failed" if ever_ready and failures >= 3 else "starting"

    def monitor(self) -> int:
        while not self.stop.wait(0.5):
            states = [self.worker_state(w) for w in self.config["workers"]]
            if self.children["model"].poll() is not None:
                emit("child_exit", code=self.children["model"].returncode)
                states.append("failed")
            now = time.monotonic()
            state = "failed" if "failed" in states else "starting" if "starting" in states else "ready"
            if state == "starting" and now - self.started > self.config["startupTimeoutSeconds"]:
                emit("startup_timeout")
                state = "failed"
            self.snapshot = (state, now)
            if state == "failed":
                emit("progress_stale")
                self.failed = True
                self.snapshot = ("failed", time.monotonic())
                if self.diagnostics is not None:
                    self.diagnostics.request(self.rank_pids)
                    time.sleep(SNAPSHOT_SECONDS + 0.2)
                self.stop.set()
        self.snapshot = ("failed", time.monotonic())
        return 1 if self.failed else 0

    def shutdown(self) -> None:
        self.stop.set()
        self.snapshot = ("failed", time.monotonic())
        # Signal groups even when their leaders exited; schedulers must not
        # survive an HTTP supervisor and keep the pair's GPU allocations alive.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for child in self.children.values():
                try:
                    os.killpg(child.pid, sig)
                except ProcessLookupError:
                    pass
            if sig == signal.SIGTERM:
                deadline = time.monotonic() + self.config["shutdownTimeoutSeconds"]
                while time.monotonic() < deadline:
                    if all(p.poll() is not None for p in self.children.values()):
                        # Leaders can exit before their descendants. Still send
                        # the bounded SIGKILL below to every original group.
                        break
                    time.sleep(0.1)
        reap_deadline = time.monotonic() + 5
        for child in self.children.values():
            try:
                child.wait(timeout=max(0, reap_deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                emit("shutdown_timeout")
        # PID 1 adopts grandchildren after their worker leader exits. Reap only
        # after Popen has collected the leaders' exit status.
        try:
            while os.waitpid(-1, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.events is not None:
            self.events.close()
        if self.diagnostics is not None:
            self.diagnostics.close()
        for path in self.directory.glob("*"):
            if path.is_file() or path.is_socket():
                path.unlink(missing_ok=True)


def main() -> int:
    global LOG_SINK, LOG_STDOUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-json", required=True)
    parser.add_argument("--run-dir", type=Path, default=Path("/run/dsv41/pair"))
    args = parser.parse_args()
    supervisor = None
    try:
        # Core files can include prompts, tensors and credentials. No raw core
        # file belongs to the reviewed error-only diagnostics profile.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        LOG_STDOUT = NonblockingStdout()
        LOG_SINK = LogSink.from_environment()
        supervisor = Supervisor(json.loads(args.config_json), args.run_dir, assigned_gpus())
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGQUIT):
            signal.signal(sig, lambda *_: supervisor.stop.set())
        supervisor.start()
        return supervisor.monitor()
    except Exception:
        emit("supervisor_failed")  # Never format exceptions or configuration.
        return 1
    finally:
        if supervisor is not None:
            supervisor.shutdown()
        if LOG_SINK is not None:
            delivery = LOG_SINK.close(timeout=1)
            LOG_SINK = None
            if delivery["dropped"] or delivery["pending"] or delivery["failures"]:
                emit("diagnostic_delivery_failed", **delivery)


if __name__ == "__main__":
    raise SystemExit(main())
