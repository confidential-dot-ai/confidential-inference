"""Run with the GPU acceptance checks on the isolated test CVM.

These tests need no model. They exercise the same supervisor with fake device
identities and real child processes. GPU correctness is a separate gate.
"""

import contextlib
import importlib.util
import http.client
import io
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "images/sglang"))
sys.path.insert(0, str(ROOT / "images/sglang-router"))
spec = importlib.util.spec_from_file_location("pair_supervisor", ROOT / "images/sglang/pair_supervisor.py")
pair = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pair)
# Supervisor tests run without a GPU; PrewarmTests cover the prewarm step itself.
pair.PREWARM_COMMAND = [sys.executable, "-c", "pass"]


def unused_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class PrivacyTests(unittest.TestCase):
    def test_status_handler_exception_cannot_export_client_data(self):
        canary = "PRIVATE_PROMPT_RESPONSE_API_CREDENTIAL"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                raise RuntimeError(self.headers["Authorization"] + self.path)

            def log_message(self, *_):
                pass

        def run(server_type):
            output, errors = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                server = server_type(("127.0.0.1", 0), Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
                try:
                    connection.request("GET", "/" + canary, headers={"Authorization": canary})
                    with self.assertRaises(http.client.RemoteDisconnected):
                        connection.getresponse()
                finally:
                    connection.close()
                    server.shutdown()
                    server.server_close()
                    thread.join(2)
            return output.getvalue(), errors.getvalue()

        # A positive control proves this fixture reaches the unsafe base path.
        self.assertIn(canary, run(ThreadingHTTPServer)[1])
        output, errors = run(pair.PrivateStatusServer)
        self.assertNotIn(canary, output + errors)
        self.assertEqual("", errors)
        record = json.loads(output)
        self.assertEqual({"timestamp_ns", "run_id", "source_revision", "event", "role"}, set(record))
        self.assertRegex(record["run_id"], r"^[0-9a-f]{32}$")
        self.assertEqual("status_request_failed", record["event"])

    def test_rejects_sensitive_or_unreviewed_fields_whole(self):
        fake = "FAKE-API-KEY-and-FAKE-CUSTOMER-PROMPT"
        for field in ("message", "prompt", "output", "tensor", "api_key", "customer", "locals", "rid", "run_id", "headers", "path", "exception"):
            self.assertIsNone(pair.reviewed_event({"event": "rank_failed", "role": "decode", field: fake}))
        for value in (fake, True, None, [], {}, float("nan"), float("inf")):
            self.assertIsNone(pair.reviewed_event({"event": "cuda_error", "role": "prefill", "code": value}))

    def test_only_fixed_codes_and_numeric_metadata_are_emitted(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pair.emit("nccl_error", "decode", rank=1, code=7, count=2)
        record = json.loads(output.getvalue())
        self.assertEqual({"timestamp_ns", "run_id", "source_revision", "event", "role", "rank", "code", "count"}, set(record))
        self.assertEqual("nccl_error", record["event"])

    def test_refuses_raw_artifact_outputs(self):
        for flag in ("--log-requests", "--crash-dump-folder", "--debug-tensor-dump-output-folder", "--enable-trace",
                     "--log-req", "--crash-dump-f", "--debug-tensor-dump-o", "--enable-tr", "--enable_trace"):
            cfg = config()
            cfg["workers"][0]["command"].append(flag)
            with self.assertRaises(ValueError):
                pair.validate_config(cfg)
        for name in ("TORCH_NCCL_DUMP_ON_TIMEOUT", "TORCH_NCCL_DEBUG_INFO_TEMP_FILE",
                     "TORCH_NCCL_DEBUG_INFO_PIPE_FILE", "NCCL_DEBUG_FILE", "TORCH_COMPILE_DEBUG",
                     "CUDA_ENABLE_COREDUMP", "SGLANG_LOGGING_CONFIG_PATH", "TORCH_LOGS",
                     "TORCH_LOGS_OUT", "TORCHINDUCTOR_SAVE_ARGS", "TORCHDYNAMO_REPRO_AFTER"):
            cfg = config()
            cfg["workers"][0]["env"][name] = "PRIVATE_PATH_OR_VALUE"
            with self.assertRaises(ValueError):
                pair.validate_config(cfg)


def config():
    return {"modelGate": [sys.executable, "-c", "import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(120)", "/run/dsv41/engram.ready"], "workers": [{"role": role, "gpus": 1, "ranks": 1, "port": unused_port(),
                         "command": [sys.executable, "-c", "pass"], "env": {}}
                        for role in ("prefill", "decode")],
            "statusPort": unused_port(), "progressTimeoutSeconds": 1,
            "startupTimeoutSeconds": 5, "shutdownTimeoutSeconds": 1}


class RankHealthTests(unittest.TestCase):
    def test_failure_details_export_only_reason_and_ages(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decode-0.json"
            now = 1000.0  # A new CI VM may have less than 120 seconds of uptime.
            path.write_text(json.dumps({"pid": os.getpid(), "state": "busy", "updated": now,
                                        "completed": 0, "pending_since": now - 120}))
            self.assertEqual({"code": 3, "age_ms": 0, "gpu_pending_ms": 120000},
                             pair.rank_failure_details(path, now, 90))
            path.write_text(json.dumps({"prompt": "PRIVATE_CUSTOMER_TEXT"}))
            self.assertEqual({"code": 1}, pair.rank_failure_details(path, now, 90))

    def test_restart_records_stay_bounded_without_following_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "pair"
            outside = Path(directory) / "outside"
            outside.mkdir()
            marker = outside / "keep"
            marker.write_text("unrelated")
            for index in range(20):
                current = pair.new_generation(base)
                (current / "decode-0.json").write_text(json.dumps({"pid": index}))
                self.assertLessEqual(len([p for p in base.iterdir() if p.is_dir()]), 2)
            (base / "generation-link").symlink_to(outside, target_is_directory=True)
            pair.new_generation(base)
            self.assertEqual("unrelated", marker.read_text())
            self.assertTrue((base / "generation-link").is_symlink())

    def test_dead_and_stale_rank_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decode-0.json"
            now = time.monotonic()
            record = {"pid": os.getpid(), "state": "idle", "updated": now, "completed": now, "pending_since": 0}
            path.write_text(json.dumps(record))
            self.assertEqual("ready", pair.rank_status(path, now, 1, None)[0])
            self.assertEqual("failed", pair.rank_status(path, now + 2, 1, os.getpid())[0])
            record.update(state="busy", pending_since=now - 2, updated=now)
            path.write_text(json.dumps(record))
            self.assertEqual("failed", pair.rank_status(path, now, 1, None)[0])

    def test_idle_is_healthy_without_completed_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prefill-0.json"
            now = time.monotonic()
            path.write_text(json.dumps({"pid": os.getpid(), "state": "idle", "updated": now,
                                       "completed": 0, "pending_since": 0}))
            self.assertEqual("ready", pair.rank_status(path, now, 1, None)[0])

    def test_rank_startup_uses_startup_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prefill-0.json"
            now = 1000.0
            path.write_text(json.dumps({"pid": os.getpid(), "state": "starting", "updated": now - 100,
                                       "completed": 0, "pending_since": 0}))
            self.assertEqual("starting", pair.rank_status(path, now, 1, None)[0])

    def test_changed_pid_and_unknown_fields_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decode-0.json"
            now = time.monotonic()
            record = {"pid": os.getpid(), "state": "idle", "updated": now, "completed": now, "pending_since": 0}
            path.write_text(json.dumps(record))
            self.assertEqual("failed", pair.rank_status(path, now, 1, os.getpid() + 1)[0])
            record["prompt"] = "FAKE-SECRET"
            path.write_text(json.dumps(record))
            self.assertEqual("failed", pair.rank_status(path, now, 1, None)[0])


class DeviceAssignmentTests(unittest.TestCase):
    def test_requires_exact_distinct_devices(self):
        for devices in ([], ["GPU-a"], ["GPU-a", "GPU-a"], ["GPU-a", "GPU-b", "GPU-c"]):
            with self.assertRaises(ValueError):
                pair.Supervisor(config(), Path("/unused"), devices)


class ProcessAcceptanceTests(unittest.TestCase):
    def test_failure_in_one_pair_does_not_stop_the_other_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            supervisors, controls, monitors = [], [], []
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                try:
                    for index in range(2):
                        cfg = config()
                        control = Path(directory) / f"decode-{index}"
                        controls.append(control)
                        for w in cfg["workers"]:
                            marker = control if w["role"] == "decode" else Path(directory) / f"prefill-{index}"
                            w["command"] = [sys.executable, str(Path(__file__).with_name("pair_fake_worker.py")),
                                            "--port", str(w["port"])]
                            w["env"] = {"PAIR_TEST_CONTROL": str(marker)}
                        supervisor = pair.Supervisor(cfg, Path(directory) / f"run-{index}",
                                                     [f"GPU-{index}-a", f"GPU-{index}-b"])
                        supervisors.append(supervisor)
                        supervisor.start()
                        monitor = threading.Thread(target=supervisor.monitor, daemon=True)
                        monitors.append(monitor)
                        monitor.start()
                    controls[1].write_text("stall")
                    monitors[1].join(timeout=5)
                    self.assertFalse(monitors[1].is_alive())
                    supervisors[1].shutdown()
                    self.assertEqual("ready", supervisors[0].snapshot[0])
                    for _ in range(10):
                        for w in supervisors[0].config["workers"]:
                            conn = http.client.HTTPConnection("127.0.0.1", w["port"], timeout=1)
                            conn.request("GET", "/v1/models")
                            self.assertEqual(200, conn.getresponse().status)
                            conn.close()
                finally:
                    for supervisor in supervisors:
                        supervisor.stop.set()
                    for monitor in monitors:
                        monitor.join(timeout=3)
                    for supervisor in supervisors:
                        supervisor.shutdown()

    def exercise_failure(self, failure):
        with tempfile.TemporaryDirectory() as directory:
            cfg = config()
            controls = {}
            for worker in cfg["workers"]:
                role = worker["role"]
                controls[role] = Path(directory) / role
                worker["command"] = [sys.executable, str(Path(__file__).with_name("pair_fake_worker.py")),
                                     "--port", str(worker["port"])]
                worker["env"] = {"PAIR_TEST_CONTROL": str(controls[role])}
            supervisor = pair.Supervisor(cfg, Path(directory) / "run", ["GPU-fake-a", "GPU-fake-b"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                try:
                    supervisor.start()
                    result = []
                    monitor = threading.Thread(target=lambda: result.append(supervisor.monitor()), daemon=True)
                    monitor.start()
                    deadline = time.monotonic() + 4
                    while supervisor.snapshot[0] != "ready" and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertEqual("ready", supervisor.snapshot[0])
                    # The status handler stays fast and never contacts a worker.
                    for _ in range(10):
                        started = time.monotonic()
                        connection = http.client.HTTPConnection("127.0.0.1", cfg["statusPort"], timeout=1)
                        connection.request("GET", "/livez")
                        self.assertEqual(200, connection.getresponse().status)
                        connection.close()
                        self.assertLess(time.monotonic() - started, 0.25)
                    controls["decode"].write_text(failure)
                    monitor.join(timeout=5)
                    self.assertFalse(monitor.is_alive())
                    self.assertEqual([1], result)
                    self.assertEqual("failed", supervisor.snapshot[0])
                finally:
                    supervisor.shutdown()
            raw = output.getvalue()
            for canary in ("FAKE-KEY-DO-NOT-LOG", "FAKE-PROMPT-DO-NOT-LOG"):
                self.assertNotIn(canary, raw)
            records = [json.loads(line) for line in raw.splitlines()]
            self.assertTrue(any(record["event"] == "cuda_error" for record in records))
            for record in records:
                    self.assertRegex(record["run_id"], r"^[0-9a-f]{32}$")
                    self.assertIsNotNone(pair.reviewed_event({k: v for k, v in record.items() if k not in {"timestamp_ns", "run_id", "source_revision"}}))
            self.assertTrue(all(child.poll() is not None for child in supervisor.children.values()))

    def test_http_alive_gpu_progress_stalled_fails_and_stops_pair(self):
        self.exercise_failure("stall")

    def test_clean_frontend_cannot_hide_exited_worker(self):
        self.exercise_failure("exit")


class PrewarmTests(unittest.TestCase):
    """FlashInfer sampling kernels compile before any worker starts, inside the startup budget."""

    def run_start(self, command, startup_timeout=5):
        directory = tempfile.mkdtemp()
        cache = Path(directory) / "flashinfer"
        cfg = config()
        cfg["startupTimeoutSeconds"] = startup_timeout
        for worker in cfg["workers"]:
            worker["command"] = [sys.executable, str(Path(__file__).with_name("pair_fake_worker.py")),
                                 "--port", str(worker["port"])]
            worker["env"] = {"PAIR_TEST_CONTROL": str(Path(directory) / worker["role"]),
                             "FLASHINFER_WORKSPACE_BASE": str(cache), "PRIVATE_WORKER_ONLY": "1"}
        previous = pair.PREWARM_COMMAND
        pair.PREWARM_COMMAND = command
        supervisor = pair.Supervisor(cfg, Path(directory) / "run", ["GPU-fake-a", "GPU-fake-b"])
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                try:
                    supervisor.start()
                    roles = {role for role in ("prefill", "decode") if role in supervisor.children}
                    failed = supervisor.failed
                finally:
                    supervisor.shutdown()
        finally:
            pair.PREWARM_COMMAND = previous
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        for record in records:
            self.assertIsNotNone(pair.reviewed_event({k: v for k, v in record.items()
                                                      if k not in {"timestamp_ns", "run_id", "source_revision"}}))
        return cache, roles, failed, records, supervisor

    def test_prewarm_finishes_before_workers_with_worker_cache_and_first_gpu(self):
        record = ("import json,os,pathlib; p=pathlib.Path(os.environ['FLASHINFER_WORKSPACE_BASE']);"
                  "p.mkdir(parents=True); (p/'warm').write_text(json.dumps(dict(os.environ)))")
        cache, roles, failed, records, _ = self.run_start([sys.executable, "-c", record])
        self.assertFalse(failed)
        self.assertEqual({"prefill", "decode"}, roles)
        env = json.loads((cache / "warm").read_text())
        self.assertEqual("GPU-fake-a", env["CUDA_VISIBLE_DEVICES"])
        self.assertNotIn("PRIVATE_WORKER_ONLY", env)
        self.assertNotIn("PAIR_TEST_CONTROL", env)
        events = [r["event"] for r in records]
        self.assertIn("flashinfer_prewarm_finished", events)
        self.assertNotIn("flashinfer_prewarm_failed", events)

    def test_prewarm_failure_fails_startup_before_any_worker(self):
        _, roles, failed, records, _ = self.run_start([sys.executable, "-c", "raise SystemExit(3)"])
        self.assertTrue(failed)
        self.assertEqual(set(), roles)
        failure = [r for r in records if r["event"] == "flashinfer_prewarm_failed"]
        self.assertEqual(1, len(failure))
        self.assertEqual(3, failure[0]["code"])

    def test_prewarm_counts_against_the_startup_budget(self):
        _, roles, failed, records, supervisor = self.run_start(
            [sys.executable, "-c", "import time; time.sleep(60)"], startup_timeout=1)
        self.assertTrue(failed)
        self.assertEqual(set(), roles)
        self.assertIn("startup_timeout", [r["event"] for r in records])
        self.assertTrue(all(child.poll() is not None for child in supervisor.children.values()))

    def test_prewarm_program_reports_only_an_exit_status(self):
        # Without torch or a GPU the program fails closed and prints nothing.
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "images/sglang/prewarm_flashinfer.py")],
                                capture_output=True, timeout=120)
        if result.returncode == 0:
            self.skipTest("a GPU with FlashInfer is available")
        self.assertEqual(1, result.returncode)
        self.assertEqual(b"", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
