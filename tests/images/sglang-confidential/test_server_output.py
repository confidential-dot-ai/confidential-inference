"""The supervisor reduces private SGLang output to fixed contract events."""

from __future__ import annotations

import importlib.util
import io
import json
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "images/sglang-confidential/wait_for_model.py"
SPEC = importlib.util.spec_from_file_location("wait_for_model", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
wfm = importlib.util.module_from_spec(SPEC)
sys.modules["wait_for_model"] = wfm
SPEC.loader.exec_module(wfm)

MARKER = "ZQXCANARY7731"
REVISION = "9e165c30e2704aec5d9d593cce3eebd58bbef1cb"
SITE = "/usr/local/lib/python3.12/dist-packages"

# The contract, written out here and not taken from the module under test.
KEYS = {
    "worker_ready": {"event", "model_revision", "gpus", "load_seconds"},
    "request_failed": {"event", "error_class", "http_status", "phase", "input_tokens_bucket",
                       "duration_ms", "exception", "location"},
    "gpu_oom": {"event", "location"},
    "cuda_error": {"event", "code", "location"},
    "nccl_error": {"event", "code", "location"},
    "worker_error": {"event", "error_class", "exception", "location"},
    "worker_exit": {"event", "exit_code", "signal"},
}
EXCEPTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,95}$")
LOCATION = re.compile(r"^[A-Za-z0-9_./-]{1,160}:[0-9]{1,7}$")
ERROR_CLASS = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
CODE = re.compile(r"^(cudaError[A-Za-z]+|nccl[A-Z][A-Za-z]+|timeout|unknown)$")


def assert_contract(test: unittest.TestCase, event: dict) -> None:
    test.assertIn(event.get("event"), KEYS, event)
    test.assertEqual(KEYS[event["event"]], set(event), event)
    test.assertLessEqual(len(json.dumps(event, separators=(",", ":")).encode()), 4096)
    for key in ("exception",):
        if key in event and event[key] is not None:
            test.assertRegex(event[key], EXCEPTION)
    if event.get("location") is not None:
        test.assertRegex(event["location"], LOCATION)
    if "error_class" in event:
        test.assertRegex(event["error_class"], ERROR_CLASS)
    if "code" in event:
        test.assertRegex(event["code"], CODE)
    if event["event"] == "request_failed":
        test.assertIn(event["phase"], {"http", "tokenize", "schedule", "model", "unknown"})
        test.assertIn(event["input_tokens_bucket"],
                      {"unknown", "lt_1k", "1k_8k", "8k_32k", "32k_128k", "128k_512k", "ge_512k"})
        test.assertIsNone(event["duration_ms"])
        status = event["http_status"]
        test.assertTrue(status is None or (isinstance(status, int) and 100 <= status <= 599))
    if event["event"] == "worker_ready":
        test.assertRegex(event["model_revision"], r"^[0-9a-f]{40}$")
        test.assertIsInstance(event["gpus"], int)
        test.assertIsInstance(event["load_seconds"], int)
    if event["event"] == "worker_exit":
        test.assertTrue(event["exit_code"] is None or isinstance(event["exit_code"], int))
        test.assertTrue(event["signal"] is None or re.fullmatch(r"SIG[A-Z0-9]+", event["signal"]))


def traceback_lines(frames: list[tuple[str, int, str]], final: str, prefix: str = "") -> list[str]:
    lines = [f"{prefix}Traceback (most recent call last):"]
    for path, line, code in frames:
        lines.append(f'  File "{path}", line {line}, in handler')
        lines.append(f"    {code}")
    lines.append(final)
    return lines


SCHEDULER = f"{SITE}/sglang/srt/managers/scheduler.py"
SERVING = f"{SITE}/sglang/srt/entrypoints/openai/serving_chat.py"
MODEL = f"{SITE}/sglang/srt/models/qwen3.py"
TORCH = f"{SITE}/torch/nn/modules/module.py"
ACCESS = '[2026-11-16 01:02:03] INFO:     10.1.2.3:51234 - "POST /v1/chat/completions HTTP/1.1" {status}'


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class ClassifierTests(unittest.TestCase):
    def classify(self, lines: list[str]) -> list[dict]:
        events = wfm.classify_lines(lines)
        for event in events:
            assert_contract(self, event)
        return events

    def test_traceback_reduces_to_type_and_last_sglang_location(self) -> None:
        lines = ["[2026-11-16 01:02:03 TP0] Scheduler hit an exception: Traceback (most recent call last):"]
        lines += traceback_lines([(SCHEDULER, 1234, "self.run()"), (TORCH, 99, "x()")],
                                 "KeyError: 'secret'")[1:]
        self.assertEqual([{"event": "worker_error", "error_class": "unclassified", "exception": "KeyError",
                           "location": "sglang/srt/managers/scheduler.py:1234"}], self.classify(lines))

    def test_unknown_exception_is_unclassified_with_location(self) -> None:
        lines = traceback_lines([(MODEL, 77, "forward()")], "mylib.WeirdThingError: boom")
        self.assertEqual([{"event": "worker_error", "error_class": "unclassified",
                           "exception": "mylib.WeirdThingError", "location": "sglang/srt/models/qwen3.py:77"}],
                         self.classify(lines))

    def test_no_sglang_frame_gives_null_location(self) -> None:
        lines = traceback_lines([(TORCH, 5, "x()")], "AssertionError")
        self.assertEqual([{"event": "worker_error", "error_class": "internal_assertion",
                           "exception": "AssertionError", "location": None}], self.classify(lines))

    def test_chained_traceback_classifies_the_final_exception(self) -> None:
        lines = traceback_lines([(TORCH, 5, "x()")], "KeyError: 'a'")
        lines += ["", "During handling of the above exception, another exception occurred:", ""]
        lines += traceback_lines([(SCHEDULER, 10, "y()")], "TimeoutError: slow")
        self.assertEqual([{"event": "worker_error", "error_class": "timeout", "exception": "TimeoutError",
                           "location": "sglang/srt/managers/scheduler.py:10"}], self.classify(lines))

    def test_gpu_oom(self) -> None:
        lines = traceback_lines([(MODEL, 300, "self.mlp(x)")],
                                "torch.OutOfMemoryError: CUDA out of memory. Tried to allocate 2.00 GiB")
        # The same error on another line within 5 s is not reported again.
        lines.append("[2026-11-16 01:02:04 TP1] torch.cuda.OutOfMemoryError: CUDA out of memory.")
        self.assertEqual([{"event": "gpu_oom", "location": "sglang/srt/models/qwen3.py:300"}], self.classify(lines))
        self.assertEqual([{"event": "gpu_oom", "location": None}],
                         self.classify(["[2026-11-16 01:02:04 TP1] torch.cuda.OutOfMemoryError: CUDA out of memory."]))

    def test_cuda_errors(self) -> None:
        lines = traceback_lines([(MODEL, 12, "k()")], "RuntimeError: CUDA error: an illegal memory access was encountered")
        lines.append("CUDA kernel errors might be asynchronously reported at some other API call")
        events = self.classify(lines)
        self.assertEqual([{"event": "cuda_error", "code": "cudaErrorIllegalAddress",
                           "location": "sglang/srt/models/qwen3.py:12"}], events)
        self.assertEqual("cudaErrorAssert", self.classify(["RuntimeError: CUDA error: device-side assert triggered"])[0]["code"])
        self.assertEqual("cudaErrorLaunchFailure",
                         self.classify(["CUDA error: cudaErrorLaunchFailure unspecified"])[0]["code"])
        self.assertEqual("unknown", self.classify([f"CUDA error: {MARKER} cudaError{MARKER}"])[0]["code"])

    def test_nccl_errors(self) -> None:
        final = ("torch.distributed.DistBackendError: NCCL error in: ProcessGroupNCCL.cpp:1970, "
                 "unhandled cuda error (run with NCCL_DEBUG=INFO for details)")
        events = self.classify(traceback_lines([(SCHEDULER, 55, "all_reduce()")], final))
        self.assertEqual([{"event": "nccl_error", "code": "ncclUnhandledCudaError",
                           "location": "sglang/srt/managers/scheduler.py:55"}], events)
        watchdog = ("[rank0]:[E1116 01:02:03 ProcessGroupNCCL.cpp:616] [Rank 0] Watchdog caught collective "
                    "operation timeout: WorkNCCL(SeqNum=9, OpType=ALLREDUCE) ran for 600000 milliseconds")
        self.assertEqual([{"event": "nccl_error", "code": "timeout", "location": None}],
                         self.classify([watchdog, watchdog]))
        self.assertEqual("ncclRemoteError", self.classify(["NCCL error: ncclRemoteError: peer gone"])[0]["code"])

    def test_access_log_400_is_invalid_request_in_http_phase(self) -> None:
        self.assertEqual([{"event": "request_failed", "error_class": "invalid_request", "http_status": 400,
                           "phase": "http", "input_tokens_bucket": "unknown", "duration_ms": None,
                           "exception": None, "location": None}], self.classify([ACCESS.format(status=400)]))

    def test_status_classes(self) -> None:
        for status, expected in ((404, "not_found"), (413, "request_too_large"), (429, "overloaded"),
                                 (503, "unavailable"), (504, "timeout"), (418, "client_error"),
                                 (502, "unclassified")):
            self.assertEqual(expected, self.classify([ACCESS.format(status=status)])[0]["error_class"])
        self.assertEqual([], self.classify([ACCESS.format(status=200)]))

    def test_500_after_error_in_request_takes_the_exception_class(self) -> None:
        lines = [f"[2026-11-16 01:02:03 TP0] Error in request: {MARKER}"]
        lines += traceback_lines([(SERVING, 88, "await self._handle()"), (TORCH, 3, "z()")],
                                 f"asyncio.exceptions.CancelledError: {MARKER}")
        lines.append(ACCESS.format(status=500))
        self.assertEqual([{"event": "request_failed", "error_class": "aborted", "http_status": 500,
                           "phase": "tokenize", "input_tokens_bucket": "unknown", "duration_ms": None,
                           "exception": "asyncio.exceptions.CancelledError",
                           "location": "sglang/srt/entrypoints/openai/serving_chat.py:88"}], self.classify(lines))

    def test_request_error_older_than_the_window_is_not_used(self) -> None:
        clock = Clock()
        events: list[dict] = []
        classifier = wfm.OutputClassifier(events.append, clock)
        for line in ["Error in request: x"] + traceback_lines([(SERVING, 1, "a()")], "ValueError: x"):
            classifier.feed(line)
        clock.now += 10
        classifier.feed(ACCESS.format(status=500))
        classifier.finish()
        self.assertEqual(["worker_error", "request_failed"], [event["event"] for event in events])
        self.assertEqual("unclassified", events[1]["error_class"])
        self.assertEqual("http", events[1]["phase"])

    def test_input_tokens_bucket(self) -> None:
        lines = [f"[2026-11-16 TP0] The input (40000 tokens) is longer than the model's context length (32768 tokens).",
                 ACCESS.format(status=400)]
        self.assertEqual("32k_128k", self.classify(lines)[0]["input_tokens_bucket"])

    def test_health_metrics_readiness_paths_are_ignored(self) -> None:
        lines = [f'[2026] INFO:     1.2.3.4:5 - "GET {path} HTTP/1.1" 503'
                 for path in ("/health", "/health_generate", "/metrics", "/readiness?x=1")]
        self.assertEqual([], self.classify(lines))

    def test_overlong_line_is_capped_and_the_rest_discarded(self) -> None:
        long_line = b"A" * (wfm.LINE_MAX_BYTES * 3) + MARKER.encode() + b"\n"
        stream = io.BufferedReader(io.BytesIO(long_line + ACCESS.format(status=429).encode() + b"\n\xff\xfe\n"))
        lines = list(wfm.bounded_lines(stream))
        self.assertEqual(3, len(lines))
        self.assertLessEqual(len(lines[0].encode()), wfm.LINE_MAX_BYTES)
        self.assertNotIn(MARKER, "".join(lines))
        self.assertIn("�", lines[2])
        events = self.classify(lines)
        self.assertEqual(["overloaded"], [event["error_class"] for event in events])

    def test_frames_are_bounded(self) -> None:
        frames = [(TORCH, n, "x()") for n in range(1000)] + [(SCHEDULER, 7, "y()")]
        events = self.classify(traceback_lines(frames, "OSError: x"))
        self.assertEqual("sglang/srt/managers/scheduler.py:7", events[0]["location"])

    def test_writer_refuses_invalid_or_oversized_events(self) -> None:
        self.assertFalse(wfm.valid_event({"event": "worker_exit", "exit_code": 0, "signal": None, "x": 1}))
        self.assertFalse(wfm.valid_event({"event": "worker_error", "error_class": "Bad Class",
                                          "exception": None, "location": None}))
        read_fd, write_fd = __import__("os").pipe()
        try:
            writer = wfm.NonblockingStdout(write_fd)
            self.assertFalse(writer.write({"event": "x", "pad": "a" * 5000}))
            self.assertEqual(1, writer.dropped)
            self.assertTrue(writer.write({"event": "worker_exit", "exit_code": 0, "signal": None}))
        finally:
            __import__("os").close(read_fd)
            __import__("os").close(write_fd)

    def test_canary_never_appears_in_events(self) -> None:
        m = MARKER
        lines = [
            f"[2026-11-16 01:02:03 TP0] Prompt: {m} please summarize",
            m,
            f"{m}: {m}",
            f"[2026-11-16 01:02:03 TP0] Error in request: {m}",
            *traceback_lines([(SERVING, 10, f"prompt = '{m}'"), (f"/tmp/{m}/x.py", 3, f"{m}()")],
                             f"ValueError: The input (9000 tokens) {m} is longer than"),
            f'[2026-11-16 01:02:04] INFO:     1.2.3.4:5 - "POST /v1/{m}?q={m} HTTP/1.1" 500',
            f"The input (900000 tokens) is longer than {m}",
            f'[2026-11-16 01:02:04] INFO:     1.2.3.4:5 - "GET /{m} HTTP/1.1" 400',
            *traceback_lines([(SCHEDULER, 20, f"x = '{m}'")], f"Fake {m} Type With Spaces: {m}"),
            *traceback_lines([(SCHEDULER, 21, "y()")], m),
            *traceback_lines([(SCHEDULER, 22, "y()")], f"{m}Error with no colon"),
            f"CUDA error: {m} cudaError{m}",
            f"NCCL error {m} nccl{m}Xyz",
            f"torch.OutOfMemoryError: CUDA out of memory {m}",
            "Traceback (most recent call last):",
            f'  File "{SCHEDULER}", line 30, in run',
            f"    {m}",
        ]
        events = self.classify(lines)
        self.assertGreaterEqual(len(events), 7)
        for event in events:
            self.assertNotIn(m, json.dumps(event))
        kinds = [event["event"] for event in events]
        self.assertIn("request_failed", kinds)
        self.assertIn("worker_error", kinds)
        failed = [event for event in events if event["event"] == "request_failed"]
        self.assertEqual({"lt_1k", "ge_512k"} - {e["input_tokens_bucket"] for e in failed}, {"lt_1k"})
        errors = [event for event in events if event["event"] == "worker_error"]
        self.assertTrue(all(event["exception"] is None for event in errors), errors)


class SupervisionTests(unittest.TestCase):
    """run_server against a tiny fake server, without the model check."""

    def run_child(self, child_code: str, extra: list[str] | None = None, timeout: float = 20) -> tuple[int, str, str]:
        driver = (
            "import sys, time, importlib.util\n"
            f"spec = importlib.util.spec_from_file_location('wait_for_model', {str(SCRIPT)!r})\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "from pathlib import Path\n"
            "command = [sys.executable, '-c', sys.argv[1], *sys.argv[3:]]\n"
            f"raise SystemExit(m.run_server(command, {REVISION!r}, started=time.monotonic(),"
            " dev_dir=Path(sys.argv[2]), health_interval=0.1))\n"
        )
        with tempfile.TemporaryDirectory() as dev:
            for name in ("nvidia0", "nvidia1", "nvidiactl", "nvidia-uvm"):
                Path(dev, name).touch()
            result = subprocess.run([sys.executable, "-c", driver, child_code, dev, *(extra or [])],
                                    capture_output=True, timeout=timeout)
        return result.returncode, result.stdout.decode(), result.stderr.decode()

    def events(self, stdout: str) -> list[dict]:
        events = [json.loads(line) for line in stdout.splitlines()]
        for event in events:
            assert_contract(self, event)
        return events

    def test_child_output_is_reduced_to_events_and_exit_code(self) -> None:
        m = MARKER
        code = (
            "import sys\n"
            f"print('prompt {m}')\n"
            f"print('Error in request: {m}', file=sys.stderr)\n"
            "print('Traceback (most recent call last):', file=sys.stderr)\n"
            f"print('  File \"{SERVING}\", line 9, in h', file=sys.stderr)\n"
            f"print('    {m}()', file=sys.stderr)\n"
            f"print('ValueError: {m}', file=sys.stderr)\n"
            f"print('[t] INFO:     1.2.3.4:5 - \"POST /v1/{m} HTTP/1.1\" 500', flush=True)\n"
            f"raise RuntimeError('{m}')\n"
        )
        returncode, stdout, stderr = self.run_child(code)
        self.assertEqual(1, returncode)
        self.assertNotIn(m, stdout + stderr)
        events = self.events(stdout)
        self.assertEqual(["request_failed", "worker_error", "worker_exit"], [e["event"] for e in events])
        self.assertEqual("invalid_request", events[0]["error_class"])
        self.assertEqual({"event": "worker_exit", "exit_code": 1, "signal": None}, events[-1])

    def test_killed_child_reports_the_signal(self) -> None:
        code = f"import os, signal; print('{MARKER}', flush=True); os.kill(os.getpid(), signal.SIGKILL)"
        returncode, stdout, stderr = self.run_child(code)
        self.assertNotEqual(0, returncode)
        self.assertNotIn(MARKER, stdout + stderr)
        self.assertEqual([{"event": "worker_exit", "exit_code": None, "signal": "SIGKILL"}], self.events(stdout))

    def test_health_200_emits_worker_ready_once(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        code = (
            "import http.server, sys, threading, time\n"
            "class H(http.server.BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        self.send_response(200 if self.path == '/health' else 404); self.end_headers()\n"
            "    def log_message(self, *a):\n"
            f"        print('{MARKER}', flush=True)\n"
            "s = http.server.HTTPServer(('127.0.0.1', int(sys.argv[2])), H)\n"
            "threading.Thread(target=s.serve_forever, daemon=True).start()\n"
            "time.sleep(1.5)\n"
        )
        returncode, stdout, _stderr = self.run_child(code, ["--port", str(port)])
        self.assertEqual(0, returncode)
        self.assertNotIn(MARKER, stdout)
        events = self.events(stdout)
        self.assertEqual(["worker_ready", "worker_exit"], [e["event"] for e in events])
        self.assertEqual(REVISION, events[0]["model_revision"])
        self.assertEqual(2, events[0]["gpus"])

    def test_server_port_parsing(self) -> None:
        self.assertEqual(30000, wfm.server_port(["python3", "-m", "sglang.launch_server"]))
        self.assertEqual(8000, wfm.server_port(["x", "--port", "8000"]))
        self.assertEqual(8001, wfm.server_port(["x", "--port=8001"]))


if __name__ == "__main__":
    unittest.main()
