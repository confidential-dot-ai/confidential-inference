"""The supervisor reduces private SGLang output to fixed contract events."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
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
    "jit_compile": {"event", "cache", "files"},
}
CACHES = {"flashinfer", "triton", "inductor", "deep_gemm", "sglang_jit", "cuda", "tilelang", "cute_dsl", "tvm_ffi",
          "other"}
# The cache variables a test must not inherit from the machine that runs it.
CACHE_ENV = ("SGLANG_CACHE_DIR", "FLASHINFER_WORKSPACE_BASE", "TRITON_CACHE_DIR", "TRITON_HOME",
             "TORCHINDUCTOR_CACHE_DIR", "DG_JIT_CACHE_DIR", "DJ_JIT_CACHE_DIR", "SGLANG_DG_CACHE_DIR",
             "SGLANG_JIT_CACHE_DIR", "CUDA_CACHE_PATH", "TILELANG_CACHE_DIR", "CUTE_DSL_CACHE_DIR",
             "SGLANG_CUTE_AOT_CACHE_DIR", "TVM_FFI_CACHE_DIR")
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
    if event["event"] == "jit_compile":
        test.assertIn(event["cache"], CACHES)
        test.assertIsInstance(event["files"], int)
        test.assertGreaterEqual(event["files"], 1)
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


class CompileWatcherTests(unittest.TestCase):
    """Run-time kernel compiles after worker_ready are reported (see wait_for_model.py).

    On 2026-11-19 a 67 s FlashInfer JIT compile of the sampling module, on the
    first top-k/top-p request, let the liveness probe kill both staging
    workers. These tests make such a compile visible as a fixed event,
    independent of probe timing.
    """

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.home = Path(os.path.realpath(self._directory.name))
        self.environ = {"HOME": str(self.home), "TMPDIR": str(self.home)}
        self.events: list[dict] = []
        self.watcher = wfm.CompileWatcher(self.emit, lambda: wfm.compile_cache_roots(self.environ))

    def tearDown(self) -> None:
        self._directory.cleanup()

    def emit(self, event: dict) -> None:
        self.assertTrue(wfm.valid_event(event), event)
        assert_contract(self, event)
        self.events.append(event)

    def write(self, relative: str, data: bytes = b"x") -> Path:
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_pod_roots_cover_every_compiler_and_the_sglang_redirect(self) -> None:
        roots = set(wfm.compile_cache_roots({"HOME": "/tmp", "TMPDIR": "/tmp"}))
        real = os.path.realpath("/tmp")
        expected = {
            ("flashinfer", ".cache/sglang/.cache/flashinfer"), ("flashinfer", ".cache/flashinfer"),
            ("triton", ".cache/sglang/triton"), ("triton", ".triton"),
            ("inductor", ".cache/sglang/inductor"),
            ("deep_gemm", ".cache/sglang/deep_gemm"), ("deep_gemm", ".dj"),
            ("sglang_jit", ".cache/sglang/jit"),
            ("cuda", ".cache/sglang/nv"), ("cuda", ".nv/ComputeCache"),
            ("tilelang", ".cache/sglang/tilelang"), ("tilelang", ".tilelang"),
            ("cute_dsl", ".cache/sglang/cute_aot"), ("cute_dsl", "cutlass_python_cache"),
            ("tvm_ffi", ".cache/tvm-ffi"),
            ("other", ".cache/sglang"), ("other", ".cache"),
        }
        self.assertLessEqual({(name, os.path.join(real, path)) for name, path in expected}, roots)
        self.assertEqual(set(wfm.COMPILE_CACHES), {name for name, _path in roots})

    def test_environment_overrides_are_watched(self) -> None:
        environ = {**self.environ, "TRITON_CACHE_DIR": "/x/triton", "FLASHINFER_WORKSPACE_BASE": "/x/fi",
                   "DG_JIT_CACHE_DIR": "/x/dg:/x/dg-readonly", "SGLANG_CACHE_DIR": "~/sgl",
                   "CUDA_CACHE_PATH": "/x/nv", "SGLANG_JIT_CACHE_DIR": "/x/jit"}
        roots = set(wfm.compile_cache_roots(environ))
        for pair in (("triton", "/x/triton"), ("flashinfer", "/x/fi/.cache/flashinfer"), ("deep_gemm", "/x/dg"),
                     ("deep_gemm", "/x/dg-readonly"), ("cuda", "/x/nv"), ("sglang_jit", "/x/jit"),
                     ("triton", f"{self.home}/sgl/triton"), ("other", f"{self.home}/sgl")):
            self.assertIn(pair, roots)

    def test_startup_files_are_the_baseline(self) -> None:
        self.write(".cache/sglang/.cache/flashinfer/0.7.2/100a/cached_ops/norm/norm.so")
        self.write(".cache/sglang/triton/abc/kernel.cubin")
        self.watcher.start()
        self.assertEqual([], self.watcher.check())
        self.assertEqual([], self.events)

    def test_a_file_after_ready_is_one_event_per_cache(self) -> None:
        self.write(".cache/sglang/.cache/flashinfer/0.7.2/100a/cached_ops/norm/norm.so")
        self.watcher.start()
        self.write(".cache/sglang/.cache/flashinfer/0.7.2/100a/cached_ops/sampling/sampling.so")
        self.write(".cache/sglang/.cache/flashinfer/0.7.2/100a/cached_ops/sampling/sampling.cuda.o")
        self.write(".cache/sglang/triton/def/kernel.cubin")
        self.write(".nv/ComputeCache/a/b/0")
        self.watcher.check()
        self.assertEqual([{"event": "jit_compile", "cache": "flashinfer", "files": 2},
                          {"event": "jit_compile", "cache": "triton", "files": 1},
                          {"event": "jit_compile", "cache": "cuda", "files": 1}], self.events)
        self.watcher.check()
        self.assertEqual(3, len(self.events))

    def test_every_cache_name_is_reported_under_its_own_name(self) -> None:
        self.watcher.start()
        paths = {
            "flashinfer": ".cache/flashinfer/cubins/x.cubin", "triton": ".triton/cache/k/k.so",
            "inductor": "torchinductor_uid_1001/ab/c.py", "deep_gemm": ".cache/sglang/deep_gemm/cache/k/k.cubin",
            "sglang_jit": ".cache/sglang/jit/sm100/mod/build-1/mod.so", "cuda": ".cache/sglang/nv/ComputeCache/0",
            "tilelang": ".tilelang/cache/k.so", "cute_dsl": "uid/cutlass_python_cache/k.mlir",
            "tvm_ffi": ".cache/tvm-ffi/m/m.so", "other": ".cache/unknown-compiler/k.bin",
        }
        for path in paths.values():
            self.write(path)
        self.watcher.check()
        self.assertEqual([{"event": "jit_compile", "cache": name, "files": 1} for name in wfm.COMPILE_CACHES],
                         self.events)

    def test_a_cache_hit_touch_is_not_a_compile_but_a_rewrite_is(self) -> None:
        marker = self.write(".cache/sglang/deep_gemm/cache/k.abc/.committed", b"")
        ninja_log = self.write(".cache/sglang/.cache/flashinfer/0.7.2/100a/cached_ops/.ninja_log", b"a\n")
        self.watcher.start()
        os.utime(marker, (time.time() + 100, time.time() + 100))
        self.watcher.check()
        self.assertEqual([], self.events)
        ninja_log.write_bytes(b"a\nb\n")
        self.watcher.check()
        self.assertEqual([{"event": "jit_compile", "cache": "flashinfer", "files": 1}], self.events)

    def test_a_deleted_file_is_not_a_compile(self) -> None:
        old = self.write(".cache/sglang/jit/sm100/mod/build-1/mod.so")
        self.watcher.start()
        old.unlink()
        self.watcher.check()
        self.assertEqual([], self.events)

    def test_events_hold_no_path_or_file_name(self) -> None:
        self.watcher.start()
        self.write(f".cache/sglang/triton/{MARKER}/{MARKER}.cubin")
        self.watcher.check()
        self.assertEqual(1, len(self.events))
        self.assertNotIn(MARKER, json.dumps(self.events))
        self.assertFalse(wfm.valid_event({"event": "jit_compile", "cache": MARKER, "files": 1}))
        self.assertFalse(wfm.valid_event({"event": "jit_compile", "cache": "triton", "files": 0}))
        self.assertFalse(wfm.valid_event({"event": "jit_compile", "cache": "triton", "files": 1, "path": "/x"}))

    def test_a_scan_is_bounded(self) -> None:
        for index in range(5):
            self.write(f".cache/sglang/triton/{index}")
        found = wfm.scan_compile_caches(wfm.compile_cache_roots(self.environ), max_files=3)
        self.assertEqual(3, sum(len(files) for files in found.values()))


class SupervisionTests(unittest.TestCase):
    """run_server against a tiny fake server, without the model check."""

    def run_child(self, child_code: str, extra: list[str] | None = None, timeout: float = 20,
                  home: str | None = None) -> tuple[int, str, str]:
        driver = (
            "import sys, time, importlib.util\n"
            f"spec = importlib.util.spec_from_file_location('wait_for_model', {str(SCRIPT)!r})\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "from pathlib import Path\n"
            "command = [sys.executable, '-c', sys.argv[1], *sys.argv[3:]]\n"
            f"raise SystemExit(m.run_server(command, {REVISION!r}, started=time.monotonic(),"
            " dev_dir=Path(sys.argv[2]), health_interval=0.1, scan_interval=0.1))\n"
        )
        with tempfile.TemporaryDirectory() as dev, tempfile.TemporaryDirectory() as own_home:
            for name in ("nvidia0", "nvidia1", "nvidiactl", "nvidia-uvm"):
                Path(dev, name).touch()
            # The compile watcher lists HOME and TMPDIR: never the caches of this machine.
            env = {key: value for key, value in os.environ.items() if key not in CACHE_ENV}
            env["HOME"] = env["TMPDIR"] = home or own_home
            result = subprocess.run([sys.executable, "-c", driver, child_code, dev, *(extra or [])],
                                    capture_output=True, timeout=timeout, env=env)
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

    def test_a_compile_after_worker_ready_is_reported_once(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        code = (
            "import http.server, os, sys, threading, time\n"
            "home = os.environ['HOME']\n"
            "def put(path):\n"
            "    path = os.path.join(home, path); os.makedirs(os.path.dirname(path), exist_ok=True)\n"
            "    open(path, 'wb').write(b'x')\n"
            "put('.cache/sglang/.cache/flashinfer/0.7.2/100a/cached_ops/norm/norm.so')\n"
            "class H(http.server.BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        self.send_response(200); self.end_headers()\n"
            "    def log_message(self, *a):\n"
            "        pass\n"
            "s = http.server.HTTPServer(('127.0.0.1', int(sys.argv[2])), H)\n"
            "threading.Thread(target=s.serve_forever, daemon=True).start()\n"
            "time.sleep(0.8)\n"
            f"put('.cache/sglang/.cache/flashinfer/0.7.2/100a/cached_ops/{MARKER}/{MARKER}.so')\n"
            "time.sleep(0.8)\n"
        )
        returncode, stdout, _stderr = self.run_child(code, ["--port", str(port)])
        self.assertEqual(0, returncode)
        self.assertNotIn(MARKER, stdout)
        events = self.events(stdout)
        self.assertEqual([{"event": "jit_compile", "cache": "flashinfer", "files": 1}],
                         [event for event in events if event["event"] == "jit_compile"])
        self.assertEqual(["worker_ready", "jit_compile", "worker_exit"], [e["event"] for e in events])

    def test_server_port_parsing(self) -> None:
        self.assertEqual(30000, wfm.server_port(["python3", "-m", "sglang.launch_server"]))
        self.assertEqual(8000, wfm.server_port(["x", "--port", "8000"]))
        self.assertEqual(8001, wfm.server_port(["x", "--port=8001"]))


if __name__ == "__main__":
    unittest.main()
