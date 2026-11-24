#!/usr/bin/env python3
"""Wait for a verified model mount (c8s dm-verity volume or plain cache), then supervise the server process."""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import errno
import glob
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Iterator, Mapping

# Every model file is hashed before the server starts. Hashing threads release
# the GIL inside hashlib, so parallel reads keep a large volume's check short.
HASH_WORKERS = max(1, min(16, os.cpu_count() or 1))
HASH_BLOCK_BYTES = 8 * 1024 * 1024
PROGRESS_STEP = 0.1


class ModelMountError(ValueError):
    """The model mount does not match the release contract."""


class MountUnavailable(ModelMountError):
    """The c8s sidecar has not propagated the model mount yet."""


def decode_mount_path(value: str) -> str:
    for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(encoded, decoded)
    return value


def mount_record(path: Path, mountinfo: Path) -> tuple[set[str], str, str, set[str]] | None:
    target = str(path.resolve())
    active = None
    for line in mountinfo.read_text(encoding="utf-8").splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        fields = left.split()
        after = right.split()
        if len(fields) < 6 or len(after) < 3:
            continue
        if decode_mount_path(fields[4]) == target:
            # Linux lists a later mount over the earlier mount at the same
            # target. c8s overlays its EROFS mapper over Kubernetes emptyDir.
            active = (
                set(fields[5].split(",")),
                after[0],
                after[1],
                set(after[2].split(",")),
            )
    return active


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(HASH_BLOCK_BYTES), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_expected_file(value: str) -> tuple[str, str]:
    name, separator, digest = value.partition("=")
    if not separator or not name or name.startswith("/") or ".." in Path(name).parts:
        raise argparse.ArgumentTypeError("an expected file must use RELATIVE_PATH=SHA256")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise argparse.ArgumentTypeError("an expected file needs a lowercase SHA-256 value")
    return name, digest


def verify_revision(
    path: Path,
    metadata_name: str,
    repository: str,
    expected: str,
    expected_files: dict[str, str],
) -> dict[str, tuple[str, int]]:
    metadata = path / metadata_name
    try:
        value = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError) as error:
        raise ModelMountError("the model revision manifest is invalid") from error
    expected_keys = {
        "canonical_local_manifest_sha256", "classification", "files", "immutable_ref",
        "immutable_revision", "repository", "schema", "source_remote_inventory_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ModelMountError("the model revision manifest has invalid fields")
    if value["schema"] != "confidential-benchmark/local-model-byte-manifest/v1":
        raise ModelMountError("the model revision manifest has an invalid schema")
    if value["classification"] != "verified_local_snapshot_bytes":
        raise ModelMountError("the model revision manifest has an invalid classification")
    if value["repository"] != repository or value["immutable_revision"] != expected:
        raise ModelMountError("the model revision manifest does not match the release")
    if value["immutable_ref"] != f"{repository}@{expected}":
        raise ModelMountError("the model revision manifest reference does not match the release")
    if not isinstance(value["files"], list) or not value["files"]:
        raise ModelMountError("the model revision manifest has no file inventory")
    for digest_name in ("canonical_local_manifest_sha256", "source_remote_inventory_sha256"):
        digest = value[digest_name]
        if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ModelMountError("the model revision manifest has an invalid digest")
    inventory = {}
    for item in value["files"]:
        if not isinstance(item, dict) or set(item) != {"content_sha256", "path", "size"}:
            raise ModelMountError("the model revision manifest has an invalid file record")
        name = item["path"]
        digest = item["content_sha256"]
        size = item["size"]
        if (
            not isinstance(name, str) or not name or name.startswith("/") or ".." in Path(name).parts
            or name in inventory or not isinstance(size, int) or size < 1
            or not isinstance(digest, str) or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ModelMountError("the model revision manifest has an invalid file record")
        inventory[name] = (digest, size)
    for name, expected_digest in expected_files.items():
        if name == metadata_name:
            continue
        if inventory.get(name) != (expected_digest, (path / name).stat().st_size):
            raise ModelMountError("the model revision manifest file inventory does not match the release")
    if metadata_name in inventory:
        raise ModelMountError("the model revision manifest lists itself")
    return inventory


def list_model_files(path: Path) -> set[str]:
    """List every regular file below the mount. Anything else fails closed."""
    found = set()
    for directory, directories, files in os.walk(path, followlinks=False):
        base = Path(directory)
        for name in directories:
            if (base / name).is_symlink():
                raise ModelMountError(f"the model volume contains a symbolic link: {(base / name).relative_to(path)}")
        for name in files:
            candidate = base / name
            relative = str(candidate.relative_to(path))
            if candidate.is_symlink() or not candidate.is_file():
                raise ModelMountError(f"the model volume contains a non-regular file: {relative}")
            found.add(relative)
    return found


def verify_every_file(path: Path, metadata_name: str, inventory: dict[str, tuple[str, int]]) -> None:
    """Check every file on the volume against the pinned byte manifest.

    The manifest is trusted because its own SHA-256 is pinned in the
    release argv. A file that is missing, extra, of the wrong size, or of the
    wrong digest stops the worker before the server reads any weight.
    """
    found = list_model_files(path)
    expected = set(inventory) | {metadata_name}
    missing = sorted(expected - found)
    if missing:
        raise ModelMountError(f"the model volume is missing a manifest file: {missing[0]}")
    extra = sorted(found - expected)
    if extra:
        raise ModelMountError(f"the model volume contains a file the manifest does not list: {extra[0]}")
    for name, (_digest, size) in inventory.items():
        if (path / name).stat().st_size != size:
            raise ModelMountError(f"the model file has the wrong size: {name}")
    total = sum(size for _digest, size in inventory.values())
    done = 0
    next_report = PROGRESS_STEP
    started = time.monotonic()
    print(
        f"model-mount: hashing {len(inventory)} files, {total} bytes, with {HASH_WORKERS} threads",
        file=sys.stderr,
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=HASH_WORKERS) as pool:
        # Largest files first, so the slowest hash does not start last.
        order = sorted(inventory, key=lambda name: inventory[name][1], reverse=True)
        futures = {pool.submit(sha256_file, path / name): name for name in order}
        try:
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                if future.result() != inventory[name][0]:
                    raise ModelMountError(f"the model file has the wrong digest: {name}")
                done += inventory[name][1]
                if total and done / total >= next_report:
                    print(
                        f"model-mount: hashed {done * 100 // total}% "
                        f"in {time.monotonic() - started:.0f}s",
                        file=sys.stderr,
                    )
                    while next_report <= done / total:
                        next_report += PROGRESS_STEP
        except BaseException:
            for future in futures:
                future.cancel()
            raise
    print(
        f"model-mount: every model file matches the manifest ({time.monotonic() - started:.0f}s)",
        file=sys.stderr,
    )


def verify_index(path: Path) -> None:
    """Check the shard index, or the one weight file of an unsharded model."""
    index = path / "model.safetensors.index.json"
    if not os.path.lexists(index):
        single = path / "model.safetensors"
        if single.is_symlink() or not single.is_file() or single.stat().st_size == 0:
            raise ModelMountError("the model has no index and no single model.safetensors file")
        return
    try:
        value = json.loads(index.read_text(encoding="utf-8"))
        weight_map = value["weight_map"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ModelMountError("the model index is invalid") from error
    if not isinstance(weight_map, dict) or not weight_map:
        raise ModelMountError("the model index has no weights")
    shards = set(weight_map.values())
    if any(not isinstance(name, str) or Path(name).name != name for name in shards):
        raise ModelMountError("the model index contains an invalid shard name")
    missing = [name for name in sorted(shards) if not (path / name).is_file() or (path / name).stat().st_size == 0]
    if missing:
        raise ModelMountError(f"the model index references a missing shard: {missing[0]}")


def verify_no_write(path: Path) -> None:
    probe = path / f".c8s-write-probe-{os.getpid()}"
    try:
        descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        if error.errno in {errno.EROFS, errno.EACCES, errno.EPERM}:
            return
        raise ModelMountError(f"the write probe failed unexpectedly: {error}") from error
    else:
        os.close(descriptor)
        probe.unlink(missing_ok=True)
        raise ModelMountError("the model mount permits writes")


def verify_once(args: argparse.Namespace) -> None:
    path = args.path.resolve()
    record = mount_record(path, args.mountinfo)
    if record is None:
        raise MountUnavailable("the model path is not a mount point")
    _mount_options, _filesystem, source, _super_options = record
    # Kubernetes can hide the host filesystem type and report rw flags for a
    # read-only c8s bind mount. Require the c8s dm-verity source and a failed
    # write probe. These are the actual integrity and write-protection checks.
    # A plain cache (public weights on a host-readable disk) has no dm-verity
    # source: its integrity is the full byte check below, on every start.
    if not args.plain_cache and "c8s-verity-" not in source:
        raise MountUnavailable(
            "the c8s dm-verity mapping is not attached yet "
            f"(filesystem={_filesystem}, source={source})"
        )
    verify_no_write(path)
    for name, expected in args.expected_file:
        candidate = path / name
        if not candidate.is_file():
            raise ModelMountError(f"the required model file is missing: {name}")
        if sha256_file(candidate) != expected:
            raise ModelMountError(f"the required model file has the wrong digest: {name}")
    expected_files = dict(args.expected_file)
    if args.revision_metadata not in expected_files:
        raise ModelMountError("the release does not pin the model byte manifest digest")
    inventory = verify_revision(
        path,
        args.revision_metadata,
        args.expected_repository,
        args.expected_revision,
        expected_files,
    )
    verify_index(path)
    verify_every_file(path, args.revision_metadata, inventory)


# ---------------------------------------------------------------------------
# Private server output.
#
# SGLang output can hold prompt text, response text and exception messages.
# The supervisor reads that output through a pipe, in memory only. It never
# writes it to stdout, stderr or disk. It writes only the fixed JSON events
# below to its own stdout. The node log agent keeps these events and fields
# and drops everything else.
# ---------------------------------------------------------------------------

EVENT_MAX_BYTES = 4096
LINE_MAX_BYTES = 64 * 1024
FRAMES_MAX = 256
QUEUE_MAX = 64
CORRELATION_SECONDS = 5.0
PENDING_TRACEBACK_SECONDS = 1.0
HEALTH_INTERVAL_SECONDS = 2.0
DEFAULT_SERVER_PORT = 30000

ERROR_CLASSES = frozenset({
    "invalid_request", "not_found", "request_too_large", "overloaded", "unavailable", "timeout",
    "client_error", "connection_error", "aborted", "internal_assertion", "unclassified",
})
PHASES = frozenset({"http", "tokenize", "schedule", "model", "unknown"})
TOKEN_BUCKETS = ("lt_1k", "1k_8k", "8k_32k", "32k_128k", "128k_512k", "ge_512k")
TOKEN_BUCKET_LIMITS = (1024, 8 * 1024, 32 * 1024, 128 * 1024, 512 * 1024)

CUDA_TEXT_CODES = (
    ("illegal memory access", "cudaErrorIllegalAddress"),
    ("device-side assert", "cudaErrorAssert"),
    ("unspecified launch failure", "cudaErrorLaunchFailure"),
    ("illegal instruction", "cudaErrorIllegalInstruction"),
    ("misaligned address", "cudaErrorMisalignedAddress"),
    ("uncorrectable ecc", "cudaErrorECCUncorrectable"),
    ("no cuda-capable device", "cudaErrorNoDevice"),
    ("driver version is insufficient", "cudaErrorInsufficientDriver"),
    ("launch timed out", "cudaErrorLaunchTimeout"),
)
# Only real CUDA runtime names pass. An arbitrary "cudaErrorXyz" token in a
# prompt line must not become an exported value.
CUDA_CODES = frozenset({code for _text, code in CUDA_TEXT_CODES} | {
    "cudaErrorInvalidValue", "cudaErrorMemoryAllocation", "cudaErrorInitializationError",
    "cudaErrorCudartUnloading", "cudaErrorInvalidConfiguration", "cudaErrorInvalidDevice",
    "cudaErrorInvalidDeviceFunction", "cudaErrorInvalidResourceHandle", "cudaErrorNotReady",
    "cudaErrorLaunchOutOfResources", "cudaErrorNoKernelImageForDevice", "cudaErrorDevicesUnavailable",
    "cudaErrorHardwareStackError", "cudaErrorInvalidPc", "cudaErrorIllegalState",
    "cudaErrorNotPermitted", "cudaErrorNotSupported", "cudaErrorSystemNotReady",
    "cudaErrorSystemDriverMismatch", "cudaErrorStreamCaptureUnsupported", "cudaErrorUnknown",
    "cudaErrorPeerAccessUnsupported", "cudaErrorInvalidPtx", "cudaErrorNvlinkUncorrectable",
    "cudaErrorJitCompilerNotFound", "cudaErrorUnsupportedPtxVersion", "cudaErrorContextIsDestroyed",
    "cudaErrorCooperativeLaunchTooLarge", "cudaErrorTimeout", "cudaErrorDeviceUninitialized",
})
NCCL_TEXT_CODES = (
    ("unhandled cuda error", "ncclUnhandledCudaError"),
    ("unhandled system error", "ncclSystemError"),
    ("internal error", "ncclInternalError"),
    ("invalid argument", "ncclInvalidArgument"),
    ("invalid usage", "ncclInvalidUsage"),
    ("remote process exited or there was a network error", "ncclRemoteError"),
)
NCCL_CODES = frozenset({code for _text, code in NCCL_TEXT_CODES} | {"ncclInProgress"})

EVENT_KEYS = {
    "worker_ready": frozenset({"event", "model_revision", "gpus", "load_seconds"}),
    "request_failed": frozenset({
        "event", "error_class", "http_status", "phase", "input_tokens_bucket",
        "duration_ms", "exception", "location",
    }),
    "gpu_oom": frozenset({"event", "location"}),
    "cuda_error": frozenset({"event", "code", "location"}),
    "nccl_error": frozenset({"event", "code", "location"}),
    "worker_error": frozenset({"event", "error_class", "exception", "location"}),
    "worker_exit": frozenset({"event", "exit_code", "signal"}),
    "jit_compile": frozenset({"event", "cache", "files"}),
}

EXCEPTION_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,95}")
LOCATION_PATTERN = re.compile(r"sglang(_simulator)?/[A-Za-z0-9_/.-]{1,150}[.]py:[0-9]{1,7}")
ERROR_CLASS_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,47}")
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
SIGNAL_PATTERN = re.compile(r"SIG[A-Z0-9]{1,12}")

LINE_PREFIX = re.compile(r"\[[^\]\n]{1,128}\]\s?")
TRACEBACK_START = "Traceback (most recent call last):"
CHAIN_MARKERS = (
    "During handling of the above exception, another exception occurred:",
    "The above exception was the direct cause of the following exception:",
)
FRAME_PATTERN = re.compile(r"[ \t|+]*File \"(?P<file>[^\"]{1,4096})\", line (?P<line>[0-9]{1,7})")
EXCEPTION_LINE = re.compile(r"(?P<type>[A-Za-z_][A-Za-z0-9_.]{0,95})(?::(?: |$)|$)")
ACCESS_LOG = re.compile(r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/[0-9.]+" (?P<status>[1-5][0-9]{2})')
IGNORED_PATHS = ("/health", "/metrics", "/readiness")
INPUT_TOKENS = re.compile(r"The input \((?P<tokens>[0-9]{1,12}) tokens\) is longer than")
CUDA_TOKEN = re.compile(r"cudaError[A-Za-z]+")
NCCL_TOKEN = re.compile(r"nccl[A-Z][A-Za-z]+")
# The last name part a real exception type ends with. A free-text line that
# only looks like "Word: text" does not become an exported type.
EXCEPTION_SUFFIXES = ("Error", "Exception", "Interrupt", "Exit", "Warning", "Iteration", "Failure", "Timeout")


def valid_event(event: object) -> bool:
    """Return True only for an event that matches the exported contract exactly."""
    if not isinstance(event, dict):
        return False
    name = event.get("event")
    if name not in EVENT_KEYS or set(event) != EVENT_KEYS[name]:
        return False

    def nullable(value: object, pattern: re.Pattern[str]) -> bool:
        return value is None or (isinstance(value, str) and pattern.fullmatch(value) is not None)

    def integer(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    if name == "worker_ready":
        return (
            isinstance(event["model_revision"], str) and REVISION_PATTERN.fullmatch(event["model_revision"]) is not None
            and integer(event["gpus"]) and 0 <= event["gpus"] <= 1024
            and integer(event["load_seconds"]) and event["load_seconds"] >= 0
        )
    if name == "request_failed":
        status = event["http_status"]
        return (
            event["error_class"] in ERROR_CLASSES
            and (status is None or (integer(status) and 100 <= status <= 599))
            and event["phase"] in PHASES
            and event["input_tokens_bucket"] in ("unknown", *TOKEN_BUCKETS)
            and (event["duration_ms"] is None or (integer(event["duration_ms"]) and event["duration_ms"] >= 0))
            and nullable(event["exception"], EXCEPTION_PATTERN)
            and nullable(event["location"], LOCATION_PATTERN)
        )
    if name == "gpu_oom":
        return nullable(event["location"], LOCATION_PATTERN)
    if name == "cuda_error":
        return (event["code"] in CUDA_CODES or event["code"] == "unknown") and nullable(event["location"], LOCATION_PATTERN)
    if name == "nccl_error":
        return (event["code"] in NCCL_CODES or event["code"] in ("timeout", "unknown")) and nullable(
            event["location"], LOCATION_PATTERN)
    if name == "worker_error":
        return (
            event["error_class"] in ERROR_CLASSES
            and nullable(event["exception"], EXCEPTION_PATTERN)
            and nullable(event["location"], LOCATION_PATTERN)
        )
    if name == "jit_compile":
        return event["cache"] in COMPILE_CACHES and integer(event["files"]) and event["files"] >= 1
    exit_code, signal_name = event["exit_code"], event["signal"]
    return (
        (exit_code is None or (integer(exit_code) and -255 <= exit_code <= 255))
        and nullable(signal_name, SIGNAL_PATTERN)
    )


class NonblockingStdout:
    """Write one bounded record to a container pipe without waiting for readers.

    The caller must review the schema. This is not a content filter. A full
    pipe drops that record. This is the same writer design as the sglang-router
    private log sink, copied here so the worker image needs no extra module.
    """

    def __init__(self, fd: int = 1) -> None:
        self.fd = fd
        self.dropped = 0
        self.lock = threading.Lock()
        os.set_blocking(fd, False)

    def write(self, record: dict) -> bool:
        payload = (json.dumps(record, separators=(",", ":")) + "\n").encode()
        # Linux pipe writes at or below PIPE_BUF are atomic. A full pipe must
        # never leave half a JSON line or block the supervisor.
        with self.lock:
            if len(payload) > EVENT_MAX_BYTES:
                self.dropped += 1
                return False
            try:
                written = os.write(self.fd, payload) == len(payload)
            except OSError:
                written = False
            if not written:
                self.dropped += 1
            return written


def exception_name(type_name: str | None) -> str | None:
    if not type_name or EXCEPTION_PATTERN.fullmatch(type_name) is None:
        return None
    if not type_name.rsplit(".", 1)[-1].endswith(EXCEPTION_SUFFIXES):
        return None
    return type_name


def error_class_for(exception: str | None) -> str:
    short = (exception or "").rsplit(".", 1)[-1]
    if short == "ValueError":
        return "invalid_request"
    if short == "TimeoutError":
        return "timeout"
    if short in {"ConnectionError", "ConnectionResetError", "ConnectionRefusedError",
                 "ConnectionAbortedError", "BrokenPipeError"}:
        return "connection_error"
    if short == "CancelledError":
        return "aborted"
    if short == "AssertionError":
        return "internal_assertion"
    return "unclassified"


def error_class_for_status(status: int) -> str:
    known = {400: "invalid_request", 404: "not_found", 413: "request_too_large", 429: "overloaded",
             503: "unavailable", 504: "timeout"}
    if status in known:
        return known[status]
    return "client_error" if status < 500 else "unclassified"


def sglang_location(frames: Iterable[tuple[str, int]]) -> str | None:
    """Return "sglang/.../file.py:line" for the last SGLang frame, or None."""
    for filename, line in reversed(list(frames)):
        index = max(filename.rfind("/sglang/"), filename.rfind("/sglang_simulator/"))
        if index < 0:
            continue
        location = f"{filename[index + 1:]}:{line}"
        if filename.endswith(".py") and LOCATION_PATTERN.fullmatch(location):
            return location
        return None
    return None


def phase_for(location: str | None) -> str:
    if location is None:
        return "unknown"
    path = location.rsplit(":", 1)[0]
    base = path.rsplit("/", 1)[-1]
    if "tokenizer_manager" in base or base.startswith("serving_") or "http_server" in base:
        return "tokenize"
    if base.startswith("scheduler"):
        return "schedule"
    if any(f"/{part}/" in f"/{path}" for part in ("model_executor", "layers", "models")):
        return "model"
    return "unknown"


def is_request_frame(filename: str) -> bool:
    return "/sglang/srt/entrypoints/" in filename or "/sglang/srt/managers/tokenizer_manager" in filename


def tokens_bucket(tokens: int) -> str:
    for limit, bucket in zip(TOKEN_BUCKET_LIMITS, TOKEN_BUCKETS):
        if tokens < limit:
            return bucket
    return TOKEN_BUCKETS[-1]


def cuda_code(text: str) -> str:
    for token in CUDA_TOKEN.findall(text):
        if token in CUDA_CODES:
            return token
    lowered = text.lower()
    for needle, code in CUDA_TEXT_CODES:
        if needle in lowered:
            return code
    return "unknown"


def nccl_code(text: str) -> str:
    for token in NCCL_TOKEN.findall(text):
        if token in NCCL_CODES:
            return token
    lowered = text.lower()
    if "watchdog caught collective operation timeout" in lowered or (
            "watchdog" in lowered and "timeout" in lowered):
        return "timeout"
    for needle, code in NCCL_TEXT_CODES:
        if needle in lowered:
            return code
    return "unknown"


def hardware_kind(text: str, exception: str | None) -> str | None:
    """Classify one line, or a traceback's final line, as gpu_oom, nccl_error or cuda_error."""
    short = (exception or "").rsplit(".", 1)[-1]
    if "CUDA out of memory" in text or short == "OutOfMemoryError":
        return "gpu_oom"
    if (short == "DistBackendError" or "NCCL error" in text or "Watchdog caught collective operation timeout" in text
            or any(token in NCCL_CODES for token in NCCL_TOKEN.findall(text))):
        return "nccl_error"
    if "CUDA error:" in text or "CUDA driver version is insufficient" in text:
        return "cuda_error"
    return None


def hardware_event(kind: str, text: str, location: str | None) -> dict:
    if kind == "gpu_oom":
        return {"event": "gpu_oom", "location": location}
    code = nccl_code(text) if kind == "nccl_error" else cuda_code(text)
    return {"event": kind, "code": code, "location": location}


class _Traceback:
    __slots__ = ("frames", "request", "exception", "kind", "started")

    def __init__(self, request: bool, started: float) -> None:
        self.frames: collections.deque[tuple[str, int]] = collections.deque(maxlen=FRAMES_MAX)
        self.request = request
        self.exception: str | None = None
        self.kind: dict | None = None
        self.started = started


class OutputClassifier:
    """Reduce SGLang output lines to contract events.

    feed() takes one decoded line. Events go to emit(event). Nothing from a
    line is kept except fixed enum values, exception type names that pass
    EXCEPTION_PATTERN, SGLang source locations, integers and timestamps.
    Every buffer is bounded. The class is not thread-safe; the caller locks.
    """

    def __init__(self, emit: Callable[[dict], object], clock: Callable[[], float] = time.monotonic) -> None:
        self._emit = emit
        self._clock = clock
        self._block: _Traceback | None = None
        self._pending: _Traceback | None = None
        self._pending_at = 0.0
        self._chained = False
        self._request_hint_at: float | None = None
        # (time, error_class, exception, location, phase) of request errors not yet matched to an access-log line.
        self._request_errors: collections.deque[tuple[float, str, str | None, str | None, str]] = (
            collections.deque(maxlen=QUEUE_MAX))
        self._input_tokens: collections.deque[tuple[float, str]] = collections.deque(maxlen=QUEUE_MAX)
        self._recent_hardware: collections.deque[tuple[float, str, str]] = collections.deque(maxlen=QUEUE_MAX)

    # -- public ---------------------------------------------------------------

    def feed(self, raw: str) -> None:
        now = self._clock()
        self._expire(now)
        line = raw.rstrip("\r\n")
        stripped = LINE_PREFIX.sub("", line, count=1) if line.startswith("[") else line
        if self._block is not None:
            self._feed_block(line, stripped, now)
            return
        if TRACEBACK_START in stripped:
            self._start_block(stripped, now)
            return
        if not stripped.strip():
            return
        if self._pending is not None:
            if any(marker in stripped for marker in CHAIN_MARKERS):
                self._chained = True
                return
            self._flush_pending()
        self._plain_line(stripped, now)

    def tick(self) -> None:
        now = self._clock()
        if self._pending is not None and now - self._pending_at >= PENDING_TRACEBACK_SECONDS:
            self._flush_pending()
        self._expire(now)

    def finish(self) -> None:
        """Flush every held record at the end of the output stream."""
        if self._block is not None:
            # The stream ended inside a traceback: classify what is known.
            self._pending, self._block = self._block, None
        self._flush_pending()
        self._expire(float("inf"))

    # -- internals -------------------------------------------------------------

    def _out(self, event: dict) -> None:
        if valid_event(event):
            self._emit(event)

    def _start_block(self, stripped: str, now: float) -> None:
        request = self._request_hint_at is not None and now - self._request_hint_at <= CORRELATION_SECONDS
        if "Error in request" in stripped:
            request = True
        self._request_hint_at = None
        if self._pending is not None:
            if self._chained:
                request = request or self._pending.request
                self._pending = None
            else:
                self._flush_pending()
        self._chained = False
        self._block = _Traceback(request, now)

    def _feed_block(self, line: str, stripped: str, now: float) -> None:
        block = self._block
        assert block is not None
        if line[:1] in (" ", "\t") or not line.strip():
            match = FRAME_PATTERN.match(line)
            if match:
                block.frames.append((match["file"], int(match["line"])))
            return
        if ACCESS_LOG.search(stripped):
            # Another thread's access-log line between traceback lines.
            self._access_line(stripped, now)
            return
        if TRACEBACK_START in stripped:
            self._block = None
            self._start_block(stripped, now)
            return
        match = EXCEPTION_LINE.match(stripped)
        block.exception = exception_name(match["type"]) if match else None
        kind = hardware_kind(stripped, block.exception)
        if kind is not None:
            block.kind = hardware_event(kind, stripped, None)
        self._note_input_tokens(stripped, now)
        self._block = None
        self._pending, self._pending_at, self._chained = block, now, False

    def _flush_pending(self) -> None:
        block, self._pending, self._chained = self._pending, None, False
        if block is None:
            return
        location = sglang_location(block.frames)
        if block.kind is not None:
            event = dict(block.kind)
            event["location"] = location
            self._out(event)
            self._recent_hardware.append((self._clock(), event["event"], event.get("code", "")))
            return
        error_class = error_class_for(block.exception)
        if block.request or any(is_request_frame(name) for name, _line in block.frames):
            self._request_errors.append((block.started, error_class, block.exception, location, phase_for(location)))
            return
        self._out({"event": "worker_error", "error_class": error_class, "exception": block.exception,
                   "location": location})

    def _plain_line(self, stripped: str, now: float) -> None:
        if "Error in request" in stripped:
            self._request_hint_at = now
        self._note_input_tokens(stripped, now)
        if ACCESS_LOG.search(stripped):
            self._access_line(stripped, now)
            return
        kind = hardware_kind(stripped, None)
        if kind is None:
            return
        event = hardware_event(kind, stripped, None)
        key = (event["event"], event.get("code", ""))
        if any(name == key[0] and code == key[1] and now - at <= CORRELATION_SECONDS
               for at, name, code in self._recent_hardware):
            return
        self._recent_hardware.append((now, key[0], key[1]))
        self._out(event)

    def _note_input_tokens(self, stripped: str, now: float) -> None:
        match = INPUT_TOKENS.search(stripped)
        if match:
            self._input_tokens.append((now, tokens_bucket(int(match["tokens"]))))

    def _access_line(self, stripped: str, now: float) -> None:
        match = ACCESS_LOG.search(stripped)
        assert match is not None
        status = int(match["status"])
        if status < 400 or match["path"].startswith(IGNORED_PATHS):
            return
        # A request traceback is logged before its response line.
        self._flush_pending()
        self._expire(now)
        bucket = self._input_tokens.popleft()[1] if self._input_tokens else "unknown"
        if self._request_errors:
            _at, error_class, exception, location, phase = self._request_errors.popleft()
        else:
            error_class, exception, location, phase = error_class_for_status(status), None, None, "http"
        self._out({
            "event": "request_failed", "error_class": error_class, "http_status": status, "phase": phase,
            "input_tokens_bucket": bucket, "duration_ms": None, "exception": exception, "location": location,
        })

    def _expire(self, now: float) -> None:
        while self._request_errors and now - self._request_errors[0][0] > CORRELATION_SECONDS:
            # No response line claimed this traceback: report it as a worker error.
            _at, error_class, exception, location, _phase = self._request_errors.popleft()
            self._out({"event": "worker_error", "error_class": error_class, "exception": exception,
                       "location": location})
        while self._input_tokens and now - self._input_tokens[0][0] > CORRELATION_SECONDS:
            self._input_tokens.popleft()
        while self._recent_hardware and now - self._recent_hardware[0][0] > CORRELATION_SECONDS:
            self._recent_hardware.popleft()


def classify_lines(lines: Iterable[str], clock: Callable[[], float] | None = None) -> list[dict]:
    """Classify a finished list of lines and return the events (for tests and tools)."""
    events: list[dict] = []
    classifier = OutputClassifier(events.append, clock or (lambda: 0.0))
    for line in lines:
        classifier.feed(line)
    classifier.finish()
    return events


def bounded_lines(stream: BinaryIO) -> Iterator[str]:
    """Yield decoded lines of at most LINE_MAX_BYTES; the rest of a longer line is discarded."""
    while True:
        chunk = stream.readline(LINE_MAX_BYTES)
        if not chunk:
            return
        if not chunk.endswith(b"\n") and len(chunk) >= LINE_MAX_BYTES:
            while True:
                rest = stream.readline(LINE_MAX_BYTES)
                if not rest or rest.endswith(b"\n"):
                    break
        yield chunk.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Run-time kernel compilation.
#
# Why this exists: on 2026-11-19 the staging deployment staging-826711f4bd9d
# failed validation. The first request with top-k/top-p sampling made each
# Qwen3.5 worker JIT-compile FlashInfer's sampling module (about 67 s) inside
# the SGLang scheduler. During the compile, /health (a 1-token generation)
# could not answer. The liveness probe (30 s period, 3 failures) killed both
# workers mid-compile, and every request returned 503. An earlier run that
# passed had the same 67 s stall on each worker; it passed only because the
# probe timing landed later. The 2026-11-06 production incident had the same
# cause. A kernel compiled at run time is also not part of the measured
# (attested) image.
#
# So the supervisor reports every compile after worker_ready, by any
# compiler, without depending on timing. Startup compiles (before
# worker_ready, under the startup probe) are the baseline and are not
# reported. Every SCAN_SECONDS it lists the cache directories of each
# compiler in the image and compares file names and sizes. It reads no file
# content. The event names a cache from COMPILE_CACHES and a file count. It
# holds no path and no file name: a kernel file name can encode request
# shapes.
#
# Where each compiler writes. HOME is /tmp in the pod (chart and Dockerfile).
# SGLang's package __init__ (sglang/__init__.py, sglang.srt.environ
# redirect_third_party_caches) sets, when unset, TRITON_CACHE_DIR,
# TORCHINDUCTOR_CACHE_DIR, CUDA_CACHE_PATH, TILELANG_CACHE_DIR and
# FLASHINFER_WORKSPACE_BASE below SGLANG_CACHE_DIR (default ~/.cache/sglang).
# The supervisor does not import SGLang, so it watches both that redirect and
# each library's own default:
#
# - flashinfer: <FLASHINFER_WORKSPACE_BASE or ~>/.cache/flashinfer
#   (flashinfer/jit/env.py, 0.7.2). The cubins/ folder there is a run-time
#   download, which is also unmeasured code.
# - triton: TRITON_CACHE_DIR, else <TRITON_HOME or ~>/.triton (triton
#   knobs.py: .triton/cache; tokenspeed-triton: .triton/tokenspeed-cache).
# - inductor: TORCHINDUCTOR_CACHE_DIR, else <tmp>/torchinductor_<user>
#   (torch/_inductor/runtime/cache_dir_utils.py).
# - deep_gemm: DG_JIT_CACHE_DIR (a PATH-style list; SGLang sets it to
#   SGLANG_DG_CACHE_DIR, default <SGLANG_CACHE_DIR>/deep_gemm), else
#   DJ_JIT_CACHE_DIR, else ~/.dj (deep_jit/cache/disk.hpp, sgl-deep-gemm 0.2.3).
# - sglang_jit: SGLANG_JIT_CACHE_DIR, else ~/.cache/sglang/jit
#   (sglang/kernels/jit/utils/compile/cache.py cache_root).
# - cuda: the driver's PTX JIT cache, CUDA_CACHE_PATH, else ~/.nv/ComputeCache.
# - tilelang: TILELANG_CACHE_DIR, else ~/.tilelang (tilelang/env.py).
# - cute_dsl: CUTE_DSL_CACHE_DIR, else <tmp>/<user>/cutlass_python_cache or
#   <tmp>/cutlass_python_cache (cutlass/base_dsl/cache_helpers.py), and
#   SGLang's SGLANG_CUTE_AOT_CACHE_DIR (default <SGLANG_CACHE_DIR>/cute_aot).
# - tvm_ffi: TVM_FFI_CACHE_DIR, else ~/.cache/tvm-ffi (tvm_ffi/cpp/extension.py).
# - other: any other file below SGLANG_CACHE_DIR or ~/.cache, so that a
#   compiler not named here is still seen.
#
# A file belongs to the most specific watched directory that holds it.
# Only a new file name or a changed size counts. A changed mtime alone does
# not: SGLang's JIT cache and DeepGEMM touch an entry on every cache hit.
# A compile that only NVRTC or the driver does in memory leaves no file;
# FLASHINFER_DISABLE_JIT=1 (chart value inference.flashinferDisableJit) and
# a startup that loads every kernel close that gap for FlashInfer.
# ---------------------------------------------------------------------------

COMPILE_CACHES = ("flashinfer", "triton", "inductor", "deep_gemm", "sglang_jit", "cuda", "tilelang",
                  "cute_dsl", "tvm_ffi", "other")
SCAN_SECONDS = 5.0
# A scan stops after this many files. The pod caches hold far fewer.
SCAN_MAX_FILES = 200_000


def compile_cache_roots(environ: Mapping[str, str]) -> list[tuple[str, str]]:
    """Return (cache name, directory) pairs to watch, the named caches before `other`.

    Globs are expanded on every call, so a directory that a compiler creates
    after worker_ready is found on the next scan.
    """
    home = environ.get("HOME") or os.path.expanduser("~")
    tmp = environ.get("TMPDIR") or "/tmp"

    def user(path: str) -> str:
        return path if not path.startswith("~") else home + path[1:]

    def env(name: str) -> list[str]:
        value = environ.get(name)
        return [user(value)] if value else []

    sglang = user(environ.get("SGLANG_CACHE_DIR") or "~/.cache/sglang")
    deep_gemm = [user(item) for name in ("DG_JIT_CACHE_DIR", "DJ_JIT_CACHE_DIR")
                 for item in (environ.get(name) or "").split(":") if item]
    roots = {
        "flashinfer": [os.path.join(base, ".cache", "flashinfer")
                       for base in [*env("FLASHINFER_WORKSPACE_BASE"), sglang, home]],
        "triton": [*env("TRITON_CACHE_DIR"), os.path.join(sglang, "triton"),
                   os.path.join(user(environ.get("TRITON_HOME") or home), ".triton")],
        "inductor": [*env("TORCHINDUCTOR_CACHE_DIR"), os.path.join(sglang, "inductor"),
                     *sorted(glob_dirs(os.path.join(tmp, "torchinductor_*")))],
        "deep_gemm": [*deep_gemm, *env("SGLANG_DG_CACHE_DIR"), os.path.join(sglang, "deep_gemm"),
                      os.path.join(home, ".dj")],
        "sglang_jit": [*env("SGLANG_JIT_CACHE_DIR"), os.path.join(home, ".cache", "sglang", "jit")],
        "cuda": [*env("CUDA_CACHE_PATH"), os.path.join(sglang, "nv"), os.path.join(home, ".nv", "ComputeCache")],
        "tilelang": [*env("TILELANG_CACHE_DIR"), os.path.join(sglang, "tilelang"), os.path.join(home, ".tilelang")],
        "cute_dsl": [*env("CUTE_DSL_CACHE_DIR"), *env("SGLANG_CUTE_AOT_CACHE_DIR"), os.path.join(sglang, "cute_aot"),
                     os.path.join(tmp, "cutlass_python_cache"),
                     *sorted(glob_dirs(os.path.join(tmp, "*", "cutlass_python_cache")))],
        "tvm_ffi": [*env("TVM_FFI_CACHE_DIR"), os.path.join(home, ".cache", "tvm-ffi")],
        "other": [sglang, os.path.join(home, ".cache")],
    }
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name in COMPILE_CACHES:
        for directory in roots[name]:
            # The first name that claims a directory keeps it.
            key = os.path.realpath(directory)
            if key not in seen:
                seen.add(key)
                pairs.append((name, key))
    return pairs


def glob_dirs(pattern: str) -> list[str]:
    return [path for path in glob.glob(pattern) if os.path.isdir(path) and not os.path.islink(path)]


def scan_compile_caches(roots: list[tuple[str, str]],
                        max_files: int = SCAN_MAX_FILES) -> dict[str, dict[str, int]]:
    """Return {cache name: {file path: size}}. No file content is read.

    A directory that is itself a watched root is skipped inside another
    root and listed under its own name, so no file is counted twice.
    """
    owned = {directory for _name, directory in roots}
    found: dict[str, dict[str, int]] = {name: {} for name in COMPILE_CACHES}
    budget = max_files
    for name, root in roots:
        files = found[name]
        for directory, directories, names in os.walk(root, followlinks=False):
            directories[:] = [item for item in directories if os.path.join(directory, item) not in owned]
            for item in names:
                if budget <= 0:
                    return found
                budget -= 1
                path = os.path.join(directory, item)
                try:
                    files[path] = os.lstat(path).st_size
                except OSError:
                    continue
    return found


class CompileWatcher:
    """Report files that compilers write after worker_ready.

    start() takes the baseline: what startup compiled. check() reports, per
    cache, the files that are new or changed in size since the last scan,
    as one jit_compile event per cache. A file that stays the same is
    reported once.
    """

    def __init__(self, emit: Callable[[dict], object],
                 roots: Callable[[], list[tuple[str, str]]] = lambda: compile_cache_roots(os.environ),
                 max_files: int = SCAN_MAX_FILES) -> None:
        self._emit = emit
        self._roots = roots
        self._max_files = max_files
        self._seen: dict[str, dict[str, int]] | None = None

    def start(self) -> None:
        self._seen = scan_compile_caches(self._roots(), self._max_files)

    def check(self) -> list[dict]:
        current = scan_compile_caches(self._roots(), self._max_files)
        if self._seen is None:
            self._seen = current
            return []
        events = []
        for name in COMPILE_CACHES:
            before = self._seen.get(name, {})
            changed = sum(1 for path, size in current[name].items() if before.get(path) != size)
            if changed:
                events.append({"event": "jit_compile", "cache": name, "files": changed})
        self._seen = current
        for event in events:
            self._emit(event)
        return events


def server_port(command: list[str]) -> int:
    port = DEFAULT_SERVER_PORT
    for index, item in enumerate(command):
        value = None
        if item.startswith("--port="):
            value = item.split("=", 1)[1]
        elif item == "--port" and index + 1 < len(command):
            value = command[index + 1]
        if value is not None and value.isdigit() and 1 <= int(value) <= 65535:
            port = int(value)
    return port


def count_gpus(dev_dir: Path = Path("/dev")) -> int:
    try:
        return sum(1 for name in os.listdir(dev_dir) if re.fullmatch(r"nvidia[0-9]+", name))
    except OSError:
        return 0


def exit_event(returncode: int | None) -> dict:
    if returncode is not None and returncode < 0:
        try:
            name: str | None = signal.Signals(-returncode).name
        except ValueError:
            name = None
        return {"event": "worker_exit", "exit_code": None, "signal": name}
    return {"event": "worker_exit", "exit_code": returncode, "signal": None}


def run_server(
    command: list[str],
    model_revision: str,
    *,
    started: float,
    out: NonblockingStdout | None = None,
    dev_dir: Path = Path("/dev"),
    health_interval: float = HEALTH_INTERVAL_SECONDS,
    compile_roots: Callable[[], list[tuple[str, str]]] | None = None,
    scan_interval: float = SCAN_SECONDS,
) -> int:
    """Start the server, capture its output in memory, export only contract events, and return its code.

    After worker_ready the health thread watches the compiler caches
    (CompileWatcher) until the server exits.
    """
    out = out or NonblockingStdout()
    lock = threading.Lock()

    def emit(event: dict) -> None:
        if valid_event(event):
            out.write(event)

    classifier = OutputClassifier(emit)
    exited = threading.Event()
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert child.stdout is not None
    stream = child.stdout

    def read() -> None:
        # Drain the pipe always: a stopped reader would block the server.
        for line in bounded_lines(stream):
            try:
                with lock:
                    classifier.feed(line)
            except Exception:  # noqa: BLE001 - a classifier fault must not stop the drain
                pass

    def tick() -> None:
        while not exited.wait(0.5):
            try:
                with lock:
                    classifier.tick()
            except Exception:  # noqa: BLE001
                pass

    def health() -> None:
        port = server_port(command)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while not exited.is_set():
            try:
                with opener.open(f"http://127.0.0.1:{port}/health", timeout=health_interval) as response:
                    ready = response.status == 200
            except Exception:  # noqa: BLE001 - not ready yet
                ready = False
            if ready and not exited.is_set():
                emit({"event": "worker_ready", "model_revision": model_revision, "gpus": count_gpus(dev_dir),
                      "load_seconds": max(0, int(time.monotonic() - started))})
                watch_compiles()
                return
            exited.wait(health_interval)

    def watch_compiles() -> None:
        # The baseline is what startup compiled; only later files are reported.
        def report(event: dict) -> None:
            # Nothing after worker_exit.
            if not exited.is_set():
                emit(event)

        watcher = CompileWatcher(report, compile_roots or (lambda: compile_cache_roots(os.environ)))
        try:
            watcher.start()
        except Exception:  # noqa: BLE001 - a watcher fault must not stop the server
            return
        while not exited.wait(scan_interval):
            try:
                watcher.check()
            except Exception:  # noqa: BLE001
                pass

    reader = threading.Thread(target=read, daemon=True)
    helpers = [threading.Thread(target=tick, daemon=True), threading.Thread(target=health, daemon=True)]
    for thread in [reader, *helpers]:
        thread.start()
    code = supervise(child)
    exited.set()
    # Server subprocesses can hold the pipe open after the server exits.
    reader.join(timeout=2.0)
    for thread in helpers:
        # Stop the helpers before interpreter shutdown.
        thread.join(timeout=health_interval + 1.0)
    with lock:
        try:
            classifier.finish()
        except Exception:  # noqa: BLE001
            pass
        emit(exit_event(code))
    return code


def supervise(child: subprocess.Popen) -> int:
    """Run as PID 1: pass SIGTERM/SIGINT straight to the child, then exit with its code.

    SGLang drains on SIGTERM: /health answers 503, so the router stops picking
    this worker, and the server exits once its in-flight requests finish.
    Kubernetes kills the pod after terminationGracePeriodSeconds.
    """

    def forward(signum: int, _frame: object) -> None:
        if child.poll() is None:
            child.send_signal(signum)

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    return child.wait()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True, type=Path)
    parser.add_argument("--timeout-seconds", required=True, type=int)
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--revision-metadata", required=True)
    parser.add_argument("--expected-file", action="append", type=parse_expected_file, default=[])
    parser.add_argument("--plain-cache", action="store_true",
                        help="the path is a read-only plain cache that fetch-model filled, not a c8s dm-verity volume")
    parser.add_argument("--gpu-metrics-port", type=int)
    parser.add_argument("--private-server-output", action="store_true",
                        help="accepted for compatibility; server output is always private")
    parser.add_argument("--mountinfo", type=Path, default=Path("/proc/self/mountinfo"), help=argparse.SUPPRESS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.timeout_seconds < 1 or args.poll_seconds <= 0:
        parser.error("the timeout and poll interval must be positive")
    if len(args.expected_revision) != 40 or any(character not in "0123456789abcdef" for character in args.expected_revision):
        parser.error("the expected revision must be a lowercase 40-character commit")
    if not args.expected_repository or "@" in args.expected_repository or args.expected_repository.startswith("/"):
        parser.error("the expected repository is invalid")
    if len(args.expected_file) < 3:
        parser.error("at least three expected model files are required")
    if args.gpu_metrics_port is not None and not 1024 <= args.gpu_metrics_port <= 65535:
        parser.error("the GPU metrics port must be between 1024 and 65535")
    if not args.command or args.command[0] != "--" or len(args.command) == 1:
        parser.error("a command must follow --")
    args.command = args.command[1:]
    return args


def start_failure() -> int:
    """Report a supervisor exit before the server started, then return its code."""
    try:
        NonblockingStdout().write({"event": "worker_exit", "exit_code": 1, "signal": None})
    except OSError:
        pass
    return 1


def main() -> int:
    started = time.monotonic()
    args = parse_args()
    if os.geteuid() == 0:
        print("model-mount: the wrapper must run as a non-root user", file=sys.stderr)
        return start_failure()
    deadline = time.monotonic() + args.timeout_seconds
    last_error = "the model mount is unavailable"
    while True:
        try:
            verify_once(args)
            break
        except MountUnavailable as error:
            last_error = str(error)
        except (ModelMountError, OSError, UnicodeError) as error:
            print(f"model-mount: rejected: {error}", file=sys.stderr)
            return start_failure()
        if time.monotonic() >= deadline:
            print(f"model-mount: timeout: {last_error}", file=sys.stderr)
            return start_failure()
        time.sleep(min(args.poll_seconds, max(0.0, deadline - time.monotonic())))
    print(f"model-mount: verified {args.path}", file=sys.stderr)
    if args.gpu_metrics_port is not None:
        try:
            # NVIDIA dcgm-exporter with an embedded DCGM host engine; it sees
            # only the GPUs granted to this container.
            subprocess.Popen(
                [
                    "/usr/local/bin/dcgm-exporter",
                    "--collectors=/etc/dcgm-exporter/counters.csv",
                    f"--address=:{args.gpu_metrics_port}",
                ],
                env={**os.environ, "LD_LIBRARY_PATH": "/opt/dcgm/lib"},
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
        except OSError as error:
            # Metrics must not stop inference. Prometheus reports this failure
            # because the worker metrics target stays down.
            print(f"model-mount: GPU metrics did not start: {error}", file=sys.stderr)
    # Server output is always private (see the module comment above);
    # --private-server-output is accepted for older charts and changes nothing.
    try:
        return run_server(args.command, args.expected_revision, started=started)
    except OSError as error:
        print(f"model-mount: the server did not start: {errno.errorcode.get(error.errno or 0, 'error')}",
              file=sys.stderr)
        return start_failure()


if __name__ == "__main__":
    raise SystemExit(main())
