#!/usr/bin/env python3
"""Wait for a verified c8s model mount, then supervise the server process."""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Kubernetes removes a deleted pod from Service Endpoints before it sends
# SIGTERM, so no new request should route here once this arrives. This
# wrapper is PID 1 and runs under a pinned c8s argv with no lifecycle hook
# and no exec access, so the drain must happen here.
DRAIN_DEADLINE_ENV = "WORKER_DRAIN_DEADLINE_SECONDS"
DRAIN_PATH = "/v1/loads?include=core"
DEFAULT_DRAIN_PORT = 30000
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
    try:
        value = json.loads((path / "model.safetensors.index.json").read_text(encoding="utf-8"))
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
    if "c8s-verity-" not in source:
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


def drain_port(command: list[str]) -> int:
    """Read the worker's own --port value from its pinned argv."""
    for token in command:
        if token.startswith("--port="):
            try:
                return int(token.split("=", 1)[1])
            except ValueError:
                break
    return DEFAULT_DRAIN_PORT


def drain_deadline_seconds() -> float:
    """Read the drain deadline from the environment, not the pinned argv.

    The wrapper's command-line arguments are exact-matched by the c8s
    allowlist. The deadline is derived from the Helm chart's
    terminationGracePeriodSeconds and passed as an environment variable
    instead, so the argv this wrapper receives never changes.
    """
    raw = os.environ.get(DRAIN_DEADLINE_ENV, "")
    try:
        value = float(raw)
    except ValueError:
        return 0.0
    return max(0.0, value)


def pending_requests(port: int) -> int | None:
    """Read the worker's own running-plus-queued request count, or None on failure."""
    url = f"http://127.0.0.1:{port}{DRAIN_PATH}"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            payload = json.loads(response.read())
    except (OSError, urllib.error.URLError, ValueError) as error:
        print(f"model-mount: drain: the load probe failed: {error}", file=sys.stderr)
        return None
    if not isinstance(payload, list):
        return None
    total = 0
    for load in payload:
        try:
            total += int(load["num_running_reqs"]) + int(load["num_waiting_reqs"])
        except (KeyError, TypeError, ValueError):
            return None
    return total


def drain_then_forward(
    child: subprocess.Popen, port: int, deadline_seconds: float, poll_seconds: float, signum: int, state: dict,
) -> None:
    """Wait for in-flight requests to reach zero, then send SIGTERM to the child.

    Kubernetes has already removed the pod from Service Endpoints by the
    time a signal reaches this wrapper, so no new request should arrive.
    This only waits out requests that are already running or queued.

    This function runs nested inside the outer `child.wait()` call: a
    signal delivered while that call is blocked in the kernel interrupts it,
    and Python re-enters this handler before retrying the wait. Because that
    outer `child.wait()` holds `subprocess.Popen`'s internal wait lock for
    its whole (interrupted) duration, `child.poll()` called from here can
    never observe the child as exited -- it always reports None until the
    outer call finally unwinds. So a second signal cannot be noticed via
    `child.poll()`; it is tracked with `state["escalate"]` instead, checked
    on every loop iteration so escalation is not delayed until the deadline.
    """
    name = signal.Signals(signum).name
    if deadline_seconds <= 0:
        print(f"model-mount: {name} received, stopping the worker", file=sys.stderr)
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
        return
    print(
        f"model-mount: {name} received, draining up to {deadline_seconds:.0f}s "
        "before stopping the worker",
        file=sys.stderr,
    )
    deadline = time.monotonic() + deadline_seconds
    drained = False
    while time.monotonic() < deadline:
        if state["escalate"]:
            break
        if child.poll() is not None:
            drained = True
            break
        total = pending_requests(port)
        if total == 0:
            drained = True
            break
        time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))
    if not drained and not state["escalate"]:
        print("model-mount: drain deadline reached, stopping the worker", file=sys.stderr)
    if child.poll() is None:
        child.send_signal(signal.SIGTERM)


def supervise(child: subprocess.Popen, command: list[str], poll_seconds: float) -> int:
    """Run as the PID 1 supervisor: forward SIGTERM/SIGINT through a drain, then exit with the child's code."""
    port = drain_port(command)
    deadline_seconds = drain_deadline_seconds()
    state = {"draining": False, "escalate": False}

    def handle_signal(signum: int, _frame: object) -> None:
        if state["draining"]:
            # A second signal escalates immediately; do not wait twice. The
            # drain loop above is what actually stops early -- it polls
            # state["escalate"], not child.poll(), because child.poll()
            # cannot observe the child's exit while nested like this.
            state["escalate"] = True
            print("model-mount: signal received again, stopping the worker now", file=sys.stderr)
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
            return
        state["draining"] = True
        drain_then_forward(child, port, deadline_seconds, poll_seconds, signum, state)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
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
    parser.add_argument("--gpu-metrics-port", type=int)
    parser.add_argument("--gpu-metrics-worker")
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
    if (args.gpu_metrics_port is None) != (args.gpu_metrics_worker is None):
        parser.error("GPU metrics require both a port and a worker label")
    if args.gpu_metrics_port is not None and not 1024 <= args.gpu_metrics_port <= 65535:
        parser.error("the GPU metrics port must be between 1024 and 65535")
    if args.gpu_metrics_worker is not None and (
        not args.gpu_metrics_worker
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in args.gpu_metrics_worker)
        or args.gpu_metrics_worker.startswith("-")
        or args.gpu_metrics_worker.endswith("-")
    ):
        parser.error("the GPU metrics worker label is invalid")
    if not args.command or args.command[0] != "--" or len(args.command) == 1:
        parser.error("a command must follow --")
    args.command = args.command[1:]
    return args


def main() -> int:
    args = parse_args()
    if os.geteuid() == 0:
        print("model-mount: the wrapper must run as a non-root user", file=sys.stderr)
        return 1
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
            return 1
        if time.monotonic() >= deadline:
            print(f"model-mount: timeout: {last_error}", file=sys.stderr)
            return 1
        time.sleep(min(args.poll_seconds, max(0.0, deadline - time.monotonic())))
    print(f"model-mount: verified {args.path}", file=sys.stderr)
    if args.gpu_metrics_port is not None:
        try:
            subprocess.Popen(
                [
                    "/usr/local/bin/gpu-metrics",
                    f"--port={args.gpu_metrics_port}",
                    f"--worker={args.gpu_metrics_worker}",
                ],
                stdin=subprocess.DEVNULL,
                close_fds=True,
            )
        except OSError as error:
            # Metrics must not stop inference. Prometheus reports this failure
            # because the worker metrics target stays down.
            print(f"model-mount: GPU metrics did not start: {error}", file=sys.stderr)
    # Spawn and supervise, rather than os.execvp, so this wrapper stays PID 1
    # and can forward SIGTERM through a drain before the child stops. The
    # child's argv and stdout/stderr passthrough are unchanged either way.
    child = subprocess.Popen(args.command)
    return supervise(child, args.command, args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
