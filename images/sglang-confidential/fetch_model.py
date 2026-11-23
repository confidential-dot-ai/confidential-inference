#!/usr/bin/env python3
"""Fill a plain model cache from Hugging Face and check it against a pinned byte manifest.

fetch-model manifest: print the byte manifest of a pinned revision (release
authors; it reads the Hugging Face file list, where every LFS file carries its
SHA-256, and hashes the small non-LFS files).

fetch-model fetch: runs in the TEE before the worker. The manifest file comes
from the release values and its SHA-256 is pinned in this argv. Every file
whose bytes do not match is downloaded again, files the manifest does not
list are deleted, and the manifest is written next to the files, where
wait-for-model checks every file once more before the server starts.

fetch uses CONNECTIONS parallel HTTP/1.1 connections in total. A file larger
than CHUNK is split into byte ranges, so one very large file uses many
connections. A failed range is retried; with more than one --endpoint, each
retry goes to the next one (for example an in-site mirror first, then the main
model server). The SHA-256 of the whole file, not the transport, is the check.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BLOCK = 8 * 1024 * 1024
# Measured to the us-central-1 GPU workers on 2026-11-23: 8 whole-file
# connections gave about 16 MB/s from the Azure model server, 64 ranged
# connections about 84 MB/s, and more than 64 was slower
# (confidential-inference-model-server docs/download-throughput.md).
CONNECTIONS = 64
CHUNK = 64 * 1024 * 1024
ATTEMPTS = 4
HASHERS = 8
SCHEMA = "confidential-benchmark/local-model-byte-manifest/v1"


class FetchError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(BLOCK), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_name(name: object) -> str:
    if not isinstance(name, str) or not name or name.startswith("/") or ".." in Path(name).parts:
        raise FetchError(f"unsafe path in the manifest: {name!r}")
    return name


def file_url(endpoint: str, repository: str, revision: str, name: str) -> str:
    return f"{endpoint}/{repository}/resolve/{revision}/{urllib.parse.quote(name)}"


def tree(endpoint: str, repository: str, revision: str) -> list[dict]:
    url = f"{endpoint}/api/models/{repository}/tree/{revision}?recursive=true"
    entries = []
    while url:
        with urllib.request.urlopen(url, timeout=60) as response:
            entries += json.loads(response.read())
            match = re.search(r'<([^>]+)>;\s*rel="next"', response.headers.get("Link", ""))
        url = match.group(1) if match else ""
    return sorted((item for item in entries if item.get("type") == "file"), key=lambda item: item["path"])


def build_manifest(endpoint: str, repository: str, revision: str) -> bytes:
    entries = tree(endpoint, repository, revision)
    files = []
    for item in entries:
        name = safe_name(item["path"])
        lfs = item.get("lfs")
        if lfs:
            digest, size = lfs["oid"], lfs["size"]
        else:
            with urllib.request.urlopen(file_url(endpoint, repository, revision, name), timeout=60) as response:
                body = response.read()
            digest, size = hashlib.sha256(body).hexdigest(), len(body)
        files.append({"content_sha256": digest, "path": name, "size": size})
    if not files:
        raise FetchError("the revision has no files")
    payload = {"files": files, "immutable_revision": revision, "repository": repository}
    return canonical({
        "canonical_local_manifest_sha256": hashlib.sha256(canonical(payload)).hexdigest(),
        "classification": "verified_local_snapshot_bytes",
        "files": files,
        "immutable_ref": f"{repository}@{revision}",
        "immutable_revision": revision,
        "repository": repository,
        "schema": SCHEMA,
        "source_remote_inventory_sha256": hashlib.sha256(canonical(entries)).hexdigest(),
    }) + b"\n"


class Endpoints:
    """The model servers in order of preference. One that fails a connection moves to the back for every range."""

    def __init__(self, endpoints: list[str]) -> None:
        self.order = list(endpoints)
        self.lock = threading.Lock()

    def pick(self, previous: str | None) -> str:
        """The preferred server; for a retry, the preferred one other than the server that just failed."""
        with self.lock:
            if previous == self.order[0] and len(self.order) > 1:
                return self.order[1]
            return self.order[0]

    def failed(self, endpoint: str) -> None:
        with self.lock:
            if len(self.order) > 1 and self.order[0] == endpoint:
                self.order.append(self.order.pop(0))
                print(f"fetch-model: {endpoint} failed; using {self.order[0]} first", file=sys.stderr, flush=True)


def fetch_range(endpoints: Endpoints, path: str, fd: int, start: int, end: int, whole: bool) -> None:
    """Write bytes start..end of the file at the same offset of fd. Each retry uses the next endpoint."""
    error: Exception | None = None
    endpoint: str | None = None
    for attempt in range(ATTEMPTS):
        endpoint = endpoints.pick(endpoint)
        url = endpoint + path
        request = urllib.request.Request(url, headers={} if whole else {"Range": f"bytes={start}-{end}"})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                if not whole and response.status != 206:
                    raise FetchError("the server ignored the byte range")
                buffer = memoryview(bytearray(BLOCK))
                offset = start
                while offset <= end:
                    count = response.readinto(buffer[:min(BLOCK, end + 1 - offset)])
                    if not count:
                        raise ConnectionError("the response ended early")
                    os.pwrite(fd, buffer[:count], offset)
                    offset += count
            return
        except (OSError, FetchError) as caught:  # URLError, HTTPError and timeouts are OSError
            error = caught
            if not isinstance(caught, (FetchError, urllib.error.HTTPError)):
                endpoints.failed(endpoint)  # no answer: prefer the next server for every range
            if attempt < ATTEMPTS - 1:
                time.sleep(min(8, 2 ** attempt))
    raise FetchError(f"bytes {start}-{end}: {error}")


def download_all(endpoints: Endpoints, jobs: list[tuple[str, str, Path, str, int]]) -> None:
    """Download every (name, url path, target, digest, size) with CONNECTIONS ranged connections in total.

    Each file is written to <target>.partial, checked against its SHA-256 and
    size once all its ranges are written, and only then renamed into place.
    """
    lock = threading.Lock()
    left: dict[str, int] = {}
    fds: dict[str, int] = {}
    failed: dict[str, str] = {}
    chunks = []
    for name, path, target, digest, size in jobs:
        partial = target.with_name(target.name + ".partial")
        fds[name] = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        os.ftruncate(fds[name], size)
        starts = list(range(0, size, CHUNK)) or [0]
        left[name] = len(starts)
        chunks += [(name, path, start, min(size, start + CHUNK) - 1, len(starts) == 1) for start in starts]
    info = {name: (target, digest, size) for name, _, target, digest, size in jobs}

    def verify(name: str) -> None:
        target, digest, size = info[name]
        partial = target.with_name(target.name + ".partial")
        if name in failed or partial.stat().st_size != size or sha256_file(partial) != digest:
            partial.unlink()
            failed.setdefault(name, "the download does not match the manifest")
            return
        partial.chmod(0o444)
        partial.replace(target)

    with concurrent.futures.ThreadPoolExecutor(max_workers=HASHERS) as hashers:
        checks = []

        def run(chunk: tuple[str, str, int, int, bool]) -> None:
            name, path, start, end, whole = chunk
            try:
                if name not in failed and end >= start:
                    fetch_range(endpoints, path, fds[name], start, end, whole)
            except FetchError as error:
                failed.setdefault(name, str(error))
            with lock:
                left[name] -= 1
                finished = left[name] == 0
            if finished:
                os.close(fds[name])
                checks.append(hashers.submit(verify, name))

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONNECTIONS) as pool:
            list(pool.map(run, chunks))
        for check in checks:
            check.result()
    if failed:
        raise FetchError("; ".join(f"{name}: {reason}" for name, reason in sorted(failed.items())))


def fetch(args: argparse.Namespace) -> None:
    raw = args.manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.manifest_sha256:
        raise FetchError("the manifest file does not match its pinned SHA-256")
    manifest = json.loads(raw)
    if manifest.get("schema") != SCHEMA:
        raise FetchError("the manifest has another schema")
    repository, revision = manifest["repository"], manifest["immutable_revision"]
    files = {safe_name(item["path"]): (item["content_sha256"], item["size"]) for item in manifest["files"]}
    if args.revision_metadata in files:
        raise FetchError("the manifest lists itself")
    root = args.path

    def kept(name: str) -> bool:
        digest, size = files[name]
        target = root / name
        return target.is_file() and not target.is_symlink() and target.stat().st_size == size \
            and sha256_file(target) == digest

    names = sorted(files, key=lambda name: files[name][1], reverse=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=HASHERS) as pool:
        missing = [name for name, good in zip(names, pool.map(kept, names)) if not good]
    jobs = []
    for name in missing:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or target.exists():
            target.unlink()
        jobs.append((name, file_url("", repository, revision, name), target, *files[name]))
    download_all(Endpoints(args.endpoint), jobs)
    results = ["downloaded"] * len(missing) + ["kept"] * (len(files) - len(missing))
    keep = set(files) | {args.revision_metadata}
    for directory, directories, names in os.walk(root, topdown=False):
        base = Path(directory)
        for name in names:
            if str((base / name).relative_to(root)) not in keep:
                (base / name).unlink()
        for name in directories:
            path = base / name
            if path.is_symlink():
                path.unlink()
            elif not any(path.iterdir()):
                path.rmdir()
    metadata = root / args.revision_metadata
    partial = metadata.with_name(metadata.name + ".partial")
    partial.write_bytes(raw)
    partial.chmod(0o444)
    partial.replace(metadata)
    print(f"fetch-model: {results.count('downloaded')} downloaded, {results.count('kept')} kept, "
          f"{repository}@{revision}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--endpoint", action="append",
                        help="a model server; repeat it to give fallbacks in order (default: https://huggingface.co)")
    steps = parser.add_subparsers(dest="step", required=True)
    manifest = steps.add_parser("manifest")
    manifest.add_argument("--repository", required=True)
    manifest.add_argument("--revision", required=True)
    run = steps.add_parser("fetch")
    run.add_argument("--path", required=True, type=Path)
    run.add_argument("--manifest", required=True, type=Path)
    run.add_argument("--manifest-sha256", required=True)
    run.add_argument("--revision-metadata", required=True)
    args = parser.parse_args()
    args.endpoint = [endpoint.rstrip("/") for endpoint in args.endpoint or ["https://huggingface.co"]]
    try:
        if args.step == "manifest":
            sys.stdout.buffer.write(build_manifest(args.endpoint[0], args.repository, args.revision))
        else:
            fetch(args)
    except (FetchError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"fetch-model: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
