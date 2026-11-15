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
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

BLOCK = 8 * 1024 * 1024
WORKERS = 8
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


def download(url: str, target: Path, digest: str, size: int) -> None:
    partial = target.with_name(target.name + ".partial")
    hasher = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=60) as response, partial.open("wb") as stream:
        for block in iter(lambda: response.read(BLOCK), b""):
            hasher.update(block)
            stream.write(block)
    if hasher.hexdigest() != digest or partial.stat().st_size != size:
        partial.unlink()
        raise FetchError(f"{target.name}: the download does not match the manifest")
    partial.chmod(0o444)
    partial.replace(target)


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

    def ensure(name: str) -> str:
        digest, size = files[name]
        target = root / name
        if target.is_file() and not target.is_symlink() and target.stat().st_size == size and sha256_file(target) == digest:
            return "kept"
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink() or target.exists():
            target.unlink()
        download(file_url(args.endpoint, repository, revision, name), target, digest, size)
        return "downloaded"

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(ensure, sorted(files, key=lambda name: files[name][1], reverse=True)))
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
    parser.add_argument("--endpoint", default="https://huggingface.co")
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
    try:
        if args.step == "manifest":
            sys.stdout.buffer.write(build_manifest(args.endpoint, args.repository, args.revision))
        else:
            fetch(args)
    except (FetchError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"fetch-model: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
