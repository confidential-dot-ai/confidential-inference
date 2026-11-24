#!/usr/bin/env python3
"""Write the fetch-model byte manifest of a pair's kernel cache seed.

    scripts/kernel-cache-manifest.py <cache directory> \\
      --repository confidential-ai/kernel-cache \\
      --engine-image ghcr.io/...@sha256:<64 hex> --plan dsv41-262k > manifest.json

The directory is the plan's warm kernel cache (paths.kernel_cache_dir of the
plan, /tmp/dsv41/kernel-cache in the engine image), copied from a pair of the
same engine image and plan after its warmup. Put the manifest in
inference.pair.kernelCache.seed.manifest, and serve each listed file on the
model mirror at <repository>/resolve/<revision>/<path>, where revision is
sha256-<engine image digest>-<plan>. The chart refuses a manifest whose
revision is not that of the engine image and plan it renders.

The manifest has the schema of fetch-model (confidential-sglang
confidential/helpers/fetch_model.py), which checks every file's SHA-256 and
size. Lock files, partial writes and the manifest's own name are left out, and
the tool refuses a symbolic link or a special file: fetch-model writes every
file read-only (0444), and a seeded lock file could not be opened for writing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

SCHEMA = "confidential-benchmark/local-model-byte-manifest/v1"
REVISION_METADATA = ".kernel-cache-manifest.json"
IMAGE = re.compile(r"^[^@\s]+@sha256:(?P<digest>[0-9a-f]{64})$")
PLAN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
REPOSITORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
SKIPPED_SUFFIXES = (".lock", ".partial", ".tmp")
BLOCK = 8 * 1024 * 1024


class ManifestError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def revision(engine_image: str, plan: str) -> str:
    match = IMAGE.fullmatch(engine_image)
    if match is None:
        raise ManifestError(f"the engine image is not digest-pinned (repository@sha256:<64 hex>): {engine_image}")
    if PLAN.fullmatch(plan) is None:
        raise ManifestError(f"the plan is not a plan name: {plan!r}")
    return f"sha256-{match.group('digest')}-{plan}"


def skipped(relative: Path) -> bool:
    return (relative.name == REVISION_METADATA or relative.name.endswith(SKIPPED_SUFFIXES)
            or "locks" in relative.parts[:-1])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(BLOCK), b""):
            digest.update(block)
    return digest.hexdigest()


def cache_files(directory: Path) -> list[dict]:
    if not directory.is_dir():
        raise ManifestError(f"{directory} is not a directory")
    files = []
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ManifestError(f"{relative} is a symbolic link; fetch-model writes only regular files")
        if stat.S_ISDIR(mode) or skipped(relative):
            continue
        if not stat.S_ISREG(mode):
            raise ManifestError(f"{relative} is not a regular file")
        files.append({"content_sha256": sha256_file(path), "path": relative.as_posix(), "size": path.stat().st_size})
    if not files:
        raise ManifestError(f"{directory} holds no cache file")
    return files


def manifest(directory: Path, repository: str, engine_image: str, plan: str) -> bytes:
    if REPOSITORY.fullmatch(repository) is None:
        raise ManifestError(f"the repository is not <owner>/<name>: {repository!r}")
    immutable_revision = revision(engine_image, plan)
    files = cache_files(directory)
    payload = {"files": files, "immutable_revision": immutable_revision, "repository": repository}
    return canonical({
        "canonical_local_manifest_sha256": hashlib.sha256(canonical(payload)).hexdigest(),
        "classification": "verified_local_snapshot_bytes",
        "files": files,
        "immutable_ref": f"{repository}@{immutable_revision}",
        "immutable_revision": immutable_revision,
        "repository": repository,
        "schema": SCHEMA,
    }) + b"\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directory", type=Path, help="the warm kernel cache directory")
    parser.add_argument("--repository", required=True, help="the mirror repository of the seed, <owner>/<name>")
    parser.add_argument("--engine-image", required=True, help="the engine image, repository@sha256:<digest>")
    parser.add_argument("--plan", required=True, help="the launch plan, for example dsv41-262k")
    args = parser.parse_args()
    try:
        sys.stdout.buffer.write(manifest(args.directory, args.repository, args.engine_image, args.plan))
    except ManifestError as error:
        print(f"kernel-cache-manifest: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
