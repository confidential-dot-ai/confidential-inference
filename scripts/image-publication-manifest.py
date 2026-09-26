#!/usr/bin/env python3
"""Create and validate evidence for deterministic image publication."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts/image-publication-manifest.schema.json"
SCHEMA = "confidential.ai/image-publication-manifest/v1"
REPOSITORY = "https://github.com/confidential-dot-ai/confidential-inference"
REGISTRY = "ghcr.io/confidential-dot-ai/confidential-inference"
VERSION = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-staging)?$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE = re.compile(r"^ghcr\.io/confidential-dot-ai/confidential-inference/[a-z0-9][a-z0-9._-]*$")


class PublicationError(ValueError):
    """The publication evidence is invalid or inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicationError(message)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PublicationError(f"cannot read {path}: {error}") from error


def validate(manifest: Any) -> dict[str, Any]:
    schema = read_json(SCHEMA_PATH)
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(manifest),
        key=lambda error: list(error.path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "manifest"
        raise PublicationError(f"publication manifest {location}: {errors[0].message}")
    require(isinstance(manifest, dict), "publication manifest is not an object")
    images = manifest["images"]
    names = [entry["name"] for entry in images]
    require(names == sorted(names), "publication images are not sorted by name")
    require(len(names) == len(set(names)), "publication manifest repeats an image")
    for entry in images:
        require(
            entry["pushedDigest"] == entry["reproducibilityDigest"],
            f"pushed digest differs from the reproducibility digest for {entry['name']}",
        )
    return manifest


def record(
    *, image: str, pushed_digest: str, reproducibility_digest: str,
    source_commit: str, release_version: str, base_ref: str, base_ref_commit: str,
) -> dict[str, Any]:
    require(IMAGE.fullmatch(image) is not None, "image name is invalid")
    require(DIGEST.fullmatch(pushed_digest) is not None, "pushed digest is invalid")
    require(DIGEST.fullmatch(reproducibility_digest) is not None,
            "reproducibility digest is invalid")
    require(pushed_digest == reproducibility_digest,
            "pushed digest differs from the deterministic reproducibility digest")
    require(COMMIT.fullmatch(source_commit) is not None, "source commit is invalid")
    require(bool(base_ref) and not any(character.isspace() for character in base_ref),
            "base reference is invalid")
    require(COMMIT.fullmatch(base_ref_commit) is not None, "base reference commit is invalid")
    require(VERSION.fullmatch(release_version) is not None, "release version is invalid")
    return {
        "schema": SCHEMA,
        "releaseVersion": release_version,
        "source": {
            "repository": REPOSITORY,
            "commit": source_commit,
            "baseRef": base_ref,
            "baseRefCommit": base_ref_commit,
        },
        "images": [{
            "name": image,
            "pushedDigest": pushed_digest,
            "reproducibilityDigest": reproducibility_digest,
        }],
    }


def merge(paths: list[Path], expected_names: list[str]) -> dict[str, Any]:
    require(bool(paths), "no publication records were supplied")
    manifests = [validate(read_json(path)) for path in sorted(paths)]
    release_versions = {item["releaseVersion"] for item in manifests}
    sources = {json.dumps(item["source"], sort_keys=True) for item in manifests}
    require(len(release_versions) == 1, "publication records have different release versions")
    require(len(sources) == 1, "publication records have different source commits")
    images = [entry for item in manifests for entry in item["images"]]
    names = [entry["name"] for entry in images]
    expected = sorted(f"{REGISTRY}/{name}" for name in expected_names)
    require(sorted(names) == expected,
            f"publication image set differs from the selected images: got={sorted(names)} expected={expected}")
    manifest = {
        "schema": SCHEMA,
        "releaseVersion": next(iter(release_versions)),
        "source": json.loads(next(iter(sources))),
        "images": sorted(images, key=lambda entry: entry["name"]),
    }
    return validate(manifest)


def encode(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("--image", required=True)
    record_parser.add_argument("--pushed-digest", required=True)
    record_parser.add_argument("--reproducibility-digest", required=True)
    record_parser.add_argument("--source-commit", required=True)
    record_parser.add_argument("--base-ref", required=True)
    record_parser.add_argument("--base-ref-commit", required=True)
    record_parser.add_argument("--release-version", required=True)
    record_parser.add_argument("--output", type=Path, required=True)
    merge_parser = subparsers.add_parser("merge")
    merge_parser.add_argument("--record", type=Path, action="append", required=True)
    merge_parser.add_argument("--expected-image", action="append", required=True)
    merge_parser.add_argument("--output", type=Path, required=True)
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "record":
            value = record(
                image=args.image,
                pushed_digest=args.pushed_digest,
                reproducibility_digest=args.reproducibility_digest,
                source_commit=args.source_commit,
                release_version=args.release_version,
                base_ref=args.base_ref,
                base_ref_commit=args.base_ref_commit,
            )
            validate(value)
            args.output.write_bytes(encode(value))
        elif args.command == "merge":
            args.output.write_bytes(encode(merge(args.record, args.expected_image)))
        else:
            validate(read_json(args.manifest))
    except (PublicationError, OSError) as error:
        print(f"image-publication-manifest: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
