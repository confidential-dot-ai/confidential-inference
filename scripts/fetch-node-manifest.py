#!/usr/bin/env python3
"""Fetch the node image manifest.json named by a release profile.

c8s publishes a measurement artifact beside each node image. The artifact
holds manifest.json, which records the TDX measurements MRTD, RTMR1, and
RTMR2 of the node image. This script downloads that file through the digest
chain that the profile specification pins, checks every digest, checks the
measurements, and writes the exact bytes to node-manifest.json in the layer
that sets `c8s` (release/node-manifest.json unless a profile overrides c8s).

Anyone can repeat the check: the SHA-256 of node-manifest.json must equal the
manifest.json layer digest of the pinned artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_profiles

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MEASUREMENT = re.compile(r"^[0-9a-f]{96}$")
MANIFEST_TITLE = "manifest.json"


class FetchError(ValueError):
    """The node manifest cannot be fetched or checked."""


def run(command: list[str]) -> bytes:
    result = subprocess.run(command, capture_output=True, check=False)
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise FetchError(f"command failed: {' '.join(command)}: {detail}")
    return result.stdout


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_spec(spec: Any) -> dict[str, Any]:
    try:
        c8s = spec["c8s"]
        reference = c8s["nodeImage"]["reference"]
        artifact = c8s["nodeManifestArtifact"]["digest"]
    except (KeyError, TypeError) as error:
        raise FetchError("the release specification has no c8s node manifest artifact") from error
    if not isinstance(reference, str) or "@" in reference or ":" in reference.rsplit("/", 1)[-1]:
        raise FetchError("c8s.nodeImage.reference must be a repository without tag or digest")
    if not isinstance(artifact, str) or not DIGEST.fullmatch(artifact):
        raise FetchError("c8s.nodeManifestArtifact.digest is not a SHA-256 digest")
    return spec


def manifest_layer(manifest: dict[str, Any]) -> str:
    layers = [
        layer for layer in manifest.get("layers", [])
        if layer.get("annotations", {}).get("org.opencontainers.image.title") == MANIFEST_TITLE
    ]
    if len(layers) != 1 or not DIGEST.fullmatch(str(layers[0].get("digest"))):
        raise FetchError("the artifact does not hold exactly one manifest.json layer")
    return layers[0]["digest"]


def check_measurements(document: dict[str, Any]) -> dict[str, str]:
    tdx = document.get("tdx")
    if not isinstance(tdx, dict):
        raise FetchError("manifest.json has no tdx section")
    values = {name: tdx.get(name) for name in ("mrtd", "rtmr1", "rtmr2")}
    for name, value in values.items():
        if not isinstance(value, str) or not MEASUREMENT.fullmatch(value):
            raise FetchError(f"manifest.json tdx.{name} is not a 96-character hex value")
    return values


def fetch(spec: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    reference = spec["c8s"]["nodeImage"]["reference"]
    artifact = spec["c8s"]["nodeManifestArtifact"]["digest"]
    raw_manifest = run(["crane", "manifest", f"{reference}@{artifact}"])
    if sha256(raw_manifest) != artifact:
        raise FetchError("the registry returned an artifact manifest with a different digest")
    layer = manifest_layer(json.loads(raw_manifest))
    data = run(["crane", "blob", f"{reference}@{layer}"])
    if sha256(data) != layer:
        raise FetchError("the registry returned a manifest.json with a different digest")
    document = json.loads(data)
    measurements = check_measurements(document)
    return data, {"artifact": artifact, "manifestJson": layer, **measurements}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, default=ROOT / "release", help="the profile directory")
    parser.add_argument("--output", type=Path, help="default: node-manifest.json in the layer that sets c8s")
    parser.add_argument(
        "--check", action="store_true",
        help="fail when the committed file differs from the registry bytes",
    )
    args = parser.parse_args()
    try:
        profile = release_profiles.for_directory(args.release)
        data, record = fetch(read_spec(release_profiles.read_spec(profile)))
        args.output = args.output or release_profiles.node_manifest(profile)
        if args.check:
            if args.output.read_bytes() != data:
                raise FetchError(f"{args.output} differs from the pinned artifact")
        else:
            args.output.write_bytes(data)
    except (OSError, FetchError, release_profiles.ProfileError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"fetch-node-manifest: {error}", file=sys.stderr)
        return 1
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
