#!/usr/bin/env python3
"""Fetch the node and CDS guest image manifest.json files named by release/spec.yaml.

c8s publishes a measurement artifact beside each guest image. The artifact
holds manifest.json, which records the TDX measurements MRTD, RTMR1, and
RTMR2 of the image. This script downloads that file through the digest
chain that release/spec.yaml pins, checks every digest, checks the
measurements, and writes the exact bytes to release/node-manifest.json, and
for the CDS guest image to release/cds-manifest.json.

Anyone can repeat the check: the SHA-256 of each file must equal the
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
import release_spec

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


# The pinned guest images: the image key and its measurement artifact key in `c8s`.
NODE = ("nodeImage", "nodeManifestArtifact")
CDS = ("cdsImage", "cdsManifestArtifact")


def read_spec(spec: Any) -> dict[str, Any]:
    """Check the pinned node and CDS guest images."""
    c8s = spec.get("c8s") if isinstance(spec, dict) else None
    if not isinstance(c8s, dict) or not all(key in c8s for key in NODE):
        raise FetchError("the release specification has no c8s node image and manifest artifact")
    for image, artifact in (NODE, CDS):
        pins = [c8s.get(key) for key in (image, artifact)]
        if not all(isinstance(pin, dict) for pin in pins):
            raise FetchError(f"the release specification pins {image} and {artifact}")
        reference = pins[0].get("reference")
        if not isinstance(reference, str) or "@" in reference or ":" in reference.rsplit("/", 1)[-1]:
            raise FetchError(f"c8s.{image}.reference must be a repository without tag or digest")
        if not DIGEST.fullmatch(str(pins[1].get("digest"))):
            raise FetchError(f"c8s.{artifact}.digest is not a SHA-256 digest")
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


def manifest_json_digest(reference: str, artifact: str) -> str:
    """Return the manifest.json layer digest of the verified artifact manifest."""
    raw_manifest = run(["crane", "manifest", f"{reference}@{artifact}"])
    if sha256(raw_manifest) != artifact:
        raise FetchError("the registry returned an artifact manifest with a different digest")
    return manifest_layer(json.loads(raw_manifest))


def fetch(spec: dict[str, Any], keys: tuple[str, str] = NODE) -> tuple[bytes, dict[str, Any]]:
    image, artifact_key = keys
    reference = spec["c8s"][image]["reference"]
    artifact = spec["c8s"][artifact_key]["digest"]
    layer = manifest_json_digest(reference, artifact)
    pinned = spec["c8s"][artifact_key].get("manifestJson")
    if pinned is not None and pinned != layer:
        raise FetchError(f"the artifact manifest.json layer differs from c8s.{artifact_key}.manifestJson")
    data = run(["crane", "blob", f"{reference}@{layer}"])
    if sha256(data) != layer:
        raise FetchError("the registry returned a manifest.json with a different digest")
    document = json.loads(data)
    measurements = check_measurements(document)
    return data, {"artifact": artifact, "manifestJson": layer, **measurements}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, default=release_spec.SPEC, help="the release specification")
    parser.add_argument("--output", type=Path, default=release_spec.NODE_MANIFEST)
    parser.add_argument("--cds-output", type=Path, default=release_spec.CDS_MANIFEST)
    parser.add_argument(
        "--check", action="store_true",
        help="fail when the committed file differs from the registry bytes",
    )
    args = parser.parse_args()
    try:
        spec = read_spec(release_spec.read_spec(args.spec))
        data, record = fetch(spec)
        cds_data, record["cds"] = fetch(spec, CDS)
        for path, content in ((args.output, data), (args.cds_output, cds_data)):
            if args.check:
                if path.read_bytes() != content:
                    raise FetchError(f"{path} differs from the pinned artifact")
            else:
                path.write_bytes(content)
    except (OSError, FetchError, release_spec.SpecError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"fetch-node-manifest: {error}", file=sys.stderr)
        return 1
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
