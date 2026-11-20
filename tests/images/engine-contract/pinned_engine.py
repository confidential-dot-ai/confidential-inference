#!/usr/bin/env python3
"""Print the engine image that release/spec.yaml pins, or nothing.

The spec pins the engine by a confidential-sglang release record
(`confidentialSglang.record: images-<12hex>`, docs/confidential-sglang-images.md).
The record bytes are release/inputs/confidential-sglang/<record>.json; the
engine is its `engine` image and digest, as
scripts/confidential_sglang_release.py checks and normalizes it. Without a record, the pin is
the first value under a key that names the engine: an image reference with
a digest, or a mapping with `reference`/`image` and `digest`. A missing pin,
the placeholder record images-000000000000, or an all-zero digest prints
nothing. Then the contract workflow skips the image tests.
"""
from __future__ import annotations

import json

import re
import sys
from pathlib import Path
from typing import Any

import yaml

PINNED = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
PLACEHOLDER = "sha256:" + "0" * 64


def reference(value: Any) -> str | None:
    if isinstance(value, str):
        return value if PINNED.fullmatch(value) else None
    if isinstance(value, dict):
        if isinstance(value.get("image"), str) and PINNED.fullmatch(value["image"]):
            return value["image"]
        name = value.get("reference") or value.get("repository") or value.get("image")
        if isinstance(name, str) and isinstance(value.get("digest"), str):
            candidate = f"{name}@{value['digest']}"
            return candidate if PINNED.fullmatch(candidate) else None
    return None


def find(node: Any) -> str | None:
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and "engine" in key.lower() and (found := reference(value)):
                return found
        for value in node.values():
            if found := find(value):
                return found
    return None


PLACEHOLDER_RECORD = "images-000000000000"


def from_record(spec: dict, inputs: Path) -> str | None:
    """The engine of the pinned confidential-sglang record, or None."""
    section = spec.get("confidentialSglang") if isinstance(spec, dict) else None
    name = section.get("record") if isinstance(section, dict) else None
    if not isinstance(name, str) or name == PLACEHOLDER_RECORD:
        return None
    # The one record parser and checker: scripts/confidential_sglang_release.py. It returns the
    # record normalized (images by component, each with image and digest).
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
    import confidential_sglang_release

    _data, record = confidential_sglang_release.read_record(name, inputs)
    return reference(record["images"]["engine"])


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[3] / "release/spec.yaml"
    inputs = Path(sys.argv[2]) if len(sys.argv) > 2 else path.parent / "inputs/confidential-sglang"
    spec = yaml.safe_load(path.read_text())
    found = from_record(spec, inputs) if isinstance(spec, dict) and "confidentialSglang" in spec else find(spec)
    if found and not found.endswith(PLACEHOLDER):
        print(found)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
