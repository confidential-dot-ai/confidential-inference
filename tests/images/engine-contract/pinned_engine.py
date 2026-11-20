#!/usr/bin/env python3
"""Print the engine image that release/spec.yaml pins, or nothing.

The pin is the first value under a key that names the engine (for example
`images.engine` or `confidentialSglang.engine`): an image reference with a
digest, or a mapping with `reference`/`image` and `digest`. A missing pin,
or a placeholder digest (all zeros), prints nothing. Then the contract
workflow skips the image tests.
"""
from __future__ import annotations

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
        name = value.get("reference") or value.get("repository")
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


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[3] / "release/spec.yaml"
    found = find(yaml.safe_load(path.read_text()))
    if found and not found.endswith(PLACEHOLDER):
        print(found)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
