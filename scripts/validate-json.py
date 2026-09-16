#!/usr/bin/env python3
"""Parse each repository JSON file that Git includes in a clean checkout."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def repository_json_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [ROOT / name for name in result.stdout.splitlines()]


def main() -> int:
    failures: list[str] = []
    files = repository_json_files()
    for path in files:
        try:
            with path.open(encoding="utf-8") as source:
                json.load(source)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            failures.append(f"{path.relative_to(ROOT)}: {error}")

    if failures:
        print("Invalid JSON files:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Parsed {len(files)} JSON files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
