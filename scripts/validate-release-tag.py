#!/usr/bin/env python3
"""Validate a production release tag against release/spec.yaml.

A production release tag is vX.Y.Z. There are no release candidates: a fix is
a new version. The tag must point to a commit on main, and release/spec.yaml
at that commit must name the same version.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml


TAG_RE = re.compile(
    r"v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
)


class ReleaseTagError(ValueError):
    """The release tag is not valid."""


def parse_tag(tag: str) -> str:
    if TAG_RE.fullmatch(tag) is None:
        raise ReleaseTagError(
            "the production release tag must use vX.Y.Z, with no release-candidate suffix"
        )
    return tag


def read_spec_version(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ReleaseTagError("release/spec.yaml must be a regular file")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ReleaseTagError("release/spec.yaml is not valid YAML") from error
    version = value.get("version") if isinstance(value, dict) else None
    if not isinstance(version, str):
        raise ReleaseTagError("release/spec.yaml has no version")
    return version


def require_commit_on_main(main_ref: str) -> None:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", "HEAD", main_ref],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip()
        if detail:
            raise ReleaseTagError(f"cannot verify the main branch: {detail}")
        raise ReleaseTagError("the release tag does not point to a commit on main")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--tag", required=True)
    result.add_argument("--spec", type=Path, default=Path("release/spec.yaml"))
    result.add_argument("--main-ref", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        tag = parse_tag(args.tag)
        if read_spec_version(args.spec) != tag:
            raise ReleaseTagError("release/spec.yaml names a different version than the tag")
        require_commit_on_main(args.main_ref)
    except (OSError, ReleaseTagError) as error:
        print(f"release tag validation failed: {error}", file=sys.stderr)
        return 1
    print(f"release tag validation: {args.tag} is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
