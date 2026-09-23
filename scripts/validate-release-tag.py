#!/usr/bin/env python3
"""Validate a production release tag and its release promotion input."""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


FINAL_TAG_RE = re.compile(
    r"v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
)
RC_TAG_RE = re.compile(
    rf"(?P<final>{FINAL_TAG_RE.pattern})-rc\.(?P<number>[1-9][0-9]*)"
)
MAX_BUNDLE_BYTES = 2 * 1024 * 1024


class ReleaseTagError(ValueError):
    """The release tag or promotion input is not valid."""


def parse_tag(tag: str) -> tuple[str, int | None]:
    if FINAL_TAG_RE.fullmatch(tag) is not None:
        return tag, None
    match = RC_TAG_RE.fullmatch(tag)
    if match is not None:
        return match.group("final"), int(match.group("number"))
    raise ReleaseTagError(
        "the production release tag must use vX.Y.Z or vX.Y.Z-rc.N"
    )


def read_bundle(path: Path, expected_tag: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ReleaseTagError("the release bundle must be a regular file")
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ReleaseTagError("the release bundle is too large")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseTagError("the release bundle is not valid JSON") from error
    if not isinstance(value, dict):
        raise ReleaseTagError("the release bundle must contain one JSON object")
    release = value.get("release")
    if not isinstance(release, dict) or release.get("name") != expected_tag:
        raise ReleaseTagError("the release bundle name differs from the tag")
    return value


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


def require_same_release(
    candidate: dict[str, Any], final: dict[str, Any]
) -> None:
    candidate_copy = copy.deepcopy(candidate)
    final_copy = copy.deepcopy(final)
    candidate_copy["release"]["name"] = "vX.Y.Z"
    final_copy["release"]["name"] = "vX.Y.Z"
    if candidate_copy != final_copy:
        raise ReleaseTagError(
            "the final release differs from the selected release candidate"
        )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--tag", required=True)
    result.add_argument("--bundle", type=Path, required=True)
    result.add_argument("--main-ref", required=True)
    result.add_argument("--candidate-tag")
    result.add_argument("--candidate-bundle", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        final_tag, candidate_number = parse_tag(args.tag)
        bundle = read_bundle(args.bundle, args.tag)
        require_commit_on_main(args.main_ref)
        if candidate_number is None:
            if args.candidate_tag is None or args.candidate_bundle is None:
                raise ReleaseTagError(
                    "a final release requires a published release candidate"
                )
            candidate_final, selected_number = parse_tag(args.candidate_tag)
            if selected_number is None or candidate_final != final_tag:
                raise ReleaseTagError(
                    "the selected release candidate does not match the final version"
                )
            candidate = read_bundle(args.candidate_bundle, args.candidate_tag)
            require_same_release(candidate, bundle)
        elif args.candidate_tag is not None or args.candidate_bundle is not None:
            raise ReleaseTagError(
                "a release candidate cannot select another release candidate"
            )
    except (OSError, ReleaseTagError) as error:
        print(f"release tag validation failed: {error}", file=sys.stderr)
        return 1
    print(f"release tag validation: {args.tag} is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
