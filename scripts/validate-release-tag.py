#!/usr/bin/env python3
"""Validate a release tag against its release profile.

A release tag is vX.Y.Z followed by the tag suffix of one release profile
(release/profiles.json). There are no release candidates: a fix is a new
version. The tag must point to a commit on main. The tag is the version: the
release build takes it from the tag, so a release needs no commit that
changes a version.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_profiles


class ReleaseTagError(ValueError):
    """The release tag is not valid."""


def parse_tag(tag: str) -> str:
    try:
        release_profiles.for_tag(tag)
        return tag
    except release_profiles.ProfileError:
        suffixes = ", ".join(f"vX.Y.Z{p.tag_suffix}" for p in release_profiles.load())
        raise ReleaseTagError(f"the release tag must use one of: {suffixes}") from None


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
    result.add_argument("--main-ref", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        parse_tag(args.tag)
        require_commit_on_main(args.main_ref)
    except (OSError, ReleaseTagError) as error:
        print(f"release tag validation failed: {error}", file=sys.stderr)
        return 1
    print(f"release tag validation: {args.tag} is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
