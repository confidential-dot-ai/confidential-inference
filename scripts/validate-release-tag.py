#!/usr/bin/env python3
"""Validate a release tag against its release profile.

A release tag is vX.Y.Z followed by the tag suffix of one release profile
(release/profiles.json). There are no release candidates: a fix is a new
version. The tag must point to a commit on main, and the specification of the
profile at that commit must name the same version.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_profiles

TAG_RE = release_profiles.tag_pattern()


class ReleaseTagError(ValueError):
    """The release tag is not valid."""


def parse_tag(tag: str) -> str:
    if TAG_RE.fullmatch(tag) is None:
        suffixes = ", ".join(f"vX.Y.Z{p.tag_suffix}" for p in release_profiles.load())
        raise ReleaseTagError(f"the release tag must use one of: {suffixes}")
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
    result.add_argument("--spec", type=Path,
                        help="the specification that names the version (default: the profile of the tag)")
    result.add_argument("--main-ref", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        tag = parse_tag(args.tag)
        profile = release_profiles.for_tag(tag)
        spec = args.spec or profile.spec_files[-1]
        if read_spec_version(spec) != tag:
            raise ReleaseTagError(f"{spec} names a different version than the tag")
        require_commit_on_main(args.main_ref)
    except (OSError, ReleaseTagError) as error:
        print(f"release tag validation failed: {error}", file=sys.stderr)
        return 1
    print(f"release tag validation: {args.tag} is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
