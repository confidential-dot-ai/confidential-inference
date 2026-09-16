#!/usr/bin/env python3
"""Validate and copy the exact release bytes for the tag signing job."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from release_signature import (
    RELEASE_RE,
    ROOT,
    ReleaseSignatureError,
    environment_for_tag,
    read_object,
    validate_policy,
    validate_release_schema,
)


COMMIT_RE = re.compile(r"[0-9a-f]{40}")


class PreparationError(ValueError):
    """The source release is not valid for this tag."""


def git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "git rejected the release source"
        raise PreparationError(detail)
    return result.stdout.strip()


def prepare(source: Path, output: Path, tag: str, tag_commit_output: Path | None) -> None:
    if RELEASE_RE.fullmatch(tag) is None:
        raise PreparationError("the release tag is invalid")
    try:
        expected_environment = environment_for_tag(tag)
    except ReleaseSignatureError as error:
        raise PreparationError(str(error)) from error
    source_bytes, release = read_object(source, "source release bundle")
    validate_release_schema(release)
    validate_policy(release)
    metadata = release.get("release")
    source_metadata = release.get("source")
    if not isinstance(metadata, dict) or metadata.get("environment") != expected_environment:
        raise PreparationError("the release environment does not match the protected tag")
    if metadata.get("name") != tag:
        raise PreparationError("the release name differs from the tag")
    source_commit = source_metadata.get("commit") if isinstance(source_metadata, dict) else None
    if not isinstance(source_commit, str) or COMMIT_RE.fullmatch(source_commit) is None:
        raise PreparationError("the recorded source commit is invalid")
    git("cat-file", "-e", f"{source_commit}^{{commit}}")
    tag_commit = git("rev-parse", "HEAD")
    if COMMIT_RE.fullmatch(tag_commit) is None:
        raise PreparationError("the release tag commit is invalid")
    if subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_commit, "HEAD"],
        cwd=ROOT,
        check=False,
    ).returncode != 0:
        raise PreparationError(
            "the recorded source commit is not an ancestor of the release tag; "
            "if the release PR was squash-merged, run "
            "`bin/release <environment> repin-source-commit` in the internal repo "
            "and pin the merge commit on main"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        raise PreparationError("the release output already exists")
    output.write_bytes(source_bytes)
    if tag_commit_output is not None:
        tag_commit_output.parent.mkdir(parents=True, exist_ok=True)
        if tag_commit_output.exists() or tag_commit_output.is_symlink():
            raise PreparationError("the tag-commit output already exists")
        tag_commit_output.write_text(tag_commit + "\n", encoding="ascii")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--tag-commit-output", type=Path)
    result.add_argument("--tag", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        prepare(args.source, args.output, args.tag, args.tag_commit_output)
    except (OSError, PreparationError, ReleaseSignatureError) as error:
        print(f"release preparation failed: {error}", file=sys.stderr)
        return 1
    print(f"release preparation: wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
