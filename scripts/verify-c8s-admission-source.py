#!/usr/bin/env python3
"""Verify the exact c8s source files that support admission receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class SourceError(ValueError):
    """The c8s source does not match the approved source lock."""


ENTRY_FIELDS = {"commit", "nodeImage", "c8sOperatorImage", "requiredVerifierFlags", "files"}


def read_lock(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SourceError("the source lock is not valid JSON") from error
    required_fields = {"schema"} | ENTRY_FIELDS
    if not isinstance(value, dict) or set(value) not in (
        required_fields,
        required_fields | {"candidate"},
        required_fields | {"commits"},
        required_fields | {"candidate", "commits"},
    ):
        raise SourceError("the source lock fields are invalid")
    if value["schema"] != "confidential-inference.c8s-admission-source-lock/v1":
        raise SourceError("the source lock schema is invalid")
    seen_commits: set[str] = set()
    validate_entry(value, seen_commits)
    if "commits" in value:
        commits = value["commits"]
        if not isinstance(commits, list) or not commits:
            raise SourceError("the source lock commits list is invalid")
        for entry in commits:
            if not isinstance(entry, dict) or set(entry) not in (
                ENTRY_FIELDS, ENTRY_FIELDS | {"candidate"},
            ):
                raise SourceError("the source lock commits list contains invalid fields")
            validate_entry(entry, seen_commits)
    return value


def validate_entry(value: dict[str, Any], seen_commits: set[str]) -> None:
    """Validate one pinned-commit entry (the top-level entry, or one item of
    the `commits` list) and record its commit in `seen_commits`.

    Every signed release must use a c8s commit that is one of these entries;
    an unlisted commit must never verify.
    """
    if not isinstance(value["commit"], str) or not COMMIT_RE.fullmatch(value["commit"]):
        raise SourceError("the source lock commit is invalid")
    if value["commit"] in seen_commits:
        raise SourceError("the source lock pins the same commit twice")
    seen_commits.add(value["commit"])
    for field in ("nodeImage", "c8sOperatorImage"):
        image = value[field]
        reference, separator, digest = image.rpartition("@") if isinstance(image, str) else ("", "", "")
        if not separator or not reference or not DIGEST_RE.fullmatch(digest):
            raise SourceError(f"the source lock {field} is not digest-pinned")
    files = value["files"]
    if not isinstance(files, dict) or not files:
        raise SourceError("the source lock has no files")
    for name, digest in files.items():
        path_value = Path(name)
        if (
            not isinstance(name, str)
            or path_value.is_absolute()
            or ".." in path_value.parts
            or not isinstance(digest, str)
            or not DIGEST_RE.fullmatch(digest)
        ):
            raise SourceError("the source lock contains an invalid file record")
    flags = value["requiredVerifierFlags"]
    if not isinstance(flags, list) or not flags or any(
        not isinstance(flag, str) or not flag.startswith("--") for flag in flags
    ) or len(set(flags)) != len(flags):
        raise SourceError("the source lock verifier flags are invalid")
    if "candidate" in value:
        candidate = value["candidate"]
        if (
            not isinstance(candidate, dict)
            or set(candidate) not in ({"status", "commit"}, {"status", "commit", "sourceChecks"})
            or candidate.get("status") not in {"staging-only", "release-ready"}
            or not isinstance(candidate.get("commit"), str)
            or not COMMIT_RE.fullmatch(candidate["commit"])
            or candidate["commit"] == value["commit"]
        ):
            raise SourceError("the c8s staging candidate is invalid")
        if "sourceChecks" in candidate:
            checks = candidate["sourceChecks"]
            if (
                not isinstance(checks, dict)
                or set(checks) != {"status", "files", "content"}
                or checks["status"] not in {"pending-final-integration", "verified"}
                or not isinstance(checks["files"], list)
                or not checks["files"]
                or any(not isinstance(name, str) or not _safe_relative_path(name) for name in checks["files"])
                or len(set(checks["files"])) != len(checks["files"])
                or not isinstance(checks["content"], dict)
            ):
                raise SourceError("the c8s candidate source checks are invalid")
            if set(checks["content"]) != set(checks["files"]):
                raise SourceError("the c8s candidate source checks do not cover every file")
            for name, markers in checks["content"].items():
                if not isinstance(markers, list) or not markers or any(
                    not isinstance(marker, str) or not marker for marker in markers
                ):
                    raise SourceError("the c8s candidate source markers are invalid")
            if candidate["status"] == "release-ready" and checks["status"] != "verified":
                raise SourceError("the release-ready c8s candidate source checks are not verified")
        elif candidate["status"] == "release-ready":
            raise SourceError("the release-ready c8s candidate has no source checks")


def _safe_relative_path(name: str) -> bool:
    path = Path(name)
    return not path.is_absolute() and ".." not in path.parts


def git(repository: Path, arguments: list[str]) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
        )
    except OSError as error:
        raise SourceError("git did not run") from error
    if result.returncode:
        raise SourceError("git could not read the pinned c8s commit")
    return result.stdout


def select_entry(lock: dict[str, Any], commit: str | None) -> dict[str, Any]:
    """Return the pinned entry to verify against.

    With no `--commit`, the top-level entry is used (unchanged behavior for
    every existing caller). With `--commit`, the top-level entry or one entry
    of the `commits` list whose `commit` field matches is used; an unlisted
    commit fails closed rather than silently falling back.
    """
    if commit is None:
        return lock
    if lock["commit"] == commit:
        return lock
    for entry in lock.get("commits", []):
        if entry["commit"] == commit:
            return entry
    raise SourceError("the requested c8s commit is not pinned in the source lock")


def verify(repository: Path, lock_path: Path, commit: str | None = None) -> dict[str, Any]:
    if not repository.is_dir() or repository.is_symlink():
        raise SourceError("the c8s repository is invalid")
    lock = select_entry(read_lock(lock_path), commit)
    commit = lock["commit"]
    resolved = git(repository, ["rev-parse", f"{commit}^{{commit}}"])
    if resolved.decode("ascii", "strict").strip() != commit:
        raise SourceError("git resolved a different c8s commit")
    verified: dict[str, str] = {}
    for name, expected in sorted(lock["files"].items()):
        value = git(repository, ["show", f"{commit}:{name}"])
        actual = "sha256:" + hashlib.sha256(value).hexdigest()
        if actual != expected:
            raise SourceError(f"the pinned c8s source differs at {name}")
        verified[name] = actual
    candidate = lock.get("candidate")
    candidate_checks = candidate.get("sourceChecks") if candidate is not None else None
    candidate_status = "not-declared"
    if candidate_checks is not None:
        # The current candidate is intentionally not trusted as a release. The
        # final c8s integration must update its commit and status, then this
        # verifier checks the proxy alias and complete helper inventory source.
        candidate_status = candidate_checks["status"]
        if candidate["status"] == "release-ready":
            candidate_commit = candidate["commit"]
            resolved_candidate = git(repository, ["rev-parse", f"{candidate_commit}^{{commit}}"])
            if resolved_candidate.decode("ascii", "strict").strip() != candidate_commit:
                raise SourceError("git resolved a different c8s candidate commit")
            for name in candidate_checks["files"]:
                value = git(repository, ["show", f"{candidate_commit}:{name}"])
                for marker in candidate_checks["content"][name]:
                    if marker.encode() not in value:
                        raise SourceError(f"the c8s candidate source lacks {marker!r} in {name}")
    return {
        "verified": True,
        "commit": commit,
        "nodeImage": lock["nodeImage"],
        "c8sOperatorImage": lock["c8sOperatorImage"],
        "files": verified,
        "candidateSourceStatus": candidate_status,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument(
        "--lock",
        type=Path,
        default=Path("contracts/c8s-admission-source-lock.json"),
    )
    parser.add_argument(
        "--commit",
        default=None,
        help="the pinned c8s commit to verify; defaults to the lock's top-level commit",
    )
    try:
        args = parser.parse_args()
        result = verify(args.repository, args.lock, args.commit)
    except (SourceError, UnicodeError) as error:
        print(f"source verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
