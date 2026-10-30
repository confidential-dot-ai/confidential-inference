#!/usr/bin/env python3
"""Fetch the locked SGLang source for the DeepSeek-V4.1 image.

The image build runs this in its `source` stage. The source is an explicit,
pinned build input: one commit of the Sglang-public fork, from source.lock.
Nothing else from the network reaches the source tree. The fork is public,
so the fetch needs no credentials.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

COMMIT = re.compile(r"[0-9a-f]{40}")


class LockError(ValueError):
    pass


def check_lock(lock: dict) -> None:
    """Validate the source pin: one GitHub repository, one full commit, nothing applied on top."""
    source = lock.get("source") or {}
    repository = source.get("repository", "")
    if not repository.startswith("https://github.com/"):
        raise LockError("source.repository must be an https://github.com/ URL")
    if not COMMIT.fullmatch(source.get("commit", "")):
        raise LockError("source.commit must be a full 40-hex commit")
    if "patches" in source:
        raise LockError("source.patches is not supported: pin a commit of the fork instead")


def git(*args: str, cwd: Path, env: dict | None = None) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, check=True, text=True, stdout=subprocess.PIPE
    ).stdout.strip()


def fetch(lock: dict, out: Path) -> dict:
    check_lock(lock)
    source = lock["source"]
    out.mkdir(parents=True)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    git("init", "-q", ".", cwd=out)
    git("remote", "add", "origin", source["repository"], cwd=out)
    git("fetch", "-q", "--depth=1", "origin", source["commit"], cwd=out, env=env)
    git("checkout", "-q", "--detach", "FETCH_HEAD", cwd=out)
    head = git("rev-parse", "HEAD", cwd=out)
    if head != source["commit"]:
        raise LockError(f"fetched {head}, expected {source['commit']}")
    record = {"repository": source["repository"], "commit": head}
    shutil.rmtree(out / ".git")
    (out / "SOURCE_RECORD.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    lock = json.loads((args.recipe / "source.lock").read_text(encoding="utf-8"))
    try:
        record = fetch(lock, args.out)
    except (LockError, subprocess.CalledProcessError) as error:
        print(f"fetch-source: {error}", file=sys.stderr)
        return 1
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
