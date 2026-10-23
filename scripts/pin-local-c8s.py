#!/usr/bin/env python3
"""Pin the staging profile to a local c8s build directory.

Usage:

    scripts/pin-local-c8s.py <local-c8s dir> --c8s-repo <c8s checkout>
        [--confos-repo <confidential-os-builder checkout>]

The directory holds the build's node manifest.json and its c8s CLI
(internal deploy/tools/staging-dev-c8s writes it). The CLI's version names the
build: a C8s release tag or the Go pseudo-version of an unsigned dev build.
When release/staging already pins that version and that manifest.json, the
script changes nothing. Otherwise it moves the staging profile with
scripts/bump-c8s.py (--profile staging; it checks out the version's commit in
--c8s-repo) and then requires the new pin to name the directory's
manifest.json. Protocol source changes are accepted for review, as
bump-c8s.py --protocol-review does; the diff is printed.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_profiles

ROOT = Path(__file__).resolve().parents[1]
BUMP = ROOT / "scripts/bump-c8s.py"
STAGING = ROOT / "release/staging"
VERSION = re.compile(r"\bc8s version (v[0-9]+\.[0-9]+\.[0-9]+(?:-beta\.[1-9][0-9]*|-0\.[0-9]{14}-([0-9a-f]{12}))?)\b")


def run(command: list[str], cwd: Path | None = None) -> str:
    return subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True).stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directory", type=Path, help="the local c8s build directory (manifest.json, c8s)")
    parser.add_argument("--c8s-repo", required=True, type=Path, help="a clean c8s checkout")
    parser.add_argument("--confos-repo", type=Path, help="a confidential-os-builder checkout")
    args = parser.parse_args()
    match = VERSION.search(run([str(args.directory / "c8s"), "--version"]))
    if match is None:
        print(f"pin-local-c8s: {args.directory}/c8s reports no c8s release or pseudo-version", file=sys.stderr)
        return 1
    version, commit = match.group(1), match.group(2)
    manifest = "sha256:" + hashlib.sha256((args.directory / "manifest.json").read_bytes()).hexdigest()
    profile = release_profiles.for_directory(STAGING)
    pinned = release_profiles.read_spec(profile)["c8s"]
    if pinned["release"] == version and pinned["nodeManifestArtifact"]["manifestJson"] == manifest:
        print(f"pin-local-c8s: release/staging already pins c8s {version}")
        return 0
    run(["git", "-C", str(args.c8s_repo), "checkout", "-q", "--detach", commit or version])
    with tempfile.TemporaryDirectory() as directory:
        diff = Path(directory) / "protocol.diff"
        command = [sys.executable, str(BUMP), "--tag", version, "--profile", "staging",
                   "--c8s-repo", str(args.c8s_repo), "--protocol-review", "--protocol-diff-out", str(diff)]
        if "-beta." in version:
            command.append("--allow-beta")
        if args.confos_repo is not None:
            command += ["--confos-repo", str(args.confos_repo)]
        result = subprocess.run(command, cwd=ROOT, text=True)
        if result.returncode:
            return result.returncode
        if diff.exists() and diff.stat().st_size:
            print(diff.read_text())
    pinned = release_profiles.read_spec(profile)["c8s"]
    if pinned["nodeManifestArtifact"]["manifestJson"] != manifest:
        print(f"pin-local-c8s: the published c8s {version} node manifest is not {args.directory}/manifest.json",
              file=sys.stderr)
        return 1
    print(f"pin-local-c8s: pinned release/staging to c8s {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
