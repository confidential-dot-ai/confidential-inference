#!/usr/bin/env python3
"""Find the image publication evidence of a release commit.

The evidence of a release is the publication artifact of the nearest
first-parent ancestor of the release commit, the commit itself included,
that a successful release-images run on main published. An unsigned branch
build (release-bundle.yml by workflow_dispatch) also trusts the runs on its
own branch (--branch); a signed release trusts main only. The walk stops at a
commit that changes an image build input: older evidence cannot hold the
images of the release. build-release-manifest.py checks the same boundary.
The selector of the release commit decides what an input is, so a change of
the selector alone is no boundary.

A commit can have more than one trusted run, for example a run by hand and
a run by staging with another base. The lookup then fails, unless the
annotated release tag names one of them with the trailer

    Image-Publication-Run: <workflow run id>

The trailer only selects among trusted runs: a named run must be a trusted
run of the commit that the walk finds.

It prints, for $GITHUB_OUTPUT:

    image_source_commit=<commit>
    artifact_name=release-image-publication-<commit>
    run_id=<workflow run id>
"""

from __future__ import annotations

import argparse
import json
import re
import runpy
import subprocess
import sys
import urllib.parse
from pathlib import Path


class LookupError(ValueError):
    """No unique trusted workflow artifact was found."""


COMMIT = re.compile(r"^[0-9a-f]{40}$")
RUN_TRAILER = re.compile(r"^Image-Publication-Run: *([0-9]+) *$", re.MULTILINE)
ROOT = Path(__file__).resolve().parents[1]
SELECTOR = "scripts/affected-release-images.py"
IMAGE_SELECTOR = runpy.run_path(str(ROOT / SELECTOR))
# The walk gives up after this many commits without evidence.
MAX_COMMITS = 200


def gh_api(path: str) -> dict:
    result = subprocess.run(["gh", "api", path], capture_output=True, text=True, check=False)
    if result.returncode:
        raise LookupError(f"gh api {path} failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def artifact_name(commit: str) -> str:
    return f"release-image-publication-{commit}"


def trusted_runs(
    repository: str,
    artifact_name: str,
    source_commit: str,
    branches: tuple[str, ...] = ("main",),
) -> list[int]:
    if COMMIT.fullmatch(source_commit) is None:
        raise LookupError("source commit must be a full lowercase Git commit")
    query = urllib.parse.urlencode({"name": artifact_name, "per_page": 100})
    artifacts = gh_api(f"repos/{repository}/actions/artifacts?{query}").get("artifacts", [])
    candidates: set[int] = set()
    for artifact in artifacts:
        workflow_run = artifact.get("workflow_run") or {}
        if artifact.get("name") == artifact_name and not artifact.get("expired", True):
            run_id = workflow_run.get("id")
            if isinstance(run_id, int) and run_id > 0:
                candidates.add(run_id)
    trusted: list[int] = []
    for run_id in sorted(candidates):
        run = gh_api(f"repos/{repository}/actions/runs/{run_id}")
        if (
            run.get("event") == "workflow_dispatch"
            and run.get("path") == ".github/workflows/release-images.yml"
            and run.get("conclusion") == "success"
            and run.get("head_branch") in branches
            and run.get("head_sha") == source_commit
            and (run.get("repository") or {}).get("full_name") == repository
        ):
            trusted.append(run_id)
    return trusted


def named_run(repository: str, tag: str) -> int | None:
    """Return the run that the annotated tag names, or None."""
    reference = gh_api(f"repos/{repository}/git/ref/tags/{urllib.parse.quote(tag, safe='')}").get("object") or {}
    if reference.get("type") != "tag":
        return None
    message = gh_api(f"repos/{repository}/git/tags/{reference.get('sha')}").get("message", "")
    matches = RUN_TRAILER.findall(message)
    if len(matches) > 1:
        raise LookupError(f"the {tag} tag names more than one image publication run")
    return int(matches[0]) if matches else None


def git(*args: str, repo: Path = ROOT) -> str:
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=False)
    if result.returncode:
        raise LookupError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def changes_images(commit: str, repo: Path = ROOT) -> bool:
    """Report whether a commit changes an image build input, as the release commit's selector sees it."""
    parents = git("rev-list", "--parents", "-n", "1", commit, repo=repo).split()[1:]
    if not parents:
        return True
    paths = git("diff", "--name-only", "--no-renames", parents[0], commit, repo=repo).splitlines()
    return bool(IMAGE_SELECTOR["affected_images"](paths))


def find_nearest(
    repository: str,
    release_commit: str,
    repo: Path = ROOT,
    selected_run: int | None = None,
    branches: tuple[str, ...] = ("main",),
) -> tuple[str, int]:
    """Return the image source commit and run of the evidence of a release commit.

    With selected_run, the evidence must be that run.
    """
    if COMMIT.fullmatch(release_commit) is None:
        raise LookupError("the release commit must be a full lowercase Git commit")
    commits = git("rev-list", "--first-parent", f"--max-count={MAX_COMMITS}", release_commit,
                  repo=repo).split()
    for commit in commits:
        runs = trusted_runs(repository, artifact_name(commit), commit, branches)
        if runs and selected_run is not None:
            if selected_run not in runs:
                raise LookupError(f"the tag names run {selected_run}, which is not a trusted "
                                  f"release-images run of {commit}: {runs}")
            return commit, selected_run
        if len(runs) > 1:
            raise LookupError(f"found more than one release-images run for {commit}: {runs}; "
                              "name one in the release tag with Image-Publication-Run")
        if runs:
            return commit, runs[0]
        if changes_images(commit, repo):
            raise LookupError(
                f"{commit} changes an image build input, and no successful release-images run "
                f"on {' or '.join(branches)} published its images; run release-images at or after it"
            )
    raise LookupError(f"no image publication in the last {MAX_COMMITS} commits of {release_commit}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--tag", help="The release tag, whose annotation can name the run")
    parser.add_argument("--branch", help="An unsigned branch build: also trust the release-images runs on this branch")
    args = parser.parse_args()
    try:
        selected = named_run(args.repository, args.tag) if args.tag else None
        commit, run_id = find_nearest(
            args.repository, args.release_commit, selected_run=selected,
            branches=("main", args.branch) if args.branch else ("main",),
        )
    except LookupError as error:
        print(f"find-image-publication-run: {error}", file=sys.stderr)
        return 1
    print(f"image_source_commit={commit}")
    print(f"artifact_name={artifact_name(commit)}")
    print(f"run_id={run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
