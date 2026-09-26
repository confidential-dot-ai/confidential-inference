#!/usr/bin/env python3
"""Find the successful release-images run that owns exact publication evidence."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


class LookupError(ValueError):
    """No unique trusted workflow artifact was found."""


COMMIT = re.compile(r"^[0-9a-f]{40}$")


def request_json(url: str, token: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except (urllib.error.URLError, json.JSONDecodeError) as error:
        raise LookupError(f"GitHub API request failed: {error}") from error


def find_run(
    api_url: str,
    repository: str,
    token: str,
    artifact_name: str,
    source_commit: str,
) -> int:
    if COMMIT.fullmatch(source_commit) is None:
        raise LookupError("source commit must be a full lowercase Git commit")
    query = urllib.parse.urlencode({"name": artifact_name, "per_page": 100})
    artifacts = request_json(
        f"{api_url}/repos/{repository}/actions/artifacts?{query}", token,
    ).get("artifacts", [])
    candidates: set[int] = set()
    for artifact in artifacts:
        workflow_run = artifact.get("workflow_run") or {}
        if artifact.get("name") == artifact_name and not artifact.get("expired", True):
            run_id = workflow_run.get("id")
            if isinstance(run_id, int) and run_id > 0:
                candidates.add(run_id)
    trusted: list[int] = []
    for run_id in sorted(candidates):
        run = request_json(f"{api_url}/repos/{repository}/actions/runs/{run_id}", token)
        if (
            run.get("event") == "workflow_dispatch"
            and run.get("path") == ".github/workflows/release-images.yml"
            and run.get("conclusion") == "success"
            and run.get("head_branch") == "main"
            and run.get("head_sha") == source_commit
            and (run.get("repository") or {}).get("full_name") == repository
        ):
            trusted.append(run_id)
    if len(trusted) != 1:
        raise LookupError(
            f"expected one successful release-images run on main at {source_commit} "
            f"for {artifact_name}; "
            f"found {trusted}"
        )
    return trusted[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    args = parser.parse_args()
    token = os.environ.get(args.token_env, "")
    if not token:
        print(f"find-image-publication-run: {args.token_env} is absent", file=sys.stderr)
        return 1
    try:
        run_id = find_run(
            args.api_url.rstrip("/"), args.repository, token,
            args.artifact_name, args.source_commit,
        )
    except LookupError as error:
        print(f"find-image-publication-run: {error}", file=sys.stderr)
        return 1
    print(run_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
