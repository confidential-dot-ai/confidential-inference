#!/usr/bin/env python3
"""Rebuild public release images once and compare them with release digests."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OWNED_PREFIX = "ghcr.io/confidential-dot-ai/confidential-inference/"
SOURCE_REPOSITORY = "https://github.com/confidential-dot-ai/confidential-inference"
BUILDKIT_IMAGE = (
    "moby/buildkit@sha256:"
    "28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
)
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
IMAGE_TITLES = {
    "gateway": "Confidential Inference gateway",
    "sglang": "Confidential Inference stock SGLang",
    "maintenance-gateway": "Confidential Inference maintenance gateway",
    "metrics-collector": "Confidential Inference metrics collector",
    "kube-state-metrics": "Confidential Inference kube-state metrics",
}


class AuditError(ValueError):
    """The release cannot be rebuilt from the recorded public source."""


def run(command: list[str], cwd: Path = ROOT) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise AuditError(f"{command[0]} failed: {detail}")
    return result.stdout.strip()


def read_bundle(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuditError("the release bundle is not valid JSON") from error
    if not isinstance(value, dict) or not isinstance(value.get("workloads"), list):
        raise AuditError("the release bundle has no workload list")
    return value


def release_images(bundle: dict[str, Any]) -> list[dict[str, str]]:
    unique: dict[tuple[str, str], dict[str, str]] = {}
    for workload in bundle["workloads"]:
        image = workload.get("image", {})
        reference = image.get("reference")
        digest = image.get("digest")
        if not isinstance(reference, str) or not reference.startswith(OWNED_PREFIX):
            continue
        build = workload.get("build")
        if not isinstance(build, dict):
            raise AuditError(f"{workload.get('name', 'workload')} has no build record")
        record = {
            "name": reference.removeprefix(OWNED_PREFIX),
            "reference": reference,
            "digest": str(digest),
            "repository": str(build.get("repository", "")),
            "commit": str(build.get("commit", "")),
            "context": str(build.get("context", "")),
            "dockerfile": str(build.get("dockerfile", "")),
            "platform": str(build.get("platform", "")),
        }
        if DIGEST.fullmatch(record["digest"]) is None:
            raise AuditError(f"{record['name']} has an invalid digest")
        if COMMIT.fullmatch(record["commit"]) is None:
            raise AuditError(f"{record['name']} has an invalid source commit")
        if record["repository"].removesuffix(".git") != SOURCE_REPOSITORY:
            raise AuditError(f"{record['name']} points to another source repository")
        if record["platform"] != "linux/amd64":
            raise AuditError(f"{record['name']} does not use linux/amd64")
        if not record["context"] or not record["dockerfile"]:
            raise AuditError(f"{record['name']} has an incomplete build record")
        if record["name"] not in IMAGE_TITLES:
            raise AuditError(f"{record['name']} has no public release title")
        key = (reference, record["digest"])
        previous = unique.get(key)
        if previous is not None and previous != record:
            raise AuditError(f"{record['name']} has conflicting build records")
        unique[key] = record
    if not unique:
        raise AuditError("the release contains no repository-owned images")
    return sorted(unique.values(), key=lambda item: item["name"])


def extra_build_args(name: str, source: Path) -> list[str]:
    """Return image-specific build-args a Dockerfile requires beyond the shared ones."""
    del name, source
    return []


def extract_commit(commit: str, destination: Path) -> None:
    run(["git", "cat-file", "-e", f"{commit}^{{commit}}"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    archive_path = destination.with_suffix(".tar")
    with archive_path.open("wb") as archive:
        result = subprocess.run(
            ["git", "archive", "--format=tar", commit],
            cwd=ROOT,
            stdout=archive,
            stderr=subprocess.PIPE,
        )
    if result.returncode:
        raise AuditError(f"git archive failed: {result.stderr.decode().strip()}")
    destination.mkdir(parents=True)
    with tarfile.open(archive_path) as archive:
        archive.extractall(destination, filter="data")
    archive_path.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--image",
        action="append",
        help="rebuild one image name from the bundle; repeat to select more",
    )
    args = parser.parse_args()
    builder = f"confidential-inference-rebuild-{os.getpid()}"
    builder_created = False
    try:
        for command in ("docker", "git"):
            if shutil.which(command) is None:
                raise AuditError(f"{command} is not installed")
        output = args.output.resolve()
        if output.exists():
            raise AuditError("the output path already exists")
        output.mkdir(parents=True)
        records = release_images(read_bundle(args.bundle))
        if args.image:
            selected = set(args.image)
            unknown = selected - {item["name"] for item in records}
            if unknown:
                raise AuditError(f"unknown image selection: {', '.join(sorted(unknown))}")
            records = [item for item in records if item["name"] in selected]
        run([
            "docker", "buildx", "create", "--name", builder,
            "--driver", "docker-container", "--driver-opt", f"image={BUILDKIT_IMAGE}",
        ])
        builder_created = True
        run(["docker", "buildx", "inspect", "--builder", builder, "--bootstrap"])
        sources: dict[str, Path] = {}
        results: list[dict[str, str]] = []
        failed = False
        for record in records:
            commit = record["commit"]
            source = sources.get(commit)
            if source is None:
                source = output / "source" / commit
                extract_commit(commit, source)
                sources[commit] = source
            epoch = run(["git", "show", "-s", "--format=%ct", commit])
            archive = output / f"{record['name']}.oci.tar"
            run([
                "docker", "buildx", "build", "--builder", builder,
                "--no-cache", "--platform", record["platform"],
                "--file", str(source / record["dockerfile"]),
                "--build-arg", f"SOURCE_REVISION={commit}",
                "--build-arg", f"SOURCE_DATE_EPOCH={epoch}",
                *extra_build_args(record["name"], source),
                "--output", f"type=oci,dest={archive},rewrite-timestamp=true",
                "--label", f"org.opencontainers.image.title={IMAGE_TITLES[record['name']]}",
                "--label", f"org.opencontainers.image.source={SOURCE_REPOSITORY}",
                "--label", f"org.opencontainers.image.revision={commit}",
                "--label", f"org.opencontainers.image.version=sha-{commit}",
                "--provenance=false", "--sbom=false",
                str(source / record["context"]),
            ])
            verification = subprocess.run(
                [
                    "python3", str(ROOT / "scripts/verify-reproducible-oci.py"),
                    str(archive), "--platform", record["platform"],
                    "--revision", commit, "--source-date-epoch", epoch,
                    "--expected-digest", record["digest"],
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            status = "matched" if verification.returncode == 0 else "mismatch"
            failed = failed or verification.returncode != 0
            results.append({
                "name": record["name"],
                "image": f"{record['reference']}@{record['digest']}",
                "commit": commit,
                "status": status,
                "detail": (verification.stdout or verification.stderr).strip(),
            })
        report = {
            "schema": "confidential.ai/rebuilt-release-images/v1",
            "bundle": str(args.bundle),
            "images": results,
            "verified": not failed,
        }
        (output / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1 if failed else 0
    except AuditError as error:
        print(f"rebuild-release-images: {error}", file=sys.stderr)
        return 1
    finally:
        if builder_created:
            subprocess.run(
                ["docker", "buildx", "rm", builder],
                cwd=ROOT,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    raise SystemExit(main())
