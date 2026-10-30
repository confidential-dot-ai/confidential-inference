#!/usr/bin/env python3
"""Select the container images affected since a prior release."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_profiles


@dataclass(frozen=True)
class Image:
    image: str
    context: str
    dockerfile: str
    title: str
    paths: tuple[str, ...]

    def matrix_entry(self) -> dict[str, str]:
        return {
            "image": self.image,
            "context": self.context,
            "dockerfile": self.dockerfile,
            "title": self.title,
        }


RUST_IMAGE_INPUTS = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "services/gateway/Cargo.toml",
    "services/gateway/src/**",
    "services/maintenance-gateway/Cargo.toml",
    "services/maintenance-gateway/src/**",
)
# A base is a commit, a release tag, or a legacy release candidate tag.
BASE_REF = re.compile(
    f"[0-9a-f]{{40}}|{release_profiles.tag_pattern().pattern}"
    f"|{release_profiles.VERSION}-rc\\.[1-9][0-9]*"
)
IMAGES = (
    Image(
        "gateway",
        ".",
        "images/gateway/Dockerfile",
        "Confidential Inference gateway",
        (
            *RUST_IMAGE_INPUTS,
            "images/gateway/Dockerfile",
            "images/gateway/Dockerfile.dockerignore",
        ),
    ),
    Image(
        "maintenance-gateway",
        ".",
        "images/maintenance-gateway/Dockerfile",
        "Confidential Inference maintenance gateway",
        (*RUST_IMAGE_INPUTS, "images/maintenance-gateway/Dockerfile"),
    ),
    Image(
        "sglang",
        ".",
        "images/sglang/Dockerfile",
        "Confidential Inference SGLang",
        (
            "images/sglang/Dockerfile",
            "images/sglang/Dockerfile.dockerignore",
            "images/sglang/source.lock",
            "images/sglang/requirements.lock",
            "images/sglang/fetch_source.py",
            "images/sglang/harden_http.py",
            "images/sglang/wait_for_model.py",
            "images/sglang/fetch_model.py",
            "images/sglang/patches/**",
            "images/sglang/simulator-upstream/**",
        ),
    ),
    Image(
        "sglang-router",
        "images/sglang-router",
        "images/sglang-router/Dockerfile",
        "Confidential Inference SGLang Router",
        ("images/sglang-router/Dockerfile", "images/sglang-router/source.lock", "images/sglang-router/patches/**",
         "images/sglang-router/canonicalize_wheel.py", "images/sglang-router/requirements.in", "images/sglang-router/requirements.lock", "images/sglang-router/Cargo.lock"),
    ),
    Image(
        "kube-state-metrics",
        "images/kube-state-metrics",
        "images/kube-state-metrics/Dockerfile",
        "Confidential Inference kube-state metrics",
        ("images/kube-state-metrics/Dockerfile",),
    ),
    Image(
        "rollout-client",
        "images/rollout-client",
        "images/rollout-client/Dockerfile",
        "Confidential Inference rollout client",
        ("images/rollout-client/Dockerfile",),
    ),
)


def affected_images(paths: list[str]) -> list[Image]:
    """Return each affected image once, in stable release order."""
    return [
        image
        for image in IMAGES
        if any(
            fnmatch.fnmatchcase(path, pattern)
            for path in paths
            for pattern in image.paths
        )
    ]


# The SOURCE_DATE_EPOCH of a build stamped by input_revision: 1980-01-01,
# the earliest time a ZIP entry (a wheel) can hold.
INPUT_EPOCH = "315532800"


def input_revision(image: Image, head: str, cwd: str | None = None) -> tuple[str, str]:
    """A content id of the image's inputs at head, and a fixed source epoch.

    The id is the SHA-1 of the image's `git ls-tree -r` lines (mode, object id,
    path). It depends on the input files only, not on the commit that holds
    them, so two commits with the same inputs (a branch and its merge into
    main) give the same image digest, and an upgrade rolls only changed images.
    """
    listing = subprocess.check_output(["git", "ls-tree", "-r", "-z", "--full-tree", head], cwd=cwd)
    entries = [
        entry
        for entry in listing.split(b"\0")
        if entry and any(
            fnmatch.fnmatchcase(entry.split(b"\t", 1)[1].decode(), pattern) for pattern in image.paths
        )
    ]
    if not entries:
        raise ValueError(f"{head} has none of the inputs of {image.image}")
    return hashlib.sha1(b"\0".join(entries)).hexdigest(), INPUT_EPOCH


def changed_paths(base_ref: str, head: str) -> list[str]:
    if BASE_REF.fullmatch(base_ref) is None:
        raise ValueError("base ref must be a full commit or a historical or current release tag")
    subprocess.run(
        ["git", "rev-parse", "--verify", f"{base_ref}^{{commit}}"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", base_ref, head],
        check=True,
    )
    output = subprocess.check_output(
        ["git", "diff", "--name-only", "--diff-filter=ACMRTD", base_ref, head],
        text=True,
    )
    return [path for path in output.splitlines() if path]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args()

    selected = affected_images(changed_paths(args.base_ref, args.head))
    matrix = [
        {**image.matrix_entry(), **dict(zip(("revision", "epoch"), input_revision(image, args.head)))}
        for image in selected
    ]
    large = [entry for entry in matrix if entry["image"] == "sglang"]
    standard = [entry for entry in matrix if entry not in large]
    print("matrix=" + json.dumps({"include": matrix}, separators=(",", ":")))
    print("standard_matrix=" + json.dumps({"include": standard}, separators=(",", ":")))
    # One job per clean build: the audit builds each standard image twice.
    passes = [{**entry, "pass": number} for entry in standard for number in (1, 2)]
    print("standard_pass_matrix=" + json.dumps({"include": passes}, separators=(",", ":")))
    print("sglang=" + str(bool(large)).lower())
    print("large_matrix=" + json.dumps({"include": large}, separators=(",", ":")))
    print("large_pass_matrix=" + json.dumps({"include": [{**entry, "pass": number} for entry in large for number in (1, 2)]}, separators=(",", ":")))
    print("names=" + ",".join(image.image for image in selected))
    print("standard_names=" + ",".join(entry["image"] for entry in standard))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
