#!/usr/bin/env python3
"""Select the container images affected since a prior release."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_spec


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
# A base is a commit, a release tag (also of the earlier -staging and
# -transition forms), or a legacy release candidate tag.
BASE_REF = re.compile(
    f"[0-9a-f]{{40}}|{release_spec.HISTORICAL_TAG.pattern}"
    f"|{release_spec.VERSION}-rc\\.[1-9][0-9]*"
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
    matrix = [image.matrix_entry() for image in selected]
    print("matrix=" + json.dumps({"include": matrix}, separators=(",", ":")))
    # One job per clean build: the audit builds each image twice.
    passes = [{**entry, "pass": number} for entry in matrix for number in (1, 2)]
    print("pass_matrix=" + json.dumps({"include": passes}, separators=(",", ":")))
    print("names=" + ",".join(image.image for image in selected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
