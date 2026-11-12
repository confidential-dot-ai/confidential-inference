#!/usr/bin/env python3
"""Read the framework release inputs, and describe one deployment's inputs.

The framework release is the product: release/spec.yaml pins the C8s release,
its node image, and every image that the chart can run. A release tag
`vX.Y.Z` releases the tagged tree. The repository holds no deployment value.

A deployment is the private input set of one installation: Helm values files,
an allowlist policy, and optionally the accepted lint findings. The operator
of the installation keeps them. scripts/render-allowlist.py renders the
allowlist of a deployment from a verified framework release.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "release/spec.yaml"
NODE_MANIFEST = ROOT / "release/node-manifest.json"
IMAGE_CONFIG = ROOT / "release/inputs/image-config.json"
# The registry of the images that this repository builds. spec.yaml names
# these images without a digest; the release build adds the published digest.
REPOSITORY_IMAGES = "ghcr.io/confidential-dot-ai/confidential-inference/"
VERSION = r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
# A framework release tag.
TAG = re.compile(VERSION)
# Every tag that a signed release used, for reading the base release of an
# image publication. Earlier releases had -staging and -transition tags.
HISTORICAL_TAG = re.compile(VERSION + r"(?:-transition)?(?:-staging)?")


class SpecError(ValueError):
    """The release inputs are invalid."""


def read_spec(path: Path = SPEC) -> dict[str, Any]:
    import yaml

    try:
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise SpecError(f"cannot read {path}: {error}") from error
    if not isinstance(spec, dict):
        raise SpecError(f"{path} is not a mapping")
    return spec


def merge_values(base: Any, layer: Any) -> Any:
    """Merge Helm values: maps merge by key, any other value replaces."""
    if isinstance(base, dict) and isinstance(layer, dict):
        merged = dict(base)
        for key, value in layer.items():
            merged[key] = merge_values(base.get(key), value) if key in base else value
        return merged
    return layer


@dataclass(frozen=True)
class Deployment:
    """The inputs of one deployment, outside this repository or in a test fixture."""

    values_files: tuple[Path, ...]
    policy: Path
    accepted_findings: Path | None = None

    def relative(self, path: Path) -> str:
        path = path.resolve()
        return path.relative_to(ROOT).as_posix() if ROOT in path.parents else str(path)

    def read_values(self) -> dict[str, Any]:
        import yaml

        values: dict[str, Any] = {}
        for path in self.values_files:
            values = merge_values(values, yaml.safe_load(path.read_text(encoding="utf-8")) or {})
        return values

    def helm_values_args(self, overlay: Path | None = None) -> list[str]:
        """Give helm each values file in order, then the overlay."""
        files = [*self.values_files, *([overlay] if overlay is not None else [])]
        return [argument for path in files for argument in ("--values", str(path))]
