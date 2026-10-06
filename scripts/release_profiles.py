#!/usr/bin/env python3
"""Read the release profiles in release/profiles.json.

A profile is one kind of release. It names its tag suffix, the environment
that its signed manifest states, the GitHub environment that signs it, and
its layers. A layer is a directory that can hold spec.yaml and values.yaml.
The tools apply the layers in order:

- spec.yaml: a later layer replaces each top-level key that it sets;
- values.yaml: Helm merges the files in order, so a later layer replaces
  each value that it sets and keeps the other values.

The last layer is the profile directory. It holds the files that belong to
that profile only: allowlist-policy.json and accepted-lint-findings.json. The
node manifest is in the layer that sets `c8s`. The image configuration is
shared by all profiles.

The values name each repository image without a digest. The release build
takes the digests from the image publication evidence and gives them to Helm
as one more values file after the layers (`helm_values_args(overlay=...)`).

Usage:

    scripts/release_profiles.py resolve --tag v0.14.0-staging
    scripts/release_profiles.py resolve --release release/staging --format github
"""

from __future__ import annotations

import argparse
import functools
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ROOT / "release/profiles.json"
IMAGE_CONFIG = ROOT / "release/inputs/image-config.json"
# The registry of the images that this repository builds. Release values name
# these images without a digest; the release build adds the published digest.
REPOSITORY_IMAGES = "ghcr.io/confidential-dot-ai/confidential-inference/"
SCHEMA = "confidential.ai/release-profiles/v1"
VERSION = r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
NAME = re.compile(r"^[a-z][a-z0-9-]*$")
SUFFIX = re.compile(r"^(?:-[a-z][a-z0-9]*)?$")


class ProfileError(ValueError):
    """The release profiles are invalid, or no profile matches."""


@dataclass(frozen=True)
class Profile:
    name: str
    tag_suffix: str
    environment: str
    signing_environment: str
    layers: tuple[Path, ...]

    @property
    def directory(self) -> Path:
        return self.layers[-1]

    @property
    def policy(self) -> Path:
        return self.directory / "allowlist-policy.json"

    @property
    def accepted_findings(self) -> Path:
        return self.directory / "accepted-lint-findings.json"

    @property
    def allowlist(self) -> Path:
        """The name that the release manifest gives the generated allowlist.

        The release build generates the allowlist and publishes it as the
        release asset allowlist.json. It is not in the repository.
        """
        return self.directory / "allowlist.json"

    @property
    def release_values(self) -> Path:
        """The name that the release manifest gives the generated values overlay.

        The release build generates it and publishes it as the release asset
        release-values.yaml. It is not in the repository.
        """
        return self.directory / "release-values.yaml"

    @property
    def spec_files(self) -> list[Path]:
        return [layer / "spec.yaml" for layer in self.layers if (layer / "spec.yaml").is_file()]

    @property
    def values_files(self) -> list[Path]:
        return [layer / "values.yaml" for layer in self.layers if (layer / "values.yaml").is_file()]

    def relative(self, path: Path) -> str:
        return path.relative_to(ROOT).as_posix()


@functools.cache
def load(path: Path = PROFILES) -> tuple[Profile, ...]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProfileError(f"cannot read {path}: {error}") from error
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        raise ProfileError(f"{path} has the wrong schema")
    profiles = []
    for item in document.get("profiles", []):
        fields = {"name", "tagSuffix", "environment", "signingEnvironment", "layers"}
        if not isinstance(item, dict) or set(item) != fields:
            raise ProfileError(f"a profile must hold exactly {sorted(fields)}")
        if NAME.fullmatch(str(item["name"])) is None or SUFFIX.fullmatch(str(item["tagSuffix"])) is None:
            raise ProfileError(f"profile {item['name']!r} has an invalid name or tag suffix")
        layers = item["layers"]
        if not isinstance(layers, list) or not layers or layers[0] != "release":
            raise ProfileError(f"profile {item['name']} must start from the release layer")
        resolved = tuple((ROOT / layer).resolve() for layer in layers)
        if any(ROOT / "release" not in (*layer.parents, layer) or not layer.is_dir() for layer in resolved):
            raise ProfileError(f"profile {item['name']} has a layer outside release/")
        profiles.append(Profile(item["name"], item["tagSuffix"], item["environment"],
                                item["signingEnvironment"], resolved))
    for field in ("name", "tag_suffix", "directory"):
        values = [getattr(profile, field) for profile in profiles]
        if not values or len(set(values)) != len(values):
            raise ProfileError(f"the release profiles repeat a {field.replace('_', ' ')}")
    return tuple(profiles)


def tag_pattern() -> re.Pattern[str]:
    """Match every release tag that a profile accepts."""
    suffixes = sorted((re.escape(p.tag_suffix) for p in load()), key=len, reverse=True)
    return re.compile(f"{VERSION}(?:{'|'.join(suffixes)})")


def for_tag(tag: str) -> Profile:
    # A longer suffix first: every tag also ends with the empty suffix.
    for profile in sorted(load(), key=lambda p: len(p.tag_suffix), reverse=True):
        version = tag[:len(tag) - len(profile.tag_suffix)]
        if tag.endswith(profile.tag_suffix) and re.fullmatch(VERSION, version):
            return profile
    raise ProfileError(f"no release profile accepts the tag {tag!r}")


def for_directory(path: Path) -> Profile:
    directory = (path if path.is_absolute() else ROOT / path).resolve()
    for profile in load():
        if profile.directory == directory:
            return profile
    raise ProfileError(f"no release profile has the directory {path}")


def read_spec(profile: Profile) -> dict[str, Any]:
    """Return the profile specification: each layer replaces the keys it sets."""
    import yaml

    spec: dict[str, Any] = {}
    for path in profile.spec_files:
        try:
            layer = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            raise ProfileError(f"cannot read {path}: {error}") from error
        if not isinstance(layer, dict):
            raise ProfileError(f"{path} is not a mapping")
        spec.update(layer)
    return spec


def owning_file(files: list[Path], key_path: tuple[str, ...]) -> Path:
    """Return the last of the layer files that sets the key path."""
    import yaml

    for path in reversed(files):
        current: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for key in key_path:
            current = current.get(key) if isinstance(current, dict) else None
        if current is not None:
            return path
    raise ProfileError(f"no layer file sets {'.'.join(key_path)}: {[str(path) for path in files]}")


def spec_layer(profile: Profile, key: str) -> Path:
    """Return the last layer whose spec.yaml sets `key`."""
    return owning_file(profile.spec_files, (key,)).parent


def node_manifest(profile: Profile) -> Path:
    """The node manifest belongs to the c8s pins, so it is in their layer."""
    return spec_layer(profile, "c8s") / "node-manifest.json"


def merge_values(base: Any, layer: Any) -> Any:
    """Merge Helm values: maps merge by key, any other value replaces."""
    if isinstance(base, dict) and isinstance(layer, dict):
        merged = dict(base)
        for key, value in layer.items():
            merged[key] = merge_values(base.get(key), value) if key in base else value
        return merged
    return layer


def read_values(profile: Profile) -> dict[str, Any]:
    import yaml

    values: dict[str, Any] = {}
    for path in profile.values_files:
        values = merge_values(values, yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    return values


def helm_values_args(profile: Profile, overlay: Path | None = None) -> list[str]:
    """Give helm each values file of the profile in layer order, then the overlay."""
    files = [*profile.values_files, *([overlay] if overlay is not None else [])]
    return [argument for path in files for argument in ("--values", str(path))]


def describe(profile: Profile) -> dict[str, Any]:
    return {
        "name": profile.name,
        "directory": profile.relative(profile.directory),
        "environment": profile.environment,
        "signing_environment": profile.signing_environment,
        "values": [profile.relative(path) for path in profile.values_files],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)
    resolve = subparsers.add_parser("resolve", help="print the profile of a tag or a directory")
    target = resolve.add_mutually_exclusive_group(required=True)
    target.add_argument("--tag")
    target.add_argument("--release", type=Path)
    resolve.add_argument("--format", choices=("json", "github"), default="json")
    args = parser.parse_args()
    try:
        profile = for_tag(args.tag) if args.tag else for_directory(args.release)
    except ProfileError as error:
        print(f"release-profiles: {error}", file=sys.stderr)
        return 1
    value = describe(profile)
    if args.format == "github":
        for key, item in value.items():
            print(f"{key}={' '.join(item) if isinstance(item, list) else item}")
    else:
        print(json.dumps(value, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
