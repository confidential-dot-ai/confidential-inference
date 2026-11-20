#!/usr/bin/env python3
"""Pin engine and router images from the publisher selected in release/spec.yaml.

confidential-sglang builds one SGLang engine image and one router image. Its
image workflow builds each image twice on clean runners, requires equal
digests, pushes the image, and publishes a release record: the JSON asset
`images.json` of the GitHub release `images-<12hex>`, where <12hex> is the
first 12 hex digits of the source commit. docs/confidential-sglang-images.md
describes the record.

This repository does not build these images, so a framework release has no
Release-images build proof for them. It carries the confidential-sglang
record instead, as it carries the C8s release for the C8s images:

- release/spec.yaml `confidentialSglang.record` names the record, for
  example `images-0123456789ab`. Optional `repository` selects its publisher;
  it defaults to confidential-dot-ai/confidential-sglang.
- release/inputs/confidential-sglang/<record>.json holds the record bytes.
  `pin` downloads them and writes the file and the line.
- The release build (scripts/build-release-manifest.py) reads the file,
  checks it, adds the two images to the release images by chart image key,
  and binds the record and its SHA-256 in the signed manifest.

The spec ships with a placeholder record, `images-000000000000`. The release
build refuses to build a release while the placeholder is the pin.

    python3 scripts/confidential_sglang_release.py pin images-0123456789ab
    python3 scripts/confidential_sglang_release.py check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "release/spec.yaml"
INPUTS = ROOT / "release/inputs/confidential-sglang"
REPOSITORY = "confidential-dot-ai/confidential-sglang"
REPOSITORY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
RECORD_SCHEMA = "confidential.ai/confidential-sglang-images/v1"
ASSET = "images.json"
RECORD = re.compile(r"images-[0-9a-f]{12}")
# The record name in release/spec.yaml until confidential-sglang publishes
# its first record. The release build refuses it.
PLACEHOLDER = "images-000000000000"
# Each record component and its chart image key (values.yaml `images`).
CHART_KEYS = {"engine": "confidentialSglangEngine", "router": "confidentialSglangRouter"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
MAX_RECORD_BYTES = 65536


class RecordError(ValueError):
    """The confidential-sglang pin or record is invalid."""


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecordError(message)


def validate_name(name: Any) -> str:
    require(isinstance(name, str) and RECORD.fullmatch(name) is not None,
            f"confidentialSglang.record must be images-<12 hex>, not {name!r}")
    return name


def repository_of(section: Any) -> str:
    """The reviewed spec chooses the publisher; a downloaded record cannot change it."""
    require(isinstance(section, dict) and set(section) in ({"record"}, {"record", "repository"}),
            "confidentialSglang holds record and an optional repository")
    repository = section.get("repository", REPOSITORY)
    require(isinstance(repository, str) and REPOSITORY_NAME.fullmatch(repository) is not None,
            "confidentialSglang.repository must be a GitHub owner/repository")
    return repository


def validate_record(record: Any, name: str, repository: str = REPOSITORY) -> dict[str, Any]:
    """Check one record and that it is the record `name` names."""
    require(isinstance(record, dict) and set(record) == {"schema", "repository", "sourceCommit", "runId", "images"},
            "the record holds exactly schema, repository, sourceCommit, runId and images")
    require(record["schema"] == RECORD_SCHEMA, f"the record schema is not {RECORD_SCHEMA}")
    repository_of({"record": name, "repository": repository})
    require(record["repository"] == repository, f"the record repository is not {repository}")
    image_prefix = f"ghcr.io/{repository.lower()}/"
    image_pattern = re.compile(re.escape(image_prefix) + r"[a-z0-9][a-z0-9._/-]*")
    commit = record["sourceCommit"]
    require(isinstance(commit, str) and COMMIT.fullmatch(commit) is not None, "record sourceCommit is not a full commit")
    require(name == f"images-{commit[:12]}", f"the record {name} names source commit {commit}")
    run_id = record["runId"]
    require(isinstance(run_id, int) and not isinstance(run_id, bool) and run_id > 0, "record runId is not a run ID")
    images = record["images"]
    require(isinstance(images, dict) and set(images) == set(CHART_KEYS),
            f"record images are exactly {sorted(CHART_KEYS)}")
    for component, entry in images.items():
        require(isinstance(entry, dict) and set(entry) == {"image", "digest", "buildDigests"},
                f"record images.{component} holds exactly image, digest and buildDigests")
        require(isinstance(entry["image"], str) and image_pattern.fullmatch(entry["image"]) is not None
                and "@" not in entry["image"] and ":" not in entry["image"],
                f"record images.{component}.image is not an untagged {image_prefix} name")
        require(isinstance(entry["digest"], str) and DIGEST.fullmatch(entry["digest"]) is not None,
                f"record images.{component}.digest is not a SHA-256 digest")
        builds = entry["buildDigests"]
        # Two clean builds with equal digests: the reproducibility evidence
        # that replaces this repository's own build proof.
        require(isinstance(builds, list) and len(builds) == 2 and all(build == entry["digest"] for build in builds),
                f"record images.{component} needs two build digests equal to its digest")
    return record


def read_record(name: str, inputs: Path = INPUTS, repository: str = REPOSITORY) -> tuple[bytes, dict[str, Any]]:
    """Return the bytes and the checked record of `name` from release/inputs/confidential-sglang/."""
    validate_name(name)
    require(name != PLACEHOLDER,
            f"release/spec.yaml confidentialSglang.record is the placeholder {PLACEHOLDER}: "
            "pin a published record with scripts/confidential_sglang_release.py pin images-<12hex>")
    path = inputs / f"{name}.json"
    try:
        data = path.read_bytes()
        record = json.loads(data)
    except (OSError, json.JSONDecodeError) as error:
        raise RecordError(f"cannot read the record {path}: {error}") from error
    return data, validate_record(record, name, repository)


def release_pin(spec_section: Any, inputs: Path = INPUTS) -> dict[str, Any]:
    """The manifest block of the pin: the record, its SHA-256, and each image by digest."""
    repository = repository_of(spec_section)
    data, record = read_record(spec_section["record"], inputs, repository)
    return {
        "repository": repository,
        "record": spec_section["record"],
        "recordAsset": ASSET,
        "recordSha256": sha256(data),
        "sourceCommit": record["sourceCommit"],
        "runId": record["runId"],
        "images": {component: {"reference": f"{entry['image']}@{entry['digest']}",
                               "buildDigests": list(entry["buildDigests"])}
                   for component, entry in sorted(record["images"].items())},
    }


def chart_images(pin: dict[str, Any]) -> dict[str, str]:
    """The pinned images by chart image key."""
    return {CHART_KEYS[component]: entry["reference"] for component, entry in pin["images"].items()}


def download(name: str, directory: Path,
             run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
             *, repository: str = REPOSITORY) -> bytes:
    """Download the record asset of release `name` with gh."""
    repository_of({"record": name, "repository": repository})
    result = run(["gh", "release", "download", name, "--repo", repository, "--pattern", ASSET,
                  "--dir", str(directory), "--clobber"], text=True, capture_output=True, check=False)
    require(result.returncode == 0, f"cannot download {ASSET} of {repository} {name}: {result.stderr.strip()}")
    data = (directory / ASSET).read_bytes()
    require(len(data) <= MAX_RECORD_BYTES, "the record is too large")
    return data


SPEC_LINE = re.compile(r"^(  record: )(images-[0-9a-f]{12})([ \t]*(?:#.*)?)$", re.MULTILINE)


def pin(name: str, spec: Path = SPEC, inputs: Path = INPUTS,
        fetch: Callable[[str, Path], bytes] | None = None) -> None:
    """Download and check record `name`, write it to inputs/, and set the one spec line."""
    validate_name(name)
    require(name != PLACEHOLDER, "the placeholder is not a published record")
    import yaml

    text = spec.read_text(encoding="utf-8")
    repository = repository_of(yaml.safe_load(text).get("confidentialSglang"))
    with tempfile.TemporaryDirectory(prefix="confidential-sglang-record-") as directory:
        data = fetch(name, Path(directory)) if fetch else download(name, Path(directory), repository=repository)
    try:
        validate_record(json.loads(data), name, repository)
    except json.JSONDecodeError as error:
        raise RecordError(f"the record is not JSON: {error}") from error
    matches = SPEC_LINE.findall(text)
    require(len(matches) == 1, f"{spec} must set confidentialSglang.record on one line")
    inputs.mkdir(parents=True, exist_ok=True)
    (inputs / f"{name}.json").write_bytes(data)
    spec.write_text(SPEC_LINE.sub(lambda m: f"{m.group(1)}{name}", text), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    pin_command = commands.add_parser("pin", help="download a record and pin it in release/spec.yaml")
    pin_command.add_argument("record", help="the record release name, images-<12hex>")
    commands.add_parser("check", help="check the pinned record")
    args = parser.parse_args()
    try:
        import yaml

        if args.command == "pin":
            pin(args.record)
        section = yaml.safe_load(SPEC.read_text(encoding="utf-8")).get("confidentialSglang")
        print(json.dumps(release_pin(section), indent=2, sort_keys=True))
    except (RecordError, OSError) as error:
        print(f"confidential_sglang_release: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
