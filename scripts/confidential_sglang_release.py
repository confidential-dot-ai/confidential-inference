#!/usr/bin/env python3
"""Pin the images that confidential-dot-ai/confidential-sglang publishes.

confidential-sglang builds one SGLang engine image and one router image. Its
image workflow builds each image twice on clean runners, requires equal
digests, pushes the image, and publishes a release record: the JSON asset
`images-<12hex>.json` of the GitHub release `images-<12hex>`, where <12hex> is the
first 12 hex digits of the source commit. docs/confidential-sglang-images.md
describes the record.

This repository does not build these images, so a framework release has no
Release-images build proof for them. It carries the confidential-sglang
record instead, as it carries the C8s release for the C8s images:

- release/spec.yaml `confidentialSglang.record` names the record, for
  example `images-0123456789ab`. That one line is the pin.
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
RECORD_SCHEMA = "confidential.ai/confidential-sglang-images/v1"
# The record asset of release images-<12hex> is images-<12hex>.json.
RECORD = re.compile(r"images-[0-9a-f]{12}")
# The record name in release/spec.yaml until confidential-sglang publishes
# its first record. The release build refuses it.
PLACEHOLDER = "images-000000000000"
IMAGE_PREFIX = "ghcr.io/confidential-dot-ai/confidential-sglang/"
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


# The only run that may publish a record: confidential-sglang's own images workflow on main. (The
# first record, images-d0169679925d, came from confidential-sglang-ci, now archived, which called
# that workflow while Actions were off in confidential-sglang. It is no longer accepted.)
RECORD_KEYS = {"schema", "repository", "sourceCommit", "run", "images"}
OPTIONAL_RECORD_KEYS = {"sourceDateEpoch"}


def validate_record(record: Any, name: str) -> dict[str, Any]:
    """Check one record (confidential-sglang `confidential/ci/release_record.py`, schema v1) and that it
    is the record `name` names. Return it normalized: images by component with image, digest and
    buildDigests, and the run ID as runId."""
    require(isinstance(record, dict) and RECORD_KEYS <= set(record) <= RECORD_KEYS | OPTIONAL_RECORD_KEYS,
            f"the record holds exactly {sorted(RECORD_KEYS)} (and optionally {sorted(OPTIONAL_RECORD_KEYS)})")
    require(record["schema"] == RECORD_SCHEMA, f"the record schema is not {RECORD_SCHEMA}")
    require(record["repository"] == f"https://github.com/{REPOSITORY}",
            f"the record repository is not https://github.com/{REPOSITORY}")
    commit = record["sourceCommit"]
    require(isinstance(commit, str) and COMMIT.fullmatch(commit) is not None, "record sourceCommit is not a full commit")
    require(name == f"images-{commit[:12]}", f"the record {name} names source commit {commit}")
    if "sourceDateEpoch" in record:
        require(type(record["sourceDateEpoch"]) is int and record["sourceDateEpoch"] > 0,
                "record sourceDateEpoch is not a positive integer")
    run = record["run"]
    require(isinstance(run, dict) and set(run) == {"repository", "id", "attempt", "url", "workflow"},
            "record run holds exactly repository, id, attempt, url and workflow")
    run_id = run.get("id")
    require(isinstance(run_id, int) and not isinstance(run_id, bool) and run_id > 0, "record run.id is not a run ID")
    repository = run["repository"]
    require(repository == REPOSITORY, f"record run.repository is not {REPOSITORY}")
    attempt = run["attempt"]
    require(type(attempt) is int and attempt > 0, "record run.attempt is not a positive integer")
    require(run["url"] == f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{attempt}",
            "record run.url does not name its repository, run ID and attempt")
    # Like this repository's own rule (find-image-publication-run.py): trust only runs on main.
    require(run["workflow"] == f"{repository}/.github/workflows/images.yml@refs/heads/main",
            "record run.workflow is not its repository's images workflow on main")
    images = record["images"]
    require(isinstance(images, list) and all(isinstance(entry, dict) for entry in images)
            and [entry.get("name") for entry in images] == sorted(CHART_KEYS),
            f"record images are exactly {sorted(CHART_KEYS)}, once each")
    normalized: dict[str, dict[str, Any]] = {}
    for entry in images:
        require(set(entry) == {"name", "image", "digest", "builds", "reference", "tag"},
                "record image holds exactly name, image, digest, builds, reference and tag")
        component = entry["name"]
        image, digest, builds = entry.get("image"), entry.get("digest"), entry.get("builds")
        require(image == IMAGE_PREFIX + component,
                f"record image {component} is not the untagged {IMAGE_PREFIX + component} image")
        require(isinstance(digest, str) and DIGEST.fullmatch(digest) is not None,
                f"record image {component} digest is not a SHA-256 digest")
        # Two clean builds with equal digests: the reproducibility evidence that replaces this
        # repository's own build proof.
        require(isinstance(builds, list) and len(builds) == 2 and all(build == digest for build in builds),
                f"record image {component} needs two build digests equal to its digest")
        require(entry["reference"] == f"{image}@{digest}", f"record image {component} reference is not image@digest")
        require(entry["tag"] == f"sha-{commit}", f"record image {component} tag is not sha-<sourceCommit>")
        normalized[component] = {"image": image, "digest": digest, "buildDigests": list(builds)}
    return {"schema": record["schema"], "repository": REPOSITORY, "sourceCommit": commit, "runId": run_id,
            "images": normalized}


def read_record(name: str, inputs: Path = INPUTS) -> tuple[bytes, dict[str, Any]]:
    """Return the bytes and the checked record of `name` from release/inputs/confidential-sglang/."""
    validate_name(name)
    require(name != PLACEHOLDER,
            f"release/spec.yaml confidentialSglang.record is the placeholder {PLACEHOLDER}: "
            "pin a published record with scripts/confidential_sglang_release.py pin images-<12hex>")
    path = inputs / f"{name}.json"
    try:
        data = path.read_bytes()
        require(len(data) <= MAX_RECORD_BYTES, "the record is too large")
        record = json.loads(data)
    except (OSError, json.JSONDecodeError) as error:
        raise RecordError(f"cannot read the record {path}: {error}") from error
    return data, validate_record(record, name)


def release_pin(spec_section: Any, inputs: Path = INPUTS) -> dict[str, Any]:
    """The manifest block of the pin: the record, its SHA-256, and each image by digest."""
    require(isinstance(spec_section, dict) and set(spec_section) == {"record"},
            "confidentialSglang holds exactly record")
    data, record = read_record(spec_section["record"], inputs)
    return {
        "repository": REPOSITORY,
        "record": spec_section["record"],
        "recordAsset": f"{spec_section['record']}.json",
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
             run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> bytes:
    """Download the record asset of release `name` with gh."""
    asset = f"{validate_name(name)}.json"
    result = run(["gh", "release", "download", name, "--repo", REPOSITORY, "--pattern", asset,
                  "--dir", str(directory), "--clobber"], text=True, capture_output=True, check=False)
    require(result.returncode == 0, f"cannot download {asset} of {REPOSITORY} {name}: {result.stderr.strip()}")
    data = (directory / asset).read_bytes()
    require(len(data) <= MAX_RECORD_BYTES, "the record is too large")
    return data


SPEC_LINE = re.compile(r"^(  record: )(images-[0-9a-f]{12})([ \t]*(?:#.*)?)$", re.MULTILINE)


def pin(name: str, spec: Path = SPEC, inputs: Path = INPUTS,
        fetch: Callable[[str, Path], bytes] = download) -> None:
    """Download and check record `name`, write it to inputs/, and set the one spec line."""
    validate_name(name)
    require(name != PLACEHOLDER, "the placeholder is not a published record")
    with tempfile.TemporaryDirectory(prefix="confidential-sglang-record-") as directory:
        data = fetch(name, Path(directory))
    try:
        validate_record(json.loads(data), name)
    except json.JSONDecodeError as error:
        raise RecordError(f"the record is not JSON: {error}") from error
    text = spec.read_text(encoding="utf-8")
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
