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

The engine image bakes confidential-sglang's DeepSeek-V4.1 launch plans
(layouts) at /opt/sglang/layouts/<name>.json (confidential/layouts/README.md
there). A pair recipe names one (recipes/README.md). `pin` also copies every
layout of the pinned engine image to
release/inputs/confidential-sglang/layouts/<record>/<name>.json: it reads the
image's layers by digest from the top and stops at the layout layer, so it
needs crane, not the whole image. The release build checks each layout (its
schema, its name, and its revision equal to the record's source commit) and
binds its SHA-256 in the signed manifest (confidentialSglang.layouts).
`check-image` compares the committed layouts with the image again.

The spec ships with a placeholder record, `images-000000000000`. The release
build refuses to build a release while the placeholder is the pin.

    python3 scripts/confidential_sglang_release.py pin images-0123456789ab
    python3 scripts/confidential_sglang_release.py check
    python3 scripts/confidential_sglang_release.py check-image
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
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
# The baked launch plans of the engine image (confidential-sglang confidential/layouts).
LAYOUT_SCHEMA = "confidential-sglang/dsv41-layout/v1"
LAYOUT_DIRECTORY = "opt/sglang/layouts"
LAYOUT_NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}")
MAX_LAYOUT_BYTES = 1 << 20
# The pin reads the engine image's layers from the top; the layouts layer is
# among the last few small ones. A larger layer is not read.
MAX_LAYER_BYTES = 64 << 20


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


def layouts_directory(name: str, inputs: Path = INPUTS) -> Path:
    """release/inputs/confidential-sglang/layouts/<record>: the layouts of the record's engine image."""
    return inputs / "layouts" / validate_name(name)


def validate_layout(data: bytes, layout: str, source_commit: str) -> dict[str, Any]:
    """Check one layout file of the engine image: its schema, its name and its source revision."""
    require(len(data) <= MAX_LAYOUT_BYTES, f"layout {layout} is too large")
    require(LAYOUT_NAME.fullmatch(layout) is not None, f"layout name {layout!r} is invalid")
    try:
        value = json.loads(data)
    except json.JSONDecodeError as error:
        raise RecordError(f"layout {layout} is not JSON: {error}") from error
    require(isinstance(value, dict) and value.get("schema") == LAYOUT_SCHEMA,
            f"layout {layout} schema is not {LAYOUT_SCHEMA}")
    require(value.get("layout") == layout, f"layout {layout} names layout {value.get('layout')!r}")
    require(value.get("revision") == source_commit and isinstance(value.get("plan"), dict)
            and value["plan"].get("revision") == source_commit,
            f"layout {layout} was built from {value.get('revision')!r}, not the record's source commit {source_commit}")
    return value


def read_layouts(name: str, source_commit: str, inputs: Path = INPUTS) -> dict[str, bytes]:
    """The committed layouts of record `name`, by layout name, each checked. None committed: {}."""
    directory = layouts_directory(name, inputs)
    if not directory.is_dir():
        return {}
    layouts: dict[str, bytes] = {}
    for path in sorted(directory.iterdir()):
        require(path.is_file() and path.suffix == ".json", f"{path} is not a layout file")
        data = path.read_bytes()
        validate_layout(data, path.stem, source_commit)
        layouts[path.stem] = data
    return layouts


def read_layout(name: str, layout: str, inputs: Path | None = None) -> dict[str, Any]:
    """The checked layout `layout` of record `name` (from release/inputs), with its SHA-256 as `_sha256`."""
    inputs = INPUTS if inputs is None else inputs
    _, record = read_record(name, inputs)
    layouts = read_layouts(name, record["sourceCommit"], inputs)
    require(layout in layouts, f"the engine image of {name} has no layout {layout} "
            f"(release/inputs/confidential-sglang/layouts/{name} holds {sorted(layouts)}); "
            f"pin the record again with scripts/confidential_sglang_release.py pin {name}")
    return {**json.loads(layouts[layout]), "_sha256": sha256(layouts[layout])}


def release_pin(spec_section: Any, inputs: Path = INPUTS) -> dict[str, Any]:
    """The manifest block of the pin: the record, its SHA-256, each image by digest, and each layout."""
    require(isinstance(spec_section, dict) and set(spec_section) == {"record"},
            "confidentialSglang holds exactly record")
    data, record = read_record(spec_section["record"], inputs)
    layouts = read_layouts(spec_section["record"], record["sourceCommit"], inputs)
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
        **({"layouts": {layout: sha256(content) for layout, content in sorted(layouts.items())}} if layouts else {}),
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


def image_layouts(reference: str,
                  run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run) -> dict[str, bytes]:
    """Every /opt/sglang/layouts/*.json of the engine image `reference` (repository@sha256:...).

    Reads the layers by digest with crane, from the top layer down, and stops at
    the first layer that holds the layouts directory: an upper layer wins, as in
    the image's filesystem. A whiteout of the directory or of a layout, or a
    large layer before the layouts, is an error. zstd and gzip layers.
    """
    require(re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", reference) is not None,
            f"the engine image {reference} is not pinned by digest")
    repository = reference.split("@", 1)[0]

    def crane(*arguments: str) -> bytes:
        result = run(["crane", *arguments], capture_output=True, check=False)
        require(result.returncode == 0, f"crane {arguments[0]} {arguments[1]} failed: "
                f"{result.stderr.decode(errors='replace').strip()}")
        return result.stdout

    manifest = json.loads(crane("manifest", reference))
    require(isinstance(manifest.get("layers"), list), f"{reference} is not an image manifest")
    prefix = LAYOUT_DIRECTORY + "/"
    for layer in reversed(manifest["layers"]):
        require(int(layer.get("size", 0)) <= MAX_LAYER_BYTES,
                f"{reference}: no layer above {layer.get('digest')} ({layer.get('size')} bytes) holds {prefix}")
        blob = crane("blob", f"{repository}@{layer['digest']}")
        media = layer.get("mediaType", "")
        if media.endswith("+zstd") or media.endswith(".zstd"):
            result = run(["zstd", "-dcq"], input=blob, capture_output=True, check=False)
            require(result.returncode == 0, f"cannot decompress layer {layer['digest']}")
            blob = result.stdout
        with tempfile.TemporaryFile() as handle:
            handle.write(blob)
            handle.seek(0)
            with tarfile.open(fileobj=handle, mode="r:*") as archive:
                members = archive.getmembers()
                found: dict[str, bytes] = {}
                for member in members:
                    path = member.name.removeprefix("./")
                    parent, _, base = path.rpartition("/")
                    if base.startswith(".wh."):
                        # A whiteout removes parent/<name>; an opaque one, everything below parent.
                        removed = parent if base == ".wh..wh..opq" else f"{parent}/{base[4:]}".lstrip("/")
                        if (removed + "/").startswith(prefix) or prefix.startswith(removed + "/"):
                            raise RecordError(f"{reference}: layer {layer['digest']} removes {removed}")
                    if path.startswith(prefix) and "/" not in path[len(prefix):] and path.endswith(".json"):
                        require(member.isfile(), f"{reference}: {path} is not a regular file")
                        extracted = archive.extractfile(member)
                        found[path[len(prefix):-len(".json")]] = extracted.read() if extracted else b""
                if found:
                    return found
    raise RecordError(f"{reference} has no {prefix}")


def write_layouts(name: str, layouts: dict[str, bytes], source_commit: str, inputs: Path = INPUTS) -> None:
    """Replace the committed layouts of record `name` with `layouts`, each checked first."""
    for layout, data in layouts.items():
        validate_layout(data, layout, source_commit)
    directory = layouts_directory(name, inputs)
    if directory.is_dir():
        for path in directory.iterdir():
            path.unlink()
    directory.mkdir(parents=True, exist_ok=True)
    for layout, data in sorted(layouts.items()):
        (directory / f"{layout}.json").write_bytes(data)


def check_image(name: str, inputs: Path = INPUTS,
                extract: Callable[[str], dict[str, bytes]] = image_layouts) -> None:
    """Require the committed layouts of record `name` to be exactly the layouts of its engine image."""
    _, record = read_record(name, inputs)
    engine = record["images"]["engine"]
    committed = read_layouts(name, record["sourceCommit"], inputs)
    baked = extract(f"{engine['image']}@{engine['digest']}")
    require(committed == baked, f"the committed layouts of {name} ({sorted(committed)}) differ from the layouts "
            f"of its engine image ({sorted(baked)}); pin the record again")


SPEC_LINE = re.compile(r"^(  record: )(images-[0-9a-f]{12})([ \t]*(?:#.*)?)$", re.MULTILINE)


def pin(name: str, spec: Path = SPEC, inputs: Path = INPUTS,
        fetch: Callable[[str, Path], bytes] = download,
        extract: Callable[[str], dict[str, bytes]] = image_layouts) -> None:
    """Download and check record `name`, write it and its engine image's layouts to inputs/, and set
    the one spec line."""
    validate_name(name)
    require(name != PLACEHOLDER, "the placeholder is not a published record")
    with tempfile.TemporaryDirectory(prefix="confidential-sglang-record-") as directory:
        data = fetch(name, Path(directory))
    try:
        record = validate_record(json.loads(data), name)
    except json.JSONDecodeError as error:
        raise RecordError(f"the record is not JSON: {error}") from error
    text = spec.read_text(encoding="utf-8")
    matches = SPEC_LINE.findall(text)
    require(len(matches) == 1, f"{spec} must set confidentialSglang.record on one line")
    engine = record["images"]["engine"]
    layouts = extract(f"{engine['image']}@{engine['digest']}")
    inputs.mkdir(parents=True, exist_ok=True)
    (inputs / f"{name}.json").write_bytes(data)
    write_layouts(name, layouts, record["sourceCommit"], inputs)
    spec.write_text(SPEC_LINE.sub(lambda m: f"{m.group(1)}{name}", text), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    pin_command = commands.add_parser("pin", help="download a record and pin it in release/spec.yaml")
    pin_command.add_argument("record", help="the record release name, images-<12hex>")
    commands.add_parser("check", help="check the pinned record")
    commands.add_parser("check-image", help="check the committed layouts against the pinned engine image")
    args = parser.parse_args()
    try:
        import yaml

        if args.command == "pin":
            pin(args.record)
        section = yaml.safe_load(SPEC.read_text(encoding="utf-8")).get("confidentialSglang")
        if args.command == "check-image":
            check_image(validate_name(section["record"]))
        print(json.dumps(release_pin(section), indent=2, sort_keys=True))
    except (RecordError, OSError) as error:
        print(f"confidential_sglang_release: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
