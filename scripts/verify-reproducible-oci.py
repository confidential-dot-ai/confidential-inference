#!/usr/bin/env python3
"""Compare clean OCI builds, or a rebuild with a release digest.

Also supports recording one OCI build's platform manifest, config, and
digest to a small JSON file, and later comparing two such recordings. Use
this split when the two clean builds run on separate runners: each build's
job records its result, and a small compare job downloads and checks both
recordings without moving the (large) OCI tarballs between runners.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path
from typing import Any


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class VerificationError(ValueError):
    """The OCI archives do not prove a repeatable platform image."""


def read_blob(archive: tarfile.TarFile, digest: str) -> bytes:
    if DIGEST.fullmatch(digest) is None:
        raise VerificationError(f"an OCI descriptor has an invalid digest: {digest}")
    name = "blobs/sha256/" + digest.removeprefix("sha256:")
    member = archive.extractfile(name)
    if member is None:
        raise VerificationError(f"the OCI archive lacks {name}")
    data = member.read()
    actual = "sha256:" + hashlib.sha256(data).hexdigest()
    if actual != digest:
        raise VerificationError(f"the OCI blob digest does not match {name}")
    return data


def read_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"the {label} is not JSON: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"the {label} is not an object")
    return value


def platform_manifest(
    archive_path: Path, operating_system: str, architecture: str
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    try:
        archive = tarfile.open(archive_path, "r:*")
    except (OSError, tarfile.TarError) as error:
        raise VerificationError(f"cannot open {archive_path}: {error}") from error
    with archive:
        index_file = archive.extractfile("index.json")
        if index_file is None:
            raise VerificationError(f"{archive_path} lacks index.json")
        current = read_json(index_file.read(), "OCI index")
        while "manifests" in current:
            descriptors = current.get("manifests")
            if not isinstance(descriptors, list):
                raise VerificationError("the OCI manifests value is invalid")
            matches = [
                item
                for item in descriptors
                if isinstance(item, dict)
                and item.get("platform", {}).get("os") == operating_system
                and item.get("platform", {}).get("architecture") == architecture
            ]
            if len(matches) != 1:
                raise VerificationError(
                    f"the OCI archive needs one {operating_system}/{architecture} manifest"
                )
            digest = str(matches[0].get("digest", ""))
            current = read_json(read_blob(archive, digest), "OCI platform manifest")
        manifest = current
        descriptor = matches[0]
        manifest_digest = str(descriptor["digest"])
        config_descriptor = manifest.get("config")
        if not isinstance(config_descriptor, dict):
            raise VerificationError("the platform manifest lacks its image configuration")
        config_digest = str(config_descriptor.get("digest", ""))
        config = read_json(read_blob(archive, config_digest), "image configuration")
        return manifest_digest, manifest, config


def verify(
    first: Path,
    second: Path,
    platform: str,
    revision: str,
    source_epoch: str,
) -> str:
    try:
        operating_system, architecture = platform.split("/", 1)
    except ValueError as error:
        raise VerificationError("the platform must use the os/architecture form") from error
    first_digest, first_manifest, first_config = platform_manifest(
        first, operating_system, architecture
    )
    second_digest, second_manifest, second_config = platform_manifest(
        second, operating_system, architecture
    )
    if first_digest != second_digest or first_manifest != second_manifest:
        raise VerificationError("the repeated platform manifests differ")
    if first_config != second_config:
        raise VerificationError("the repeated image configurations differ")
    verify_labels(first_config, revision, source_epoch)
    return first_digest


def verify_labels(config: dict[str, Any], revision: str, source_epoch: str) -> None:
    labels = config.get("config", {}).get("Labels", {})
    required = {
        "org.opencontainers.image.source": "https://github.com/confidential-dot-ai/confidential-inference",
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.version": f"sha-{revision}",
        "ai.confidential.build.source-date-epoch": source_epoch,
    }
    for name, expected in required.items():
        if labels.get(name) != expected:
            raise VerificationError(f"the image label {name} does not match the source")


def record(
    archive: Path,
    platform: str,
    revision: str,
    source_epoch: str,
) -> tuple[str, dict[str, Any]]:
    """Record one clean build's platform manifest, config, and digest."""
    try:
        operating_system, architecture = platform.split("/", 1)
    except ValueError as error:
        raise VerificationError("the platform must use the os/architecture form") from error
    digest, manifest, config = platform_manifest(archive, operating_system, architecture)
    verify_labels(config, revision, source_epoch)
    return digest, {
        "platform": platform,
        "digest": digest,
        "manifest": manifest,
        "config": config,
    }


def load_record(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read the recorded manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"the recorded manifest {path} is not an object")
    for key in ("platform", "digest", "manifest", "config"):
        if key not in value:
            raise VerificationError(f"the recorded manifest {path} lacks {key}")
    return value


def compare_recorded(first: Path, second: Path) -> str:
    """Compare two recordings made by `record`, one build per runner."""
    first_record = load_record(first)
    second_record = load_record(second)
    if first_record["platform"] != second_record["platform"]:
        raise VerificationError("the recorded builds used different platforms")
    if (
        first_record["digest"] != second_record["digest"]
        or first_record["manifest"] != second_record["manifest"]
    ):
        raise VerificationError("the repeated platform manifests differ")
    if first_record["config"] != second_record["config"]:
        raise VerificationError("the repeated image configurations differ")
    return str(first_record["digest"])


def verify_expected(
    archive: Path,
    platform: str,
    revision: str,
    source_epoch: str,
    expected_digest: str,
) -> str:
    if DIGEST.fullmatch(expected_digest) is None:
        raise VerificationError("the expected digest is invalid")
    try:
        operating_system, architecture = platform.split("/", 1)
    except ValueError as error:
        raise VerificationError("the platform must use the os/architecture form") from error
    actual_digest, _manifest, config = platform_manifest(
        archive, operating_system, architecture
    )
    verify_labels(config, revision, source_epoch)
    if actual_digest != expected_digest:
        raise VerificationError(
            f"the rebuilt digest {actual_digest} does not match {expected_digest}"
        )
    return actual_digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", nargs="?", type=Path)
    parser.add_argument("second", nargs="?", type=Path)
    parser.add_argument("--platform", default="linux/amd64")
    parser.add_argument("--revision")
    parser.add_argument("--source-date-epoch")
    parser.add_argument("--expected-digest")
    parser.add_argument(
        "--record",
        type=Path,
        metavar="OUT_JSON",
        help="record the `first` OCI archive's platform manifest, config, "
        "and digest to OUT_JSON instead of comparing two builds",
    )
    parser.add_argument(
        "--compare-records",
        nargs=2,
        type=Path,
        metavar=("FIRST_JSON", "SECOND_JSON"),
        help="compare two recordings made by --record, one per clean build",
    )
    args = parser.parse_args()
    try:
        if args.compare_records is not None:
            if any(
                value is not None
                for value in (args.first, args.second, args.record, args.expected_digest)
            ):
                raise VerificationError("--compare-records takes no other build arguments")
            first_json, second_json = args.compare_records
            digest = compare_recorded(first_json, second_json)
            message = "repeated builds matched"
        elif args.record is not None:
            if args.first is None:
                raise VerificationError("--record needs the archive to record as `first`")
            if args.second is not None or args.expected_digest is not None:
                raise VerificationError("--record takes only the `first` archive")
            if args.revision is None or args.source_date_epoch is None:
                raise VerificationError("--record needs --revision and --source-date-epoch")
            digest, payload = record(
                args.first, args.platform, args.revision, args.source_date_epoch
            )
            args.record.write_text(json.dumps(payload), encoding="utf-8")
            message = "recorded the platform manifest"
        elif args.first is None:
            raise VerificationError("supply a first build")
        elif args.revision is None or args.source_date_epoch is None:
            raise VerificationError("supply --revision and --source-date-epoch")
        elif args.second is not None and args.expected_digest is not None:
            raise VerificationError("use either a second build or --expected-digest")
        elif args.second is not None:
            digest = verify(
                args.first,
                args.second,
                args.platform,
                args.revision,
                args.source_date_epoch,
            )
            message = "repeated builds matched"
        elif args.expected_digest is not None:
            digest = verify_expected(
                args.first,
                args.platform,
                args.revision,
                args.source_date_epoch,
                args.expected_digest,
            )
            message = "rebuilt image matched the release"
        else:
            raise VerificationError("supply a second build or --expected-digest")
    except VerificationError as error:
        print(f"reproducible-oci: {error}")
        return 1
    print(f"reproducible-oci: {message}: {args.platform} {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
