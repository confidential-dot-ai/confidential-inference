#!/usr/bin/env python3
"""Tests for the repeatable OCI platform manifest verifier."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify-reproducible-oci.py"
SPEC = importlib.util.spec_from_file_location("verify_reproducible_oci", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("the OCI verifier cannot load")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REVISION = "a" * 40
EPOCH = "1700000000"


def encoded(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def make_archive(path: Path, marker: str = "same", revision: str = REVISION) -> None:
    config_data = encoded(
        {
            "config": {
                "Labels": {
                    "org.opencontainers.image.source": "https://github.com/confidential-dot-ai/confidential-inference",
                    "org.opencontainers.image.revision": revision,
                    "org.opencontainers.image.version": f"sha-{revision}",
                    "ai.confidential.build.source-date-epoch": EPOCH,
                }
            },
            "marker": marker,
        }
    )
    config_digest = digest(config_data)
    manifest_data = encoded(
        {
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config_data),
            },
            "layers": [],
        }
    )
    manifest_digest = digest(manifest_data)
    index_data = encoded(
        {
            "schemaVersion": 2,
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": manifest_digest,
                    "size": len(manifest_data),
                    "platform": {"os": "linux", "architecture": "amd64"},
                }
            ],
        }
    )
    with tarfile.open(path, "w") as archive:
        for name, data in (
            ("index.json", index_data),
            ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
            ("blobs/sha256/" + config_digest[7:], config_data),
            ("blobs/sha256/" + manifest_digest[7:], manifest_data),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = int(EPOCH)
            archive.addfile(info, io.BytesIO(data))


class ReproducibleOciTests(unittest.TestCase):
    def test_accepts_equal_platform_manifests_and_source_labels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.tar"
            second = Path(directory) / "second.tar"
            make_archive(first)
            make_archive(second)
            result = MODULE.verify(first, second, "linux/amd64", REVISION, EPOCH)
            self.assertRegex(result, r"^sha256:[0-9a-f]{64}$")

    def test_rejects_different_platform_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.tar"
            second = Path(directory) / "second.tar"
            make_archive(first)
            make_archive(second, marker="different")
            with self.assertRaisesRegex(MODULE.VerificationError, "platform manifests differ"):
                MODULE.verify(first, second, "linux/amd64", REVISION, EPOCH)

    def test_rejects_a_wrong_source_revision_label(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.tar"
            second = Path(directory) / "second.tar"
            make_archive(first, revision="b" * 40)
            make_archive(second, revision="b" * 40)
            with self.assertRaisesRegex(MODULE.VerificationError, "revision"):
                MODULE.verify(first, second, "linux/amd64", REVISION, EPOCH)

    def test_accepts_one_rebuild_with_the_release_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "rebuilt.tar"
            make_archive(archive)
            expected, _manifest, _config = MODULE.platform_manifest(
                archive, "linux", "amd64"
            )
            self.assertEqual(
                expected,
                MODULE.verify_expected(
                    archive, "linux/amd64", REVISION, EPOCH, expected
                ),
            )

    def test_rejects_one_rebuild_with_a_different_release_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "rebuilt.tar"
            make_archive(archive)
            with self.assertRaisesRegex(MODULE.VerificationError, "does not match"):
                MODULE.verify_expected(
                    archive, "linux/amd64", REVISION, EPOCH, "sha256:" + "0" * 64
                )

    def test_records_a_single_build_for_a_later_cross_runner_compare(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "first.tar"
            make_archive(archive)
            digest, payload = MODULE.record(archive, "linux/amd64", REVISION, EPOCH)
            self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(payload["digest"], digest)
            self.assertEqual(payload["platform"], "linux/amd64")

    def test_record_rejects_a_wrong_source_revision_label(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "first.tar"
            make_archive(archive, revision="b" * 40)
            with self.assertRaisesRegex(MODULE.VerificationError, "revision"):
                MODULE.record(archive, "linux/amd64", REVISION, EPOCH)

    def test_compare_recorded_accepts_two_matching_recordings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_tar = Path(directory) / "first.tar"
            second_tar = Path(directory) / "second.tar"
            make_archive(first_tar)
            make_archive(second_tar)
            first_json = Path(directory) / "first.json"
            second_json = Path(directory) / "second.json"
            _, first_payload = MODULE.record(first_tar, "linux/amd64", REVISION, EPOCH)
            _, second_payload = MODULE.record(second_tar, "linux/amd64", REVISION, EPOCH)
            first_json.write_text(json.dumps(first_payload), encoding="utf-8")
            second_json.write_text(json.dumps(second_payload), encoding="utf-8")
            result = MODULE.compare_recorded(first_json, second_json)
            self.assertRegex(result, r"^sha256:[0-9a-f]{64}$")

    def test_compare_recorded_rejects_two_different_recordings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_tar = Path(directory) / "first.tar"
            second_tar = Path(directory) / "second.tar"
            make_archive(first_tar)
            make_archive(second_tar, marker="different")
            first_json = Path(directory) / "first.json"
            second_json = Path(directory) / "second.json"
            _, first_payload = MODULE.record(first_tar, "linux/amd64", REVISION, EPOCH)
            _, second_payload = MODULE.record(second_tar, "linux/amd64", REVISION, EPOCH)
            first_json.write_text(json.dumps(first_payload), encoding="utf-8")
            second_json.write_text(json.dumps(second_payload), encoding="utf-8")
            with self.assertRaisesRegex(MODULE.VerificationError, "platform manifests differ"):
                MODULE.compare_recorded(first_json, second_json)


if __name__ == "__main__":
    unittest.main()
