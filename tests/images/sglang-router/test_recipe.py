#!/usr/bin/env python3
"""Focused tests for the public SGLang router image recipe."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RECIPE = ROOT / "images" / "sglang-router"
LOCK = json.loads((RECIPE / "source.lock").read_text(encoding="utf-8"))
DOCKERFILE = (RECIPE / "Dockerfile").read_text(encoding="utf-8")

EXPECTED_SOURCE = "https://github.com/sgl-project/sglang"
EXPECTED_COMMIT = "a7fd2e1158c389c33077bae67fb797efa8dd09bd"
# The reviewed patches, in the order the build applies them. A change to a
# patch's bytes must change this list, source.lock and the Dockerfile labels.
EXPECTED_PATCHES = [
    ("patches/worker-withdrawal.patch", "c19733adbf8ec8c25bb58a517bfa35cb5f93d7c1a4b5a8b439e50104a9d6b3fa"),
    ("patches/admission-caps.patch", "eb542bb49728c7f926253da0a21ac521567382cf00cfc47c93e0022f337ad021"),
    ("patches/pd-router.patch", "f69f0d7910123bf080d46c362b8d019a04c393149c5b17010254cefcc419df0b"),
    ("patches/http-no-tokenizer.patch", "85e982bf2bf2e21da3c27615819c3880f3a30da08495893de27ffbe9c30ba1c4"),
]


def instructions() -> list[str]:
    return [
        line.strip()
        for line in DOCKERFILE.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def label_name(patch_path: str) -> str:
    return f"ai.confidential.sglang-router.{Path(patch_path).stem}-patch.sha256"


class RouterImageRecipeTests(unittest.TestCase):
    def test_source_lock_pins_the_upstream_commit(self) -> None:
        self.assertEqual(1, LOCK["schemaVersion"])
        self.assertEqual(EXPECTED_SOURCE, LOCK["source"]["repository"])
        self.assertEqual(EXPECTED_COMMIT, LOCK["source"]["commit"])
        self.assertNotIn("patch", LOCK, "source.lock lists its patches under `patches`")

    def test_each_patch_matches_its_locked_digest(self) -> None:
        self.assertEqual(EXPECTED_PATCHES, [(p["path"], p["sha256"]) for p in LOCK["patches"]])
        for path, digest in EXPECTED_PATCHES:
            self.assertEqual(digest, hashlib.sha256((RECIPE / path).read_bytes()).hexdigest(), path)

    def test_the_patch_directory_holds_only_locked_patches(self) -> None:
        locked = {Path(path).name for path, _ in EXPECTED_PATCHES}
        present = {path.name for path in (RECIPE / "patches").iterdir()}
        self.assertEqual(locked, present)

    def test_the_build_applies_every_patch_in_lock_order(self) -> None:
        applied = re.findall(r"git apply (/inputs/patches/\S+)", DOCKERFILE)
        checked = re.findall(r"git apply --check (/inputs/patches/\S+)", DOCKERFILE)
        expected = [f"/inputs/{path}" for path, _ in EXPECTED_PATCHES]
        self.assertEqual(expected, applied)
        self.assertEqual(expected, checked)
        # Each check comes before its apply, and the first patch fully applies
        # before the next is checked: later patches are diffs on earlier ones.
        positions = []
        for patch in expected:
            positions.append(DOCKERFILE.index(f"git apply --check {patch}"))
            positions.append(DOCKERFILE.index(f"git apply {patch}"))
        self.assertEqual(sorted(positions), positions)
        # The build itself rejects an unlisted or changed patch.
        self.assertIn('ps=d["patches"]', DOCKERFILE)
        self.assertIn('hexdigest()==p["sha256"]', DOCKERFILE)

    def test_labels_mirror_the_lock(self) -> None:
        lines = set(instructions())
        self.assertIn(f'LABEL ai.confidential.upstream.source="{EXPECTED_SOURCE}"', lines)
        self.assertIn(f'LABEL ai.confidential.upstream.revision="{LOCK["source"]["commit"]}"', lines)
        for patch in LOCK["patches"]:
            self.assertIn(f'LABEL {label_name(patch["path"])}="{patch["sha256"]}"', lines)
        self.assertIn(
            f'LABEL ai.confidential.sglang-router.cargo-lock.sha256="{LOCK["cargoLockSha256"]}"', lines
        )
        patch_labels = [line for line in lines if re.match(r"LABEL ai\.confidential\.sglang-router\..*-patch\.sha256=", line)]
        self.assertEqual(len(LOCK["patches"]), len(patch_labels))

    def test_cargo_lock_matches_the_lock(self) -> None:
        self.assertEqual(
            LOCK["cargoLockSha256"],
            hashlib.sha256((RECIPE / "Cargo.lock").read_bytes()).hexdigest(),
        )

    def test_admission_patch_adds_only_off_by_default_router_flags(self) -> None:
        # The chart's aggregated router command passes none of these flags, so
        # the patch must leave a router without them unchanged: every cap is
        # off by default and --max-concurrent-requests stays -1 (disabled).
        patch = (RECIPE / "patches" / "admission-caps.patch").read_text(encoding="utf-8")
        for field in (
            "max_inflight_images: int = 0",
            "max_inflight_megapixels: int = 0",
            "max_images_per_request: int = 0",
            "unmeasured_image_megapixels: int = 0",
            "reject_video: bool = False",
        ):
            self.assertIn(f"+    {field}", patch)
        self.assertNotIn("max_concurrent_requests: int =", patch)

    def test_pd_router_patch_touches_only_the_pd_router(self) -> None:
        # The prefill/decode fixes must not change the regular router that the
        # aggregated workers use.
        patch = (RECIPE / "patches" / "pd-router.patch").read_text(encoding="utf-8")
        self.assertEqual(
            [
                "sgl-model-gateway/src/routers/http/pd_router.rs",
                "sgl-model-gateway/tests/reliability/upstream_cancel_test.rs",
            ],
            re.findall(r"^diff --git a/(\S+) b/", patch, re.MULTILINE),
        )

    def test_every_base_image_is_pinned_by_digest(self) -> None:
        for line in instructions():
            if line.upper().startswith("FROM "):
                self.assertRegex(line, r"^FROM \S+@sha256:[0-9a-f]{64}( AS \S+)?$")


if __name__ == "__main__":
    unittest.main()
