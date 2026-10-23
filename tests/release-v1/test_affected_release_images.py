from __future__ import annotations

import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE = runpy.run_path(str(ROOT / "scripts/affected-release-images.py"))
affected_images = MODULE["affected_images"]
BASE_REF = MODULE["BASE_REF"]
IMAGES = {image.image: image for image in MODULE["IMAGES"]}
input_revision = MODULE["input_revision"]


def names(paths: list[str]) -> list[str]:
    return [image.image for image in affected_images(paths)]


class AffectedReleaseImagesTests(unittest.TestCase):
    def test_rust_source_change_selects_both_rust_images(self) -> None:
        self.assertEqual(
            names(["services/gateway/src/main.rs"]),
            ["gateway", "maintenance-gateway"],
        )

    def test_image_change_selects_only_its_image(self) -> None:
        self.assertEqual(names(["images/gateway/Dockerfile"]), ["gateway"])
        self.assertEqual(names(["images/sglang/Dockerfile"]), ["sglang"])
        self.assertEqual(names(["images/rollout-client/Dockerfile"]), ["rollout-client"])

    def test_router_patch_and_source_pin_do_not_select_workers(self) -> None:
        self.assertEqual(names(['images/sglang-router/patches/worker-withdrawal.patch',
                                'images/sglang-router/source.lock',
                                'images/sglang-router/canonicalize_wheel.py']), ['sglang-router'])

    def test_shared_rust_input_selects_both_rust_images(self) -> None:
        self.assertEqual(
            names(["Cargo.lock"]),
            ["gateway", "maintenance-gateway"],
        )

    def test_unrelated_change_selects_no_image(self) -> None:
        self.assertEqual(
            names(
                [
                    "README.md",
                    "images/gateway/README.md",
                    "images/gateway/build.sh",
                    "images/sglang/README.md",
                    "services/gateway/tests/fake_upstream.rs",
                    "helm/confidential-inference/values.yaml",
                    ".github/workflows/release-images.yml",
                ]
            ),
            [],
        )

    def test_sglang_build_mount_selects_sglang(self) -> None:
        self.assertEqual(
            names(["images/sglang/simulator-upstream/src/usercustomize.py"]),
            ["sglang"],
        )

    def test_base_ref_accepts_only_release_tags_or_full_commits(self) -> None:
        self.assertIsNotNone(BASE_REF.fullmatch("v0.14.3"))
        self.assertIsNotNone(BASE_REF.fullmatch("v0.14.3-staging"))
        self.assertIsNotNone(BASE_REF.fullmatch("v0.14.3-rc.2"))
        self.assertIsNotNone(BASE_REF.fullmatch("a" * 40))
        self.assertIsNone(BASE_REF.fullmatch("main"))
        self.assertIsNone(BASE_REF.fullmatch("staging-v12"))

    def test_input_revision_is_the_last_commit_that_changed_an_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            def git(*args: str) -> str:
                return subprocess.check_output(
                    ["git", "-C", tmp, "-c", "user.name=t", "-c", "user.email=t@t", *args], text=True
                ).strip()

            git("init", "-q")
            (Path(tmp) / "images/kube-state-metrics").mkdir(parents=True)
            (Path(tmp) / "images/kube-state-metrics/Dockerfile").write_text("a\n")
            git("add", ".")
            git("commit", "-q", "-m", "inputs", "--date=@1700000000")
            inputs = git("rev-parse", "HEAD")
            (Path(tmp) / "README.md").write_text("b\n")
            git("add", ".")
            git("commit", "-q", "-m", "unrelated")
            head = git("rev-parse", "HEAD")
            self.assertEqual(
                input_revision(IMAGES["kube-state-metrics"], head, cwd=tmp),
                (inputs, git("show", "-s", "--format=%ct", inputs)),
            )


if __name__ == "__main__":
    unittest.main()
