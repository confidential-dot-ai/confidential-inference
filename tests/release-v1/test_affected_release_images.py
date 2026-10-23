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

    def test_input_revision_depends_only_on_the_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            def git(*args: str) -> str:
                return subprocess.check_output(
                    ["git", "-C", tmp, "-c", "user.name=t", "-c", "user.email=t@t", *args], text=True
                ).strip()

            def commit(path: str, text: str, message: str = "change") -> str:
                (Path(tmp) / path).parent.mkdir(parents=True, exist_ok=True)
                (Path(tmp) / path).write_text(text)
                git("add", ".")
                git("commit", "-q", "-m", message)
                return git("rev-parse", "HEAD")

            image = IMAGES["kube-state-metrics"]
            git("init", "-q", "-b", "main")
            inputs = commit("images/kube-state-metrics/Dockerfile", "a\n")
            unrelated = commit("README.md", "b\n")
            # The same input on another branch, by another commit.
            git("checkout", "-q", "--orphan", "other")
            git("rm", "-q", "-r", "--cached", ".")
            (Path(tmp) / "README.md").unlink()
            other = commit("images/kube-state-metrics/Dockerfile", "a\n", "same input, other commit")
            changed = commit("images/kube-state-metrics/Dockerfile", "c\n")

            revision, epoch = input_revision(image, inputs, cwd=tmp)
            self.assertRegex(revision, "^[0-9a-f]{40}$")
            self.assertEqual(epoch, "315532800")
            self.assertNotEqual(other, inputs)
            self.assertEqual(input_revision(image, unrelated, cwd=tmp), (revision, epoch))
            self.assertEqual(input_revision(image, other, cwd=tmp), (revision, epoch))
            self.assertNotEqual(input_revision(image, changed, cwd=tmp)[0], revision)

if __name__ == "__main__":
    unittest.main()
