from __future__ import annotations

import runpy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE = runpy.run_path(str(ROOT / "scripts/rebuild-release-images.py"))


class RebuildReleaseImagesTests(unittest.TestCase):
    def test_deduplicates_one_image_used_by_multiple_workloads(self) -> None:
        build = {
            "repository": "https://github.com/confidential-dot-ai/confidential-inference",
            "commit": "a" * 40,
            "context": "images/sglang",
            "dockerfile": "images/sglang/Dockerfile",
            "platform": "linux/amd64",
        }
        image = {
            "reference": "ghcr.io/confidential-dot-ai/confidential-inference/sglang",
            "digest": "sha256:" + "b" * 64,
        }
        bundle = {
            "workloads": [
                {"name": "router", "image": image, "build": build},
                {"name": "worker", "image": image, "build": build},
            ]
        }
        records = MODULE["release_images"](bundle)
        self.assertEqual(1, len(records))
        self.assertEqual("sglang", records[0]["name"])

    def test_rejects_owned_image_without_build_record(self) -> None:
        bundle = {
            "workloads": [{
                "name": "gateway",
                "image": {
                    "reference": "ghcr.io/confidential-dot-ai/confidential-inference/gateway",
                    "digest": "sha256:" + "b" * 64,
                },
            }]
        }
        with self.assertRaisesRegex(MODULE["AuditError"], "no build record"):
            MODULE["release_images"](bundle)

    def test_no_image_needs_extra_build_args_today(self) -> None:
        self.assertEqual([], MODULE["extra_build_args"]("gateway", ROOT))


if __name__ == "__main__":
    unittest.main()
