from __future__ import annotations

import copy
import runpy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE = runpy.run_path(str(ROOT / "scripts/validate-release-tag.py"))
ReleaseTagError = MODULE["ReleaseTagError"]
parse_tag = MODULE["parse_tag"]
require_same_release = MODULE["require_same_release"]


class ReleaseTagTests(unittest.TestCase):
    def test_accepts_final_and_candidate_semantic_versions(self) -> None:
        self.assertEqual(parse_tag("v0.14.3"), ("v0.14.3", None))
        self.assertEqual(parse_tag("v0.14.3-rc.1"), ("v0.14.3", 1))
        self.assertEqual(parse_tag("v12.4.103-rc.27"), ("v12.4.103", 27))

    def test_rejects_other_release_names(self) -> None:
        for tag in (
            "v0.14",
            "v0.14.3-candidate",
            "v0.14.3-rc.0",
            "v00.14.3",
            "candidate-v1",
            "staging-v12",
        ):
            with self.subTest(tag=tag), self.assertRaises(ReleaseTagError):
                parse_tag(tag)

    def test_final_must_equal_candidate_except_for_release_name(self) -> None:
        candidate = {
            "release": {"name": "v0.14.3-rc.1", "environment": "production"},
            "workloads": [{"image": {"digest": "sha256:" + "1" * 64}}],
        }
        final = copy.deepcopy(candidate)
        final["release"]["name"] = "v0.14.3"
        require_same_release(candidate, final)

        final["workloads"][0]["image"]["digest"] = "sha256:" + "2" * 64
        with self.assertRaisesRegex(ReleaseTagError, "differs"):
            require_same_release(candidate, final)


if __name__ == "__main__":
    unittest.main()
