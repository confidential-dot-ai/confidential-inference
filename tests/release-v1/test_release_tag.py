from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import release_spec  # noqa: E402


class ReleaseTagTests(unittest.TestCase):
    def test_a_framework_release_tag_is_a_semantic_version(self) -> None:
        for tag in ("v0.14.0", "v12.4.103", "v0.17.0"):
            with self.subTest(tag=tag):
                self.assertIsNotNone(release_spec.TAG.fullmatch(tag))

    def test_rejects_release_candidates_and_other_names(self) -> None:
        for tag in (
            "v0.14.3-rc.1",
            "v01.2.3",
            "v1.2",
            "0.14.3",
            "v0.14.0-staging",
            "v0.14.18-transition",
            "integration-staging-v0.14.3",
        ):
            with self.subTest(tag=tag):
                self.assertIsNone(release_spec.TAG.fullmatch(tag))

    def test_earlier_release_tags_remain_readable_as_base_releases(self) -> None:
        for tag in ("v0.14.0", "v0.14.0-staging", "v0.14.18-transition", "v0.14.18-transition-staging"):
            with self.subTest(tag=tag):
                self.assertIsNotNone(release_spec.HISTORICAL_TAG.fullmatch(tag))
        for tag in ("v0.14.3-staging.1", "v0.14.18-staging-transition", "v0.14.3-rc.1"):
            with self.subTest(tag=tag):
                self.assertIsNone(release_spec.HISTORICAL_TAG.fullmatch(tag))


if __name__ == "__main__":
    unittest.main()
