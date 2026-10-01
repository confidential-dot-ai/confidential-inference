from __future__ import annotations

import runpy
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE = runpy.run_path(str(ROOT / "scripts/validate-release-tag.py"))
ReleaseTagError = MODULE["ReleaseTagError"]
parse_tag = MODULE["parse_tag"]
read_spec_version = MODULE["read_spec_version"]


class ReleaseTagTests(unittest.TestCase):
    def test_accepts_semantic_versions(self) -> None:
        self.assertEqual(parse_tag("v0.14.0"), "v0.14.0")
        self.assertEqual(parse_tag("v0.14.0-staging"), "v0.14.0-staging")
        self.assertEqual(parse_tag("v12.4.103"), "v12.4.103")

    def test_rejects_release_candidates_and_other_names(self) -> None:
        for tag in (
            "v0.14.3-rc.1",
            "v0.14.3-rc.0",
            "v01.2.3",
            "v1.2",
            "0.14.3",
            "v0.14.3-t-v0.13.0",
            "integration-staging-v0.14.3",
            "v0.14.3-staging.1",
        ):
            with self.subTest(tag=tag), self.assertRaises(ReleaseTagError):
                parse_tag(tag)

    def test_reads_the_spec_version(self) -> None:
        self.assertEqual(read_spec_version(ROOT / "release/spec.yaml"), "v0.14.0")
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as handle:
            handle.write("c8s: {}\n")
            handle.flush()
            with self.assertRaises(ReleaseTagError):
                read_spec_version(Path(handle.name))


if __name__ == "__main__":
    unittest.main()
