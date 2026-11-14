"""The C8s v0.99.29 verification and migration steps match what C8s accepts."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def section(path: str, heading: str) -> str:
    text = (ROOT / path).read_text()
    start = text.index(heading)
    end = text.find("\n## ", start + len(heading))
    return " ".join(text[start:end if end >= 0 else None].split())


class MigrationDocsTest(unittest.TestCase):
    def test_the_worker_cds_pin_embeds_the_launch_file(self):
        # cmdsutil.CDSLaunchFile refuses a CDS pin entry without launch_file.
        steps = section("docs/verification.md", "## Releases on C8s v0.99.29")
        self.assertIn("embed the exact bytes of `cds-config.yaml` as `launch_file`", steps)
        self.assertIn("refuses an entry that carries only `launch_file_digest`", steps)

    def test_the_cds_manifest_comes_from_the_release_and_its_digest_is_checked(self):
        steps = section("docs/verification.md", "## Releases on C8s v0.99.29")
        self.assertIn("Download the release's `cds-manifest.json` asset", steps)
        self.assertIn("jq -r .cdsImage.manifestSha256 release-bundle.json", steps)

    def test_worker_admission_comes_from_the_decree_in_force(self):
        # A worker document embeds cds-config.yaml, so cds-config.yaml cannot pin it.
        steps = section("release/README.md", "## Move a deployment to C8s v0.99.29")
        self.assertNotIn("the CDS configuration does not pin", steps)
        self.assertIn("c8s cds ha decree genesis", steps)
        self.assertIn("`node-images` decree", steps)
        self.assertIn("c8s cds ha decrees --config cds-config.yaml", steps)


if __name__ == "__main__":
    unittest.main()
