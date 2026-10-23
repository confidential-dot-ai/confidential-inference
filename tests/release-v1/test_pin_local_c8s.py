import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import release_profiles


class PinLocalC8sTests(unittest.TestCase):
    def local_dir(self, root: Path, version: str) -> Path:
        directory = root / "local-c8s"
        directory.mkdir()
        (directory / "c8s").write_text(f"#!/bin/sh\necho 'c8s version {version}'\n")
        os.chmod(directory / "c8s", 0o755)
        staging = release_profiles.for_directory(ROOT / "release/staging")
        (directory / "manifest.json").write_bytes(release_profiles.node_manifest(staging).read_bytes())
        return directory

    def test_a_build_that_staging_pins_changes_nothing(self):
        staging = release_profiles.for_directory(ROOT / "release/staging")
        version = release_profiles.read_spec(staging)["c8s"]["release"]
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "scripts/pin-local-c8s.py", str(self.local_dir(Path(directory), version)),
                                     "--c8s-repo", "/nonexistent"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already pins", result.stdout)

    def test_a_cli_without_a_version_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "scripts/pin-local-c8s.py", str(self.local_dir(Path(directory), "dev")),
                                     "--c8s-repo", "/nonexistent"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no c8s release or pseudo-version", result.stderr)


if __name__ == "__main__":
    unittest.main()
