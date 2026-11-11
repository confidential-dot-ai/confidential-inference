import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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

    def test_relative_paths_reach_the_bump_as_absolute_paths(self):
        spec = importlib.util.spec_from_file_location("pin_local_c8s", ROOT / "scripts/pin-local-c8s.py")
        pin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pin)
        bumps = []
        with tempfile.TemporaryDirectory() as directory:
            self.local_dir(Path(directory), "v0.99.40")
            (Path(directory) / "c8s-repo").mkdir()
            (Path(directory) / "confos").mkdir()
            cwd = os.getcwd()
            os.chdir(directory)
            self.addCleanup(os.chdir, cwd)
            argv = ["pin-local-c8s.py", "local-c8s", "--c8s-repo", "c8s-repo", "--confos-repo", "confos"]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(pin, "run", return_value="c8s version v0.99.40\n"), \
                    mock.patch.object(pin.subprocess, "run", side_effect=lambda command, **kwargs: bumps.append(command)
                                      or subprocess.CompletedProcess(command, 1)):
                self.assertEqual(pin.main(), 1)
            base = Path(directory).resolve()
        command = bumps[0]
        self.assertEqual(command[command.index("--c8s") + 1], str(base / "local-c8s/c8s"))
        self.assertEqual(command[command.index("--c8s-repo") + 1], str(base / "c8s-repo"))
        self.assertEqual(command[command.index("--confos-repo") + 1], str(base / "confos"))


if __name__ == "__main__":
    unittest.main()
