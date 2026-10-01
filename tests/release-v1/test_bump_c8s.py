#!/usr/bin/env python3
"""Tests for the parts of scripts/bump-c8s.py that need no registry."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("bump_c8s", ROOT / "scripts/bump-c8s.py")
BUMP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUMP)

OLD = {"release": "v0.33.4", "commit": "a" * 40, "nodeImage": "sha256:" + "1" * 64,
       "nodeManifestArtifact": "sha256:" + "2" * 64, "core:cds": "sha256:" + "3" * 64}
NEW = {"release": "v0.33.7", "commit": "b" * 40, "nodeImage": "sha256:" + "4" * 64,
       "nodeManifestArtifact": "sha256:" + "5" * 64, "core:cds": "sha256:" + "6" * 64}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


class BumpTests(unittest.TestCase):
    def test_pairs_replace_the_full_commit_before_the_short_one(self):
        pairs = BUMP.pairs_for(OLD, NEW)
        keys = [old for old, _ in pairs]
        self.assertLess(keys.index("a" * 40), keys.index("a" * 8))
        self.assertEqual(pairs[-1], ("v0.33.4", "v0.33.7"))
        text = f"commit {'a' * 40} short {'a' * 8} digest sha256:{'3' * 64}"
        for old, new in pairs:
            text = text.replace(old, new)
        self.assertEqual(text, f"commit {'b' * 40} short {'b' * 8} digest sha256:{'6' * 64}")

    def test_only_an_extra_profile_gets_a_release_argument(self):
        self.assertEqual(BUMP.release_args(ROOT / "release"), [])
        self.assertEqual(BUMP.release_args(ROOT / "release/staging"), ["--release", "release/staging"])

    def test_the_node_image_text_matches_any_version(self):
        text = "The CDI specification of the c8s v0.33.2 node image mounts"
        self.assertEqual(BUMP.NODE_IMAGE_TEXT.sub("c8s v0.33.7 node image", text),
                         "The CDI specification of the c8s v0.33.7 node image mounts")

    def test_changed_protocol_files_stop_the_bump(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "c8s"
            (repo / "pkg/types").mkdir(parents=True)
            git(repo.parent, "init", "-q", str(repo))
            (repo / "server.go").write_text("old\n")
            (repo / "pkg/types/verify.go").write_text("types\n")
            git(repo, "add", "-A")
            git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "old")
            old = git(repo, "rev-parse", "HEAD")
            (repo / "server.go").write_text("new\n")
            git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "new")
            new = git(repo, "rev-parse", "HEAD")
            protocols = Path(directory) / "protocols"
            protocols.mkdir()
            manifest = {"commit": old, "sharedWithCommits": [], "capturedFrom": {"routes": "server.go"},
                        "capturedFromNote": "Captured."}
            (protocols / f"{old}.json").write_text(json.dumps(manifest, indent=2) + "\n")
            original = BUMP.PROTOCOLS
            BUMP.PROTOCOLS = protocols
            try:
                with self.assertRaisesRegex(BUMP.BumpError, "server.go"):
                    BUMP.share_protocol_manifest(repo, old, new, "v0.33.7")
            finally:
                BUMP.PROTOCOLS = original


if __name__ == "__main__":
    unittest.main()
