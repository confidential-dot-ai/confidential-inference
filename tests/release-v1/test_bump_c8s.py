#!/usr/bin/env python3
"""Tests for the parts of scripts/bump-c8s.py that need no registry."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("bump_c8s", ROOT / "scripts/bump-c8s.py")
BUMP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUMP)

SPEC_TEXT = """# A comment that must stay.
version: v0.14.0

c8s:
  # The c8s release.
  release: v0.33.4
  sourceCommit: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  coreImages:
    - ghcr.io/confidential-dot-ai/cds@sha256:1111111111111111111111111111111111111111111111111111111111111111
    - nginxinc/nginx-unprivileged@sha256:2222222222222222222222222222222222222222222222222222222222222222

model:
  repository: example/model
"""


def git_repo(directory: Path) -> Path:
    repo = directory / "c8s"
    repo.mkdir()
    BUMP.git(repo, "init", "-q")
    return repo


def commit(repo: Path, files: dict[str, str]) -> str:
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    BUMP.git(repo, "add", "-A")
    BUMP.git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "change")
    return BUMP.git(repo, "rev-parse", "HEAD")


class BumpTests(unittest.TestCase):
    def write(self, text: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "spec.yaml"
        path.write_text(text)
        return path

    def new_c8s(self) -> dict:
        value = BUMP.yaml.safe_load(SPEC_TEXT)["c8s"]
        value.update({"release": "v0.33.7", "sourceCommit": "b" * 40})
        value["coreImages"][0] = "ghcr.io/confidential-dot-ai/cds@sha256:" + "3" * 64
        return value

    def test_the_c8s_edit_keeps_every_other_byte(self):
        path = self.write(SPEC_TEXT)
        with mock.patch.object(BUMP, "ROOT", path.parent):
            BUMP.edit_yaml(path, ("c8s",), self.new_c8s())
        expected = (SPEC_TEXT.replace("v0.33.4", "v0.33.7").replace("a" * 40, "b" * 40)
                    .replace("1" * 64, "3" * 64))
        self.assertEqual(path.read_text(), expected)

    def test_the_c8s_edit_refuses_to_change_another_key(self):
        path = self.write(SPEC_TEXT + "other: v0.33.4\n")
        with mock.patch.object(BUMP, "ROOT", path.parent), self.assertRaisesRegex(BUMP.BumpError, "changed more"):
            BUMP.edit_yaml(path, ("c8s",), self.new_c8s())
        self.assertIn("release: v0.33.4", path.read_text())

    def test_an_absent_key_is_appended(self):
        path = self.write("version: v0.14.0-staging\n")
        with mock.patch.object(BUMP, "ROOT", path.parent):
            BUMP.edit_yaml(path, ("images", "c8sOperator"), "example@sha256:" + "4" * 64)
        self.assertEqual(BUMP.yaml.safe_load(path.read_text()),
                         {"version": "v0.14.0-staging", "images": {"c8sOperator": "example@sha256:" + "4" * 64}})

    def test_a_shared_layer_moves_only_with_every_profile_that_uses_it(self):
        production, staging = BUMP.release_profiles.load()
        shared = ROOT / "release/spec.yaml"
        self.assertEqual(BUMP.target_file(shared, staging, [production, staging], [production, staging]), shared)
        self.assertEqual(BUMP.target_file(shared, staging, [staging], [production, staging]),
                         ROOT / "release/staging/spec.yaml")

    def test_the_cdi_record_extends_only_while_the_driver_inputs_hold(self):
        old = {"sourceCommit": "", "nodeImage": {"reference": "example/node", "digest": "sha256:" + "1" * 64}}
        new = {"sourceCommit": "", "nodeImage": {"reference": "example/node", "digest": "sha256:" + "2" * 64}}
        pins = '{"builds": {"node-image": {"confos_ref": "%s"}}}'
        with tempfile.TemporaryDirectory() as directory:
            repo = git_repo(Path(directory))
            old["sourceCommit"] = commit(repo, {BUMP.BUILD_PINS: pins % "c1"})
            new["sourceCommit"] = commit(repo, {"README": "same pins\n"})
            cdi = Path(directory) / "cdi"
            cdi.mkdir()
            record = cdi / "nvidia.json"
            record.write_text(json.dumps({"nodeImages": ["example/node@sha256:" + "1" * 64]}, indent=2) + "\n")
            with mock.patch.object(BUMP, "CDI_DIR", cdi):
                BUMP.extend_cdi_record(repo, None, old, new)
                self.assertEqual(json.loads(record.read_text())["nodeImages"][-1], "example/node@sha256:" + "2" * 64)
                newer = {**new, "sourceCommit": commit(repo, {BUMP.BUILD_PINS: pins % "c2"}),
                         "nodeImage": {"reference": "example/node", "digest": "sha256:" + "3" * 64}}
                with self.assertRaisesRegex(BUMP.BumpError, "--confos-repo"):
                    BUMP.extend_cdi_record(repo, None, new, newer)

    def test_changed_protocol_files_stop_the_bump(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "c8s"
            (repo / "pkg/types").mkdir(parents=True)
            BUMP.git(repo.parent, "init", "-q", str(repo))
            (repo / "server.go").write_text("old\n")
            (repo / "pkg/types/verify.go").write_text("types\n")
            BUMP.git(repo, "add", "-A")
            BUMP.git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "old")
            old = BUMP.git(repo, "rev-parse", "HEAD")
            (repo / "server.go").write_text("new\n")
            BUMP.git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "new")
            new = BUMP.git(repo, "rev-parse", "HEAD")
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
