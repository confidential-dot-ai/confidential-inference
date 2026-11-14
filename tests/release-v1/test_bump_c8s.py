#!/usr/bin/env python3
"""Tests for the parts of scripts/bump-c8s.py that need no registry."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import shutil
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


# Long enough for git to see the renamed file as a rename after a one-line change.
TLS_SOURCE = "package ratls\n\n" + "".join(f"func F{index}() {{}}\n" for index in range(20))


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

    def test_new_seed_record_is_written_and_existing_format_is_still_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new-seed.json"
            with mock.patch.object(BUMP, "ROOT", path.parent):
                BUMP.write_json(path, {"allowlist": {"workloads": {}}})
                self.assertEqual(path.read_text(), '{\n  "allowlist": {\n    "workloads": {}\n  }\n}\n')
                path.write_text('{"unreviewed":"format"}')
                with self.assertRaisesRegex(BUMP.BumpError, "expected JSON form"):
                    BUMP.write_json(path, {})

    def test_shared_module_moves_staging_first_then_production_without_reverting(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory)
            path = tool / "go.mod"
            path.write_text("module example\n\nrequire " + BUMP.C8S_MODULE + " v0.43.0\n")
            with mock.patch.object(BUMP, "CANONICAL_TOOL", tool), mock.patch.object(BUMP, "run") as run:
                BUMP.bump_module("v0.43.0", "v0.44.6-beta.1")
                BUMP.bump_module("v0.37.0-beta.1", "v0.44.6-beta.1")
                self.assertEqual(path.read_text(), "module example\n\nrequire " + BUMP.C8S_MODULE + " v0.44.6-beta.1\n")
                self.assertEqual(run.call_count, 2)

    def test_core_images_follow_the_chart_component_inventory_and_its_nginx_pin(self):
        inventory = {"components": [
            {"valuePath": "image"}, {"valuePath": "attestationApi.image", "pinnedDigest": "sha256:" + "7" * 64},
            {"valuePath": "armtlsMesh.image"}, {"valuePath": "nriImagePolicy.image", "argvPinned": True}],
            "routerNginx": {"image": {"repository": "nginxinc/nginx-unprivileged", "digest": "sha256:" + "8" * 64}}}
        values = {"image": {"repository": BUMP.REGISTRY + "c8s-operator"},
                  "attestationApi": {"image": {"repository": BUMP.REGISTRY + "attestation-api"}},
                  "armtlsMesh": {"image": {"repository": BUMP.REGISTRY + "armtls-mesh"}},
                  "nriImagePolicy": {"image": {"repository": BUMP.REGISTRY + "nri-image-policy"}}}
        files = {BUMP.COMPONENTS: inventory, BUMP.CHART_VALUES: values}
        with mock.patch.object(BUMP, "git_show", side_effect=lambda _repo, _commit, name: BUMP.yaml.safe_dump(files[name]).encode()), \
             mock.patch.object(BUMP, "digest", side_effect=lambda reference: "sha256:" + "9" * 64) as digest:
            core = BUMP.core_images(Path("selected-source"), "a" * 40, "v0.99.29")
        self.assertEqual(core, [BUMP.REGISTRY + name + "@sha256:" + "9" * 64
                                for name in ("c8s-operator", "armtls-mesh", "nri-image-policy")]
                         + ["nginxinc/nginx-unprivileged@sha256:" + "8" * 64])
        self.assertEqual(digest.call_args_list[0], mock.call(BUMP.REGISTRY + "c8s-operator:v0.99.29"))

    def test_new_pins_move_to_the_worker_and_cds_guest_images(self):
        old = {"release": "v0.80.10", "sourceCommit": "a" * 40, "coreImages": [],
               "nodeImage": {"reference": BUMP.REGISTRY + "node-guest-base", "tag": "rke2-tdx-cdi-v0.80.10",
                             "digest": "sha256:" + "1" * 64},
               "nodeManifestArtifact": {"tag": "rke2-tdx-v0.80.10", "digest": "sha256:" + "2" * 64,
                                        "manifestJson": "sha256:" + "3" * 64}}
        digests = {f"{BUMP.REGISTRY}guests/worker:v0.99.29-tdx-kubevirt": "4", f"{BUMP.REGISTRY}guests/worker:v0.99.29-tdx": "5",
                   f"{BUMP.REGISTRY}guests/cds:v0.99.29-kubevirt": "6", f"{BUMP.REGISTRY}guests/cds:v0.99.29": "7"}
        with mock.patch.object(BUMP, "digest", side_effect=lambda reference: "sha256:" + digests[reference] * 64), \
             mock.patch.object(BUMP, "core_images", return_value=["core"]), \
             mock.patch.dict(BUMP.NODE, {"manifest_json_digest": lambda reference, artifact: reference + artifact[7]}):
            new = BUMP.new_c8s("v0.99.29", "b" * 40, old, Path("c8s"))
            self.assertEqual(new["nodeImage"], {"reference": BUMP.REGISTRY + "guests/worker", "tag": "v0.99.29-tdx-kubevirt",
                                                "digest": "sha256:" + "4" * 64})
            self.assertEqual(new["nodeManifestArtifact"], {"tag": "v0.99.29-tdx", "digest": "sha256:" + "5" * 64,
                                                           "manifestJson": BUMP.REGISTRY + "guests/worker5"})
            self.assertEqual(new["cdsImage"], {"reference": BUMP.REGISTRY + "guests/cds", "tag": "v0.99.29-kubevirt",
                                               "digest": "sha256:" + "6" * 64})
            self.assertEqual(new["cdsManifestArtifact"], {"tag": "v0.99.29", "digest": "sha256:" + "7" * 64,
                                                          "manifestJson": BUMP.REGISTRY + "guests/cds7"})
            self.assertEqual((new["release"], new["sourceCommit"], new["coreImages"]), ("v0.99.29", "b" * 40, ["core"]))
            with self.assertRaisesRegex(BUMP.BumpError, "v0.99.0 and later"):
                BUMP.new_c8s("v0.95.0", "b" * 40, old, Path("c8s"))
            with self.assertRaisesRegex(BUMP.BumpError, "do not follow"):
                BUMP.new_c8s("v0.99.30", "c" * 40, {**new, "nodeImage": {**new["nodeImage"], "tag": "custom"}}, Path("c8s"))

    def test_new_c8s_keys_are_appended_to_the_mapping(self):
        path = self.write(SPEC_TEXT)
        value = self.new_c8s()
        value["cdsImage"] = {"reference": BUMP.CDS_IMAGE, "tag": "v0.99.29-kubevirt", "digest": "sha256:" + "5" * 64}
        with mock.patch.object(BUMP, "ROOT", path.parent):
            BUMP.pin_c8s_mapping(path, value)
            self.assertEqual(BUMP.yaml.safe_load(path.read_text())["c8s"], value)
            self.assertIn("  cdsImage:\n    reference: ghcr.io/confidential-dot-ai/guests/cds\n", path.read_text())
            self.assertIn("\nmodel:\n  repository: example/model\n", path.read_text())
            del value["sourceCommit"]
            with self.assertRaisesRegex(BUMP.BumpError, "drop sourceCommit"):
                BUMP.pin_c8s_mapping(path, value)

    def test_the_seed_record_is_the_render_of_the_pinned_cli_with_the_worker_build_inputs(self):
        sync = 'HELM_VERSION="v3.14.4"\nKUBERNETES_VERSION="v1.36.4"\n'
        operator = BUMP.REGISTRY + "c8s-operator@sha256:" + "1" * 64
        mesh = BUMP.REGISTRY + "armtls-mesh@sha256:" + "2" * 64
        new = {"sourceCommit": "b" * 40, "coreImages": [operator, mesh]}
        seed = {"schema": "c8s.allowlist/v1", "workloads": {"c8s-router-" + "0" * 12: {}}}
        rendered = []

        def render_seed(binary, inputs):
            rendered.append((binary, inputs))
            return seed

        generator = {"render_seed": render_seed, "GenerationError": ValueError,
                     "canonicalize": lambda document, _tool: json.dumps(document).encode()}
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(BUMP, "ROOT", Path(directory)), mock.patch.object(BUMP, "run"), \
                mock.patch.object(BUMP, "git_show", return_value=sync.encode()), \
                mock.patch.object(BUMP.runpy, "run_path", return_value=generator):
            (Path(directory) / "release/inputs/c8s-seeds").mkdir(parents=True)
            inputs, value = BUMP.render_core_seed(Path("c8s"), Path("repo"), new)
            BUMP.record_core_seed(inputs, value, {"sourceCommit": "a" * 40})
            record = json.loads((Path(directory) / "release/inputs/c8s-seeds" / (new["sourceCommit"] + ".json")).read_text())
        expected = {"sourceCommit": "b" * 40, "coreImages": [operator, mesh], "hardwarePlatform": "tdx",
                    "kubeVersion": "v1.36.4", "helmVersion": "v3.14.4"}
        self.assertEqual(record, {**expected, "allowlist": seed})
        self.assertEqual(rendered, [(Path("c8s"), expected)])

    def test_a_failed_prerequisite_writes_nothing_and_a_failed_step_restores_the_tree(self):
        args = BUMP.argparse.Namespace(c8s=None, tag="v0.99.30", protocol_review=False, confos_repo=None)
        steps = ("pin_spec", "bump_module", "add_source_lock", "share_protocol_manifest", "extend_cdi_record",
                 "record_core_seed", "regenerate", "regenerate_fixture", "restore_tree")
        with contextlib.ExitStack() as stack:
            called = {name: stack.enter_context(mock.patch.object(BUMP, name)) for name in steps}
            stack.enter_context(mock.patch.object(BUMP, "c8s_cli", return_value=Path("c8s")))
            render = stack.enter_context(mock.patch.object(
                BUMP, "render_core_seed", side_effect=BUMP.BumpError("the C8s seed renders with Helm v3.14.4")))
            with self.assertRaisesRegex(BUMP.BumpError, "Helm v3.14.4"):
                BUMP.write_bump(args, Path("c8s"), "b" * 40, {}, {})
            self.assertEqual([name for name, step in called.items() if step.called], [])
            render.side_effect = None
            render.return_value = ({}, {})
            called["share_protocol_manifest"].side_effect = BUMP.BumpError("protocol source files changed")
            with self.assertRaisesRegex(BUMP.BumpError, "protocol"):
                BUMP.write_bump(args, Path("c8s"), "b" * 40, {"release": "v0.99.29", "sourceCommit": "a" * 40}, {})
            called["restore_tree"].assert_called_once_with()
            self.assertFalse(called["record_core_seed"].called)

    def test_core_inventory_growth_preserves_comments_and_other_pins(self):
        path = self.write(SPEC_TEXT)
        value = self.new_c8s()
        value["coreImages"].append(BUMP.REGISTRY + "nri-image-policy@sha256:" + "4" * 64)
        with mock.patch.object(BUMP, "ROOT", path.parent):
            BUMP.pin_c8s_mapping(path, value)
        self.assertEqual(BUMP.yaml.safe_load(path.read_text())["c8s"], value)
        self.assertTrue(path.read_text().startswith("# A comment that must stay.\n"))
        self.assertIn("  # The c8s release.\n", path.read_text())
        original, updated = BUMP.yaml.safe_load(SPEC_TEXT), BUMP.yaml.safe_load(path.read_text())
        original.pop("c8s"); updated.pop("c8s")
        self.assertEqual(original, updated)

    def test_a_release_tag_drops_the_dev_build_base_release(self):
        dev = SPEC_TEXT.replace("  # The c8s release.\n",
                                "  # The release the dev build previews.\n  baseRelease: v0.73.0\n  # The c8s release.\n", 1)
        self.assertIn("baseRelease", dev)
        path = self.write(dev)
        value = self.new_c8s()
        self.assertNotIn("baseRelease", value)
        with mock.patch.object(BUMP, "ROOT", path.parent):
            BUMP.pin_c8s_mapping(path, value)
        self.assertEqual(BUMP.yaml.safe_load(path.read_text())["c8s"], value)
        self.assertNotIn("previews", path.read_text())
        self.assertIn("  # The c8s release.\n", path.read_text())

    def test_the_c8s_edit_keeps_every_other_byte(self):
        path = self.write(SPEC_TEXT)
        with mock.patch.object(BUMP, "ROOT", path.parent):
            BUMP.edit_yaml(path, ("c8s",), self.new_c8s())
        expected = (SPEC_TEXT.replace("v0.33.4", "v0.33.7").replace("a" * 40, "b" * 40)
                    .replace("1" * 64, "3" * 64))
        self.assertEqual(path.read_text(), expected)

    def test_the_c8s_edit_keeps_another_key_with_the_same_value(self):
        path = self.write(SPEC_TEXT + "other: v0.33.4\n")
        with mock.patch.object(BUMP, "ROOT", path.parent):
            BUMP.edit_yaml(path, ("c8s",), self.new_c8s())
        self.assertIn("  release: v0.33.7\n", path.read_text())
        self.assertTrue(path.read_text().endswith("\nother: v0.33.4\n"))

    def test_a_stable_bump_moves_the_committed_pins_whose_tags_repeat_the_release(self):
        # cdsManifestArtifact.tag repeats c8s.release for a stable release.
        path = self.write((ROOT / "release/spec.yaml").read_text())
        old = BUMP.yaml.safe_load(path.read_text())["c8s"]
        self.assertEqual(old["cdsManifestArtifact"]["tag"], old["release"])
        new = json.loads(json.dumps(old).replace("v0.99.29", "v0.99.40"))
        new["sourceCommit"] = "f" * 40
        for index, image in enumerate(new["coreImages"]):
            new["coreImages"][index] = image.split("@")[0] + "@sha256:" + "%x" % (index + 1) * 64
        for key in ("nodeImage", "nodeManifestArtifact", "cdsImage", "cdsManifestArtifact"):
            new[key]["digest"] = "sha256:" + "a" * 64
        for key in ("nodeManifestArtifact", "cdsManifestArtifact"):
            new[key]["manifestJson"] = "sha256:" + "b" * 64
        before = BUMP.yaml.safe_load(path.read_text())
        with mock.patch.object(BUMP, "ROOT", path.parent):
            BUMP.pin_c8s_mapping(path, new)
        after = BUMP.yaml.safe_load(path.read_text())
        self.assertEqual(after["c8s"], new)
        del before["c8s"], after["c8s"]
        self.assertEqual(after, before)

    def test_an_absent_key_is_appended(self):
        path = self.write("version: v0.14.0-staging\n")
        with mock.patch.object(BUMP, "ROOT", path.parent):
            BUMP.edit_yaml(path, ("images", "c8sOperator"), "example@sha256:" + "4" * 64)
        self.assertEqual(BUMP.yaml.safe_load(path.read_text()),
                         {"version": "v0.14.0-staging", "images": {"c8sOperator": "example@sha256:" + "4" * 64}})

    def test_the_pin_moves_c8s_and_the_operator_image_in_the_spec(self):
        path = self.write(SPEC_TEXT + "images:\n  gateway: example/gateway\n  c8sOperator: old@sha256:" + "9" * 64 + "\n")
        new = self.new_c8s()
        new["coreImages"].append("ghcr.io/confidential-dot-ai/c8s-operator@sha256:" + "5" * 64)
        with mock.patch.object(BUMP, "ROOT", path.parent):
            BUMP.pin_spec(new, path)
        pinned = BUMP.yaml.safe_load(path.read_text())
        self.assertEqual(pinned["c8s"], new)
        self.assertEqual(pinned["images"], {"gateway": "example/gateway", "c8sOperator": BUMP.operator_image(new)})

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

    def test_a_manifest_captured_for_the_new_commit_wins_over_sharing_the_old_one(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = git_repo(Path(directory))
            old = commit(repo, {"server.go": "old\n"})
            new = commit(repo, {"server.go": "new\n"})
            protocols = Path(directory) / "protocols"
            protocols.mkdir()
            # The old commit's manifest sorts first, so one ordered pass would share it.
            for name, value in (("a", old), ("b", new)):
                manifest = {"commit": value, "capturedFrom": {"routes": "server.go"}, "capturedFromNote": "Captured."}
                (protocols / f"{name}.json").write_text(json.dumps(manifest, indent=2) + "\n")
            before = {path.name: path.read_text() for path in protocols.iterdir()}
            with mock.patch.object(BUMP, "PROTOCOLS", protocols):
                BUMP.share_protocol_manifest(repo, old, new, "v0.99.29")
            self.assertEqual({path.name: path.read_text() for path in protocols.iterdir()}, before)

    def protocol_bump(self, old_source: str, new_source: str, diff_out: Path | None = None) -> dict:
        """Share the manifest of a commit with one that changes pkg/types/codes.go."""
        with tempfile.TemporaryDirectory() as directory:
            repo = git_repo(Path(directory))
            old = commit(repo, {"server.go": "package cds\n", "pkg/types/codes.go": old_source})
            new = commit(repo, {"pkg/types/codes.go": new_source})
            protocols = Path(directory) / "protocols"
            protocols.mkdir()
            manifest = {"commit": old, "sharedWithCommits": [], "capturedFrom": {"routes": "server.go"},
                        "capturedFromNote": "Captured."}
            (protocols / f"{old}.json").write_text(json.dumps(manifest, indent=2) + "\n")
            with mock.patch.object(BUMP, "PROTOCOLS", protocols):
                BUMP.share_protocol_manifest(repo, old, new, "v0.36.0", diff_out)
            result = json.loads((protocols / f"{old}.json").read_text())
            self.assertEqual(result["sharedWithCommits"], [new])
            return result

    @unittest.skipIf(shutil.which("go") is None, "tools/go-strip-comments needs Go")
    def test_a_change_only_in_comments_shares_the_manifest(self):
        # c8s v0.36.0 changed two doc comments of pkg/types/error_codes.go.
        source = 'package types\n\n// Codes of the c8s envelope.\nconst A = "a" // stable\n'
        changed = 'package types\n\n// Codes of the C8s envelope.\nconst A = "a"   // kept\n'
        manifest = self.protocol_bump(source, changed)
        self.assertIn("only in Go comments", manifest["capturedFromNote"])

    @unittest.skipIf(shutil.which("go") is None, "tools/go-strip-comments needs Go")
    def test_a_code_change_needs_a_review(self):
        source = 'package types\n\nconst A = "a"\n'
        for changed in ('package types\n\nconst A = "b"\n',
                        '//go:build linux\n\npackage types\n\nconst A = "a"\n'):
            with self.assertRaisesRegex(BUMP.BumpError, "pkg/types/codes.go"):
                self.protocol_bump(source, changed)
            with tempfile.TemporaryDirectory() as directory:
                diff_out = Path(directory) / "protocol.diff"
                manifest = self.protocol_bump(source, changed, diff_out)
                self.assertIn("+", diff_out.read_text())
                self.assertIn("pkg/types/codes.go", diff_out.read_text())
                self.assertIn("only after a person reviews that diff", manifest["capturedFromNote"])
                self.assertNotIn("only in Go comments", manifest["capturedFromNote"])

    def source_lock_bump(self, change) -> dict:
        """Add the lock entry of a commit that applies change() to the pinned tree."""
        with tempfile.TemporaryDirectory() as directory:
            repo = git_repo(Path(directory))
            old = commit(repo, {"pkg/ratls/tls.go": TLS_SOURCE, "cmd/cds/main.go": "package main\n"})
            change(repo)
            new = commit(repo, {})
            lock_path = Path(directory) / "lock.json"
            entry = {"commit": old, "tag": "v0.33.4", "nodeImage": "node@sha256:" + "1" * 64,
                     "c8sOperatorImage": "op@sha256:" + "2" * 64,
                     "files": {"pkg/ratls/tls.go": "sha256:" + "3" * 64, "cmd/cds/main.go": "sha256:" + "4" * 64}}
            lock_path.write_text(json.dumps({"commits": [entry]}, indent=2) + "\n")
            core = ["ghcr.io/confidential-dot-ai/c8s-operator@sha256:" + "5" * 64]
            node = {"reference": "ghcr.io/confidential-dot-ai/node-guest-base", "digest": "sha256:" + "6" * 64}
            with mock.patch.object(BUMP, "SOURCE_LOCK", lock_path):
                BUMP.add_source_lock(repo, {"sourceCommit": old},
                                     {"sourceCommit": new, "release": "v0.33.7", "nodeImage": node, "coreImages": core})
            added = json.loads(lock_path.read_text())["commits"][1]
            self.assertEqual(added["commit"], new)
            return added

    def test_a_renamed_pinned_file_keeps_its_pin_under_the_new_name(self):
        def rename(repo: Path) -> None:
            (repo / "pkg/armtls").mkdir()
            (repo / "pkg/ratls/tls.go").rename(repo / "pkg/armtls/tls.go")
            (repo / "pkg/armtls/tls.go").write_text(TLS_SOURCE.replace("ratls", "armtls", 1))
        added = self.source_lock_bump(rename)
        self.assertEqual(list(added["files"]), ["pkg/armtls/tls.go", "cmd/cds/main.go"])
        self.assertEqual(added["files"]["pkg/armtls/tls.go"],
                         BUMP.sha256_bytes(TLS_SOURCE.replace("ratls", "armtls", 1).encode()))
        self.assertEqual(added["files"]["cmd/cds/main.go"], BUMP.sha256_bytes(b"package main\n"))

    def test_a_deleted_pinned_file_stops_the_bump(self):
        with self.assertRaisesRegex(BUMP.BumpError, "pkg/ratls/tls.go are gone"):
            self.source_lock_bump(lambda repo: (repo / "pkg/ratls/tls.go").unlink())

    def test_a_deleted_pinned_file_with_a_successor_moves_its_pin_and_new_sources_join(self):
        def replace(repo: Path) -> None:
            (repo / "pkg/ratls/tls.go").unlink()
            (repo / "pkg/cdsconfig").mkdir()
            (repo / "pkg/cdsconfig/pin.go").write_text("package cdsconfig\n")
            (repo / "pkg/cdsconfig/cdsconfig.go").write_text("package cdsconfig // config\n")
        with mock.patch.dict(BUMP.SOURCE_SUCCESSORS, {"pkg/ratls/tls.go": "pkg/cdsconfig/cdsconfig.go"}), \
                mock.patch.object(BUMP, "ADDED_SOURCES", ("pkg/cdsconfig/cdsconfig.go", "pkg/cdsconfig/pin.go",
                                                          "pkg/absent.go")):
            added = self.source_lock_bump(replace)
        self.assertEqual(added["files"], {
            "pkg/cdsconfig/cdsconfig.go": BUMP.sha256_bytes(b"package cdsconfig // config\n"),
            "cmd/cds/main.go": BUMP.sha256_bytes(b"package main\n"),
            "pkg/cdsconfig/pin.go": BUMP.sha256_bytes(b"package cdsconfig\n"),
        })

    def test_the_fixture_is_generated_with_the_given_c8s_cli(self):
        binaries = []

        def staging_allowlist(binary):
            binaries.append(binary)
            return b'{"schema": "c8s.allowlist/v1"}\n'

        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "staging-allowlist.json"
            tests = {"staging_allowlist": staging_allowlist, "MAN": mock.Mock(), "REN": mock.Mock(),
                     "STAGING_ALLOWLIST": fixture}
            with mock.patch.object(BUMP.runpy, "run_path", return_value=tests):
                BUMP.regenerate_fixture(Path("c8s"))
            self.assertEqual(fixture.read_bytes(), b'{"schema": "c8s.allowlist/v1"}\n')
        self.assertEqual(binaries, [Path("c8s")])

    def test_without_a_cli_the_bump_builds_one_from_the_checkout_and_checks_its_commit(self):
        checked = []
        generator = {"verify_c8s_binary": lambda binary, commit, tag: checked.append((binary, commit, tag)),
                     "GenerationError": ValueError}
        no_signed = mock.patch.object(BUMP.c8s_release, "signed_cli",
                                      side_effect=BUMP.c8s_release.ReleaseError("no statement"))
        with mock.patch.object(BUMP, "run") as run, mock.patch.object(BUMP.runpy, "run_path", return_value=generator), \
                no_signed, contextlib.redirect_stderr(io.StringIO()):
            binary = BUMP.c8s_cli(None, Path("c8s"), "a" * 40, "v0.99.29", Path("build"))
            self.assertEqual(binary, Path("build/c8s"))
            self.assertEqual(run.call_args.args[0], ["go", "build", "-o", "build/c8s", "./cmd/c8s"])
            self.assertEqual(run.call_args.kwargs["cwd"], Path("c8s"))
            run.reset_mock()
            self.assertEqual(BUMP.c8s_cli(Path("given"), Path("c8s"), "a" * 40, "v0.99.29", Path("build")), Path("given"))
            run.assert_not_called()
        self.assertEqual(checked, [(Path("build/c8s"), "a" * 40, "v0.99.29"), (Path("given"), "a" * 40, "v0.99.29")])


    def test_the_bump_uses_the_signed_release_cli_by_default(self):
        checked = []
        generator = {"verify_c8s_binary": lambda binary, commit, tag: checked.append((binary, commit, tag)),
                     "GenerationError": ValueError}
        signed = mock.patch.object(BUMP.c8s_release, "signed_cli",
                                   return_value=({"asset": "c8s-linux-amd64"}, Path("build/c8s-linux-amd64")))
        with mock.patch.object(BUMP, "run") as run, mock.patch.object(BUMP.runpy, "run_path", return_value=generator), \
                signed as signed_cli:
            self.assertEqual(BUMP.c8s_cli(None, Path("c8s"), "a" * 40, "v0.101.5", Path("build")),
                             Path("build/c8s-linux-amd64"))
            run.assert_not_called()
            self.assertTrue(signed_cli.call_args.kwargs["download"])
            signed_cli.reset_mock()
            self.assertEqual(BUMP.c8s_cli(None, Path("c8s"), "a" * 40, "v0.101.5", Path("build"), source_build=True),
                             Path("build/c8s"))
            signed_cli.assert_not_called()
            self.assertEqual(run.call_args.args[0], ["go", "build", "-o", "build/c8s", "./cmd/c8s"])
        self.assertEqual(checked, [(Path("build/c8s-linux-amd64"), "a" * 40, "v0.101.5"),
                                   (Path("build/c8s"), "a" * 40, "v0.101.5")])


if __name__ == "__main__":
    unittest.main()


class BetaCompatibilityTests(unittest.TestCase):
    def test_beta_requires_opt_in_before_network(self):
        with mock.patch('sys.argv', ['bump-c8s', '--tag', 'v0.37.0-beta.1', '--c8s-repo', '/unused']), mock.patch.object(BUMP.c8s_release, 'verify_c8s_tag') as verify:
            self.assertEqual(BUMP.main(), 1)
            verify.assert_not_called()

    def test_a_dev_build_is_refused(self):
        dev = 'v0.72.1-0.20261023005616-90bd65abd955'
        self.assertEqual(BUMP.image_tag(dev), 'dev-90bd65abd955')
        self.assertEqual(BUMP.image_tag('v0.72.0'), 'v0.72.0')
        with mock.patch('sys.argv', ['bump-c8s', '--tag', dev, '--c8s-repo', '/unused']), \
                mock.patch.object(BUMP, 'git') as git:
            self.assertEqual(BUMP.main(), 1)
            git.assert_not_called()

    def test_a_beta_still_requires_signature_verification(self):
        with mock.patch('sys.argv', ['bump-c8s', '--tag', 'v0.37.0-beta.1', '--c8s-repo', '/unused', '--allow-beta']), mock.patch.object(BUMP.c8s_release, 'verify_c8s_tag', side_effect=BUMP.c8s_release.ReleaseError('invalid signature')) as verify:
            self.assertEqual(BUMP.main(), 1)
            verify.assert_called_once_with('v0.37.0-beta.1', allow_beta=True)

    def test_channel_identity_is_exact_and_beta_orders_below_stable(self):
        release = BUMP.c8s_release
        self.assertLess(release.version('v0.37.0-beta.1'), release.version('v0.37.0'))
        self.assertEqual(release.signer('v0.37.0-beta.1', True), 'https://github.com/confidential-dot-ai/C8s/.github/workflows/semver-tag.yml@refs/heads/beta')
        with self.assertRaises(ValueError):
            release.signer('v0.37.0-beta.1')

    def test_signed_beta_requires_branch_prerelease_and_exact_statement(self):
        tag, commit = 'v0.37.0-beta.1', 'a' * 40
        release = BUMP.c8s_release
        statement = {'repository': 'confidential-dot-ai/C8s', 'tag': tag, 'commit': commit}
        calls = []

        def run(argv, **kwargs):
            import subprocess
            calls.append(argv)
            if argv[0] == 'cosign':
                self.assertEqual(argv[argv.index('--certificate-identity') + 1], release.signer(tag, True))
                value = ''
            elif argv[1] == 'release':
                directory = Path(argv[argv.index('--dir') + 1])
                (directory / release.C8S_STATEMENT).write_text(json.dumps(statement))
                (directory / release.C8S_BUNDLE).write_text('{}')
                value = ''
            else:
                path = argv[2]
                if '/git/ref/' in path:
                    value = {'object': {'type': 'commit', 'sha': commit}}
                elif '/commits/' in path:
                    value = {'commit': {'verification': {'verified': True}}}
                elif path.endswith('...beta'):
                    value = {'status': 'ahead'}
                elif path.endswith('...main'):
                    value = {'status': 'diverged'}
                elif '/releases/tags/' in path:
                    value = {'prerelease': True, 'assets': [{'name': name} for name in (release.C8S_STATEMENT, release.C8S_BUNDLE)]}
                else:
                    raise AssertionError(argv)
            return subprocess.CompletedProcess(argv, 0, value if isinstance(value, str) else json.dumps(value), '')

        result = release.verify_c8s_tag(tag, run=run, cosign='cosign', allow_beta=True)
        self.assertEqual(result['releaseSignature'], 'verified')
        self.assertFalse(result['onMain'])
        statement['allowlistSeeds'] = {}
        self.assertEqual(release.verify_c8s_tag(tag, run=run, cosign='cosign', allow_beta=True)['releaseSignature'],
                         'verified')
        del statement['allowlistSeeds']
        statement['chart'] = 'ghcr.io/confidential-dot-ai/charts/c8s-cloud@sha256:' + 'c' * 64
        self.assertEqual(release.verify_c8s_tag(tag, run=run, cosign='cosign', allow_beta=True)['releaseSignature'],
                         'verified')
        statement['chart'] = 'ghcr.io/confidential-dot-ai/charts/c8s-cloud:0.99.29'
        with self.assertRaisesRegex(release.ReleaseError, 'no digest-pinned C8s chart'):
            release.verify_c8s_tag(tag, run=run, cosign='cosign', allow_beta=True)
        del statement['chart']
        statement['cli'] = {'linux-amd64': {'asset': 'c8s-linux-amd64', 'sha256': 'd' * 64}}
        self.assertEqual(release.verify_c8s_tag(tag, run=run, cosign='cosign', allow_beta=True)['releaseSignature'],
                         'verified')
        del statement['cli']
        statement['extra'] = True
        with self.assertRaisesRegex(release.ReleaseError, 'does not name'):
            release.verify_c8s_tag(tag, run=run, cosign='cosign', allow_beta=True)
        del statement['extra']
        statement['commit'] = 'b' * 40
        with self.assertRaisesRegex(release.ReleaseError, 'does not name'):
            release.verify_c8s_tag(tag, run=run, cosign='cosign', allow_beta=True)
