#!/usr/bin/env python3
"""Tests for the parts of scripts/bump-c8s.py that need no registry."""

from __future__ import annotations

import importlib.util
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

    def test_the_staging_fixture_moves_only_with_the_staging_profile(self):
        production, staging = BUMP.release_profiles.load()
        with mock.patch.object(BUMP, "run") as run, mock.patch.object(BUMP.runpy, "run_path") as run_path:
            BUMP.regenerate_staging_fixture(Path("c8s"), [production])
        run.assert_not_called()
        run_path.assert_not_called()

    def test_the_staging_fixture_is_generated_with_the_c8s_cli_of_the_tag(self):
        production, staging = BUMP.release_profiles.load()
        binaries = []

        def staging_allowlist(binary):
            binaries.append(binary)
            return b'{"schema": "c8s.allowlist/v1"}\n'

        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "staging-allowlist.json"
            tests = {"staging_allowlist": staging_allowlist, "MAN": mock.Mock(), "STAGING_ALLOWLIST": fixture}
            with mock.patch.object(BUMP, "run") as run, mock.patch.object(BUMP.runpy, "run_path", return_value=tests):
                BUMP.regenerate_staging_fixture(Path("c8s"), [production, staging])
            self.assertEqual(fixture.read_bytes(), b'{"schema": "c8s.allowlist/v1"}\n')
        command = run.call_args.args[0]
        self.assertEqual(command, ["go", "build", "-o", command[3], "./cmd/c8s"])
        self.assertEqual(run.call_args.kwargs["cwd"], Path("c8s"))
        self.assertEqual(binaries, [Path(command[3])])


if __name__ == "__main__":
    unittest.main()


class BetaCompatibilityTests(unittest.TestCase):
    def test_beta_requires_explicit_profile_and_opt_in_before_network(self):
        for extra in ([], ['--allow-beta'], ['--profile', 'production']):
            with mock.patch('sys.argv', ['bump-c8s', '--tag', 'v0.37.0-beta.1', '--c8s-repo', '/unused', *extra]), mock.patch.object(BUMP.c8s_release, 'verify_c8s_tag') as verify:
                self.assertEqual(BUMP.main(), 1)
                verify.assert_not_called()

    def test_explicit_production_beta_still_requires_signature_verification(self):
        with mock.patch('sys.argv', ['bump-c8s', '--tag', 'v0.37.0-beta.1', '--c8s-repo', '/unused', '--allow-beta', '--profile', 'production']), mock.patch.object(BUMP.c8s_release, 'verify_c8s_tag', side_effect=BUMP.c8s_release.ReleaseError('invalid signature')) as verify:
            self.assertEqual(BUMP.main(), 1)
            verify.assert_called_once_with('v0.37.0-beta.1', allow_beta=True)

    def test_renamed_mesh_uses_the_new_registry_repository(self):
        old = {
            'release': 'v0.36.2',
            'coreImages': ['ghcr.io/confidential-dot-ai/ratls-mesh@sha256:' + '1' * 64],
            'nodeImage': {'reference': BUMP.REGISTRY + 'node-guest-base', 'tag': 'rke2-tdx-cdi-v0.36.2'},
            'nodeManifestArtifact': {'tag': 'rke2-tdx-v0.36.2'},
        }
        with mock.patch.object(BUMP, 'digest', return_value='sha256:' + '2' * 64) as digest, mock.patch.dict(BUMP.NODE, {'manifest_json_digest': lambda *_: 'sha256:' + '3' * 64}):
            result = BUMP.new_c8s('v0.37.0-beta.1', 'a' * 40, old, renamed_mesh=True)
        self.assertEqual(result['coreImages'], ['ghcr.io/confidential-dot-ai/armtls-mesh@sha256:' + '2' * 64])
        self.assertIn(mock.call('ghcr.io/confidential-dot-ai/armtls-mesh:v0.37.0-beta.1'), digest.call_args_list)

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
        statement['commit'] = 'b' * 40
        with self.assertRaisesRegex(release.ReleaseError, 'does not name'):
            release.verify_c8s_tag(tag, run=run, cosign='cosign', allow_beta=True)
