from __future__ import annotations

import hashlib
import json
import re
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "scripts/verify-release-bundle-signature.py"
MANIFEST = ROOT / "tests/release-v1/fixtures/v0.15.15-release-manifest.json"
POLICY = ROOT / "release/trust/release-signing-policy.json"
TRUSTED_ROOT = ROOT / "release/trust/sigstore-public-good-trusted-root.json"
WORKFLOW = ROOT / ".github/workflows/release-bundle.yml"
RELEASE_SIGNATURE = ROOT / "scripts/release_signature.py"
LOCK = ROOT / "scripts/requirements-release-signing.txt"
SIGNATURE_MODULE = runpy.run_path(str(RELEASE_SIGNATURE))
environment_for_tag = SIGNATURE_MODULE["environment_for_tag"]
validate_policy = SIGNATURE_MODULE["validate_policy"]


class ReleaseSignatureTests(unittest.TestCase):
    def test_current_and_historical_tags_map_to_their_signed_environment(self) -> None:
        self.assertEqual(environment_for_tag("v0.14.0"), "production")
        self.assertEqual(environment_for_tag("v0.14.0-staging"), "staging")
        self.assertEqual(environment_for_tag("v0.13.28-rc.2"), "production")
        self.assertEqual(environment_for_tag("integration-staging-v20"), "integration-staging")

    def test_production_releases_have_no_release_candidate_path(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("--prerelease", workflow)
        self.assertNotIn("-rc.", workflow)
        self.assertNotIn("--candidate-bundle", workflow)
        self.assertIn('release_profiles.py resolve --tag "$RELEASE_TAG"', workflow)
        self.assertIn('--tag "$RELEASE_TAG"', workflow)
        self.assertIn("scripts/build-release-manifest.py", workflow)
        self.assertIn('--source-commit "$(git rev-parse HEAD)"', workflow)

    def test_policy_and_release_pin_the_exact_trusted_inputs(self) -> None:
        policy_bytes = POLICY.read_bytes()
        policy = json.loads(policy_bytes)
        trusted_root_bytes = TRUSTED_ROOT.read_bytes()
        production = json.loads(MANIFEST.read_text())

        self.assertEqual(
            production["releaseTrust"]["policySha256"],
            "sha256:" + hashlib.sha256(policy_bytes).hexdigest(),
        )
        self.assertEqual(
            policy["trustedRoot"]["sha256"],
            "sha256:" + hashlib.sha256(trusted_root_bytes).hexdigest(),
        )
        self.assertEqual(policy["cosign"]["gitVersion"], "v3.1.2")
        self.assertEqual(
            policy["certificateOidcIssuer"],
            "https://token.actions.githubusercontent.com",
        )
        self.assertIn("release-bundle.yml@refs/tags/{release}", policy["certificateIdentityTemplate"])

    def test_shared_policy_rejects_a_tag_environment_mismatch(self) -> None:
        release = json.loads(MANIFEST.read_text())
        release["release"]["environment"] = "staging"
        with self.assertRaisesRegex(ValueError, "environment does not match"):
            validate_policy(release)

    def test_verifier_rejects_an_incomplete_release(self) -> None:
        release = json.loads(MANIFEST.read_text())
        release.pop("images")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "release.json"
            source.write_text(json.dumps(release))
            cosign = directory / "cosign"
            cosign.write_text("#!/bin/sh\nexit 1\n")
            cosign.chmod(0o755)
            result = subprocess.run(
                [
                    "python3", str(VERIFY),
                    "--bundle", str(source),
                    "--signature-bundle", str(directory / "missing-signature.json"),
                    "--cosign", str(cosign),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("release-bundle schema", result.stderr)

    def test_workflow_uses_keyless_oidc_and_refuses_asset_replacement(self) -> None:
        workflow = WORKFLOW.read_text()
        self.assertIn("id-token: write", workflow)
        # The signing environment (and its protection rules) applies to tag
        # pushes only; a dispatched unsigned branch build runs without it.
        self.assertIn(
            "name: ${{ github.event_name == 'push' && "
            "needs.select-profile.outputs.signing_environment || '' }}",
            workflow,
        )
        profiles = (ROOT / "release/profiles.json").read_text(encoding="utf-8")
        self.assertIn('"signed-release-production"', profiles)
        self.assertIn('"signed-release-staging"', profiles)
        self.assertNotIn("environment: signed-release\n", workflow)
        self.assertIn("group: signed-release-${{ github.ref_name }}", workflow)
        self.assertIn("cosign-release: v3.1.2", workflow)
        self.assertNotIn('"integration-staging-v[0-9]*"', workflow)
        self.assertNotIn("releases/integration-staging/release-bundle.json", workflow)
        self.assertIn("cosign sign-blob --yes", workflow)
        self.assertIn("--bundle dist/release-bundle.sigstore.json", workflow)
        self.assertIn("git rev-parse HEAD > dist/release-tag-commit.txt", workflow)
        self.assertIn("--require-hashes", workflow)
        self.assertIn("git merge-base --is-ancestor HEAD refs/remotes/origin/main", workflow)
        self.assertIn("refs/remotes/origin/main", workflow)
        self.assertIn("The release version is already published", workflow)
        self.assertIn("sha256sum --check --strict", workflow)
        self.assertIn("release-bundle.sigstore.json", workflow)
        self.assertIn("The release tag moved after signing", workflow)
        self.assertIn("Refusing to replace signed assets", workflow)
        self.assertIn("The release tag changed during publication", workflow)
        self.assertIn('--target "$expected_commit"', workflow)
        self.assertEqual(workflow.count("if ! check_tag"), 2)
        self.assertNotIn("--insecure-ignore", workflow)
        self.assertNotIn("--clobber", workflow)
        self.assertIn('"--offline"', RELEASE_SIGNATURE.read_text())
        signing_job, publishing_job = workflow.split("  publish-release:\n", 1)
        self.assertIn("contents: read", signing_job)
        self.assertNotIn("contents: write", signing_job)
        self.assertIn("contents: write", publishing_job)
        self.assertNotIn("id-token: write", publishing_job)

    def test_release_signing_dependencies_are_exact_and_hash_locked(self) -> None:
        lock = LOCK.read_text()
        entries = [
            entry
            for entry in re.split(r"\n(?! )", lock)
            if entry.strip() and not entry.startswith("#")
        ]
        self.assertGreaterEqual(len(entries), 6)
        for entry in entries:
            requirement, *hashes = entry.splitlines()
            self.assertIn("==", requirement)
            self.assertTrue(hashes)
            self.assertTrue(all(line.strip().startswith("--hash=sha256:") for line in hashes))

    def test_verifier_bounds_release_input_and_rejects_a_cosign_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            oversized = directory / "oversized.json"
            oversized.write_bytes(b"{" + b" " * (2 * 1024 * 1024) + b"}")
            cosign = directory / "cosign-real"
            cosign.write_text("#!/bin/sh\nexit 1\n")
            cosign.chmod(0o755)
            signature = directory / "signature.json"
            signature.write_text("{}")
            result = subprocess.run(
                [
                    "python3", str(VERIFY),
                    "--bundle", str(oversized),
                    "--signature-bundle", str(signature),
                    "--cosign", str(cosign),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("release bundle is too large", result.stderr)

            cosign_link = directory / "cosign-link"
            cosign_link.symlink_to(cosign)
            result = subprocess.run(
                [
                    "python3", str(VERIFY),
                    "--bundle", str(MANIFEST),
                    "--signature-bundle", str(signature),
                    "--cosign", str(cosign_link),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Cosign verifier is not a file", result.stderr)

    def test_new_and_published_policy_references_use_the_same_trust(self) -> None:
        release = json.loads(MANIFEST.read_text())
        for reference in (
            "release/trust/release-signing-policy.json",
            "releases/trust/release-signing-policy.json",
        ):
            with self.subTest(reference=reference):
                release["releaseTrust"]["policyPath"] = reference
                SIGNATURE_MODULE["validate_release_schema"](release)
                _, _, root_path, _, identity = validate_policy(release)
                self.assertEqual(root_path, TRUSTED_ROOT)
                self.assertTrue(identity.endswith("@refs/tags/v0.15.15"))

    def test_release_cannot_select_another_policy_or_publisher(self) -> None:
        changes = (
            ("releaseTrust", "policyPath", "tests/policy.json"),
            ("releaseTrust", "policyPath", str(POLICY)),
            ("releaseTrust", "policyPath", "release/trust/../trust/release-signing-policy.json"),
            ("releaseTrust", "policySha256", "sha256:" + "0" * 64),
            ("source", "repository", "https://github.com/other/publisher"),
        )
        for section, key, value in changes:
            with self.subTest(section=section, key=key, value=value):
                release = json.loads(MANIFEST.read_text())
                release[section][key] = value
                with self.assertRaises(ValueError):
                    validate_policy(release)

    def test_the_release_schema_accepts_only_the_known_policy_paths(self) -> None:
        for reference in (
            "release/trust/release-signing-policy.json",
            "releases/trust/release-signing-policy.json",
            "tests/policy.json",
            "release/trust/../trust/release-signing-policy.json",
        ):
            with self.subTest(reference=reference):
                release = json.loads(MANIFEST.read_text())
                release["releaseTrust"] = {
                    "policyPath": reference,
                    "policySha256": "sha256:" + hashlib.sha256(POLICY.read_bytes()).hexdigest(),
                    "signatureType": "sigstore-keyless",
                }
                if reference.startswith(("release/trust/../", "tests/")):
                    with self.assertRaises(ValueError):
                        SIGNATURE_MODULE["validate_release_schema"](release)
                else:
                    SIGNATURE_MODULE["validate_release_schema"](release)

    def test_a_release_in_another_format_is_refused(self) -> None:
        release = json.loads(MANIFEST.read_text())
        release.pop("schema")
        with self.assertRaises(ValueError):
            SIGNATURE_MODULE["validate_release_schema"](release)

    def test_both_root_references_resolve_to_the_moved_file(self) -> None:
        for reference in (
            "release/trust/sigstore-public-good-trusted-root.json",
            "releases/trust/sigstore-public-good-trusted-root.json",
        ):
            with self.subTest(reference=reference), tempfile.TemporaryDirectory() as temporary:
                policy = json.loads(POLICY.read_text())
                policy["trustedRoot"]["path"] = reference
                path = Path(temporary) / "policy.json"
                path.write_text(json.dumps(policy))
                release = json.loads(MANIFEST.read_text())
                release["releaseTrust"]["policySha256"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                with mock.patch.dict(validate_policy.__globals__, {"POLICY_PATH": path}):
                    self.assertEqual(validate_policy(release)[2], TRUSTED_ROOT)

    def test_policy_cannot_select_another_root_or_ignore_its_digest(self) -> None:
        for change in (
            {"path": "tests/root.json"},
            {"path": str(TRUSTED_ROOT)},
            {"sha256": "sha256:" + "0" * 64},
        ):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                policy = json.loads(POLICY.read_text())
                policy["trustedRoot"].update(change)
                path = Path(temporary) / "policy.json"
                path.write_text(json.dumps(policy))
                release = json.loads(MANIFEST.read_text())
                release["releaseTrust"]["policySha256"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                with mock.patch.dict(validate_policy.__globals__, {"POLICY_PATH": path}):
                    with self.assertRaises(ValueError):
                        validate_policy(release)

    def test_accepted_publisher_comes_from_the_local_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            policy = json.loads(POLICY.read_text())
            policy["repository"] = "https://github.com/example/approved"
            policy["githubWorkflow"]["repository"] = "example/approved"
            policy["certificateIdentityTemplate"] = (
                "https://github.com/example/approved/"
                ".github/workflows/release-bundle.yml@refs/tags/{release}"
            )
            path = Path(temporary) / "policy.json"
            path.write_text(json.dumps(policy))
            release = json.loads(MANIFEST.read_text())
            release["source"]["repository"] = policy["repository"]
            release["releaseTrust"]["policySha256"] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            with mock.patch.dict(validate_policy.__globals__, {"POLICY_PATH": path}):
                identity = validate_policy(release)[-1]
            self.assertEqual(identity, policy["certificateIdentityTemplate"].replace("{release}", "v0.15.15"))

    def test_standalone_verifier_requires_all_inputs(self) -> None:
        result = subprocess.run(
            ["python3", str(VERIFY)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--signature-bundle", result.stderr)


if __name__ == "__main__":
    unittest.main()
