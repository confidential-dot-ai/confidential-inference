from __future__ import annotations

import hashlib
import json
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PREPARE = ROOT / "scripts/prepare-signed-release.py"
VERIFY = ROOT / "scripts/verify-release-bundle-signature.py"
PRODUCTION = ROOT / "releases/production/release-bundle.json"
CONF_INFERENCE_PROD = ROOT / "releases/conf-inference-prod/release-bundle.json"
POLICY = ROOT / "releases/trust/release-signing-policy.json"
TRUSTED_ROOT = ROOT / "releases/trust/sigstore-public-good-trusted-root.json"
WORKFLOW = ROOT / ".github/workflows/release-bundle.yml"
RELEASE_SIGNATURE = ROOT / "scripts/release_signature.py"
LOCK = ROOT / "scripts/requirements-release-signing.txt"
PRE_HISTORY_RELEASES = ROOT / "releases/pre-history-releases.json"


def pre_history_bundle_paths() -> set[Path]:
    """Bundles this repository cannot check for source-commit ancestry.

    These bundles were built from a source history that predates this
    repository's recreation, so their recorded commit is genuinely absent.
    See `releases/pre-history-releases.json` for the reason each is listed.
    """
    entries = json.loads(PRE_HISTORY_RELEASES.read_text())["bundles"]
    return {(ROOT / entry["path"]).resolve() for entry in entries}


class ReleaseSignatureTests(unittest.TestCase):
    def test_policy_and_release_pin_the_exact_trusted_inputs(self) -> None:
        policy_bytes = POLICY.read_bytes()
        policy = json.loads(policy_bytes)
        trusted_root_bytes = TRUSTED_ROOT.read_bytes()
        production = json.loads(PRODUCTION.read_text())

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

    def test_prepare_keeps_the_exact_release_bytes(self) -> None:
        pre_history = pre_history_bundle_paths()
        validate_release_schema = runpy.run_path(str(RELEASE_SIGNATURE))[
            "validate_release_schema"
        ]
        for source in (PRODUCTION, CONF_INFERENCE_PROD):
            with self.subTest(source=source):
                release = json.loads(source.read_text())
                if source.resolve() in pre_history:
                    # `prepare-signed-release.py` cannot check this bundle's
                    # source-commit ancestry: the commit predates this
                    # repository's recreation and is genuinely absent from
                    # its history. Check everything else the script would
                    # have checked instead of running it.
                    validate_release_schema(release)
                    self.assertEqual(
                        release["source"]["repository"],
                        "https://github.com/confidential-dot-ai/confidential-inference",
                    )
                    continue
                with tempfile.TemporaryDirectory() as temporary:
                    output = Path(temporary) / "release-bundle.json"
                    tag_commit = Path(temporary) / "release-tag-commit.txt"
                    result = subprocess.run(
                        [
                            "python3", str(PREPARE),
                            "--source", str(source),
                            "--output", str(output),
                            "--tag-commit-output", str(tag_commit),
                            "--tag", release["release"]["name"],
                        ],
                        cwd=ROOT,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_bytes(), source.read_bytes())
                    self.assertEqual(
                        tag_commit.read_text().strip(),
                        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    )

    def test_prepare_rejects_a_tag_for_the_other_environment(self) -> None:
        release = json.loads(CONF_INFERENCE_PROD.read_text())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "release-bundle.json"
            result = subprocess.run(
                [
                    "python3", str(PREPARE),
                    "--source", str(CONF_INFERENCE_PROD),
                    "--output", str(output),
                    "--tag", "v0.13.0",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("environment does not match", result.stderr)
            self.assertFalse(output.exists())

    def test_prepare_rejects_a_different_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "release-bundle.json"
            result = subprocess.run(
                [
                    "python3", str(PREPARE),
                    "--source", str(PRODUCTION),
                    "--output", str(output),
                    "--tag", "v0-wrong-tag",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("differs from the tag", result.stderr)
            self.assertFalse(output.exists())

    def test_shared_policy_rejects_a_tag_environment_mismatch(self) -> None:
        release = json.loads(CONF_INFERENCE_PROD.read_text())
        release["release"]["environment"] = "production"
        validate_policy = runpy.run_path(str(RELEASE_SIGNATURE))["validate_policy"]
        with self.assertRaisesRegex(ValueError, "environment does not match"):
            validate_policy(release)

    def test_prepare_and_verifier_reject_an_incomplete_release(self) -> None:
        release = json.loads(PRODUCTION.read_text())
        release.pop("workloads")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "release.json"
            source.write_text(json.dumps(release))
            output = directory / "output.json"
            result = subprocess.run(
                [
                    "python3", str(PREPARE),
                    "--source", str(source),
                    "--output", str(output),
                    "--tag", release["release"]["name"],
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("release-bundle schema", result.stderr)
            self.assertFalse(output.exists())

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

    def test_prepare_rejects_a_dangling_output_symlink(self) -> None:
        # This exercises the output-symlink check, which runs only after the
        # source-commit ancestry check passes. `PRODUCTION` is a pre-history
        # bundle (see `releases/pre-history-releases.json`) whose recorded
        # commit cannot pass that check here, so this test repoints the
        # commit at the checked-out HEAD to reach the code path under test.
        release = json.loads(PRODUCTION.read_text())
        release["source"]["commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "source-release-bundle.json"
            source.write_text(json.dumps(release))
            output = directory / "release.json"
            output.symlink_to(directory / "missing-target")
            result = subprocess.run(
                [
                    "python3", str(PREPARE),
                    "--source", str(source),
                    "--output", str(output),
                    "--tag", release["release"]["name"],
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("output already exists", result.stderr)

    def test_workflow_uses_keyless_oidc_and_refuses_asset_replacement(self) -> None:
        workflow = WORKFLOW.read_text()
        self.assertIn("id-token: write", workflow)
        self.assertIn("signed-release-production", workflow)
        self.assertIn("signed-release-conf-inference-prod", workflow)
        self.assertIn("signed-release-staging", workflow)
        self.assertIn("signed-release-candidate", workflow)
        self.assertNotIn("environment: signed-release\n", workflow)
        self.assertIn("group: signed-release-${{ github.ref_name }}", workflow)
        self.assertIn("cosign-release: v3.1.2", workflow)
        self.assertIn('"conf-inference-prod-v[0-9]*"', workflow)
        self.assertIn('"staging-v[0-9]*"', workflow)
        self.assertIn('"candidate-v[0-9]*"', workflow)
        self.assertIn("releases/conf-inference-prod/release-bundle.json", workflow)
        self.assertIn("releases/staging/release-bundle.json", workflow)
        self.assertIn("releases/candidate/release-bundle.json", workflow)
        self.assertIn("cosign sign-blob --yes", workflow)
        self.assertIn("--bundle dist/release-bundle.sigstore.json", workflow)
        self.assertIn("--tag-commit-output dist/release-tag-commit.txt", workflow)
        self.assertIn("--require-hashes", workflow)
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
        requirements = [line for line in lock.splitlines() if line and not line.startswith(" ")]
        self.assertGreaterEqual(len(requirements), 6)
        self.assertTrue(all("==" in line for line in requirements))
        self.assertEqual(lock.count("--hash=sha256:"), len(requirements))

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
                    "--bundle", str(PRODUCTION),
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

    def test_checked_in_releases_have_no_placeholder_signature(self) -> None:
        signatures = list((ROOT / "releases").glob("**/*.sigstore.json"))
        self.assertEqual(signatures, [])
        self.assertIn(
            "unsigned development artifacts",
            (ROOT / "releases/README.md").read_text(),
        )

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
