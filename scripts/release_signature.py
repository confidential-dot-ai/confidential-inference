#!/usr/bin/env python3
"""Verify a keyless Sigstore signature on exact release-bundle bytes."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import jsonschema

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_profiles


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "releases/trust/release-signing-policy.json"
RELEASE_SCHEMA_PATH = ROOT / "api/release-bundle.schema.json"
# v0.14.0 and later sign a release manifest built from release/. The signed
# file names its own schema; each schema has one contract file.
RELEASE_MANIFEST_SCHEMA = "confidential.ai/release-manifest/v1"
RELEASE_MANIFEST_SCHEMA_PATH = ROOT / "api/release-manifest.schema.json"
MAX_RELEASE_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_SIGNATURE_BUNDLE_BYTES = 2 * 1024 * 1024
RELEASE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
# A release profile maps its tags to its environment (release/profiles.json).
# Keep these other mappings for verification of signed historical releases.
# The publication workflow no longer accepts either legacy prefix.
LEGACY_TAG_ENVIRONMENTS = (
    (re.compile(r"v[0-9][a-z0-9._-]{0,126}"), "production"),
    (re.compile(r"integration-staging-v[0-9][a-z0-9._-]{0,106}"), "integration-staging"),
    (re.compile(r"conf-inference-prod-v[0-9][a-z0-9._-]{0,107}"), "conf-inference-prod"),
)


class ReleaseSignatureError(ValueError):
    """The release signature does not meet the public trust policy."""


def environment_for_tag(tag: str) -> str:
    """Return the one environment that a protected release tag can sign."""
    try:
        return release_profiles.for_tag(tag).environment
    except release_profiles.ProfileError:
        pass
    for pattern, environment in LEGACY_TAG_ENVIRONMENTS:
        if pattern.fullmatch(tag) is not None:
            return environment
    raise ReleaseSignatureError("the release tag is not an allowed environment tag")


def read_regular_file(path: Path, label: str, maximum_bytes: int | None = None) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise ReleaseSignatureError(f"the {label} must be a regular file")
    try:
        size = path.stat().st_size
        if maximum_bytes is not None and size > maximum_bytes:
            raise ReleaseSignatureError(f"the {label} is too large")
        return path.read_bytes()
    except OSError as error:
        raise ReleaseSignatureError(f"cannot read the {label}") from error


def read_object(path: Path, label: str, maximum_bytes: int | None = None) -> tuple[bytes, dict[str, Any]]:
    value = read_regular_file(path, label, maximum_bytes)
    try:
        document = json.loads(value)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseSignatureError(f"the {label} is not valid JSON") from error
    if not isinstance(document, dict):
        raise ReleaseSignatureError(f"the {label} must contain one JSON object")
    return value, document


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseSignatureError(f"the {label} is invalid")
    return value


def resolve_repository_file(value: Any, label: str) -> Path:
    relative = Path(required_text(value, label))
    if relative.is_absolute():
        raise ReleaseSignatureError(f"the {label} must be relative to the repository")
    path = (ROOT / relative).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError as error:
        raise ReleaseSignatureError(f"the {label} leaves the repository") from error
    return path


def validate_policy(
    release: dict[str, Any],
) -> tuple[bytes, dict[str, Any], Path, bytes, str]:
    trust = release.get("releaseTrust")
    if not isinstance(trust, dict):
        raise ReleaseSignatureError("the release has no signing policy reference")
    if trust.get("policyPath") != "releases/trust/release-signing-policy.json":
        raise ReleaseSignatureError("the release signing policy path is invalid")
    policy_bytes, policy = read_object(POLICY_PATH, "release signing policy")
    if sha256(policy_bytes) != trust.get("policySha256"):
        raise ReleaseSignatureError("the release signing policy digest differs from the bundle")
    if trust.get("signatureType") != "sigstore-keyless":
        raise ReleaseSignatureError("the release signature type is invalid")
    required = {
        "schema": "confidential-inference.release-trust/v1",
        "signatureType": "sigstore-keyless",
        "repository": "https://github.com/confidential-dot-ai/confidential-inference",
        "certificateOidcIssuer": "https://token.actions.githubusercontent.com",
        "certificateIdentityTemplate": (
            "https://github.com/confidential-dot-ai/confidential-inference/"
            ".github/workflows/release-bundle.yml@refs/tags/{release}"
        ),
    }
    if any(policy.get(name) != value for name, value in required.items()):
        raise ReleaseSignatureError("the release signing policy has an unexpected trust value")
    source = release.get("source")
    if not isinstance(source, dict) or source.get("repository") != policy["repository"]:
        raise ReleaseSignatureError("the release source repository differs from the signing policy")
    release_metadata = release.get("release")
    release_name = release_metadata.get("name") if isinstance(release_metadata, dict) else None
    if not isinstance(release_name, str) or RELEASE_RE.fullmatch(release_name) is None:
        raise ReleaseSignatureError("the release name is invalid")
    expected_environment = environment_for_tag(release_name)
    if release_metadata.get("environment") != expected_environment:
        raise ReleaseSignatureError("the release environment does not match its protected tag")
    workflow = policy.get("githubWorkflow")
    if not isinstance(workflow, dict) or workflow != {
        "name": "Signed release bundle",
        "path": ".github/workflows/release-bundle.yml",
        "repository": "confidential-dot-ai/confidential-inference",
        "refTemplate": "refs/tags/{release}",
        "trigger": "push",
    }:
        raise ReleaseSignatureError("the GitHub workflow trust policy is invalid")
    trusted_root = policy.get("trustedRoot")
    if not isinstance(trusted_root, dict):
        raise ReleaseSignatureError("the Sigstore trusted-root policy is invalid")
    trusted_root_path = resolve_repository_file(trusted_root.get("path"), "trusted-root path")
    trusted_root_bytes = read_regular_file(trusted_root_path, "Sigstore trusted root")
    if sha256(trusted_root_bytes) != trusted_root.get("sha256"):
        raise ReleaseSignatureError("the Sigstore trusted-root digest differs from the policy")
    identity = policy["certificateIdentityTemplate"].replace("{release}", release_name)
    return policy_bytes, policy, trusted_root_path, trusted_root_bytes, identity


def validate_release_schema(release: dict[str, Any], schema_path: Path | None = None) -> None:
    if schema_path is None:
        schema_path = (
            RELEASE_MANIFEST_SCHEMA_PATH
            if release.get("schema") == RELEASE_MANIFEST_SCHEMA
            else RELEASE_SCHEMA_PATH
        )
    _, schema = read_object(schema_path, "release schema", 512 * 1024)
    try:
        jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER,
        ).validate(release)
    except jsonschema.ValidationError as error:
        location = ".".join(str(item) for item in error.absolute_path) or "root"
        raise ReleaseSignatureError(
            f"the release-bundle schema failed at {location}: {error.message}"
        ) from error


def cosign_version(cosign: Path, policy: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    expected = policy.get("cosign")
    if not isinstance(expected, dict):
        raise ReleaseSignatureError("the Cosign tool policy is invalid")
    try:
        result = subprocess.run([str(cosign), "version", "--json"], text=True, capture_output=True,
                                timeout=timeout_seconds, check=False)
        actual = json.loads(result.stdout) if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        raise ReleaseSignatureError("cannot run the required Cosign verifier") from error
    if not isinstance(actual, dict) or any(
        actual.get(name) != expected.get(name) for name in ("gitVersion", "gitCommit")
    ):
        raise ReleaseSignatureError("the Cosign verifier version differs from the policy")
    return actual


def verify_release_signature(
    release_path: Path,
    signature_bundle_path: Path,
    cosign: Path,
    timeout_seconds: int = 60,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    """Verify one release with no network and return its trusted signer facts.

    `cosign verify-blob --offline` checks the Sigstore bundle: the Fulcio
    certificate chain to the pinned trusted root, the transparency-log
    inclusion proof, and the signature over the exact release bytes.

    `schema_path` selects the release document schema. It defaults to the
    release-bundle schema; a v0.14.0 or later release passes the
    release-manifest schema. Both carry the same signing fields.
    """
    if not cosign.is_file() or cosign.is_symlink():
        raise ReleaseSignatureError("the required Cosign verifier is not a file")
    release_bytes, release = read_object(release_path, "release bundle", MAX_RELEASE_BUNDLE_BYTES)
    validate_release_schema(release, schema_path)
    signature_bytes, signature_document = read_object(
        signature_bundle_path, "Sigstore signature bundle", MAX_SIGNATURE_BUNDLE_BYTES,
    )
    if signature_document.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise ReleaseSignatureError("the Sigstore bundle does not use the required v0.3 format")
    policy_bytes, policy, _, trusted_root_bytes, identity = validate_policy(release)
    version = cosign_version(cosign, policy, timeout_seconds)
    release_name = release["release"]["name"]
    workflow = policy["githubWorkflow"]
    workflow_ref = workflow["refTemplate"].replace("{release}", release_name)
    # Verify snapshots of the checked bytes, with an empty Sigstore cache.
    with tempfile.TemporaryDirectory(prefix="confidential-inference-sigstore-") as home:
        snapshot = Path(home)
        (snapshot / "release-bundle.json").write_bytes(release_bytes)
        (snapshot / "release-bundle.sigstore.json").write_bytes(signature_bytes)
        (snapshot / "trusted-root.json").write_bytes(trusted_root_bytes)
        command = [
            str(cosign), "verify-blob", "--offline",
            "--bundle", str(snapshot / "release-bundle.sigstore.json"),
            "--trusted-root", str(snapshot / "trusted-root.json"),
            "--certificate-identity", identity,
            "--certificate-oidc-issuer", policy["certificateOidcIssuer"],
            "--certificate-github-workflow-repository", workflow["repository"],
            "--certificate-github-workflow-ref", workflow_ref,
            "--certificate-github-workflow-name", workflow["name"],
            "--certificate-github-workflow-trigger", workflow["trigger"],
            "--certificate-github-workflow-sha", release["source"]["commit"],
            str(snapshot / "release-bundle.json"),
        ]
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=timeout_seconds,
                                    check=False, env={"PATH": os.environ.get("PATH", ""), "HOME": home,
                                                     "SIGSTORE_NO_CACHE": "true"})
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseSignatureError("Cosign could not verify the release signature") from error
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise ReleaseSignatureError(f"the release signature is not valid{suffix}")
    return {
        "verified": True,
        "releaseBundleBytesSha256": sha256(release_bytes),
        "signatureBundleBytesSha256": sha256(signature_bytes),
        "releaseTrustPolicySha256": sha256(policy_bytes),
        "certificateIdentity": identity,
        "certificateOidcIssuer": policy["certificateOidcIssuer"],
        "githubWorkflowRepository": workflow["repository"],
        "githubWorkflowRef": workflow_ref,
        "githubWorkflowName": workflow["name"],
        "githubWorkflowTrigger": workflow["trigger"],
        "transparencyLogEntries": len(signature_document.get("verificationMaterial", {}).get("tlogEntries", [])),
        "cosignVersion": version["gitVersion"],
        "cosignCommit": version["gitCommit"],
    }
