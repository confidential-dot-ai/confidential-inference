#!/usr/bin/env python3
"""Verify a keyless Sigstore signature on exact release-bundle bytes."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "releases/trust/release-signing-policy.json"
RELEASE_SCHEMA_PATH = ROOT / "contracts/release-bundle.schema.json"
MAX_RELEASE_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_SIGNATURE_BUNDLE_BYTES = 2 * 1024 * 1024
RELEASE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
TAG_ENVIRONMENTS = (
    (re.compile(r"v[0-9][a-z0-9._-]{0,126}"), "production"),
    (re.compile(r"integration-staging-v[0-9][a-z0-9._-]{0,106}"), "integration-staging"),
    (re.compile(r"conf-inference-prod-v[0-9][a-z0-9._-]{0,107}"), "conf-inference-prod"),
)


class ReleaseSignatureError(ValueError):
    """The release signature does not meet the public trust policy."""


def environment_for_tag(tag: str) -> str:
    """Return the one environment that a protected release tag can sign."""
    for pattern, environment in TAG_ENVIRONMENTS:
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


def validate_signature_bundle(document: dict[str, Any]) -> tuple[int, bytes]:
    if document.get("mediaType") != "application/vnd.dev.sigstore.bundle.v0.3+json":
        raise ReleaseSignatureError("the Sigstore bundle does not use the required v0.3 format")
    verification = document.get("verificationMaterial")
    if not isinstance(verification, dict):
        raise ReleaseSignatureError("the Sigstore bundle has no verification material")
    certificate = verification.get("certificate")
    if not isinstance(certificate, dict):
        raise ReleaseSignatureError("the Sigstore bundle has no Fulcio certificate")
    try:
        certificate_bytes = base64.b64decode(
            required_text(certificate.get("rawBytes"), "Sigstore certificate"),
            validate=True,
        )
    except ValueError as error:
        raise ReleaseSignatureError("the Sigstore certificate is not valid base64") from error
    if not certificate_bytes:
        raise ReleaseSignatureError("the Sigstore certificate is empty")
    entries = verification.get("tlogEntries")
    if not isinstance(entries, list) or not entries:
        raise ReleaseSignatureError("the Sigstore bundle has no transparency-log entry")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReleaseSignatureError("a transparency-log entry is invalid")
        proof = entry.get("inclusionProof")
        checkpoint = proof.get("checkpoint") if isinstance(proof, dict) else None
        if (
            not isinstance(proof, dict)
            or not isinstance(proof.get("hashes"), list)
            or not isinstance(checkpoint, dict)
            or not isinstance(checkpoint.get("envelope"), str)
            or not checkpoint["envelope"]
        ):
            raise ReleaseSignatureError("a transparency-log entry has no offline inclusion proof")
    signature = document.get("messageSignature")
    digest = signature.get("messageDigest") if isinstance(signature, dict) else None
    if (
        not isinstance(signature, dict)
        or not isinstance(digest, dict)
        or digest.get("algorithm") != "SHA2_256"
        or not isinstance(digest.get("digest"), str)
        or not isinstance(signature.get("signature"), str)
    ):
        raise ReleaseSignatureError("the Sigstore message signature is invalid")
    try:
        signed_digest = base64.b64decode(digest["digest"], validate=True)
        raw_signature = base64.b64decode(signature["signature"], validate=True)
    except ValueError as error:
        raise ReleaseSignatureError("the Sigstore message signature is not valid base64") from error
    if len(signed_digest) != hashlib.sha256().digest_size or not raw_signature:
        raise ReleaseSignatureError("the Sigstore message signature is invalid")
    return len(entries), signed_digest


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


def validate_release_schema(release: dict[str, Any]) -> None:
    _, schema = read_object(RELEASE_SCHEMA_PATH, "release-bundle schema", 512 * 1024)
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
        result = subprocess.run(
            [str(cosign), "version", "--json"],
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ReleaseSignatureError("cannot run the required Cosign verifier") from error
    if result.returncode != 0:
        raise ReleaseSignatureError("the Cosign verifier did not report its version")
    try:
        actual = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ReleaseSignatureError("the Cosign version output is invalid") from error
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
) -> dict[str, Any]:
    """Verify one release with no network and return its trusted signer facts."""
    if timeout_seconds < 1:
        raise ReleaseSignatureError("the Cosign timeout must be positive")
    if not cosign.is_file() or cosign.is_symlink():
        raise ReleaseSignatureError("the required Cosign verifier is not a file")
    release_bytes, release = read_object(
        release_path,
        "release bundle",
        MAX_RELEASE_BUNDLE_BYTES,
    )
    validate_release_schema(release)
    signature_bytes, signature_document = read_object(
        signature_bundle_path,
        "Sigstore signature bundle",
        MAX_SIGNATURE_BUNDLE_BYTES,
    )
    transparency_entries, signed_digest = validate_signature_bundle(signature_document)
    if signed_digest != hashlib.sha256(release_bytes).digest():
        raise ReleaseSignatureError("the Sigstore signature covers different release bytes")
    policy_bytes, policy, _, trusted_root_bytes, identity = validate_policy(release)
    version = cosign_version(cosign, policy, timeout_seconds)
    release_name = release["release"]["name"]
    workflow = policy["githubWorkflow"]
    environment = {
        name: os.environ[name]
        for name in ("LANG", "LC_ALL", "PATH", "TMPDIR")
        if name in os.environ
    }
    environment.update({
        "SIGSTORE_NO_CACHE": "true",
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
        "ALL_PROXY": "http://127.0.0.1:1",
        "http_proxy": "http://127.0.0.1:1",
        "https_proxy": "http://127.0.0.1:1",
        "all_proxy": "http://127.0.0.1:1",
        "NO_PROXY": "",
        "no_proxy": "",
    })
    try:
        with tempfile.TemporaryDirectory(prefix="confidential-inference-sigstore-") as home:
            environment["HOME"] = home
            snapshot = Path(home)
            release_snapshot = snapshot / "release-bundle.json"
            signature_snapshot = snapshot / "release-bundle.sigstore.json"
            root_snapshot = snapshot / "trusted-root.json"
            release_snapshot.write_bytes(release_bytes)
            signature_snapshot.write_bytes(signature_bytes)
            root_snapshot.write_bytes(trusted_root_bytes)
            command = [
                str(cosign),
                "verify-blob",
                "--offline",
                "--bundle", str(signature_snapshot),
                "--trusted-root", str(root_snapshot),
                "--certificate-identity", identity,
                "--certificate-oidc-issuer", policy["certificateOidcIssuer"],
                "--certificate-github-workflow-repository", workflow["repository"],
                "--certificate-github-workflow-ref", workflow["refTemplate"].replace("{release}", release_name),
                "--certificate-github-workflow-name", workflow["name"],
                "--certificate-github-workflow-trigger", workflow["trigger"],
                str(release_snapshot),
            ]
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
                env=environment,
            )
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
        "githubWorkflowRef": workflow["refTemplate"].replace("{release}", release_name),
        "githubWorkflowName": workflow["name"],
        "githubWorkflowTrigger": workflow["trigger"],
        "transparencyLogEntries": transparency_entries,
        "cosignVersion": version["gitVersion"],
        "cosignCommit": version["gitCommit"],
    }
