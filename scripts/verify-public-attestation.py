#!/usr/bin/env python3
"""Verify the public v0 c8s receipt set without a liveness claim."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import jsonschema
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from release_signature import (
    MAX_RELEASE_BUNDLE_BYTES,
    ReleaseSignatureError,
    verify_release_signature,
)

# Import the sibling module by absolute path rather than relying on the
# caller (direct script execution, runpy.run_path, or a test harness) to
# have already put this file's directory on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import c8s_allowlist_canonical


ROOT = Path(__file__).resolve().parents[1]
RESPONSE_SCHEMA = ROOT / "contracts/workload-attestation.schema.json"
RELEASE_SCHEMA = ROOT / "contracts/release-bundle.schema.json"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ALLOWLIST_BYTES = 8 * 1024 * 1024
SOURCE_COMMIT_RE = re.compile(r"[0-9a-f]{40}")


class VerificationError(ValueError):
    """The public evidence does not satisfy the trusted policy."""


class C8sPolicyRejection(VerificationError):
    """The receipt was not admitted by one candidate allowlist."""


def _error_detail(response: http.client.HTTPResponse) -> str:
    """Read the gateway error body's "detail" string, when it carries one.

    The gateway answers every 5xx with a short detail that names the failing
    step. The detail is printable ASCII and carries no evidence bytes, so it
    is safe to repeat in a verdict line. A body that is absent, too large, or
    not the expected shape yields an empty string.
    """
    try:
        body = response.read(8192)
        document = json.loads(body.decode("utf-8", "replace"))
        detail = document["error"]["detail"]
    except Exception:  # noqa: BLE001 - a failed read must never mask the status
        return ""
    if not isinstance(detail, str) or not detail:
        return ""
    return ": " + detail[:300]


def read_bytes(path: Path, label: str, maximum_bytes: int | None = None) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise VerificationError(f"the {label} must be a regular file")
    try:
        if maximum_bytes is not None and path.stat().st_size > maximum_bytes:
            raise VerificationError(f"the {label} is too large")
        return path.read_bytes()
    except OSError as error:
        raise VerificationError(f"cannot read the {label}") from error


def read_json(
    path: Path,
    label: str,
    maximum_bytes: int | None = None,
) -> dict[str, Any]:
    try:
        value = json.loads(read_bytes(path, label, maximum_bytes))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"the {label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise VerificationError(f"the {label} must contain one JSON object")
    return value


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64url_decode(value: str, label: str) -> bytes:
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (TypeError, ValueError) as error:
        raise VerificationError(f"the {label} is not canonical base64url") from error
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise VerificationError(f"the {label} is not canonical base64url")
    return raw


def validate_schema(value: Any, schema_path: Path, label: str) -> None:
    schema = read_json(schema_path, f"{label} schema")
    try:
        jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER,
        ).validate(value)
    except jsonschema.ValidationError as error:
        location = ".".join(str(item) for item in error.absolute_path) or "root"
        raise VerificationError(
            f"the {label} schema failed at {location}: {error.message}"
        ) from error


def canonical_public_key(path: Path) -> bytes:
    data = read_bytes(path, "operator public key")
    try:
        key = serialization.load_pem_public_key(data)
        return key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (TypeError, ValueError) as error:
        raise VerificationError("the operator public key is invalid") from error


def public_key_digest(path: Path) -> str:
    key = serialization.load_pem_public_key(canonical_public_key(path))
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(der)


OPERATOR_KEY_SET_DOMAIN = b"c8s-operator-key-set-v1\0"
PUBLIC_KEY_BLOCK_RE = re.compile(
    rb"-----BEGIN PUBLIC KEY-----\s*(.*?)\s*-----END PUBLIC KEY-----",
    re.DOTALL,
)


def key_set_digest(fingerprints: list[bytes]) -> str:
    """Return c8s's canonical operator key-set commitment.

    This is `pkg/operatorauth.KeySetDigest` (c8s 466ce79): SHA-256 over the
    domain separator, then over the sorted, de-duplicated SHA-256 fingerprints
    of each key's PKIX/SPKI DER. The commitment is independent of PEM
    formatting, key order, and duplicates, so a PEM bundle and a plain list of
    fingerprints digest identically. Both callers below use this one function,
    so a bundle read locally and a key set read over an attested CDS session
    can never disagree by formula.
    """
    ordered = sorted(set(fingerprints))
    return "sha256:" + hashlib.sha256(
        OPERATOR_KEY_SET_DOMAIN + b"".join(ordered)
    ).hexdigest()


def canonical_operator_key_set(data: bytes, label: str) -> tuple[bytes, str, set[str]]:
    """Return c8s's canonical PEM, key-set commitment, and member fingerprints."""
    if not data or len(data) > 256 * 1024:
        raise VerificationError(f"the {label} is empty or too large")
    ders: list[bytes] = []
    for match in PUBLIC_KEY_BLOCK_RE.finditer(data):
        try:
            der = base64.b64decode(re.sub(rb"\s+", b"", match.group(1)), validate=True)
            key = serialization.load_der_public_key(der)
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise ValueError("operator keys must be EC public keys")
            canonical_der = key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except (TypeError, ValueError) as error:
            raise VerificationError(f"the {label} contains an invalid public key") from error
        ders.append(canonical_der)
    if not ders:
        raise VerificationError(f"the {label} contains no public keys")
    fingerprints = sorted({hashlib.sha256(der).digest() for der in ders})
    commitment = key_set_digest(fingerprints)
    blocks = []
    for der in sorted(set(ders), key=lambda value: hashlib.sha256(value).digest()):
        encoded = base64.b64encode(der)
        lines = b"\n".join(encoded[offset : offset + 64] for offset in range(0, len(encoded), 64))
        blocks.append(b"-----BEGIN PUBLIC KEY-----\n" + lines + b"\n-----END PUBLIC KEY-----\n")
    canonical = b"".join(blocks)
    return (
        canonical,
        commitment,
        {"sha256:" + fingerprint.hex() for fingerprint in fingerprints},
    )


#: The one CDS route that serves the c8s operator key set. The gateway names
#: it in c8s.operatorTrust.cdsAttestedReadHint; the verifier requires exactly
#: this value, so a response can never steer the reader at another route.
CDS_OPERATOR_KEY_SET_ROUTE = "/operator-keys"


def validate_cds_url(value: str) -> str:
    """Accept only a bare HTTPS base URL for the CDS RA-TLS endpoint."""
    parts = urlsplit(value)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
        raise VerificationError(
            "--cds-url must be a bare https://host:port base URL for the CDS RA-TLS endpoint"
        )
    return value.rstrip("/")


def read_attested_operator_key_set(
    args: argparse.Namespace,
) -> tuple[str, set[str], str]:
    """Read the c8s operator key set over an attested CDS session.

    The gateway cannot make this read. CDS serves `GET /operator-keys` over
    RA-TLS behind a self-signed certificate whose trust comes from a TEE
    evidence extension and a pinned launch measurement, not from a certificate
    authority, so no CA-trusting TLS client can verify it. The pinned c8s CLI
    is that client: `c8s verify <cds-url> --kind cds --mode ratls-cert` dials
    the RA-TLS certificate, verifies its evidence against the hardware
    signature chain, pins the launch measurement against the node image
    manifest, and reports the `/operator-keys` set it read over that same
    session (`internal/cmds/verify/operatorkeys.go`, c8s 466ce79).

    Returns the c8s key-set commitment, the member fingerprints, and the
    attested launch measurement, so the caller can compare all three.
    """
    command = [
        args.c8s, "verify", args.cds_url,
        "--kind", "cds",
        "--mode", "ratls-cert",
        "--image-manifest", str(args.node_manifest),
        *policy_verifier_flags(args),
        "--operator-keys", str(args.operator_public_key),
        "-o", "json",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=args.verifier_timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError(
            "the attested CDS operator-key read did not run"
        ) from error
    if result.returncode != 0:
        raise VerificationError(
            "the attested CDS operator-key read failed: c8s verify exited "
            f"{result.returncode}"
        )
    try:
        verdict = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError(
            "the attested CDS operator-key read returned invalid JSON"
        ) from error
    required = {
        "verified": True,
        "backend": "attestation-go",
        "platform": "tdx",
        "measurement_pinned": True,
        "debug": False,
    }
    for field, expected in required.items():
        if verdict.get(field) != expected:
            raise VerificationError(
                f"the attested CDS session is not trustworthy: {field} is not {expected!r}"
            )
    note = verdict.get("operator_keys_note")
    expected_note = "matched: the set served over the attested cert equals --operator-keys"
    if note != expected_note:
        raise VerificationError(
            "the attested CDS read did not pin the operator key set: " + str(note)
        )
    served = verdict.get("operator_keys")
    if not isinstance(served, list) or not served:
        raise VerificationError("the attested CDS read returned no operator keys")
    fingerprints: list[bytes] = []
    for item in served:
        if not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item):
            raise VerificationError("the attested CDS read returned a malformed fingerprint")
        fingerprints.append(bytes.fromhex(item))
    measurement = verdict.get("measurement")
    if not isinstance(measurement, str) or not re.fullmatch(r"[0-9a-f]{96}", measurement):
        raise VerificationError("the attested CDS session reports no launch measurement")
    members = {"sha256:" + fingerprint.hex() for fingerprint in fingerprints}
    return key_set_digest(fingerprints), members, measurement


def operator_key_set_from_path(path: Path) -> tuple[bytes, str, set[str]]:
    return canonical_operator_key_set(read_bytes(path, "operator public key set"), "operator public key set")


def certificate_digest(pem: bytes, label: str) -> str:
    """Return the stable SHA-256 fingerprint of one X.509 certificate."""
    try:
        certificate = x509.load_pem_x509_certificate(pem)
    except ValueError as error:
        raise VerificationError(f"the {label} certificate is invalid") from error
    return sha256(certificate.public_bytes(serialization.Encoding.DER))


def certificate_details(pem_text: str, label: str) -> tuple[str, str]:
    try:
        block = pem_text.split("-----END CERTIFICATE-----", 1)[0]
        certificate = x509.load_pem_x509_certificate(
            (block + "-----END CERTIFICATE-----\n").encode("ascii")
        )
    except (UnicodeError, ValueError) as error:
        raise VerificationError(f"the {label} mesh leaf is invalid") from error
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(certificate.public_bytes(serialization.Encoding.DER)), sha256(spki)


def validate_nonce(value: str) -> None:
    if len(b64url_decode(value, "nonce")) != 32:
        raise VerificationError("the nonce must contain exactly 32 bytes")


def source_lock_node_image(
    node_source_lock: dict[str, Any], environment: str
) -> dict[str, Any]:
    """Return the node image the source lock pins for one environment.

    Each environment seals its own allowlist into its own measured node image,
    so the source lock carries one entry per environment under `nodeImages`.
    `nodeImage` stays as the production entry, so an older reader keeps
    working.
    """
    per_environment = node_source_lock.get("nodeImages")
    if isinstance(per_environment, dict):
        selected = per_environment.get(environment)
        if isinstance(selected, dict):
            return selected
        if per_environment:
            raise VerificationError(
                f"the node source lock pins no node image for {environment}"
            )
    node_image = node_source_lock.get("nodeImage")
    if not isinstance(node_image, dict):
        raise VerificationError("the node source lock image is invalid")
    return node_image


def source_lock_entries(source_lock: dict[str, Any]) -> list[dict[str, Any]]:
    """Return every c8s commit the source lock pins, as full entries.

    The lock keeps its original single-entry shape at the top level (so an
    older reader, and every pin except `commit` itself, is unaffected), and
    adds an optional `commits` list of further entries with the same shape.
    A signed release may use the c8s commit any one of these entries names;
    no other c8s commit is trusted.
    """
    entries = [source_lock]
    extra = source_lock.get("commits", [])
    if isinstance(extra, list):
        entries.extend(entry for entry in extra if isinstance(entry, dict))
    return entries


def select_source_lock_entry(
    source_lock: dict[str, Any], release_commit: str,
) -> dict[str, Any]:
    for entry in source_lock_entries(source_lock):
        commit = entry.get("commit")
        if not isinstance(commit, str) or SOURCE_COMMIT_RE.fullmatch(commit) is None:
            continue
        if commit == release_commit:
            return entry
    raise VerificationError("the release uses a different c8s source commit")


def validate_source_policy(
    release: dict[str, Any], manifest: dict[str, Any], source_lock: dict[str, Any],
    node_source_lock: dict[str, Any],
) -> dict[str, Any]:
    release_commit = release["c8s"]["sourceCommit"]
    if not isinstance(release_commit, str) or SOURCE_COMMIT_RE.fullmatch(release_commit) is None:
        raise VerificationError("the release c8s source commit is invalid")
    selected_entry = select_source_lock_entry(source_lock, release_commit)
    expected_node = source_lock_node_image(
        node_source_lock, release["release"]["environment"]
    )
    node_commit = expected_node.get("sourceCommit")
    if not isinstance(node_commit, str) or SOURCE_COMMIT_RE.fullmatch(node_commit) is None:
        raise VerificationError("the node source lock commit is invalid")
    if release["node"]["sourceCommit"] != node_commit:
        raise VerificationError("the release uses a different node source commit")
    expected_reference = expected_node.get("reference")
    expected_digest = expected_node.get("digest")
    if not isinstance(expected_reference, str) or not isinstance(expected_digest, str):
        raise VerificationError("the node source lock image is invalid")
    if (
        release["node"]["image"]["reference"] != expected_reference
        or release["node"]["image"]["digest"] != expected_digest
    ):
        raise VerificationError("the release uses a different node image")
    try:
        measured = {name: manifest["tdx"][name] for name in ("mrtd", "rtmr1", "rtmr2")}
    except (KeyError, TypeError) as error:
        raise VerificationError("the node manifest lacks the TDX image tuple") from error
    if measured != release["c8s"]["measurements"]:
        raise VerificationError("the node manifest differs from the release measurements")
    return selected_entry


def argv_from_allowlist(container: dict[str, Any], label: str) -> list[str]:
    result: list[str] = []
    for field, allow_empty in (("command", False), ("args", True)):
        policy = container.get(field)
        if not isinstance(policy, dict) or set(policy) - {"policy", "argv"}:
            raise VerificationError(f"the {label} {field} policy is invalid")
        kind = policy.get("policy")
        argv = policy.get("argv", [])
        if not isinstance(argv, list) or any(not isinstance(item, str) or not item for item in argv):
            raise VerificationError(f"the {label} {field} values are invalid")
        if kind == "exact" and argv:
            result.extend(argv)
        elif not (allow_empty and kind == "deny" and not argv):
            raise VerificationError(f"the {label} {field} policy is not exact")
    return result


def target_container(
    containers: Any, release_item: dict[str, Any], identity: str,
) -> dict[str, Any]:
    if not isinstance(containers, list) or not containers:
        raise VerificationError(f"the {identity} identity has no container")
    matches = []
    for container in containers:
        if not isinstance(container, dict):
            continue
        try:
            argv = argv_from_allowlist(container, identity)
        except VerificationError:
            continue
        if (
            container.get("digest") == release_item["image"]["digest"]
            and argv == release_item["argv"]
        ):
            matches.append(container)
    if len(matches) != 1:
        raise VerificationError(
            f"the {identity} container set does not match one release workload"
        )
    return matches[0]


def expected_targets(
    release: dict[str, Any], legacy_targets: list[str],
) -> tuple[tuple[str, str, str], ...]:
    configured = release["c8s"].get("attestationTargets")
    if configured is not None:
        try:
            return tuple(
                (
                    item["target"], item["workload"],
                    item.get("identity", item["workload"])
                    if release.get("schemaVersion") == 1 else item["identity"],
                )
                for item in configured
            )
        except (KeyError, TypeError) as error:
            raise VerificationError("a release attestation target lacks its stable identity") from error
    pairs = []
    for value in legacy_targets:
        target, separator, workload = value.partition("=")
        if not separator or not target or not workload:
            raise VerificationError("a legacy target must use TARGET=WORKLOAD")
        # v1 releases did not have a separate stable identity. Their exact
        # policy name remains the identity for compatibility.
        pairs.append((target, workload, workload))
    if not pairs:
        raise VerificationError("the legacy release needs explicit expected targets")
    return tuple(pairs)


# Set by canonicalize_allowlist on every call, for the final report and for
# scripts/ci-validate.sh output: which method produced the canonical bytes
# the verifier trusted. Not thread-safe, but this script is single-threaded.
CANONICALIZATION_METHODS_USED: set[str] = set()


def canonicalize_allowlist(
    executable: str, path: Path, timeout: int, label: str,
    capabilities: dict[str, Any] | None = None,
) -> bytes:
    """Produce the canonical allowlist bytes c8s would sign off on.

    c8s commit 75af991a removed the offline `c8s allowlist canonicalize
    <file>` command (see scripts/c8s_allowlist_canonical.py); every c8s tag
    after that commit needs a live CDS connection to turn a file into
    canonical bytes via `c8s allowlist export`, which this offline verifier
    cannot use. capabilities (the matched contracts/c8s-admission-source-lock.json
    entry's "capabilities" object) says which case applies:

    - {"allowlistCanonicalize": true} (or capabilities omitted, for backward
      compatibility with older lock entries): shell out to the pinned c8s
      binary, unchanged from before this function grew capability branching.
    - {"allowlistCanonicalize": false}: reproduce the canonical bytes in
      Python via c8s_allowlist_canonical.canonicalize_mainline(), verified
      byte-identical against pkg/allowlist.Canonical() at c8s 466ce79
      (v0.20.4) for every allowlist this repository pins. This is a genuine
      independent canonicalization, not a weakened check: validate_allowlist
      still requires the file's bytes to equal these bytes and their SHA-256
      to equal the release's pinned allowlistDigest.

    A document shape the Python reproduction cannot cover (see that module's
    docstring) fails closed with VerificationError, not a silent pass.
    """
    can_use_native = capabilities is None or capabilities.get("allowlistCanonicalize", True)
    if can_use_native:
        try:
            result = subprocess.run(
                [executable, "allowlist", "canonicalize", str(path)],
                capture_output=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError(f"the c8s canonicalizer did not run for the {label}") from error
        if result.returncode != 0 or not result.stdout:
            raise VerificationError(f"c8s rejected the {label}")
        if len(result.stdout) > MAX_ALLOWLIST_BYTES:
            raise VerificationError(f"the canonical {label} is too large")
        CANONICALIZATION_METHODS_USED.add("c8s-cli")
        return result.stdout

    print(
        f"note: the pinned c8s binary has no offline 'allowlist canonicalize' "
        f"(capability allowlistCanonicalize=false); canonicalizing the {label} "
        "with the verified Python reproduction of pkg/allowlist.Canonical() instead "
        "(scripts/c8s_allowlist_canonical.py)",
        file=sys.stderr,
    )
    document = read_json(path, label)
    try:
        canonical = c8s_allowlist_canonical.canonicalize_mainline(document)
    except c8s_allowlist_canonical.UnsupportedAllowlistShape as error:
        raise VerificationError(
            f"skipped: the {label} cannot be canonicalized without the pinned c8s "
            f"binary (capability allowlistCanonicalize=false) and the Python "
            f"reproduction does not cover its shape: {error}"
        ) from error
    if len(canonical) > MAX_ALLOWLIST_BYTES:
        raise VerificationError(f"the canonical {label} is too large")
    CANONICALIZATION_METHODS_USED.add("python-mainline-reproduction")
    return canonical


def validate_allowlist(
    release: dict[str, Any], allowlist: dict[str, Any], allowlist_bytes: bytes,
    canonical: bytes, expected: tuple[tuple[str, str, str], ...],
) -> tuple[str, bytes]:
    if allowlist_bytes not in (canonical, canonical + b"\n"):
        raise VerificationError("the allowlist file differs from c8s canonical bytes")
    digest = sha256(canonical)
    if release["allowlistDigest"] != digest:
        raise VerificationError("the canonical allowlist digest differs from the release")
    release_items = release["workloads"]
    for target, workload, identity in expected:
        policy = allowlist.get("workloads", {}).get(workload)
        if not isinstance(policy, dict):
            raise VerificationError(f"the allowlist omits the {workload} policy")
        if identity != workload:
            raise VerificationError(
                f"the {workload} receipt identity is not its exact c8s workload name"
            )
        release_matches = [item for item in release_items if item.get("name") == target]
        if len(release_matches) != 1:
            raise VerificationError(f"the release must contain one {target} workload")
        target_container(policy.get("containers"), release_matches[0], workload)
    return digest, canonical


def allowlist_matches_target(
    release: dict[str, Any], allowlist: dict[str, Any], target: str, workload: str,
    identity: str,
) -> bool:
    """Return true when one allowlist entry matches the expected release workload."""
    policy = allowlist.get("workloads", {}).get(workload)
    if not isinstance(policy, dict):
        return False
    if identity != workload:
        return False
    release_matches = [item for item in release["workloads"] if item.get("name") == target]
    if len(release_matches) != 1:
        return False
    try:
        target_container(policy.get("containers"), release_matches[0], workload)
    except VerificationError:
        return False
    return True


def trusted_allowlists(
    release: dict[str, Any], expected: tuple[tuple[str, str, str], ...],
    current_path: Path, history_directory: Path | None, current: tuple[str, bytes],
    c8s: str, timeout: int, capabilities: dict[str, Any] | None = None,
) -> list[tuple[str, bytes, dict[str, Any]]]:
    """Load the current and retained allowlists used by still-running pods."""
    current_digest, current_bytes = current
    result = [(current_digest, current_bytes, read_json(current_path, "canonical allowlist"))]
    if history_directory is None or not history_directory.exists():
        return result
    seen = {current_digest}
    for path in sorted(history_directory.glob("sha256-*.json")):
        raw = read_bytes(path, "historical allowlist")
        document = read_json(path, "historical allowlist")
        if document.get("schema") != "c8s.allowlist/v1":
            raise VerificationError("a historical allowlist has the wrong schema")
        canonical = canonicalize_allowlist(
            c8s, path, timeout, "historical allowlist", capabilities
        )
        if raw not in (canonical, canonical + b"\n"):
            raise VerificationError("a historical allowlist differs from c8s canonical bytes")
        digest = sha256(canonical)
        if path.name != f"sha256-{digest[7:]}.json":
            raise VerificationError("a historical allowlist filename does not match its digest")
        if digest in seen:
            raise VerificationError("a trusted allowlist digest is duplicated")
        seen.add(digest)
        result.append((digest, canonical, document))
    for target, workload, identity in expected:
        if not any(allowlist_matches_target(release, document, target, workload, identity) for _, _, document in result):
            raise VerificationError(f"no trusted allowlist matches the {target} release workload")
    return result


def validate_model_policy(release: dict[str, Any]) -> str:
    root = release["model"]["dmVerityRoot"]
    for item in release["workloads"]:
        workload_root = item.get("modelDmVerityRoot")
        if workload_root is not None and workload_root != root:
            raise VerificationError(f"the {item['name']} model root differs from the release")
    return root


def release_policy_mode(release: dict[str, Any]) -> str:
    """Return the explicit policy mode, with operator mode for old bundles."""
    mode = release["c8s"].get("policyMode", "operator")
    if mode not in {"operator", "static"}:
        raise VerificationError("the release has an invalid c8s policy mode")
    return mode


def policy_verifier_flags(args: argparse.Namespace) -> list[str]:
    """Select the c8s policy verification path. --static-allowlist and
    --operator-pkey are independent c8s flags, not mutually exclusive ones, so
    static mode passes both: the allowlist stays sealed, and the operator
    public key still pins RTMR[3] so the TDX image tuple stays fully pinned.
    """
    # Direct helper callers from the operator-mode interface predate the
    # explicit policy_mode argument. Keep that interface fail-closed on its
    # required operator key.
    if args.operator_public_key is None:
        raise VerificationError("verification requires --operator-public-key")
    if getattr(args, "policy_mode", "operator") == "static":
        return ["--static-allowlist", "--operator-pkey", str(args.operator_public_key)]
    return ["--operator-pkey", str(args.operator_public_key)]


#: Old c8s (079aeb48): the receipt carries session_pubkey, and c8s never
#: proves the allowlist-write operator key set. The gateway omits
#: c8s.attestationProtocol on this protocol.
OLD_ATTESTATION_PROTOCOL = "c8s/attest-pq/v1"
#: New c8s (466ce79 and 2ef376a8): the receipt carries xwing_ek/xwing_ct/
#: session_id instead of session_pubkey, and serves no GPU field.
XWING_ATTESTATION_PROTOCOL = "c8s/attest-pq/v1+xwing"


def expected_attestation_protocol(source_lock_entry: dict[str, Any]) -> str:
    """Return the c8s attestation protocol the pinned source lock entry speaks.

    A lock entry with no attestationProtocol field pins the old protocol, so
    an unlisted (and thus untested) c8s commit can never silently pass as the
    new one.
    """
    protocol = source_lock_entry.get("attestationProtocol", OLD_ATTESTATION_PROTOCOL)
    if protocol not in (OLD_ATTESTATION_PROTOCOL, XWING_ATTESTATION_PROTOCOL):
        raise VerificationError("the source lock names an unknown c8s attestation protocol")
    return protocol


def validate_response_evidence(
    response: dict[str, Any], release: dict[str, Any], release_digest: str,
    allowlist: dict[str, Any], canonical_allowlist: bytes, operator_digest: str | None,
    operator_key_set_digest: str | None, mesh_ca_der_digest: str,
    attestation_protocol: str, gpu_required: bool,
    attested_key_set: tuple[str, set[str], str] | None = None,
    gpu_mode: str = "receipt-evidence",
) -> None:
    """Bind the gateway envelope to the held public release inputs."""
    if response["release"] != {
        "id": release["release"]["name"],
        "bundleSha256": release_digest,
        "source": "operator-selected-public-release",
    }:
        raise VerificationError("the response release identity differs from the trusted bundle")
    active = response["c8s"]["activeAllowlist"]
    if active["document"] != allowlist or active["sha256"] != sha256(canonical_allowlist):
        raise VerificationError("the active c8s allowlist differs from the trusted release")
    response_protocol = response["c8s"].get("attestationProtocol", OLD_ATTESTATION_PROTOCOL)
    if response_protocol != attestation_protocol:
        raise VerificationError(
            "the response c8s attestation protocol differs from the pinned source lock entry"
        )
    gpu_status = response["gpuEvidence"]["status"]
    if gpu_required and gpu_mode == "receipt-evidence" and gpu_status == "not-exposed-by-c8s":
        raise VerificationError(
            "the response claims c8s exposes no GPU evidence, but the release requires it"
        )
    if gpu_required and gpu_mode == "measured-boot-gate" and gpu_status != "not-exposed-by-c8s":
        raise VerificationError(
            "the response GPU evidence status differs from the measured boot-gate protocol"
        )
    mode = release_policy_mode(release)
    policy = response["c8s"].get("policyTrust")
    if mode == "static":
        if not isinstance(policy, dict) or policy.get("mode") != "static":
            raise VerificationError("the response does not report sealed static policy evidence")
        expected = release["allowlistDigest"]
        if (
            policy.get("expectedAllowlistSha256") != expected
            or policy.get("activeAllowlistSha256") != expected
            or policy.get("status") != "evidence-present-requires-independent-verification"
        ):
            raise VerificationError("the response static policy digest differs from the release")
        if response["c8s"]["meshCaSha256"] != mesh_ca_der_digest:
            raise VerificationError("the response mesh CA fingerprint differs from the held mesh CA")
        if response["tls"]["mode"] != response["c8s"]["discovery"]["public_tls"]["mode"]:
            raise VerificationError("the response TLS mode differs from c8s discovery")
        if gpu_status == "verified":
            raise VerificationError("the response claims GPU verification without a c8s GPU verifier")
        return

    operator = policy or response["c8s"].get("operatorTrust")
    if not isinstance(operator, dict):
        raise VerificationError("the response does not report operator policy evidence")
    if operator["expectedPublicKeySpkiSha256"] != operator_digest:
        raise VerificationError("the response operator fingerprint differs from the trusted release")
    expected_key_set = release["c8s"].get("operatorKeySetSha256")
    if not isinstance(expected_key_set, str) or expected_key_set != operator_key_set_digest:
        raise VerificationError("the release does not pin the expected operator key set")
    if operator.get("expectedKeySetSha256") != expected_key_set:
        raise VerificationError("the response operator key-set expectation differs from the release")
    # c8s binds this key set to no hardware evidence at either protocol (see
    # docs/ratls.md), so the new protocol may only ever claim the honest
    # requires-attested-cds-read status. A response that claims the stronger
    # evidence-present-and-release-matched status on this protocol is lying
    # about what c8s can prove, and must fail closed here.
    required_status = (
        "requires-attested-cds-read"
        if attestation_protocol == XWING_ATTESTATION_PROTOCOL
        else "evidence-present-and-release-matched"
    )
    if operator.get("status", operator.get("activeKeySetStatus")) != required_status:
        raise VerificationError("the active operator key set is not the pinned policy")
    if attestation_protocol == XWING_ATTESTATION_PROTOCOL:
        # The gateway cannot read the key set: the CDS leaf is self-signed and
        # is trusted through TEE evidence, not a certificate chain. So the
        # response must claim no active key set at all, must name the CDS
        # route, and the verifier must have made that attested read itself.
        for field in ("activeKeySetSha256", "activeKeySetPem", "activeKeySetC8sSha256"):
            if field in operator:
                raise VerificationError(
                    "the response claims a live operator key set the gateway cannot read"
                )
        if operator.get("cdsAttestedReadHint") != CDS_OPERATOR_KEY_SET_ROUTE:
            raise VerificationError(
                "the response does not name the CDS operator-key route to read"
            )
        if attested_key_set is None:
            raise VerificationError(
                "this protocol requires an attested CDS read of the operator key set: "
                "pass --cds-url with the CDS RA-TLS endpoint reachable to this verifier"
            )
        active_digest, active_members, _ = attested_key_set
        if active_digest != expected_key_set:
            raise VerificationError(
                "the attested CDS operator key set differs from the release key-set commitment"
            )
        if active_digest != operator.get("expectedKeySetSha256"):
            raise VerificationError(
                "the attested CDS operator key set differs from the response key-set expectation"
            )
        if operator_digest not in active_members:
            raise VerificationError(
                "the held operator key is not a member of the attested CDS key set"
            )
    else:
        active_pem = operator.get("activeKeySetPem")
        if not isinstance(active_pem, str):
            raise VerificationError("the response does not expose the active operator key set")
        try:
            active_pem_bytes = active_pem.encode("ascii")
        except UnicodeEncodeError as error:
            raise VerificationError("the active operator key set is not ASCII PEM") from error
        _, active_digest, active_members = canonical_operator_key_set(
            active_pem_bytes, "active operator key set"
        )
        if (
            operator.get("activeKeySetSha256") != active_digest
            or active_digest != expected_key_set
            or operator_digest not in active_members
        ):
            raise VerificationError("the active operator key set is not the pinned policy")
    if response["c8s"]["meshCaSha256"] != mesh_ca_der_digest:
        raise VerificationError("the response mesh CA fingerprint differs from the held mesh CA")
    if response["tls"]["mode"] != response["c8s"]["discovery"]["public_tls"]["mode"]:
        raise VerificationError("the response TLS mode differs from c8s discovery")
    if gpu_status == "verified":
        raise VerificationError("the response claims GPU verification without a c8s GPU verifier")


def expected_admitted_launch(
    allowlist: dict[str, Any], workload: str,
) -> dict[str, Any]:
    try:
        policy = allowlist["workloads"][workload]
        init_containers = policy["initContainers"]
        containers = policy["containers"]
    except (KeyError, TypeError) as error:
        raise VerificationError(f"the active allowlist omits {workload}") from error
    def launches(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{
            "image": container["image"],
            "digest": container["digest"],
            "argv": argv_from_allowlist(container, workload),
        } for container in values]
    return {
        "policyName": workload,
        "initContainers": launches(init_containers),
        "containers": launches(containers),
    }


def fetch_response(args: argparse.Namespace) -> tuple[dict[str, Any], str, str, bytes]:
    parsed = urlsplit(args.endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise VerificationError("the endpoint must be one HTTPS URL without credentials")
    if parsed.fragment or parse_qsl(parsed.query, keep_blank_values=True):
        raise VerificationError("the endpoint must not contain a query or fragment")
    context = ssl.create_default_context(cafile=str(args.endpoint_ca) if args.endpoint_ca else None)
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or 443,
        timeout=args.timeout_seconds,
        context=context,
    )
    connect_address = getattr(args, "connect_address", None)
    if connect_address is not None:
        try:
            ipaddress.ip_address(connect_address)
        except ValueError as error:
            raise VerificationError("the connect address must be one IP address") from error
        connect_port = parsed.port or 443

        def connect_exact(
            _address: tuple[str, int], timeout: float | None = None,
            source_address: tuple[str, int] | None = None, *, all_errors: bool = False,
        ):
            return socket.create_connection(
                (connect_address, connect_port), timeout, source_address,
                all_errors=all_errors,
            )

        connection._create_connection = connect_exact
    path = parsed.path or "/attestation"
    if parsed.path.endswith("/"):
        path = parsed.path + "attestation"
    path += "?" + urlencode({"nonce": args.nonce})
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        peer = connection.sock.getpeercert(binary_form=True) if connection.sock else None
        if response.status != 200:
            # The gateway names the step that failed in the error body's
            # "detail" field. Repeat it here, so one verifier run says where
            # the producer stopped without any access to the cluster.
            raise VerificationError(
                f"the public endpoint returned HTTP {response.status}"
                + _error_detail(response)
            )
        length = response.getheader("Content-Length")
        if length is not None and int(length) > args.maximum_response_bytes:
            raise VerificationError("the public response exceeds the size limit")
        body = response.read(args.maximum_response_bytes + 1)
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as error:
        if isinstance(error, VerificationError):
            raise
        raise VerificationError("the public HTTPS request failed") from error
    finally:
        connection.close()
    if len(body) > args.maximum_response_bytes:
        raise VerificationError("the public response exceeds the size limit")
    if peer is None:
        raise VerificationError("the public TLS certificate is unavailable")
    try:
        value = json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError("the public endpoint returned invalid JSON") from error
    if not isinstance(value, dict):
        raise VerificationError("the public endpoint did not return one JSON object")
    certificate = x509.load_der_x509_certificate(peer)
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    leaf_der = certificate.public_bytes(serialization.Encoding.DER)
    return value, sha256(spki), sha256(leaf_der), leaf_der


def verify_c8s_version(executable: str, commit: str, timeout: int, tag: str | None = None) -> str:
    """Fail closed unless the binary's own `--version` text names this source lock entry.

    Cobra's version text carries whatever `git describe` produced at build
    time. Off an exact tag, `git describe` prints only the tag string, with
    no commit hash — so a tagged release build is checked against the
    entry's `tag` (when the lock names one); every other build is still
    checked against the entry's commit hash, exactly as before.
    """
    try:
        result = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError("the exact c8s verifier did not run") from error
    version = (result.stdout + "\n" + result.stderr).strip()
    short_commit = commit[:7]
    version_matches = (
        commit in version
        or f"g{short_commit}" in version
        or re.search(rf"(?<![0-9a-f]){short_commit}(?![0-9a-f])", version) is not None
    )
    if not version_matches and isinstance(tag, str) and tag:
        version_matches = re.search(rf"(?<![\w.-]){re.escape(tag)}(?![\w.-])", version) is not None
    if result.returncode != 0 or not version_matches:
        raise VerificationError("the c8s verifier does not match the source lock")
    return version.splitlines()[0]


def require_c8s_capabilities(
    executable: str, required: set[str], timeout: int,
) -> None:
    """Fail closed when the supplied c8s binary lacks a required interface."""
    if not required:
        return
    try:
        result = subprocess.run(
            [executable, "verify", "--help"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError("the c8s verifier capability check did not run") from error
    help_text = result.stdout + "\n" + result.stderr
    if result.returncode != 0 or any(flag not in help_text for flag in required):
        missing = sorted(flag for flag in required if flag not in help_text)
        raise VerificationError(
            "the pinned c8s verifier does not support required flags: " + ", ".join(missing)
        )


def verify_receipt(
    item: dict[str, Any], args: argparse.Namespace, allowlist_path: Path
) -> dict[str, str]:
    receipt_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="c8s-public-receipt-", suffix=".json", mode="w", delete=False
        ) as output:
            os.chmod(output.name, 0o600)
            json.dump(item["receipt"], output, separators=(",", ":"))
            receipt_path = Path(output.name)
        command = [
            args.c8s,
            "verify",
            "--from-file", str(receipt_path),
            "--kind", "workload",
            "--image-manifest", str(args.node_manifest),
            "--mesh-ca", str(args.mesh_ca),
            "--allowlist", str(allowlist_path),
            "--workload", item["workload"],
            "-o", "json",
        ]
        command[command.index("-o"):command.index("-o")] = policy_verifier_flags(args)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=args.verifier_timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError(f"the c8s verifier did not run for {item['target']}") from error
    finally:
        if receipt_path is not None:
            receipt_path.unlink(missing_ok=True)
    if result.returncode != 0:
        raise C8sPolicyRejection(f"c8s rejected the {item['target']} receipt")
    try:
        verdict = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError(f"c8s returned invalid JSON for {item['target']}") from error
    required = {
        "verified": True,
        "backend": "attestation-go",
        "platform": "tdx",
        "measurement_pinned": True,
        "debug": False,
        "fresh": False,
        "workload": item["workload"],
    }
    for name, expected in required.items():
        if verdict.get(name) != expected:
            raise VerificationError(f"the {item['target']} c8s {name} verdict is invalid")
    if verdict.get("partial") is True or verdict.get("not_proven"):
        raise VerificationError(f"the {item['target']} c8s verdict is partial")
    if verdict.get("warnings"):
        raise VerificationError(f"the {item['target']} c8s verdict has warnings")
    if verdict.get("chain_anchor") != "verified against the pinned --mesh-ca bundle":
        raise VerificationError(f"the {item['target']} mesh CA is not pinned")
    if not str(verdict.get("binding", "")).startswith("REPORTDATA binds the identity transcript:"):
        raise VerificationError(f"the {item['target']} report_data binding is invalid")
    if not str(verdict.get("workload_note", "")).startswith("workload_verified:"):
        raise VerificationError(f"the {item['target']} allowlist identity is not verified")
    pinned = verdict.get("rtmrs_pinned")
    if not isinstance(pinned, list) or {str(value).partition(":")[0] for value in pinned} != {"1", "2", "3"}:
        raise VerificationError(f"the {item['target']} TDX image tuple is not fully pinned")
    for value in pinned:
        register, _, measurement = str(value).partition(":")
        if register not in {"1", "2", "3"} or not re.fullmatch(r"[0-9a-f]{96}", measurement):
            raise VerificationError(f"the {item['target']} TDX register pin is invalid")
    cert_sha256, spki_sha256 = certificate_details(
        item["receipt"]["cds_cert_pem"], item["target"]
    )
    rtmrs = {
        str(value).partition(":")[0]: str(value).partition(":")[2]
        for value in pinned
    }
    serving_leaf = item["receipt"].get("serving_leaf_sha256")
    if item["receipt"].get("version") == "c8s/attest-lb/v1":
        if not isinstance(serving_leaf, str) or len(b64url_decode(serving_leaf, f"{item['target']} serving leaf")) != 32:
            raise VerificationError(f"the {item['target']} attest-lb serving leaf digest is invalid")
        if verdict.get("serving_leaf_sha256") != serving_leaf:
            raise VerificationError(f"the {item['target']} c8s verifier did not verify the serving leaf")
    result = {
        "target": item["target"],
        "workload": item["workload"],
        "identity": item["identity"],
        "meshLeafSha256": cert_sha256,
        "meshLeafSpkiSha256": spki_sha256,
        "reportDataSha256": sha256(bytes.fromhex(verdict["report_data"])),
        "reportDataHex": verdict["report_data"],
        "tdx": {
            "mrtd": verdict.get("measurement"),
            "rtmr1": rtmrs["1"],
            "rtmr2": rtmrs["2"],
            "rtmr3": rtmrs["3"],
            "debug": verdict["debug"],
            "currentTcb": verdict.get("current_tcb"),
        },
        "admission": {
            "allowlistVersion": verdict.get("workload_allowlist_version"),
            "allowlistDigest": verdict.get("workload_allowlist_digest"),
        },
    }
    if serving_leaf is not None:
        result["servingLeafSha256"] = serving_leaf
        result["servingLeafVerified"] = item["receipt"].get("version") == "c8s/attest-lb/v1"
    return result


def required_gpu_policy(release: dict[str, Any], target: str, workload: str) -> dict[str, Any] | None:
    for item in release.get("workloads", []):
        if not isinstance(item, dict):
            continue
        if item.get("name") in {target, workload} and isinstance(item.get("gpu"), dict):
            policy = item["gpu"]
            if policy.get("required") is True:
                return policy
    return None


def gpu_attestation_mode(source_lock_entry: dict[str, Any]) -> str:
    """Return how the pinned c8s release enforces required GPU policy.

    Older c8s releases copied raw NVIDIA evidence into each workload receipt.
    Current node images instead verify every passed-through GPU in a measured,
    fail-closed boot unit that RKE2 requires. That verdict stays inside the
    node, so an external verifier checks the measured gate and must not demand
    receipt fields that this protocol does not expose.
    """
    capabilities = source_lock_entry.get("capabilities")
    mode = (
        capabilities.get("gpuAttestationMode", "receipt-evidence")
        if isinstance(capabilities, dict)
        else "receipt-evidence"
    )
    if mode not in {"receipt-evidence", "measured-boot-gate"}:
        raise VerificationError("the source lock names an unknown GPU attestation mode")
    return mode


def front_door_verification_mode(source_lock_entry: dict[str, Any]) -> str:
    """Return the verifier that owns the public front-door TEE check."""
    capabilities = source_lock_entry.get("capabilities")
    mode = (
        capabilities.get("frontDoorVerification", "c8s-cli")
        if isinstance(capabilities, dict)
        else "c8s-cli"
    )
    if mode not in {"c8s-cli", "external-teerminator"}:
        raise VerificationError("the source lock names an unknown front-door verification mode")
    return mode


def verify_gpu_receipt(
    item: dict[str, Any], policy: dict[str, Any], receipt: dict[str, Any],
    report_data_hex: str, args: argparse.Namespace, allowlist_path: Path,
) -> dict[str, Any]:
    """Verify worker GPU evidence and bind it to the TDX report transcript.

    The c8s verifier owns NVIDIA certificate and EAT verification. The gateway
    verifier only supplies the nonce derived from the TDX REPORTDATA transcript
    and checks the c8s result. This prevents TLS-LB-local GPU evidence from
    being mistaken for evidence about a different inference worker.
    """
    if receipt.get("gpu_attested") != "evidence_collected":
        raise VerificationError(f"the {item['target']} required GPU evidence")
    bundle = receipt.get("nvidia_gpu")
    if not isinstance(bundle, dict):
        raise VerificationError(f"the {item['target']} NVIDIA evidence is missing")
    devices = bundle.get("devices")
    binding = bundle.get("binding")
    if not isinstance(devices, list) or not devices or not isinstance(binding, dict):
        raise VerificationError(f"the {item['target']} NVIDIA evidence shape is invalid")
    if binding != {"kind": "concat", "algo": "sha256"}:
        raise VerificationError(f"the {item['target']} NVIDIA binding is invalid")
    expected_count = policy.get("deviceCount")
    if not isinstance(expected_count, int) or expected_count < 1:
        raise VerificationError(f"the {item['target']} GPU policy has no expected device count")
    if expected_count is not None and len(devices) != expected_count:
        raise VerificationError(f"the {item['target']} NVIDIA device count differs from policy")
    seen_uuids: set[str] = set()
    for device in devices:
        if not isinstance(device, dict):
            raise VerificationError(f"the {item['target']} NVIDIA device is invalid")
        if not isinstance(device.get("arch"), str) or not device["arch"]:
            raise VerificationError(f"the {item['target']} NVIDIA architecture is missing")
        for name in ("evidence_b64", "cert_chain_b64"):
            value = device.get(name)
            if not isinstance(value, str) or not value:
                raise VerificationError(f"the {item['target']} NVIDIA {name} is missing")
            try:
                base64.b64decode(value, validate=True)
            except (TypeError, ValueError) as error:
                raise VerificationError(f"the {item['target']} NVIDIA {name} is invalid") from error
        uuid = device.get("uuid")
        if not isinstance(uuid, str) or not uuid or uuid in seen_uuids:
            raise VerificationError(f"the {item['target']} NVIDIA device UUID is invalid")
        seen_uuids.add(uuid)
    try:
        report_data = bytes.fromhex(report_data_hex)
    except ValueError as error:
        raise VerificationError(f"the {item['target']} TDX report_data is invalid") from error
    # attestation-rs receives the CPU REPORTDATA as its GPU user nonce. It
    # derives each device nonce internally. Do not hash or rewrite it here.
    # The pinned c8s verifier compares the nonce against the 48-byte identity
    # transcript (ev.erd) with a strict equality check. TDX report_data is that
    # transcript zero-padded to 64 bytes, so strip only canonical zero padding;
    # pass any other framing through unchanged and let c8s fail closed.
    if len(report_data) == 64 and report_data[48:] == b"\x00" * 16:
        report_data = report_data[:48]
    gpu_nonce = report_data.hex()
    # The pinned c8s verifier reads --from-file as a literal path; "-" is a
    # filename, not stdin. Hand it a private temporary file like the other
    # verification paths in this script do.
    receipt_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="c8s-public-gpu-receipt-", suffix=".json", mode="w", delete=False
        ) as output:
            os.chmod(output.name, 0o600)
            json.dump(receipt, output, separators=(",", ":"))
            receipt_path = Path(output.name)
        command = [
            args.c8s, "verify", "--from-file", str(receipt_path), "--kind", "workload",
            "--image-manifest", str(args.node_manifest),
            "--mesh-ca", str(args.mesh_ca), "--allowlist", str(allowlist_path),
            "--workload", item["workload"], "--nvidia-gpu-user-nonce", gpu_nonce,
            "--nvidia-gpu-required", "--attestation-cli-sha256",
            args.attestation_cli_sha256, "-o", "json",
        ]
        command[command.index("-o"):command.index("-o")] = policy_verifier_flags(args)
        for architecture in policy.get("architectures", []):
            command[command.index("-o"):command.index("-o")] = [
                "--nvidia-gpu-expected-arch", architecture,
            ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True,
                timeout=args.verifier_timeout_seconds,
                env=args.gpu_verifier_environment,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError(f"the c8s GPU verifier did not run for {item['target']}") from error
    finally:
        if receipt_path is not None:
            receipt_path.unlink(missing_ok=True)
    if result.returncode != 0:
        raise VerificationError(f"the c8s GPU verifier rejected {item['target']}")
    try:
        verdict = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError(f"the c8s GPU verifier returned invalid JSON for {item['target']}") from error
    if verdict.get("gpu_verified") is not True or verdict.get("nonce_binding_ok") is not True:
        raise VerificationError(f"the {item['target']} GPU evidence is not nonce-bound")
    signed_count = verdict.get("gpu_device_count")
    signed_ueids = verdict.get("gpu_device_ueids")
    if not isinstance(signed_count, int) or signed_count != expected_count:
        raise VerificationError(f"the {item['target']} c8s signed GPU count differs from policy")
    if (
        not isinstance(signed_ueids, list)
        or len(signed_ueids) != signed_count
        or len(set(signed_ueids)) != signed_count
        or any(not isinstance(value, str) or not value for value in signed_ueids)
    ):
        raise VerificationError(f"the {item['target']} c8s signed GPU identities are invalid")
    return {
        "target": item["target"],
        "deviceCount": len(devices),
        "signedDeviceCount": signed_count,
        "signedDeviceUEIDs": signed_ueids,
        "gpuUserNonceSha256": sha256(bytes.fromhex(gpu_nonce)),
        "verified": True,
    }


def verify_receipt_with_trusted_allowlists(
    item: dict[str, Any], args: argparse.Namespace,
    release: dict[str, Any], allowlists: list[tuple[str, Path, dict[str, Any]]],
    verify_external_gpu_evidence: bool,
) -> dict[str, str]:
    """Verify one receipt against the exact retained policy which admitted it."""
    attempted = False
    for digest, path, document in allowlists:
        if not allowlist_matches_target(
            release, document, item["target"], item["workload"], item["identity"]
        ):
            continue
        attempted = True
        try:
            result = verify_receipt(item, args, path)
        except C8sPolicyRejection:
            continue
        gpu_policy = required_gpu_policy(release, item["target"], item["workload"])
        if gpu_policy is not None and verify_external_gpu_evidence:
            result["gpu"] = verify_gpu_receipt(
                item, gpu_policy, item["receipt"],
                result["reportDataHex"], args, path,
            )
        result["allowlistSha256"] = digest
        return result
    if not attempted:
        raise VerificationError(f"no trusted allowlist matches the {item['target']} release workload")
    raise VerificationError(f"no trusted allowlist admitted the {item['target']} receipt")


def verify_front_door(
    response: dict[str, Any], args: argparse.Namespace, leaf_der: bytes,
    release: dict[str, Any],
) -> dict[str, Any] | None:
    """Verify the separate c8s attest-lb bundle for the public front door."""
    if response["tls"]["mode"] == "webpki":
        return None
    front_door = response.get("frontDoor")
    if not isinstance(front_door, dict) or front_door.get("source") != "c8s-tls-lb":
        raise VerificationError("a TEE-held TLS mode requires a c8s TLS-LB front-door bundle")
    receipt = front_door.get("receipt")
    if not isinstance(receipt, dict) or receipt.get("version") != "c8s/attest-lb/v1":
        raise VerificationError("the front-door bundle is not an attest-lb receipt")
    receipt_path: Path | None = None
    leaf_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="c8s-public-front-door-", suffix=".json", mode="w", delete=False
        ) as output:
            os.chmod(output.name, 0o600)
            json.dump(receipt, output, separators=(",", ":"))
            receipt_path = Path(output.name)
        with tempfile.NamedTemporaryFile(
            prefix="c8s-public-serving-leaf-", suffix=".der", mode="wb", delete=False
        ) as output:
            os.chmod(output.name, 0o600)
            output.write(leaf_der)
            leaf_path = Path(output.name)
        command = [
            args.c8s, "verify", "--kind", "workload", "--mode", "attest-lb",
            "--from-file", str(receipt_path), "--attestation-nonce", args.nonce,
            "--observed-serving-cert", str(leaf_path),
            "--image-manifest", str(args.node_manifest),
            "--mesh-ca", str(args.mesh_ca),
            "-o", "json",
        ]
        command[command.index("-o"):command.index("-o")] = policy_verifier_flags(args)
        front_door_workload = release["c8s"].get("frontDoorWorkload")
        if not isinstance(front_door_workload, str) or not front_door_workload:
            raise VerificationError("the release has no front-door workload policy")
        command[command.index("-o"):command.index("-o")] = [
            "--allowlist", str(args.allowlist), "--workload", front_door_workload,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=args.verifier_timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError("the c8s TLS-LB verifier did not run") from error
    finally:
        if receipt_path is not None:
            receipt_path.unlink(missing_ok=True)
        if leaf_path is not None:
            leaf_path.unlink(missing_ok=True)
    if result.returncode != 0:
        raise VerificationError("the c8s TLS-LB verifier rejected the front-door bundle")
    try:
        verdict = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError("the c8s TLS-LB verifier returned invalid JSON") from error
    if verdict.get("tls_binding_verified") is not True:
        raise VerificationError("the c8s TLS-LB verifier did not prove the TLS binding")
    required = {
        "verified": True,
        "backend": "attestation-go",
        "platform": "tdx",
        "measurement_pinned": True,
        "debug": False,
        "fresh": False,
        "workload": front_door_workload,
    }
    for name, expected in required.items():
        if verdict.get(name) != expected:
            raise VerificationError(f"the c8s TLS-LB {name} verdict is invalid")
    if verdict.get("partial") is True or verdict.get("warnings"):
        raise VerificationError("the c8s TLS-LB verdict is partial or has warnings")
    if verdict.get("chain_anchor") != "verified against the pinned --mesh-ca bundle":
        raise VerificationError("the c8s TLS-LB mesh CA is not pinned")
    if not str(verdict.get("binding", "")).startswith("REPORTDATA binds the identity transcript:"):
        raise VerificationError("the c8s TLS-LB report_data binding is invalid")
    if not str(verdict.get("workload_note", "")).startswith("workload_verified:"):
        raise VerificationError("the c8s TLS-LB allowlist identity is not verified")
    pinned = verdict.get("rtmrs_pinned")
    if not isinstance(pinned, list) or {str(value).partition(":")[0] for value in pinned} != {"1", "2", "3"}:
        raise VerificationError("the c8s TLS-LB TDX image tuple is not fully pinned")
    for value in pinned:
        register, _, measurement = str(value).partition(":")
        if register not in {"1", "2", "3"} or not re.fullmatch(r"[0-9a-f]{96}", measurement):
            raise VerificationError("the c8s TLS-LB TDX register pin is invalid")
    if not isinstance(verdict.get("measurement"), str) or not re.fullmatch(
        r"[0-9a-f]{96}", verdict["measurement"]
    ):
        raise VerificationError("the c8s TLS-LB MRTD is not pinned")
    serving_leaf = receipt.get("serving_leaf_sha256")
    if verdict.get("serving_leaf_sha256") != serving_leaf:
        raise VerificationError("the c8s TLS-LB verifier returned a different serving leaf")
    return verdict


def validate_tls_binding(
    response: dict[str, Any], public_leaf_der_sha256: str, public_leaf_der: bytes,
    front_door_verdict: dict[str, Any] | None, require_verdict: bool = True,
) -> bool:
    """Bind the live TLS leaf to the separate c8s attest-lb front-door receipt."""
    if response["tls"]["mode"] == "webpki":
        return False
    front_door = response.get("frontDoor")
    if not isinstance(front_door, dict) or front_door.get("source") != "c8s-tls-lb":
        raise VerificationError("the TEE-held TLS mode has no c8s TLS-LB front door")
    receipt = front_door.get("receipt")
    if not isinstance(receipt, dict):
        raise VerificationError("the TEE-held TLS front-door receipt is missing")
    if receipt.get("version") != "c8s/attest-lb/v1":
        raise VerificationError("a TEE-held TLS mode requires an attest-lb front-door receipt")
    serving_leaf = receipt.get("serving_leaf_sha256")
    if not isinstance(serving_leaf, str) or len(b64url_decode(serving_leaf, "serving leaf")) != 32:
        raise VerificationError("the front-door serving-leaf digest is invalid")
    if public_leaf_der_sha256 != sha256(public_leaf_der):
        raise VerificationError("the observed TLS leaf digest was calculated incorrectly")
    expected = hashlib.sha256(public_leaf_der).digest()
    if b64url_decode(serving_leaf, "serving leaf") != expected:
        raise VerificationError("the front-door receipt is bound to a different TLS leaf")
    if not require_verdict:
        return False
    if front_door_verdict is None or front_door_verdict.get("tls_binding_verified") is not True:
        raise VerificationError("the c8s verifier did not confirm the front-door TLS leaf")
    if front_door_verdict.get("serving_leaf_sha256") != serving_leaf:
        raise VerificationError("the c8s verifier did not confirm the same front-door leaf")
    return True


def verify(args: argparse.Namespace) -> dict[str, Any]:
    if args.timeout_seconds < 1 or args.verifier_timeout_seconds < 1:
        raise VerificationError("the timeout must be positive")
    validate_nonce(args.nonce)
    release_bytes = read_bytes(
        args.trusted_bundle,
        "trusted release bundle",
        MAX_RELEASE_BUNDLE_BYTES,
    )
    release = read_json(
        args.trusted_bundle,
        "trusted release bundle",
        MAX_RELEASE_BUNDLE_BYTES,
    )
    args.policy_mode = release_policy_mode(release)
    manifest = read_json(args.node_manifest, "node manifest")
    source_lock_bytes = read_bytes(args.c8s_source_lock, "c8s source lock")
    source_lock = read_json(args.c8s_source_lock, "c8s source lock")
    node_source_lock_bytes = read_bytes(args.node_source_lock, "node source lock")
    node_source_lock = read_json(args.node_source_lock, "node source lock")
    allowlist_bytes = read_bytes(args.allowlist, "canonical allowlist")
    allowlist = read_json(args.allowlist, "canonical allowlist")
    mesh_ca_bytes = read_bytes(args.mesh_ca, "held mesh CA")
    validate_schema(release, RELEASE_SCHEMA, "release bundle")
    try:
        release_signature = verify_release_signature(
            args.trusted_bundle,
            args.release_signature_bundle,
            args.cosign,
            args.sigstore_timeout_seconds,
        )
    except ReleaseSignatureError as error:
        raise VerificationError(str(error)) from error
    if release_signature["releaseBundleBytesSha256"] != sha256(release_bytes):
        raise VerificationError("the verified signature covers different release bytes")
    release_trust_policy_digest = release_signature["releaseTrustPolicySha256"]
    if release["release"]["environment"] != args.environment:
        raise VerificationError("the release environment differs from the requested environment")
    targets = expected_targets(release, args.expected_target)
    gpu_required = any(
        required_gpu_policy(release, target, workload) is not None
        for target, workload, _ in targets
    )
    source_lock_entry = validate_source_policy(release, manifest, source_lock, node_source_lock)
    selected_gpu_mode = gpu_attestation_mode(source_lock_entry)
    selected_front_door_mode = front_door_verification_mode(source_lock_entry)
    verify_external_gpu_evidence = gpu_required and selected_gpu_mode == "receipt-evidence"
    attestation_protocol = expected_attestation_protocol(source_lock_entry)
    args.attestation_cli_sha256 = ""
    args.gpu_verifier_environment = None
    if verify_external_gpu_evidence:
        if args.attestation_cli is None:
            raise VerificationError(
                "GPU evidence requires --attestation-cli built from the pinned attestation-rs source"
            )
        attestation_cli = args.attestation_cli.resolve()
        if attestation_cli.name != "attestation-cli" or not attestation_cli.is_file():
            raise VerificationError("--attestation-cli must name an attestation-cli file")
        args.attestation_cli_sha256 = hashlib.sha256(attestation_cli.read_bytes()).hexdigest()
        environment = os.environ.copy()
        environment["PATH"] = str(attestation_cli.parent) + os.pathsep + environment.get("PATH", "")
        args.gpu_verifier_environment = environment
    if args.operator_public_key is None:
        raise VerificationError(
            "verification requires --operator-public-key: c8s pins RTMR[3] to "
            "its hash in both policy modes"
        )
    operator_digest: str | None = None
    operator_key_set_digest: str | None = None
    if args.policy_mode == "operator":
        operator_digest = public_key_digest(args.operator_public_key)
        if release["c8s"]["operatorPublicKeySha256"] != operator_digest:
            raise VerificationError("the operator public key differs from the release")
    mesh_ca_der_digest = certificate_digest(mesh_ca_bytes, "held mesh CA")
    mesh_ca_file_digest = sha256(mesh_ca_bytes)
    if args.policy_mode == "operator":
        mesh_ca_digest = release["c8s"]["meshCa"]["certificateSha256"]
        if mesh_ca_digest not in {mesh_ca_der_digest, mesh_ca_file_digest}:
            raise VerificationError("the held mesh CA differs from the release")
    entry_tag = source_lock_entry.get("tag")
    version = verify_c8s_version(
        args.c8s, source_lock_entry["commit"], args.verifier_timeout_seconds,
        tag=entry_tag if isinstance(entry_tag, str) else None,
    )
    allowlist_capabilities = source_lock_entry.get("capabilities")
    canonical_from_c8s = canonicalize_allowlist(
        args.c8s, args.allowlist, args.verifier_timeout_seconds, "canonical allowlist",
        allowlist_capabilities,
    )
    allowlist_digest, canonical_allowlist = validate_allowlist(
        release, allowlist, allowlist_bytes, canonical_from_c8s, targets
    )
    allowlist_documents = trusted_allowlists(
        release, targets, args.allowlist, args.allowlist_history,
        (allowlist_digest, canonical_allowlist), args.c8s, args.verifier_timeout_seconds,
        allowlist_capabilities,
    )
    model_root = validate_model_policy(release)
    release_digest = sha256(release_bytes)
    response, public_spki, public_leaf_der_sha256, public_leaf_der = fetch_response(args)
    validate_schema(response, RESPONSE_SCHEMA, "public attestation response")
    required_c8s_flags: set[str] = set(source_lock_entry.get("requiredVerifierFlags", []))
    if (
        args.policy_mode == "operator"
        and source_lock_entry.get("attestationProtocol") == XWING_ATTESTATION_PROTOCOL
    ):
        # The attested CDS operator-key read needs all four of these.
        required_c8s_flags.update({"--kind", "--mode", "--image-manifest", "--operator-keys"})
    if args.policy_mode == "static":
        required_c8s_flags.add("--static-allowlist")
    if (
        selected_front_door_mode == "c8s-cli"
        and response.get("tls", {}).get("mode") in {"tee-webpki", "cds", "acme"}
    ):
        required_c8s_flags.update({
            "--mode", "attest-lb", "--attestation-nonce", "--observed-serving-cert",
        })
    for item in response.get("receipts", []):
        if (
            verify_external_gpu_evidence
            and required_gpu_policy(release, item["target"], item["workload"]) is not None
        ):
            required_c8s_flags.update({
                "--nvidia-gpu-user-nonce", "--nvidia-gpu-required",
                "--nvidia-gpu-expected-arch", "--attestation-cli-sha256",
            })
    require_c8s_capabilities(args.c8s, required_c8s_flags, args.verifier_timeout_seconds)
    if response["nonce"] != args.nonce:
        raise VerificationError("the public response nonce differs from the request")
    actual = tuple(
        (item["target"], item["workload"], item["identity"])
        for item in response["receipts"]
    )
    if actual != targets:
        raise VerificationError("the public receipt set differs from the requested environment")
    if args.policy_mode == "operator":
        assert args.operator_public_key is not None
        _, operator_key_set_digest, operator_key_set_members = operator_key_set_from_path(
            args.operator_public_key
        )
        expected_key_set_digest = release["c8s"].get("operatorKeySetSha256")
        if expected_key_set_digest != operator_key_set_digest:
            raise VerificationError("the release operator key-set commitment differs from the held key")
        if operator_digest not in operator_key_set_members:
            raise VerificationError("the held operator key is not a member of the expected key set")
    # On the new protocol the gateway publishes only its pinned key-set
    # expectation, so the verifier must read the live key set for itself over
    # an attested CDS session. Without --cds-url there is nothing to compare
    # the pin against, and the run fails closed rather than skipping the check.
    attested_key_set: tuple[str, set[str], str] | None = None
    if args.policy_mode == "operator" and attestation_protocol == XWING_ATTESTATION_PROTOCOL:
        if args.cds_url is None:
            raise VerificationError(
                "this release speaks " + XWING_ATTESTATION_PROTOCOL + ", on which the gateway "
                "cannot read the c8s operator key set (CDS serves GET /operator-keys over "
                "RA-TLS behind a self-signed certificate). Pass --cds-url with the CDS RA-TLS "
                "base URL reachable to this verifier, so the operator key set is read here "
                "over an attested session and compared with the pinned key-set commitment"
            )
        args.cds_url = validate_cds_url(args.cds_url)
        attested_key_set = read_attested_operator_key_set(args)
    validate_response_evidence(
        response, release, release_digest, allowlist, canonical_allowlist,
        operator_digest, operator_key_set_digest, mesh_ca_der_digest,
        attestation_protocol, gpu_required, attested_key_set, selected_gpu_mode,
    )
    for item in response["receipts"]:
        if item["admittedLaunch"] != expected_admitted_launch(allowlist, item["workload"]):
            raise VerificationError(f"the {item['target']} admitted launch differs from the active allowlist")
    with tempfile.TemporaryDirectory(prefix="c8s-public-trust-") as temporary:
        trust_root = Path(temporary)
        materialized_allowlists = []
        for digest, content, document in allowlist_documents:
            path = trust_root / f"allowlist-{digest[7:]}.json"
            path.write_bytes(content)
            path.chmod(0o600)
            materialized_allowlists.append((digest, path, document))
        original_operator_path = args.operator_public_key
        assert original_operator_path is not None
        canonical_operator_path = trust_root / "operator-public.pem"
        canonical_operator_path.write_bytes(canonical_public_key(original_operator_path))
        canonical_operator_path.chmod(0o600)
        args.operator_public_key = canonical_operator_path
        try:
            receipts = [
                verify_receipt_with_trusted_allowlists(
                    item, args, release, materialized_allowlists,
                    verify_external_gpu_evidence,
                ) for item in response["receipts"]
            ]
        finally:
            args.operator_public_key = original_operator_path
    front_door_verdict = (
        verify_front_door(response, args, public_leaf_der, release)
        if selected_front_door_mode == "c8s-cli"
        else None
    )
    public_tls_attested = validate_tls_binding(
        response, public_leaf_der_sha256, public_leaf_der, front_door_verdict,
        require_verdict=selected_front_door_mode == "c8s-cli",
    )
    gpu_targets = [
        item["target"] for item in response["receipts"]
        if required_gpu_policy(release, item["target"], item["workload"]) is not None
    ]
    return {
        "schema": "confidential-inference.public-attestation-verification/v1",
        "verified": True,
        "verifiedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scope": "launch-or-admission-only",
        "operationalStatus": "not-verified",
        "environment": args.environment,
        "endpoint": urlsplit(args.endpoint)._replace(query="", fragment="").geturl(),
        "nonceSha256": sha256(b64url_decode(args.nonce, "nonce")),
        "releaseBundleBytesSha256": release_digest,
        "releaseTrustPolicySha256": release_trust_policy_digest,
        "releaseSignatureVerified": True,
        "releaseSignatureBundleBytesSha256": release_signature[
            "signatureBundleBytesSha256"
        ],
        "releaseSigner": {
            "certificateIdentity": release_signature["certificateIdentity"],
            "certificateOidcIssuer": release_signature["certificateOidcIssuer"],
            "githubWorkflowRepository": release_signature["githubWorkflowRepository"],
            "githubWorkflowRef": release_signature["githubWorkflowRef"],
            "githubWorkflowName": release_signature["githubWorkflowName"],
            "githubWorkflowTrigger": release_signature["githubWorkflowTrigger"],
            "transparencyLogEntries": release_signature["transparencyLogEntries"],
        },
        "sourceLockSha256": sha256(source_lock_bytes),
        "nodeSourceLockSha256": sha256(node_source_lock_bytes),
        "nodeManifestSha256": sha256(read_bytes(args.node_manifest, "node manifest")),
        "policyMode": args.policy_mode,
        "operatorPublicKeySha256": operator_digest,
        "operatorKeySetSha256": operator_key_set_digest,
        "activeOperatorKeySetVerified": args.policy_mode == "operator",
        "operatorKeySetSource": (
            "attested-cds-read" if attested_key_set is not None else "response-reported"
        ),
        "attestedCdsLaunchMeasurement": (
            attested_key_set[2] if attested_key_set is not None else None
        ),
        "meshCaSha256": mesh_ca_der_digest,
        "currentAllowlistSha256": allowlist_digest,
        "allowlistCanonicalizationMethods": sorted(CANONICALIZATION_METHODS_USED),
        "trustedAllowlistSha256s": [item[0] for item in allowlist_documents],
        "publicTlsSpkiSha256": public_spki,
        "publicTlsKeyAttested": public_tls_attested,
        "frontDoorVerification": selected_front_door_mode,
        "attestationProtocol": attestation_protocol,
        "gpuAttestationMode": selected_gpu_mode if gpu_targets else "not-required",
        # In receipt-evidence mode, each required GPU target passed the raw
        # NVIDIA evidence verifier above. In measured-boot-gate mode, the
        # verified node image enforces GPU checks before RKE2 can start.
        "gpuEvidenceVerified": verify_external_gpu_evidence
        and bool(gpu_targets)
        and all(
            "gpu" in item for item in receipts
            if item["target"] in gpu_targets
        ),
        "gpuBootGateEnforcedByMeasuredImage": bool(gpu_targets)
        and selected_gpu_mode == "measured-boot-gate",
        "modelDmVerityRootPolicy": model_root,
        "c8sVerifierVersion": version,
        "intelCollateralVerifiedBy": "c8s attestation-go",
        "receipts": receipts,
        "limits": [
            "This receipt proves launch or admission facts.",
            "This receipt does not prove current workload liveness.",
            "The model root is a release policy check, not proof of current model use.",
            (
                (
                    "The active operator key set was read from CDS over an attested session "
                    "and checked against the release key-set commitment and held key."
                    if attested_key_set is not None
                    else "The active operator key set is checked against the release key-set commitment and held key."
                )
                if args.policy_mode == "operator"
                else "The c8s verifier checks the sealed allowlist digest in the attested mesh CA."
            ),
            (
                "The measured c8s node image verifies each passed-through GPU before RKE2 starts; raw NVIDIA evidence is not exposed externally."
                if selected_gpu_mode == "measured-boot-gate"
                else "Raw NVIDIA worker evidence is exposed, but cryptographic GPU verification requires the c8s GPU verifier."
            ),
        ],
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Fetch and verify the public v0 TDX receipt set. This command does not verify liveness."
    )
    result.add_argument("--endpoint", required=True)
    result.add_argument("--nonce", required=True)
    result.add_argument("--trusted-bundle", required=True, type=Path)
    result.add_argument("--release-signature-bundle", required=True, type=Path)
    result.add_argument("--cosign", required=True, type=Path)
    result.add_argument("--node-manifest", required=True, type=Path)
    result.add_argument("--node-source-lock", required=True, type=Path)
    result.add_argument(
        "--c8s-source-lock", type=Path,
        default=ROOT / "contracts/c8s-admission-source-lock.json",
    )
    result.add_argument("--allowlist", required=True, type=Path)
    result.add_argument("--allowlist-history", type=Path)
    result.add_argument(
        "--operator-public-key", type=Path,
        help=(
            "the operator public key whose hash the node measured into RTMR3 "
            "at launch; required in both policy modes"
        ),
    )
    result.add_argument("--mesh-ca", required=True, type=Path)
    result.add_argument("--environment", required=True)
    result.add_argument(
        "--expected-target", action="append", default=[], metavar="TARGET=WORKLOAD",
        help="bind a legacy release bundle to one expected receipt target",
    )
    result.add_argument("--c8s", required=True)
    result.add_argument(
        "--attestation-cli",
        type=Path,
        help=(
            "attestation-cli built from the attestation-rs commit pinned by c8s; "
            "required only for source-lock entries that use receipt-evidence GPU attestation"
        ),
    )
    result.add_argument(
        "--cds-url",
        help=(
            "CDS RA-TLS base URL reachable to this verifier (for example "
            "https://127.0.0.1:30808). Required on " + XWING_ATTESTATION_PROTOCOL + ": "
            "the operator key set is read from " + CDS_OPERATOR_KEY_SET_ROUTE + " over an "
            "attested session with the pinned c8s CLI"
        ),
    )
    result.add_argument("--endpoint-ca", type=Path)
    result.add_argument(
        "--connect-address",
        help="Connect to this exact IP while keeping the endpoint hostname for TLS",
    )
    result.add_argument("--timeout-seconds", type=int, default=30)
    result.add_argument("--verifier-timeout-seconds", type=int, default=60)
    result.add_argument("--sigstore-timeout-seconds", type=int, default=60)
    result.add_argument("--maximum-response-bytes", type=int, default=MAX_RESPONSE_BYTES)
    return result


def main() -> int:
    try:
        output = verify(parser().parse_args())
    except (VerificationError, OSError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
