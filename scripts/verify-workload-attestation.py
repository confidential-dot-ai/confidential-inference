#!/usr/bin/env python3
"""Verify one already-fetched gateway attestation response.

This script checks the response against a fresh nonce and against the target
list from the release bundle. It sends each embedded receipt to an external
receipt-verifier command for the cryptographic check. It makes no liveness
claim.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import jsonschema
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts/workload-attestation.schema.json"
RELEASE_SCHEMA = ROOT / "contracts/release-bundle.schema.json"
class VerificationError(ValueError):
    """The response does not satisfy the expected policy."""


def operator_key_set_members(pem: str) -> set[str]:
    blocks = []
    marker = b"-----BEGIN PUBLIC KEY-----"
    end = b"-----END PUBLIC KEY-----"
    raw = pem.encode("ascii")
    cursor = 0
    while True:
        start = raw.find(marker, cursor)
        if start < 0:
            break
        finish = raw.find(end, start + len(marker))
        if finish < 0:
            raise VerificationError("the active operator key set PEM is malformed")
        encoded = b"".join(raw[start + len(marker):finish].split())
        try:
            der = base64.b64decode(encoded, validate=True)
            key = serialization.load_der_public_key(der)
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise ValueError("operator key is not EC")
            der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        except (UnicodeError, TypeError, ValueError) as error:
            raise VerificationError("the active operator key set contains an invalid key") from error
        blocks.append(der)
        cursor = finish + len(end)
    if not blocks:
        raise VerificationError("the active operator key set is empty")
    return {
        "sha256:" + hashlib.sha256(block).hexdigest()
        for block in blocks
    }


def operator_key_set_digest(pem: str) -> str:
    members = operator_key_set_members(pem)
    fingerprints = sorted(bytes.fromhex(value.removeprefix("sha256:")) for value in members)
    return "sha256:" + hashlib.sha256(
        b"c8s-operator-key-set-v1\0" + b"".join(fingerprints)
    ).hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read valid JSON from {path}") from error


def validate_schema(value: Any, schema_path: Path, label: str) -> None:
    try:
        jsonschema.Draft202012Validator(load_json(schema_path)).validate(value)
    except jsonschema.ValidationError as error:
        raise VerificationError(f"the {label} schema is invalid: {error.message}") from error


def run_receipt_verifier(
    item: dict[str, Any], args: argparse.Namespace
) -> dict[str, Any]:
    receipt_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="c8s-workload-receipt-", suffix=".json", delete=False, mode="w"
        ) as output:
            os.chmod(output.name, 0o600)
            json.dump(item["receipt"], output, separators=(",", ":"))
            receipt_path = Path(output.name)
        command = [
            args.receipt_verifier,
            *args.receipt_verifier_arg,
            "--receipt",
            str(receipt_path),
            "--workload",
            item["workload"],
            "--nonce",
            args.nonce,
            "--release-bundle",
            str(args.release_bundle),
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=args.receipt_verifier_timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError("the standard c8s receipt verifier did not run") from error
        if result.returncode != 0:
            raise VerificationError(f"c8s rejected the {item['workload']} receipt")
        try:
            verdict = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise VerificationError("the c8s receipt verifier returned invalid JSON") from error
    finally:
        if receipt_path is not None:
            receipt_path.unlink(missing_ok=True)

    expected = {
        "verified": True,
        "scope": "launch-or-admission-only",
        "workload": item["workload"],
        "nonce": args.nonce,
        "platform": "tdx",
        "measurementPinned": True,
        "workloadMatched": True,
        "allowlistDigest": args.allowlist_digest,
    }
    if verdict != expected:
        raise VerificationError(f"the {item['workload']} c8s verdict is not exact")
    return verdict


def verify(args: argparse.Namespace) -> dict[str, Any]:
    if args.receipt_verifier_timeout < 1:
        raise VerificationError("the receipt verifier timeout is invalid")
    response = load_json(args.attestation)
    release = load_json(args.release_bundle)
    validate_schema(response, SCHEMA, "workload attestation")
    validate_schema(release, RELEASE_SCHEMA, "release bundle")
    if response["nonce"] != args.nonce:
        raise VerificationError("the response nonce does not match")
    try:
        actual_release_digest = "sha256:" + hashlib.sha256(
            args.release_bundle.read_bytes()
        ).hexdigest()
    except OSError as error:
        raise VerificationError("the release bundle bytes are unavailable") from error
    if actual_release_digest != args.release_bundle_digest:
        raise VerificationError("the release bundle bytes do not match their digest")
    if response["release"] != {
        "id": release["release"]["name"],
        "bundleSha256": actual_release_digest,
        "source": "operator-selected-public-release",
    }:
        raise VerificationError("the response release identity does not match")
    if release["allowlistDigest"] != args.allowlist_digest:
        raise VerificationError("the release allowlist digest does not match")
    if response["c8s"]["activeAllowlist"]["sha256"] != args.allowlist_digest:
        raise VerificationError("the response active allowlist digest does not match")
    if (
        response["c8s"]["operatorTrust"]["expectedPublicKeySpkiSha256"]
        != release["c8s"]["operatorPublicKeySha256"]
    ):
        raise VerificationError("the response operator fingerprint does not match")
    expected_key_set = release["c8s"].get("operatorKeySetSha256")
    operator = response["c8s"]["operatorTrust"]
    if not isinstance(expected_key_set, str) or operator.get("expectedKeySetSha256") != expected_key_set:
        raise VerificationError("the release does not pin the operator key set")
    # c8s binds the allowlist-write operator key set to no hardware evidence
    # at either attestation protocol, so requires-attested-cds-read (an
    # attested CDS read, not a launch-time proof) is also acceptable here.
    # Either way the digest itself must still match the release exactly.
    if (
        operator.get("activeKeySetStatus")
        not in ("evidence-present-and-release-matched", "requires-attested-cds-read")
        or operator.get("activeKeySetSha256") != expected_key_set
        or operator_key_set_digest(operator.get("activeKeySetPem", "")) != expected_key_set
    ):
        raise VerificationError("the active operator key set does not match the release")
    if operator["expectedPublicKeySpkiSha256"] not in operator_key_set_members(
        operator.get("activeKeySetPem", "")
    ):
        raise VerificationError("the expected operator key is not in the active key set")

    release_targets = release["c8s"].get("attestationTargets")
    if release_targets is not None:
        try:
            expected_pairs = tuple(
                (
                    item["target"], item["workload"],
                    item.get("identity", item["workload"])
                    if release.get("schemaVersion") == 1 else item["identity"],
                )
                for item in release_targets
            )
        except (KeyError, TypeError) as error:
            raise VerificationError("a release attestation target lacks its stable identity") from error
    else:
        legacy_pairs = tuple(tuple(value.split("=", 1)) for value in args.expected_target)
        if not legacy_pairs or any(len(pair) != 2 for pair in legacy_pairs):
            raise VerificationError("the legacy release needs explicit expected targets")
        # The v1 contract used one exact name for both fields.
        expected_pairs = tuple((target, workload, workload) for target, workload in legacy_pairs)
    actual_pairs = tuple(
        (item["target"], item["workload"], item["identity"])
        for item in response["receipts"]
    )
    if any(workload != identity for _, workload, identity in expected_pairs):
        raise VerificationError("a receipt identity is not its exact c8s workload name")
    if actual_pairs != expected_pairs:
        raise VerificationError("the receipt target set differs from the release bundle")
    targets = tuple(target for target, _, _ in actual_pairs)
    names = tuple(workload for _, workload, _ in actual_pairs)
    identities = tuple(identity for _, _, identity in actual_pairs)
    release_names = {item["name"] for item in release["workloads"]}
    required_release_names = set(names)
    if not required_release_names.issubset(release_names):
        raise VerificationError("the release bundle omits a required workload")
    for item in response["receipts"]:
        if item["receipt"]["nonce"] != args.nonce:
            raise VerificationError(f"the {item['workload']} receipt nonce does not match")
        run_receipt_verifier(item, args)

    return {
        "verified": True,
        "scope": "launch-or-admission-only",
        "targets": list(targets),
        "workloads": list(names),
        "identities": list(identities),
        "operationalStatus": "not-verified",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Verify one live gateway attestation response against a nonce and "
            "the release bundle's target list. This check makes no liveness claim."
        )
    )
    result.add_argument("--attestation", required=True, type=Path)
    result.add_argument("--release-bundle", required=True, type=Path)
    result.add_argument("--release-bundle-digest", required=True)
    result.add_argument("--allowlist-digest", required=True)
    result.add_argument("--nonce", required=True)
    result.add_argument("--receipt-verifier", required=True)
    result.add_argument("--receipt-verifier-arg", action="append", default=[])
    result.add_argument("--receipt-verifier-timeout", type=int, default=30)
    result.add_argument(
        "--expected-target", action="append", default=[], metavar="TARGET=WORKLOAD",
        help="bind a legacy release bundle to one expected receipt target",
    )
    return result


def main() -> int:
    try:
        output = verify(parser().parse_args())
    except VerificationError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
