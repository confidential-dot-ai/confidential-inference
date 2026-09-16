#!/usr/bin/env python3
"""Verify admission certificates that a receipt directory holds.

The receipt directory holds certificates collected earlier from a live
cluster, for a fixed set of four workloads. This script calls the real c8s
binary once for each workload. It has no nonce and no freshness check, and it
makes no liveness claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


WORKLOADS = (
    "gateway",
    "sglang-router",
    "inference-worker-0",
    "inference-worker-1",
)
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class VerificationError(ValueError):
    """The receipt or policy does not satisfy the release."""


def read_bytes(path: Path, label: str) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise VerificationError(f"the {label} must be a regular file")
    try:
        return path.read_bytes()
    except OSError as error:
        raise VerificationError(f"cannot read the {label}") from error


def read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(read_bytes(path, label))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"the {label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise VerificationError(f"the {label} must contain one JSON object")
    return value


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise VerificationError(f"the {label} fields are invalid")


def verify_index(receipt_dir: Path) -> tuple[dict[str, Path], str]:
    index = read_json(receipt_dir / "index.json", "receipt index")
    exact_keys(
        index,
        {"schema", "scope", "operationalStatus", "context", "namespace", "meshCa", "receipts"},
        "receipt index",
    )
    if index["schema"] != "confidential-inference.c8s-admission-receipts/v1":
        raise VerificationError("the receipt schema is invalid")
    if index["scope"] != "launch-or-admission-only" or index["operationalStatus"] != "not-verified":
        raise VerificationError("the receipt scope makes an unsupported claim")
    if not isinstance(index["context"], str) or not index["context"]:
        raise VerificationError("the receipt context is invalid")
    if not isinstance(index["namespace"], str) or not index["namespace"]:
        raise VerificationError("the receipt namespace is invalid")

    mesh = index["meshCa"]
    if not isinstance(mesh, dict):
        raise VerificationError("the collected mesh CA record is invalid")
    exact_keys(mesh, {"file", "sha256"}, "collected mesh CA")
    if mesh["file"] != "collected-mesh-ca.pem" or not DIGEST_RE.fullmatch(mesh.get("sha256", "")):
        raise VerificationError("the collected mesh CA record is invalid")
    collected_ca = read_bytes(receipt_dir / mesh["file"], "collected mesh CA")
    if sha256(collected_ca) != mesh["sha256"]:
        raise VerificationError("the collected mesh CA hash is wrong")

    receipts = index["receipts"]
    if not isinstance(receipts, list) or len(receipts) != len(WORKLOADS):
        raise VerificationError("the receipt index must contain four receipts")
    paths: dict[str, Path] = {}
    for receipt in receipts:
        if not isinstance(receipt, dict):
            raise VerificationError("a receipt index entry is invalid")
        exact_keys(receipt, {"workload", "pod", "file", "sha256"}, "receipt entry")
        workload = receipt.get("workload")
        if workload not in WORKLOADS or workload in paths:
            raise VerificationError("the receipt names are wrong or duplicated")
        expected_file = f"{workload}.cert.pem"
        if receipt.get("file") != expected_file:
            raise VerificationError(f"the {workload} receipt filename is invalid")
        if not isinstance(receipt.get("pod"), str) or not receipt["pod"]:
            raise VerificationError(f"the {workload} pod name is invalid")
        path = receipt_dir / expected_file
        certificate = read_bytes(path, f"{workload} certificate")
        if sha256(certificate) != receipt.get("sha256"):
            raise VerificationError(f"the {workload} certificate hash is wrong")
        paths[workload] = path
    if set(paths) != set(WORKLOADS):
        raise VerificationError("one or more workload receipts are missing")
    return paths, mesh["sha256"]


def validate_argv_policy(policy: Any, label: str, allow_empty: bool) -> list[str]:
    if not isinstance(policy, dict) or set(policy) - {"policy", "argv"}:
        raise VerificationError(f"the {label} policy is invalid")
    kind = policy.get("policy")
    argv = policy.get("argv", [])
    if not isinstance(argv, list) or any(not isinstance(item, str) or not item for item in argv):
        raise VerificationError(f"the {label} argv is invalid")
    if kind == "exact" and argv:
        return argv
    if allow_empty and kind == "deny" and not argv:
        return []
    raise VerificationError(f"the {label} policy does not pin an exact argv")


def validate_allowlist_and_release(
    allowlist_path: Path, release_path: Path
) -> tuple[dict[str, Any], str, str]:
    allowlist_bytes = read_bytes(allowlist_path, "c8s allowlist")
    allowlist = read_json(allowlist_path, "c8s allowlist")
    release_bytes = read_bytes(release_path, "release bundle")
    release = read_json(release_path, "release bundle")
    exact_keys(allowlist, {"schema", "digests", "workloads"}, "c8s allowlist")
    if allowlist["schema"] != "c8s.allowlist/v1":
        raise VerificationError("the c8s allowlist schema is invalid")
    if not isinstance(allowlist["digests"], dict) or not isinstance(allowlist["workloads"], dict):
        raise VerificationError("the c8s allowlist structure is invalid")
    allowlist_digest = sha256(allowlist_bytes)
    if release.get("allowlistDigest") != allowlist_digest:
        raise VerificationError("the c8s allowlist hash does not match the release bundle")

    releases = release.get("workloads")
    if not isinstance(releases, list):
        raise VerificationError("the release workload list is invalid")
    for workload in WORKLOADS:
        release_matches = [item for item in releases if isinstance(item, dict) and item.get("name") == workload]
        if len(release_matches) != 1:
            raise VerificationError(f"the release must contain one {workload} workload")
        release_workload = release_matches[0]
        policy_workload = allowlist["workloads"].get(workload)
        if not isinstance(policy_workload, dict):
            raise VerificationError(f"the c8s allowlist omits the {workload} workload")
        if set(policy_workload) - {"label", "initContainers", "containers", "secrets"}:
            raise VerificationError(f"the {workload} allowlist fields are invalid")
        if policy_workload.get("initContainers") != []:
            raise VerificationError(f"the {workload} must have no init containers")
        containers = policy_workload.get("containers")
        if not isinstance(containers, list) or len(containers) != 1:
            raise VerificationError(f"the {workload} must have one main container")
        container = containers[0]
        if not isinstance(container, dict) or set(container) - {
            "digest",
            "image",
            "command",
            "args",
            "mounts",
            "env",
        }:
            raise VerificationError(f"the {workload} container policy is invalid")
        image = release_workload.get("image")
        if not isinstance(image, dict) or container.get("digest") != image.get("digest"):
            raise VerificationError(f"the {workload} image digest does not match the release")
        command = validate_argv_policy(container.get("command"), f"{workload} command", False)
        arguments = validate_argv_policy(container.get("args"), f"{workload} arguments", True)
        if command + arguments != release_workload.get("argv"):
            raise VerificationError(f"the {workload} argv does not match the release")
    return release, allowlist_digest, sha256(release_bytes)


def run_c8s(args: argparse.Namespace, certificate: Path, workload: str) -> dict[str, Any]:
    command = [
        args.c8s,
        "verify",
        "--from-file",
        str(certificate),
        "--kind",
        "workload",
        "--image-manifest",
        str(args.image_manifest),
        "--operator-pkey",
        str(args.operator_public_key),
        "--mesh-ca",
        str(args.mesh_ca),
        "--allowlist",
        str(args.allowlist),
        "--workload",
        workload,
        "-o",
        "json",
    ]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError as error:
        raise VerificationError("the c8s verifier did not run") from error
    if result.returncode:
        raise VerificationError(f"c8s rejected the {workload} certificate")
    try:
        verdict = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError(f"c8s returned invalid JSON for {workload}") from error
    if not isinstance(verdict, dict) or verdict.get("verified") is not True:
        raise VerificationError(f"c8s did not verify the {workload} certificate")
    if verdict.get("fresh") is not False:
        raise VerificationError(f"c8s made an unsupported freshness claim for {workload}")
    if verdict.get("measurement_pinned") is not True:
        raise VerificationError(f"c8s did not pin the measurement for {workload}")
    if verdict.get("platform") != "tdx":
        raise VerificationError(f"c8s did not verify TDX for {workload}")
    workload_note = verdict.get("workload_note")
    if not isinstance(workload_note, str) or not workload_note.startswith(
        "workload_verified:"
    ):
        raise VerificationError(f"c8s did not verify the workload policy for {workload}")
    pinned_rtmrs = verdict.get("rtmrs_pinned")
    if not isinstance(pinned_rtmrs, list) or {
        item.partition(":")[0] for item in pinned_rtmrs if isinstance(item, str)
    } != {"1", "2", "3"}:
        raise VerificationError(f"c8s did not pin RTMR 1, 2, and 3 for {workload}")
    reported = verdict.get("workload")
    if reported != workload:
        raise VerificationError(f"c8s returned the wrong workload for {workload}")
    return verdict


def verify(args: argparse.Namespace) -> dict[str, Any]:
    receipt_dir = args.receipt_dir.resolve(strict=True)
    if not receipt_dir.is_dir():
        raise VerificationError("the receipt directory is invalid")
    required = {
        "mesh CA": args.mesh_ca,
        "image manifest": args.image_manifest,
        "operator public key": args.operator_public_key,
        "c8s allowlist": args.allowlist,
        "release bundle": args.release_bundle,
    }
    material = {name: read_bytes(path, name) for name, path in required.items()}
    independent_ca = args.mesh_ca.resolve()
    collected_ca = (receipt_dir / "collected-mesh-ca.pem").resolve()
    if independent_ca.is_relative_to(receipt_dir) or os.path.samefile(independent_ca, collected_ca):
        raise VerificationError("the verifier needs an independent mesh CA file")

    receipts, collected_ca_digest = verify_index(receipt_dir)
    if sha256(material["mesh CA"]) != collected_ca_digest:
        raise VerificationError("the independent mesh CA does not match the collected mesh CA")
    _, allowlist_digest, release_digest = validate_allowlist_and_release(
        args.allowlist, args.release_bundle
    )
    if not DIGEST_RE.fullmatch(args.release_bundle_digest):
        raise VerificationError("the expected release bundle digest is invalid")
    if release_digest != args.release_bundle_digest:
        raise VerificationError("the release bundle bytes do not match the expected digest")
    verified: list[dict[str, str]] = []
    for workload in WORKLOADS:
        run_c8s(args, receipts[workload], workload)
        verified.append(
            {
                "workload": workload,
                "certificateSha256": sha256(read_bytes(receipts[workload], f"{workload} certificate")),
            }
        )
    return {
        "verified": True,
        "scope": "launch-or-admission-only",
        "operationalStatus": "not-verified",
        "allowlistSha256": allowlist_digest,
        "releaseBundleSha256": release_digest,
        "imageManifestSha256": sha256(material["image manifest"]),
        "operatorPublicKeySha256": sha256(material["operator public key"]),
        "meshCaSha256": sha256(material["mesh CA"]),
        "receipts": verified,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Verify certificates collected earlier from a cluster into a receipt "
            "directory. This check has no nonce and makes no liveness claim."
        )
    )
    result.add_argument("--receipt-dir", required=True, type=Path)
    result.add_argument("--mesh-ca", required=True, type=Path)
    result.add_argument("--c8s", required=True)
    result.add_argument("--image-manifest", required=True, type=Path)
    result.add_argument("--operator-public-key", required=True, type=Path)
    result.add_argument("--allowlist", required=True, type=Path)
    result.add_argument("--release-bundle", required=True, type=Path)
    result.add_argument("--release-bundle-digest", required=True)
    return result


def main() -> int:
    try:
        result = verify(parser().parse_args())
    except (VerificationError, OSError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
