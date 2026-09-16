from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts/verify-workload-attestation.py"
RELEASE_SOURCE = ROOT / "tests/contracts/fixtures/release-bundle.valid.json"
PRODUCTION_TARGETS = (
    "gateway",
    "sglang-router",
    "inference-worker-0",
    "inference-worker-1",
    "metrics-collector",
    "kube-state-metrics",
)
PRODUCTION_WORKLOADS = (
    "gateway",
    "sglang-router",
    "inference-worker-0",
    "inference-worker-1",
    "metrics-collector",
    "kube-state-metrics",
)
STAGING_TARGETS = (
    "gateway",
    "sglang-router",
    "inference-worker-0",
    "inference-worker-1",
)
STAGING_WORKLOADS = (
    "gateway",
    "sglang-router",
    "inference-worker-0",
    "inference-worker-1",
)


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class GatewayAggregatorVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.release = self.directory / "release.json"
        release = json.loads(RELEASE_SOURCE.read_text())
        release["workloads"].append(
            {
                "name": "kube-state-metrics",
                "image": {
                    "reference": "registry.k8s.io/kube-state-metrics/kube-state-metrics",
                    "digest": "sha256:" + "c" * 64,
                },
                "argv": ["/kube-state-metrics"],
            }
        )
        release["c8s"]["attestationTargets"] = [
            {"target": target, "workload": workload, "identity": workload}
            for target, workload in zip(
                PRODUCTION_TARGETS, PRODUCTION_WORKLOADS, strict=True
            )
        ]
        self.release.write_text(json.dumps(release), encoding="utf-8")
        self.release_digest = "sha256:" + hashlib.sha256(self.release.read_bytes()).hexdigest()
        self.allowlist_digest = json.loads(self.release.read_text())["allowlistDigest"]
        self.nonce = b64(bytes(range(32)))
        self.attestation = self.directory / "attestation.json"
        self.write_attestation(self.valid_attestation())
        self.fake = self.directory / "fake-c8s-verifier"
        self.fake.write_text(
            """#!/usr/bin/env python3
import json
import sys
args = sys.argv[1:]
def value(flag):
    return args[args.index(flag) + 1]
print(json.dumps({
    "verified": True,
    "scope": "launch-or-admission-only",
    "workload": value("--workload"),
    "nonce": value("--nonce"),
    "platform": "tdx",
    "measurementPinned": True,
    "workloadMatched": True,
    "allowlistDigest": "sha256:" + "7" * 64,
}))
""",
            encoding="utf-8",
        )
        self.fake.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def valid_attestation(
        self,
        targets: tuple[str, ...] = PRODUCTION_TARGETS,
        workloads: tuple[str, ...] = PRODUCTION_WORKLOADS,
    ) -> dict:
        receipt = {
            "version": "c8s/attest-pq/v1",
            "platform": "tdx",
            "generation": "",
            "nonce": self.nonce,
            "evidence": {"quote": "standard-c8s-evidence"},
            "cds_cert_pem": "-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAg==\n-----END CERTIFICATE-----\n",
            "session_pubkey": {"x25519": b64(b"x" * 32), "mlkem768": b64(b"m" * 1184)},
            "identity_proof": {
                "algorithm": "ecdsa-sha384",
                "leaf_sha256": b64(b"l" * 32),
                "mesh_ca_sha256": b64(b"c" * 32),
                "signature": b64(b"s" * 64),
            },
        }
        release = json.loads(self.release.read_text())
        releases_by_name = {item["name"]: item for item in release["workloads"]}
        return {
            "schemaVersion": 2,
            "scope": "launch-or-admission-only",
            "nonce": self.nonce,
            "operationalStatus": "not-verified",
            "release": {
                "id": release["release"]["name"],
                "bundleSha256": self.release_digest,
                "source": "operator-selected-public-release",
            },
            "c8s": {
                "discovery": {
                    "version": "v1",
                    "generated_at": "2026-09-01T00:00:00Z",
                    "public_tls": {"hostname": "api.example.test", "mode": "webpki"},
                    "cds_tls": {
                        "certificate_pem": "certificate",
                        "certificate_sha256": "sha256:" + "1" * 64,
                    },
                    "attestation": {"platform": "tdx", "evidence": {"quote": "test"}},
                },
                "activeAllowlist": {
                    "sha256": self.allowlist_digest,
                    "document": {"schema": "c8s.allowlist/v1", "digests": {}, "workloads": {}},
                },
                "operatorTrust": {
                    "expectedPublicKeySpkiSha256": release["c8s"]["operatorPublicKeySha256"],
                    "expectedKeySetSha256": release["c8s"]["operatorKeySetSha256"],
                    "activeKeySetStatus": "evidence-present-and-release-matched",
                    "activeKeySetSha256": release["c8s"]["operatorKeySetSha256"],
                    "activeKeySetPem": (ROOT / "releases/production/trust/operator-public-key.pem").read_text(),
                    "reason": "c8s operator-keys matched the release commitment",
                },
                "meshCaSha256": release["c8s"]["meshCa"]["certificateSha256"],
            },
            "tls": {
                "mode": "webpki",
                "binding": {
                    "status": "not-proven",
                    "publicKeySha256": None,
                    "reason": "not bound",
                },
            },
            "frontDoor": None,
            "gpuEvidence": {
                "status": "raw-receipt-evidence",
                "evidence": [],
                "reason": "not exposed",
            },
            "receipts": [
                {
                    "target": target,
                    "workload": workload,
                    "identity": workload,
                    "admittedLaunch": {
                        "policyName": workload,
                        "initContainers": [],
                        "containers": [{
                            "image": releases_by_name[workload]["image"]["reference"]
                            + "@" + releases_by_name[workload]["image"]["digest"],
                            "digest": releases_by_name[workload]["image"]["digest"],
                            "argv": releases_by_name[workload]["argv"],
                        }],
                    },
                    "receipt": copy.deepcopy(receipt),
                }
                for target, workload in zip(targets, workloads, strict=True)
            ],
        }

    def write_attestation(self, value: dict) -> None:
        self.attestation.write_text(json.dumps(value), encoding="utf-8")

    def verify(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(VERIFIER),
                "--attestation",
                str(self.attestation),
                "--release-bundle",
                str(self.release),
                "--release-bundle-digest",
                self.release_digest,
                "--allowlist-digest",
                self.allowlist_digest,
                "--nonce",
                self.nonce,
                "--receipt-verifier",
                str(self.fake),
            ],
            text=True,
            capture_output=True,
        )

    def test_exact_production_receipts_pass_without_a_liveness_claim(self) -> None:
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["targets"], list(PRODUCTION_TARGETS))
        self.assertEqual(output["workloads"], list(PRODUCTION_WORKLOADS))
        self.assertEqual(output["operationalStatus"], "not-verified")
        self.assertNotIn("liveness", result.stdout.lower())

    def test_exact_staging_receipts_pass_without_a_liveness_claim(self) -> None:
        release = json.loads(self.release.read_text())
        release["c8s"]["attestationTargets"] = [
            {"target": target, "workload": workload, "identity": workload}
            for target, workload in zip(STAGING_TARGETS, STAGING_WORKLOADS, strict=True)
        ]
        self.release.write_text(json.dumps(release), encoding="utf-8")
        self.release_digest = "sha256:" + hashlib.sha256(self.release.read_bytes()).hexdigest()
        self.write_attestation(self.valid_attestation(STAGING_TARGETS, STAGING_WORKLOADS))

        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["targets"], list(STAGING_TARGETS))
        self.assertEqual(output["workloads"], list(STAGING_WORKLOADS))
        self.assertEqual(output["operationalStatus"], "not-verified")
        self.assertNotIn("liveness", result.stdout.lower())

    def test_mixed_environment_receipts_fail_closed(self) -> None:
        value = self.valid_attestation()
        value["receipts"][-1]["target"] = "extraneous-worker-1"
        value["receipts"][-1]["workload"] = "extraneous-worker"
        self.write_attestation(value)
        self.assertNotEqual(self.verify().returncode, 0)

    def test_missing_duplicate_or_reordered_workloads_fail_closed(self) -> None:
        for mutation in ("missing", "duplicate", "reordered"):
            with self.subTest(mutation=mutation):
                value = self.valid_attestation()
                if mutation == "missing":
                    value["receipts"].pop()
                elif mutation == "duplicate":
                    value["receipts"][-1]["target"] = "gateway"
                else:
                    value["receipts"][0], value["receipts"][1] = (
                        value["receipts"][1],
                        value["receipts"][0],
                    )
                self.write_attestation(value)
                self.assertNotEqual(self.verify().returncode, 0)

    def test_one_wrong_receipt_nonce_fails_closed(self) -> None:
        value = self.valid_attestation()
        value["receipts"][2]["receipt"]["nonce"] = b64(b"z" * 32)
        self.write_attestation(value)
        self.assertNotEqual(self.verify().returncode, 0)

    def test_expected_operator_key_must_be_in_the_active_key_set(self) -> None:
        release = json.loads(self.release.read_text())
        release["c8s"]["operatorPublicKeySha256"] = "sha256:" + "0" * 64
        self.release.write_text(json.dumps(release), encoding="utf-8")
        self.release_digest = "sha256:" + hashlib.sha256(self.release.read_bytes()).hexdigest()
        self.write_attestation(self.valid_attestation())
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not in the active key set", result.stderr)

    def test_external_verifier_failure_fails_closed(self) -> None:
        self.fake.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        self.fake.chmod(0o755)
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("c8s rejected", result.stderr)

    def test_release_digest_mismatch_fails_closed(self) -> None:
        value = json.loads(self.release.read_text())
        value["release"]["name"] = "changed-after-digest"
        self.release.write_text(json.dumps(value), encoding="utf-8")
        self.assertNotEqual(self.verify().returncode, 0)


if __name__ == "__main__":
    unittest.main()
