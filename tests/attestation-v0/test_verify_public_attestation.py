from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[2]


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class WorkloadAttestationSchemaTests(unittest.TestCase):
    def test_versioned_inference_worker_policy_names_are_valid(self):
        schema = json.loads(
            (ROOT / "api/workload-attestation.schema.json").read_text()
        )
        nonce = b64(b"n" * 32)
        receipt = {
            "version": "c8s/attest-pq/v1",
            "platform": "tdx",
            "generation": "",
            "nonce": nonce,
            "evidence": {"quote": "test"},
            "cds_cert_pem": "certificate",
            "session_pubkey": {"x25519": "eA", "mlkem768": "bQ"},
            "identity_proof": {
                "algorithm": "ecdsa-sha384",
                "leaf_sha256": "bA",
                "mesh_ca_sha256": "bQ",
                "signature": "cw",
            },
        }
        targets = [
            ("gateway", "gateway-db0b6ee"),
            ("sglang-router", "sglang-router-684393d"),
            ("inference-worker-0", "inference-worker-0-tool-calls-v1"),
            ("inference-worker-1", "inference-worker-1-tool-calls-v1"),
            ("metrics-collector", "metrics-collector-a941ea9"),
            ("kube-state-metrics", "kube-state-metrics-a941ea9"),
        ]
        response = {
            "schemaVersion": 2,
            "scope": "launch-or-admission-only",
            "nonce": nonce,
            "operationalStatus": "not-verified",
            "release": {
                "id": "test-release",
                "bundleSha256": "sha256:" + "1" * 64,
                "source": "operator-selected-public-release",
            },
            "c8s": {
                "discovery": {
                    "version": "v1",
                    "generated_at": "2026-09-01T00:00:00Z",
                    "public_tls": {"hostname": "api.example.test", "mode": "webpki"},
                    "cds_tls": {
                        "certificate_pem": "certificate",
                        "certificate_sha256": "sha256:" + "2" * 64,
                    },
                    "attestation": {"platform": "tdx", "evidence": {"quote": "test"}},
                },
                "activeAllowlist": {
                    "sha256": "sha256:" + "3" * 64,
                    "document": {"schema": "c8s.allowlist/v1", "digests": {}, "workloads": {}},
                },
                "operatorTrust": {
                    "expectedPublicKeySpkiSha256": "sha256:" + "4" * 64,
                    "expectedKeySetSha256": "sha256:" + "7" * 64,
                    "activeKeySetStatus": "requires-attested-cds-read",
                    "cdsAttestedReadHint": "/operator-keys",
                    "reason": "not exposed",
                },
                "meshCaSha256": "sha256:" + "5" * 64,
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
                "status": "not-exposed-by-c8s",
                "evidence": [],
                "reason": "not exposed",
            },
            "receipts": [
                {
                    "target": target,
                    "workload": workload,
                    "identity": target,
                    "admittedLaunch": {
                        "policyName": workload,
                        "initContainers": [],
                        "containers": [{
                            "image": "ghcr.io/example/test@sha256:" + "6" * 64,
                            "digest": "sha256:" + "6" * 64,
                            "argv": ["/bin/test"],
                        }],
                    },
                    "receipt": receipt,
                }
                for target, workload in targets
            ],
        }
        jsonschema.Draft202012Validator(schema).validate(response)

        # Staging runs one inference worker and both observability
        # workloads, so its receipt set is five targets: the full set
        # without inference-worker-1. Measured live on staging-v6.
        five = [item for item in response["receipts"] if item["target"] != "inference-worker-1"]
        five_target = dict(response, receipts=five)
        jsonschema.Draft202012Validator(schema).validate(five_target)

        # Every other subset of the same set must still fail closed. A
        # missing router, a missing worker, or exactly one of the two
        # observability workloads is a receipt set no environment runs.
        for dropped in ("sglang-router", "inference-worker-0", "kube-state-metrics"):
            broken = [item for item in five if item["target"] != dropped]
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.Draft202012Validator(schema).validate(
                    dict(response, receipts=broken)
                )

    def test_tee_webpki_requires_a_separate_front_door_receipt(self):
        schema = json.loads(
            (ROOT / "api/workload-attestation.schema.json").read_text()
        )
        # Reuse the complete response built by the preceding contract test.
        # The test data below is intentionally small because this check targets
        # only the conditional frontDoor contract.
        nonce = b64(b"n" * 32)
        receipt = {
            "version": "c8s/attest-pq/v1", "platform": "tdx", "generation": "",
            "nonce": nonce, "evidence": {"quote": "test"},
            "cds_cert_pem": "certificate",
            "session_pubkey": {"x25519": "eA", "mlkem768": "bQ"},
            "identity_proof": {"algorithm": "ecdsa-sha384", "leaf_sha256": "bA", "mesh_ca_sha256": "bQ", "signature": "cw"},
        }
        response = {
            "schemaVersion": 2, "scope": "launch-or-admission-only", "nonce": nonce,
            "operationalStatus": "not-verified",
            "release": {"id": "test", "bundleSha256": "sha256:" + "1" * 64, "source": "operator-selected-public-release"},
            "c8s": {"discovery": {"version": "v1", "generated_at": "now", "public_tls": {"hostname": "example.test", "mode": "tee-webpki"}, "cds_tls": {"certificate_pem": "certificate", "certificate_sha256": "sha256:" + "2" * 64}, "attestation": {"platform": "tdx", "evidence": {"quote": "test"}}}, "activeAllowlist": {"sha256": "sha256:" + "3" * 64, "document": {"schema": "c8s.allowlist/v1", "digests": {}, "workloads": {}}}, "operatorTrust": {"expectedPublicKeySpkiSha256": "sha256:" + "4" * 64, "expectedKeySetSha256": "sha256:" + "5" * 64, "activeKeySetStatus": "evidence-present-and-release-matched", "activeKeySetSha256": "sha256:" + "5" * 64, "activeKeySetPem": "key", "reason": "test"}, "meshCaSha256": "sha256:" + "6" * 64},
            "tls": {"mode": "tee-webpki", "binding": {"status": "requires-attest-lb", "publicKeySha256": None, "reason": "test"}},
            "gpuEvidence": {"status": "raw-receipt-evidence", "evidence": [], "reason": "test"},
            "receipts": [{"target": target, "workload": target, "identity": target, "admittedLaunch": {"policyName": target, "initContainers": [], "containers": [{"image": "x@sha256:" + "1" * 64, "digest": "sha256:" + "1" * 64, "argv": ["/x"]}]}, "receipt": copy.deepcopy(receipt)} for target in ["gateway", "sglang-router", "inference-worker-0", "inference-worker-1", "metrics-collector", "kube-state-metrics"]],
        }
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(response)
        front_door = copy.deepcopy(receipt)
        front_door["version"] = "c8s/attest-lb/v1"
        front_door.pop("session_pubkey")
        front_door["serving_leaf_sha256"] = b64(b"l" * 32)
        response["frontDoor"] = {"source": "c8s-tls-lb", "receipt": front_door}
        jsonschema.Draft202012Validator(schema).validate(response)
        response["tls"]["mode"] = "webpki"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(response)


if __name__ == "__main__":
    unittest.main()
