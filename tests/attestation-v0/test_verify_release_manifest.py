"""Tests for the v0.14.0 release-manifest path of the aggregate verifier."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import textwrap
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-public-attestation.py"
FIXTURE = ROOT / "tests/contracts/fixtures/workload-attestation.valid.json"
NONCE = base64.urlsafe_b64encode(b"n" * 32).rstrip(b"=").decode()
C8S_COMMIT = "c9d49a67d36b16b7adc306489b6f591611c34968"
MRTD, RTMR1, RTMR2 = "a" * 96, "b" * 96, "c" * 96
WORKLOADS = (
    "gateway", "sglang-router", "inference-worker-0", "inference-worker-1",
    "metrics-collector", "kube-state-metrics",
)


def load_module():
    if str(SCRIPT.parent) not in sys.path:
        sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("verify_public_attestation_v1", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def certificate(name: str, issuer=None, issuer_key=None, ca=False):
    key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    cert = builder.sign(issuer_key or key, hashes.SHA384())
    return key, cert


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def der_sha256(cert) -> bytes:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest()


FAKE_C8S = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, sys
    log = os.environ["FAKE_C8S_LOG"]
    with open(log, "a") as out:
        out.write(json.dumps(sys.argv[1:]) + "\\n")
    if sys.argv[1:] == ["--version"]:
        print("c8s version v0.33.2")
        sys.exit(0)
    argv = sys.argv[1:]
    workload = argv[argv.index("--workload") + 1]
    verdict = {
        "verified": True, "platform": "tdx", "measurement_pinned": True, "debug": False,
        "fresh": False, "workload": workload,
        "chain_anchor": "verified against the pinned --mesh-ca bundle",
        "binding": "REPORTDATA binds the identity transcript: sha512(...)",
        "workload_note": "workload_verified: " + workload,
        "rtmrs_pinned": ["1:" + "b" * 96, "2:" + "c" * 96] + (
            ["3:" + "d" * 96] if "--operator-pkey" in argv else []
        ),
        "report_data": "00" * 64,
        "workload_allowlist_digest": "sha256:" + "e" * 64,
    }
    verdict.update(json.loads(os.environ.get("FAKE_C8S_VERDICT", "{}")))
    print(json.dumps(verdict))
''')


class ReleaseManifestVerifierTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.ca_key, self.ca = certificate("c8s Mesh CA", ca=True)
        self.c8s = self.directory / "c8s"
        self.c8s.write_text(FAKE_C8S)
        self.c8s.chmod(self.c8s.stat().st_mode | stat.S_IXUSR)
        self.log = self.directory / "c8s.log"
        os.environ["FAKE_C8S_LOG"] = str(self.log)
        os.environ.pop("FAKE_C8S_VERDICT", None)

        self.allowlist = {
            "schema": "c8s.allowlist/v1",
            "workloads": {name: {"containers": []} for name in WORKLOADS},
        }
        self.allowlist_path = self.write("allowlist.json", json.dumps(self.allowlist).encode())
        self.node_manifest_path = self.write(
            "manifest.json", json.dumps({"tdx": {"mrtd": MRTD, "rtmr1": RTMR1, "rtmr2": RTMR2}}).encode()
        )
        self.source_lock_path = self.write("source-lock.json", b'{"entries":[]}')
        self.manifest = {
            "schema": "confidential.ai/release-manifest/v1",
            "release": {"name": "v0.14.0", "environment": "production"},
            "releaseTrust": {
                "policyPath": "releases/trust/release-signing-policy.json",
                "policySha256": "sha256:" + "0" * 64,
                "signatureType": "sigstore-keyless",
            },
            "source": {
                "repository": "https://github.com/confidential-dot-ai/confidential-inference",
                "commit": "1" * 40,
            },
            "images": {"gateway": "ghcr.io/confidential-dot-ai/confidential-inference/gateway@sha256:" + "2" * 64},
            "chart": {"name": "confidential-inference", "version": "0.14.0", "sha256": "sha256:" + "3" * 64},
            "c8s": {"release": "v0.33.2", "sourceCommit": C8S_COMMIT},
            "nodeImage": {
                "reference": "ghcr.io/confidential-dot-ai/node-guest-base@sha256:" + "4" * 64,
                "manifestSha256": digest(self.node_manifest_path.read_bytes()),
            },
            "mrtd": MRTD, "rtmr1": RTMR1, "rtmr2": RTMR2,
            "sourceLock": {
                "path": "contracts/c8s-admission-source-lock.json",
                "sha256": digest(self.source_lock_path.read_bytes()),
            },
            "model": {
                "repository": "deepseek-ai/DeepSeek-V4-Flash-0731",
                "revision": "9e165c30e2704aec5d9d593cce3eebd58bbef1cb",
                "byteManifestSha256": "cd9eecd89a3d31dedd7b707158e86ebeab241c68d55e9661d3efa508015a697c",
            },
            "allowlist": {"path": "release/allowlist.json", "sha256": digest(self.allowlist_path.read_bytes())},
            "publicHostnames": ["api.confidential.ai", "candidate.api.confidential.ai"],
        }
        self.write_manifest()
        self.response = self.build_response()

    def tearDown(self):
        self.temporary.cleanup()
        os.environ.pop("FAKE_C8S_VERDICT", None)

    def write(self, name: str, data: bytes) -> Path:
        path = self.directory / name
        path.write_bytes(data)
        return path

    def write_manifest(self):
        self.manifest_bytes = json.dumps(self.manifest, separators=(",", ":")).encode()
        self.manifest_path = self.write("release-manifest.json", self.manifest_bytes)

    def receipt(self, workload: str, ca=None, ca_key=None, nonce=NONCE):
        ca = ca or self.ca
        ca_key = ca_key or self.ca_key
        _, leaf = certificate(workload, issuer=ca, issuer_key=ca_key)
        base = json.loads(FIXTURE.read_text())["receipts"][0]
        item = copy.deepcopy(base)
        item.update({"target": workload, "workload": workload, "identity": workload})
        item["receipt"]["cds_cert_pem"] = pem(leaf) + pem(ca)
        item["receipt"]["identity_proof"]["mesh_ca_sha256"] = b64(der_sha256(ca))
        item["receipt"]["nonce"] = nonce
        return item

    def build_response(self):
        response = json.loads(FIXTURE.read_text())
        response["nonce"] = NONCE
        response["release"] = {
            "id": "v0.14.0",
            "bundleSha256": digest(self.manifest_bytes),
            "source": "operator-selected-public-release",
        }
        response["c8s"]["activeAllowlist"] = {
            "document": copy.deepcopy(self.allowlist),
            "sha256": self.manifest["allowlist"]["sha256"],
        }
        response["c8s"]["meshCaSha256"] = "sha256:" + der_sha256(self.ca).hex()
        response["receipts"] = [self.receipt(name) for name in WORKLOADS]
        return response

    def args(self, **overrides):
        values = dict(
            endpoint="https://candidate.api.confidential.ai/attestation",
            nonce=NONCE,
            trusted_bundle=self.manifest_path,
            release_signature_bundle=self.directory / "sig.json",
            cosign=self.directory / "cosign",
            node_manifest=self.node_manifest_path,
            node_source_lock=None,
            c8s_source_lock=self.source_lock_path,
            allowlist=self.allowlist_path,
            allowlist_history=None,
            operator_public_key=None,
            expected_operator_key_sha256=None,
            mesh_ca=None,
            expected_mesh_ca_sha256=None,
            deployment_target="production",
            release_environment=None,
            expected_target=[],
            c8s=str(self.c8s),
            attestation_cli=None,
            cds_url=None,
            endpoint_ca=None,
            connect_address=None,
            timeout_seconds=30,
            verifier_timeout_seconds=30,
            sigstore_timeout_seconds=30,
            maximum_response_bytes=8 * 1024 * 1024,
        )
        values.update(overrides)
        return argparse.Namespace(**values)

    def run_verify(self, args=None, response=None):
        response = response if response is not None else self.response
        signature = {"releaseBundleBytesSha256": digest(self.manifest_bytes)}
        with mock.patch.object(self.module, "verify_release_signature", return_value=signature), \
                mock.patch.object(
                    self.module, "fetch_response",
                    return_value=(response, "spki", "sha256:" + "9" * 64, b"leaf"),
                ):
            return self.module.verify(args or self.args())

    def c8s_calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_verifies_without_operator_key_or_held_mesh_ca(self):
        result = self.run_verify()
        self.assertTrue(result["verified"])
        self.assertEqual(result["release"], "v0.14.0")
        self.assertEqual(result["meshCaSource"], "receipt-commitment")
        self.assertEqual(result["meshCaSha256"], "sha256:" + der_sha256(self.ca).hex())
        self.assertEqual(result["operatorKey"], {"pinned": False})
        self.assertEqual([item["fresh"] for item in result["receipts"]], ["nonce-bound"] * len(WORKLOADS))
        verify_calls = [call for call in self.c8s_calls() if call[0] == "verify"]
        self.assertEqual(len(verify_calls), len(WORKLOADS))
        for call in verify_calls:
            self.assertNotIn("--operator-pkey", call)
            self.assertIn("--mesh-ca", call)
            self.assertEqual(call[call.index("--allowlist") + 1], str(self.allowlist_path))

    def test_every_receipt_must_echo_the_request_nonce(self):
        stale = base64.urlsafe_b64encode(b"s" * 32).rstrip(b"=").decode()
        self.response["receipts"][1] = self.receipt("sglang-router", nonce=stale)
        with self.assertRaisesRegex(self.module.VerificationError, "sglang-router receipt is not bound"):
            self.run_verify()

    def test_receipts_must_commit_one_mesh_ca(self):
        other_key, other_ca = certificate("other CA", ca=True)
        self.response["receipts"][1] = self.receipt("sglang-router", ca=other_ca, ca_key=other_key)
        with self.assertRaisesRegex(self.module.VerificationError, "different mesh CAs"):
            self.run_verify()

    def test_receipt_must_serve_the_committed_ca(self):
        item = self.response["receipts"][0]
        item["receipt"]["cds_cert_pem"] = item["receipt"]["cds_cert_pem"].split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
        with self.assertRaisesRegex(self.module.VerificationError, "does not serve the mesh CA"):
            self.run_verify()

    def test_response_mesh_ca_must_match_receipts(self):
        self.response["c8s"]["meshCaSha256"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(self.module.VerificationError, "response mesh CA differs"):
            self.run_verify()

    def test_optional_mesh_ca_pin(self):
        with self.assertRaisesRegex(self.module.VerificationError, "differs from the pinned mesh CA"):
            self.run_verify(self.args(expected_mesh_ca_sha256="sha256:" + "f" * 64))
        result = self.run_verify(self.args(expected_mesh_ca_sha256=der_sha256(self.ca).hex()))
        self.assertEqual(result["meshCaSource"], "pinned")

    def test_served_allowlist_must_equal_the_signed_one(self):
        self.response["c8s"]["activeAllowlist"]["document"]["workloads"]["extra"] = {"containers": []}  # one more workload than signed
        with self.assertRaisesRegex(self.module.VerificationError, "served allowlist differs"):
            self.run_verify()

    def test_held_allowlist_must_match_the_manifest_digest(self):
        self.allowlist_path.write_bytes(json.dumps(self.allowlist, indent=1).encode())
        with self.assertRaisesRegex(self.module.VerificationError, "allowlist differs from the one"):
            self.run_verify()

    def test_node_image_registers_must_match(self):
        self.manifest["rtmr2"] = "d" * 96
        self.write_manifest()
        self.response = self.build_response()
        with self.assertRaisesRegex(self.module.VerificationError, "rtmr2 differs"):
            self.run_verify()

    def test_receipt_workload_must_be_in_the_allowlist(self):
        self.response["receipts"][-1]["workload"] = "unlisted"
        # The response schema or the allowlist check rejects it; both fail closed.
        with self.assertRaisesRegex(self.module.VerificationError, "not in the signed allowlist|schema failed at receipts"):
            self.run_verify()

    def test_operator_key_is_optional_but_pins_rtmr3_when_held(self):
        key = ec.generate_private_key(ec.SECP256R1())
        key_path = self.write(
            "operator.pub",
            key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
        )
        spki = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.response["c8s"]["operatorTrust"]["expectedPublicKeySpkiSha256"] = digest(spki)
        result = self.run_verify(self.args(operator_public_key=key_path))
        self.assertEqual(result["operatorKey"]["sha256"], digest(spki))
        self.assertTrue(result["operatorKey"]["rtmr3Pinned"])
        self.assertTrue(all(
            "--operator-pkey" in call for call in self.c8s_calls() if call[0] == "verify"
        ))
        with self.assertRaisesRegex(self.module.VerificationError, "held operator public key differs"):
            self.run_verify(self.args(
                operator_public_key=key_path, expected_operator_key_sha256="sha256:" + "0" * 64,
            ))

    def test_operator_pin_must_match_the_response(self):
        with self.assertRaisesRegex(self.module.VerificationError, "response operator key differs"):
            self.run_verify(self.args(expected_operator_key_sha256="sha256:" + "0" * 64))

    def test_partial_or_unpinned_c8s_verdicts_fail_closed(self):
        for override, message in (
            ({"verified": False}, "verified verdict"),
            ({"partial": True}, "partial"),
            ({"chain_anchor": "responder-chosen"}, "mesh CA is not pinned"),
            ({"rtmrs_pinned": ["1:" + "b" * 96]}, "registers are not pinned"),
        ):
            with self.subTest(override=override):
                os.environ["FAKE_C8S_VERDICT"] = json.dumps(override)
                with self.assertRaisesRegex(self.module.VerificationError, message):
                    self.run_verify()

    def test_tee_held_front_door_fails_closed(self):
        self.response["tls"]["mode"] = "acme"
        with self.assertRaisesRegex(self.module.VerificationError, "TEE-held front door|schema failed at frontDoor"):
            self.run_verify()

    def test_release_identity_must_match(self):
        self.response["release"]["bundleSha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(self.module.VerificationError, "release identity differs"):
            self.run_verify()

    def test_old_bundle_still_requires_its_inputs(self):
        old = self.write("old-bundle.json", json.dumps({"schema": "old"}).encode())
        with self.assertRaisesRegex(self.module.VerificationError, "requires --node-source-lock and --mesh-ca"):
            self.module.verify(self.args(trusted_bundle=old))

    def test_manifest_schema_rejects_operator_or_mesh_ca_fields(self):
        self.manifest["meshCaSha256"] = "sha256:" + "0" * 64
        self.write_manifest()
        with self.assertRaisesRegex(self.module.VerificationError, "release manifest"):
            self.run_verify()


if __name__ == "__main__":
    unittest.main()
