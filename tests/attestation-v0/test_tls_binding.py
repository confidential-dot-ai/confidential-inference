from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "verify_public_attestation", ROOT / "scripts/verify-public-attestation.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class TlsBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.live_der = b"the live DER leaf"
        leaf_digest = hashlib.sha256(self.live_der).digest()
        self.leaf_b64 = base64.urlsafe_b64encode(leaf_digest).rstrip(b"=").decode()
        self.response = {
            "tls": {"mode": "tee-webpki"},
            "frontDoor": {
                "source": "c8s-tls-lb",
                "receipt": {
                    "version": "c8s/attest-lb/v1",
                    "serving_leaf_sha256": self.leaf_b64,
                },
            },
            "receipts": [{"target": "gateway", "receipt": {
                "version": "c8s/attest-pq/v1",
            }}],
        }
        self.front_door_verdict = {
            "tls_binding_verified": True,
            "serving_leaf_sha256": self.leaf_b64,
        }
        self.live_digest = "sha256:" + leaf_digest.hex()

    def test_attest_lb_receipt_matches_live_leaf(self) -> None:
        self.assertTrue(MODULE.validate_tls_binding(
            self.response, self.live_digest, self.live_der, self.front_door_verdict
        ))

    def test_wrong_live_leaf_fails_closed(self) -> None:
        with self.assertRaises(MODULE.VerificationError):
            MODULE.validate_tls_binding(
                self.response, "sha256:" + "00" * 32, self.live_der, self.front_door_verdict
            )

    def test_missing_attest_lb_receipt_fails_closed(self) -> None:
        response = {"tls": {"mode": "tee-webpki"}, "receipts": [{
            "target": "gateway", "receipt": {"version": "c8s/attest-pq/v1"}
        }]}
        with self.assertRaises(MODULE.VerificationError):
            MODULE.validate_tls_binding(
                response, self.live_digest, self.live_der, self.front_door_verdict
            )

    def test_gateway_receipt_cannot_substitute_for_front_door(self) -> None:
        response = dict(self.response)
        response.pop("frontDoor")
        response["receipts"] = [{"target": "gateway", "receipt": {
            "version": "c8s/attest-lb/v1",
            "serving_leaf_sha256": self.leaf_b64,
        }}]
        with self.assertRaises(MODULE.VerificationError):
            MODULE.validate_tls_binding(
                response, self.live_digest, self.live_der, self.front_door_verdict
            )

    def test_front_door_is_verified_with_the_c8s_attest_lb_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            verifier = Path(directory) / "c8s"
            verifier.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                "required = ['--kind', 'workload', '--mode', 'attest-lb', '--from-file', '--attestation-nonce', '--observed-serving-cert', '-o', 'json']\n"
                "if any(flag not in sys.argv for flag in required): raise SystemExit(2)\n"
                "if json.loads(pathlib.Path(sys.argv[sys.argv.index('--from-file') + 1]).read_text())['version'] != 'c8s/attest-lb/v1': raise SystemExit(3)\n"
                "print(json.dumps({'tls_binding_verified': True, 'serving_leaf_sha256': json.loads(pathlib.Path(sys.argv[sys.argv.index('--from-file') + 1]).read_text())['serving_leaf_sha256'], 'verified': True, 'backend': 'attestation-go', 'platform': 'tdx', 'measurement_pinned': True, 'measurement': 'a' * 96, 'debug': False, 'fresh': False, 'workload': 'c8s-tls-lb', 'chain_anchor': 'verified against the pinned --mesh-ca bundle', 'binding': 'REPORTDATA binds the identity transcript: test', 'workload_note': 'workload_verified: test', 'partial': False, 'warnings': [], 'rtmrs_pinned': ['1:' + '1' * 96, '2:' + '2' * 96, '3:' + '3' * 96]}))\n"
            )
            verifier.chmod(verifier.stat().st_mode | 0o100)
            args = type("Args", (), {
                "c8s": str(verifier),
                "nonce": "A" * 43,
                "verifier_timeout_seconds": 2,
                "node_manifest": verifier,
                "operator_public_key": verifier,
                "mesh_ca": verifier,
                "allowlist": verifier,
            })()
            verdict = MODULE.verify_front_door(self.response, args, self.live_der, {"c8s": {"frontDoorWorkload": "c8s-tls-lb"}})
            self.assertTrue(verdict["tls_binding_verified"])
            self.assertEqual(verdict["serving_leaf_sha256"], self.leaf_b64)

    def test_front_door_verifier_rejects_a_wrong_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            verifier = Path(directory) / "c8s"
            verifier.write_text(
                "#!/usr/bin/env python3\n"
                "import json\n"
                "print(json.dumps({'tls_binding_verified': True, 'serving_leaf_sha256': 'A' * 43}))\n"
            )
            verifier.chmod(verifier.stat().st_mode | 0o100)
            args = type("Args", (), {
                "c8s": str(verifier),
                "nonce": "A" * 43,
                "verifier_timeout_seconds": 2,
                "node_manifest": verifier,
                "operator_public_key": verifier,
                "mesh_ca": verifier,
                "allowlist": verifier,
            })()
            with self.assertRaises(MODULE.VerificationError):
                MODULE.verify_front_door(self.response, args, self.live_der, {"c8s": {"frontDoorWorkload": "c8s-tls-lb"}})


if __name__ == "__main__":
    unittest.main()
