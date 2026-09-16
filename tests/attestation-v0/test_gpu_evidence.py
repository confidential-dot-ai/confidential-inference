from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "verify_public_attestation", ROOT / "scripts/verify-public-attestation.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class GpuEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.c8s = self.directory / "c8s"
        self.c8s.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "open(sys.argv[sys.argv.index('--from-file') + 1], 'rb').read()\n"
            "if '--nvidia-gpu-expected-arch' not in sys.argv or 'BLACKWELL' not in sys.argv: raise SystemExit(2)\n"
            "print(json.dumps({'gpu_verified': True, 'nonce_binding_ok': "
            "__import__('os').environ.get('GPU_BINDING', 'true') == 'true', "
            "'gpu_device_count': 1, 'gpu_device_ueids': ['ueid-0']}))\n"
        )
        self.c8s.chmod(0o755)
        self.args = SimpleNamespace(
            c8s=str(self.c8s),
            node_manifest=self.directory / "manifest.json",
            operator_public_key=self.directory / "operator.pem",
            mesh_ca=self.directory / "mesh.pem",
            verifier_timeout_seconds=2,
            attestation_cli_sha256="ab" * 32,
            gpu_verifier_environment=None,
        )
        self.item = {"target": "inference-worker-0", "workload": "inference-worker-0"}
        self.receipt = {
            "gpu_attested": "evidence_collected",
            "nvidia_gpu": {
                "devices": [{
                    "arch": "BLACKWELL",
                    "uuid": "gpu-0",
                    "evidence_b64": "ZXZpZGVuY2U=",
                    "cert_chain_b64": "Y2VydA==",
                }],
                "binding": {"kind": "concat", "algo": "sha256"},
            },
        }
        self.policy = {"required": True, "deviceCount": 1, "architectures": ["BLACKWELL"]}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_required_gpu_evidence_is_verified_and_nonce_bound(self) -> None:
        result = MODULE.verify_gpu_receipt(
            self.item, self.policy, self.receipt, "ab" * 64, self.args, self.directory / "allowlist"
        )
        self.assertTrue(result["verified"])
        self.assertEqual(result["deviceCount"], 1)

    def test_missing_gpu_evidence_fails_closed(self) -> None:
        receipt = json.loads(json.dumps(self.receipt))
        receipt["gpu_attested"] = "unknown"
        with self.assertRaises(MODULE.VerificationError):
            MODULE.verify_gpu_receipt(
                self.item, self.policy, receipt, "ab" * 64, self.args, self.directory / "allowlist"
            )

    def test_wrong_device_count_fails_closed(self) -> None:
        policy = {"required": True, "deviceCount": 2}
        with self.assertRaises(MODULE.VerificationError):
            MODULE.verify_gpu_receipt(
                self.item, policy, self.receipt, "ab" * 64, self.args, self.directory / "allowlist"
            )

    def test_c8s_rejects_misbound_gpu_transcript(self) -> None:
        import os

        old = os.environ.get("GPU_BINDING")
        os.environ["GPU_BINDING"] = "false"
        try:
            with self.assertRaises(MODULE.VerificationError):
                MODULE.verify_gpu_receipt(
                    self.item, self.policy, self.receipt, "ab" * 64, self.args,
                    self.directory / "allowlist",
                )
        finally:
            if old is None:
                os.environ.pop("GPU_BINDING", None)
            else:
                os.environ["GPU_BINDING"] = old

    def test_zero_padded_report_data_is_truncated_for_the_gpu_nonce(self) -> None:
        self.c8s.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "open(sys.argv[sys.argv.index('--from-file') + 1], 'rb').read()\n"
            "if sys.argv[sys.argv.index('--nvidia-gpu-user-nonce') + 1] != 'ab' * 48: raise SystemExit(2)\n"
            "print(json.dumps({'gpu_verified': True, 'nonce_binding_ok': True, 'gpu_device_count': 1, 'gpu_device_ueids': ['ueid-0']}))\n"
        )
        self.c8s.chmod(0o755)
        result = MODULE.verify_gpu_receipt(
            self.item, self.policy, self.receipt, "ab" * 48 + "00" * 16, self.args,
            self.directory / "allowlist",
        )
        self.assertTrue(result["verified"])

    def test_c8s_signed_gpu_count_must_match_policy(self) -> None:
        self.c8s.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "open(sys.argv[sys.argv.index('--from-file') + 1], 'rb').read()\n"
            "print(json.dumps({'gpu_verified': True, 'nonce_binding_ok': True, 'gpu_device_count': 2, 'gpu_device_ueids': ['u0', 'u1']}))\n"
        )
        self.c8s.chmod(0o755)
        with self.assertRaises(MODULE.VerificationError):
            MODULE.verify_gpu_receipt(
                self.item, self.policy, self.receipt, "ab" * 64, self.args,
                self.directory / "allowlist",
            )

    def test_old_c8s_binary_without_gpu_flags_is_rejected(self) -> None:
        with self.assertRaises(MODULE.VerificationError):
            MODULE.require_c8s_capabilities(
                str(self.c8s), {"--nvidia-gpu-user-nonce"}, 2
            )


if __name__ == "__main__":
    unittest.main()
