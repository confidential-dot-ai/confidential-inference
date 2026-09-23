from __future__ import annotations

import importlib.util
import json
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


class OperatorKeySetReadTests(unittest.TestCase):
    def test_attested_read_pins_the_served_set_and_rtmr3(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            verifier = root / "c8s"
            operator_key = root / "operator-public.pem"
            manifest = root / "manifest.json"
            operator_key.write_text("test key\n", encoding="utf-8")
            manifest.write_text("{}\n", encoding="utf-8")
            verifier.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "required = ['--kind', 'cds', '--mode', 'ratls-cert', "
                "'--operator-pkey', '--operator-keys', '-o', 'json']\n"
                "if any(value not in sys.argv for value in required): raise SystemExit(2)\n"
                "print(json.dumps({'verified': True, 'backend': 'attestation-go', "
                "'platform': 'tdx', 'measurement_pinned': True, 'debug': False, "
                "'operator_keys_note': 'matched: the set served over the attested cert equals --operator-keys', "
                "'operator_keys': ['11' * 32], 'measurement': '22' * 48}))\n",
                encoding="utf-8",
            )
            verifier.chmod(0o700)
            args = type("Args", (), {
                "c8s": str(verifier),
                "cds_url": "https://127.0.0.1:8443",
                "node_manifest": manifest,
                "operator_public_key": operator_key,
                "policy_mode": "operator",
                "verifier_timeout_seconds": 2,
            })()
            digest, members, measurement = MODULE.read_attested_operator_key_set(args)
            self.assertTrue(digest.startswith("sha256:"))
            self.assertEqual(members, {"sha256:" + "11" * 32})
            self.assertEqual(measurement, "22" * 48)

    def test_attested_read_rejects_an_unpinned_served_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            verifier = root / "c8s"
            operator_key = root / "operator-public.pem"
            manifest = root / "manifest.json"
            operator_key.write_text("test key\n", encoding="utf-8")
            manifest.write_text("{}\n", encoding="utf-8")
            verifier.write_text(
                "#!/usr/bin/env python3\n"
                "import json\n"
                "print(json.dumps({'verified': True, 'backend': 'attestation-go', "
                "'platform': 'tdx', 'measurement_pinned': True, 'debug': False, "
                "'operator_keys_note': 'not pinned: compared against nothing', "
                "'operator_keys': ['11' * 32], 'measurement': '22' * 48}))\n",
                encoding="utf-8",
            )
            verifier.chmod(0o700)
            args = type("Args", (), {
                "c8s": str(verifier),
                "cds_url": "https://127.0.0.1:8443",
                "node_manifest": manifest,
                "operator_public_key": operator_key,
                "policy_mode": "operator",
                "verifier_timeout_seconds": 2,
            })()
            with self.assertRaises(MODULE.VerificationError):
                MODULE.read_attested_operator_key_set(args)


if __name__ == "__main__":
    unittest.main()
