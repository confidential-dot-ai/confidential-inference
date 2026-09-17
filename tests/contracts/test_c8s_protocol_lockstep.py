"""Unit tests for scripts/check-c8s-protocol-lockstep.py.

These exercise the comparison logic directly against the manifests already
committed under contracts/c8s-attestation-protocols/, with a synthetic
gateway fixture text, so the test does not depend on services/gateway/tests/
carrying any particular shape (a parallel branch owns that file).
"""

from __future__ import annotations

import runpy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-c8s-protocol-lockstep.py"


def load_module():
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        return runpy.run_path(str(SCRIPT))
    finally:
        sys.path.pop(0)


class C8sProtocolLockstepTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.manifests = self.module["load_manifests"]()

    def entry(self, commit: str, protocol: str | None = None) -> dict:
        result = {"commit": commit}
        if protocol is not None:
            result["attestationProtocol"] = protocol
        return result

    def test_old_protocol_fixtures_pass_for_the_production_commit(self):
        fixture_text = 'let receipt = json!({"session_pubkey": {"x25519": "a", "mlkem768": "b"}});'
        verdict = self.module["check_entry"](
            self.entry("079aeb48c4d523aa7500b4bd78f0283b2d12e317"),
            self.manifests, fixture_text,
        )
        self.assertIn("c8s/attest-pq/v1'", verdict)

    def test_xwing_commit_fails_closed_without_gateway_fixtures(self):
        fixture_text = 'let receipt = json!({"session_pubkey": {"x25519": "a", "mlkem768": "b"}});'
        with self.assertRaisesRegex(self.module["LockstepError"], "do not build"):
            self.module["check_entry"](
                self.entry(
                    "466ce79e77c2fb6c014620b770066f275e889df6",
                    "c8s/attest-pq/v1+xwing",
                ),
                self.manifests, fixture_text,
            )

    def test_xwing_commit_passes_once_the_gateway_builds_the_new_shape(self):
        fixture_text = (
            'let receipt = json!({"xwing_ek": "a", "xwing_ct": "b", "session_id": "c"});'
        )
        verdict = self.module["check_entry"](
            self.entry("466ce79e77c2fb6c014620b770066f275e889df6", "c8s/attest-pq/v1+xwing"),
            self.manifests, fixture_text,
        )
        self.assertIn("v1+xwing", verdict)

    def test_the_v0_15_5_commit_shares_the_v0_20_4_manifest(self):
        fixture_text = (
            'let receipt = json!({"xwing_ek": "a", "xwing_ct": "b", "session_id": "c"});'
        )
        verdict = self.module["check_entry"](
            self.entry("2ef376a875010ac98542ab5f2f770aeb95b0082f", "c8s/attest-pq/v1+xwing"),
            self.manifests, fixture_text,
        )
        self.assertIn("v1+xwing", verdict)

    def test_a_gateway_that_builds_both_shapes_at_once_fails_closed(self):
        # c8s serves an identical `version` string on both protocols, so a
        # gateway that still emits both marker sets has not really cut over.
        fixture_text = (
            'json!({"session_pubkey": {"x25519": "a", "mlkem768": "b"}});'
            'json!({"xwing_ek": "a", "xwing_ct": "b", "session_id": "c"});'
        )
        with self.assertRaisesRegex(self.module["LockstepError"], "speak exactly one"):
            self.module["check_entry"](
                self.entry("466ce79e77c2fb6c014620b770066f275e889df6", "c8s/attest-pq/v1+xwing"),
                self.manifests, fixture_text,
            )

    def test_an_unlisted_commit_fails_closed(self):
        fixture_text = 'json!({"session_pubkey": {"x25519": "a", "mlkem768": "b"}});'
        with self.assertRaisesRegex(self.module["LockstepError"], "no protocol manifest"):
            self.module["check_entry"](
                self.entry("c" * 40, "c8s/attest-pq/v1"),
                self.manifests, fixture_text,
            )


if __name__ == "__main__":
    unittest.main()
