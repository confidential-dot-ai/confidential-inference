from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import runpy
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
MODULE = runpy.run_path(str(ROOT / "scripts/verify-public-attestation.py"))
ALLOWLIST_MATCHES_TARGET = MODULE["allowlist_matches_target"]

POLICY_NAME = "tailscale-staging-control-plane"
IMAGE_DIGEST = (
    "sha256:321ce041508c19079b57a28b6666c8d81ab0b08accc0a2585b3ab663d557ac24"
)
IMAGE = f"ghcr.io/tailscale/tailscale@{IMAGE_DIGEST}"
COMMAND = "/usr/local/bin/containerboot"


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class StagingControlAllowlistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.allowlist = json.loads(
            (ROOT / "c8s/allowlists/integration-staging.json").read_text(encoding="utf-8")
        )
        self.release = {
            "workloads": [
                {
                    "name": POLICY_NAME,
                    "image": {
                        "reference": "ghcr.io/tailscale/tailscale",
                        "digest": IMAGE_DIGEST,
                    },
                    "argv": [COMMAND],
                }
            ],
        }

    def matches(self, allowlist: dict) -> bool:
        return ALLOWLIST_MATCHES_TARGET(
            self.release, allowlist, POLICY_NAME, POLICY_NAME, POLICY_NAME
        )

    def test_policy_pins_only_the_named_exact_launch(self) -> None:
        self.assertTrue(self.matches(self.allowlist))
        release = json.loads(
            (ROOT / "releases/integration-staging/release-bundle.json").read_text(
                encoding="utf-8"
            )
        )
        allowlist_bytes = (
            ROOT / "c8s/allowlists/integration-staging.json"
        ).read_bytes()
        self.assertTrue(allowlist_bytes.endswith(b"\n"))
        self.assertEqual(release["allowlistDigest"], digest(allowlist_bytes[:-1]))
        self.assertNotIn(IMAGE_DIGEST, self.allowlist["digests"])
        policy = self.allowlist["workloads"][POLICY_NAME]
        self.assertNotIn("identity", policy)
        self.assertEqual(policy["label"], IMAGE)
        self.assertEqual(policy["initContainers"], [])
        self.assertEqual(len(policy["containers"]), 1)
        container = policy["containers"][0]
        self.assertEqual(container["image"], IMAGE)
        self.assertEqual(container["digest"], IMAGE_DIGEST)
        self.assertEqual(container["command"], {"policy": "exact", "argv": [COMMAND]})
        self.assertEqual(container["args"], {"policy": "deny"})

    def test_wrong_or_missing_digest_fails_closed(self) -> None:
        for mutation in ("wrong", "missing"):
            with self.subTest(mutation=mutation):
                allowlist = copy.deepcopy(self.allowlist)
                container = allowlist["workloads"][POLICY_NAME]["containers"][0]
                if mutation == "wrong":
                    container["digest"] = "sha256:" + "0" * 64
                else:
                    del container["digest"]
                self.assertFalse(self.matches(allowlist))

    def test_wrong_command_or_arguments_fail_closed(self) -> None:
        for field, value in (
            ("command", {"policy": "exact", "argv": ["/bin/sh"]}),
            ("args", {"policy": "exact", "argv": ["--extra"]}),
        ):
            with self.subTest(field=field):
                allowlist = copy.deepcopy(self.allowlist)
                allowlist["workloads"][POLICY_NAME]["containers"][0][field] = value
                self.assertFalse(self.matches(allowlist))

    def test_missing_named_entry_fails_closed(self) -> None:
        allowlist = copy.deepcopy(self.allowlist)
        del allowlist["workloads"][POLICY_NAME]
        self.assertFalse(self.matches(allowlist))

    def test_runtime_mounts_and_environment_remain_unconstrained_until_observed(self) -> None:
        # The private manifest does not contain the full CRI launch shape.
        # Kubernetes adds mounts and environment names. The first staging
        # admission must record these values before an exact policy is safe.
        container = self.allowlist["workloads"][POLICY_NAME]["containers"][0]
        self.assertEqual(container["mounts"], {"policy": "any"})
        self.assertEqual(container["env"], {"policy": "any"})


if __name__ == "__main__":
    unittest.main()
