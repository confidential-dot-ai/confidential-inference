"""Check that the production static allowlist digest stays current.

`c8s/production-values.yaml` pins the canonical digest of
`c8s/allowlists/production.json` in `attestationReceipts.
expectedStaticAllowlistSha256`. A stale digest here is a silent policy
drift: the value never fails a render, it only fails a real verify at
attestation time. This test recomputes the canonical digest with the
pinned c8s binary and compares it against the pinned field, so drift
fails here instead.

The pinned binary is not part of this repository. Set C8S_BINARY to its
path. There is no default path. When the variable is unset, or names a
path that is not a file, this test skips with a clear reason instead of
failing.
"""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
VALUES_PATH = ROOT / "c8s/production-values.yaml"
ALLOWLIST_PATH = ROOT / "c8s/allowlists/production.json"
C8S_BINARY_ENV = "C8S_BINARY"


def find_c8s_binary() -> Path | None:
    """Return the pinned c8s binary, or None when it is absent.

    The path comes only from the environment. A maintainer path must not
    become a default in this repository.
    """
    configured = os.environ.get(C8S_BINARY_ENV)
    if not configured:
        return None
    candidate = Path(configured)
    return candidate if candidate.is_file() else None


class ProductionAllowlistDigestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.binary = find_c8s_binary()
        if self.binary is None:
            self.skipTest(
                f"no pinned c8s binary found; set {C8S_BINARY_ENV} to the "
                "path of the pinned c8s binary"
            )

    def test_pinned_digest_matches_the_canonical_allowlist_digest(self) -> None:
        result = subprocess.run(
            [str(self.binary), "allowlist", "digest", str(ALLOWLIST_PATH)],
            capture_output=True,
            text=True,
            check=True,
        )
        canonical_digest = "sha256:" + result.stdout.strip()

        values = yaml.safe_load(VALUES_PATH.read_text(encoding="utf-8"))
        pinned_digest = values["attestationReceipts"]["expectedStaticAllowlistSha256"]

        self.assertEqual(
            pinned_digest,
            canonical_digest,
            "c8s/production-values.yaml expectedStaticAllowlistSha256 is stale; "
            "recompute it with `c8s allowlist digest c8s/allowlists/production.json` "
            "and update the field",
        )


if __name__ == "__main__":
    unittest.main()
