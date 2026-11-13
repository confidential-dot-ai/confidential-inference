import copy
import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate(instance: dict, schema: dict) -> None:
    jsonschema.validate(
        instance,
        schema,
        format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER,
    )


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_lock = load(ROOT / "images/sglang/source.lock")

    def test_source_lock_has_required_immutable_pins(self):
        lock = self.source_lock
        self.assertRegex(lock["source"]["commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(lock["source"]["upstream"]["commit"], r"^[0-9a-f]{40}$")
        for image in (lock["image"], lock["uv"]):
            self.assertRegex(image["digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(lock["deploymentImage"], {
            "reference": "ghcr.io/confidential-dot-ai/confidential-inference/sglang",
        })
        self.assertEqual(lock["python"]["requirementsLockSha256"], hashlib.sha256(
            (ROOT / "images/sglang/requirements.lock").read_bytes()).hexdigest())


class GatewayInferenceContractTests(unittest.TestCase):
    """Checks api/gateway-inference.openapi.json against the gateway source."""

    EXPECTED_PATHS = {
        "/health",
        "/ready",
        "/v1/models",
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/responses",
        "/v1/discovery",
        "/.well-known/cds-cert.pem",
        "/.well-known/mesh-ca.pem",
        "/.well-known/c8s/{path}",
        "/allowlist",
        "/readyz",
        "/healthz",
    }

    @classmethod
    def setUpClass(cls):
        cls.contract = load(ROOT / "api/gateway-inference.openapi.json")
        cls.gateway_source = (
            ROOT / "services/gateway/src/lib.rs"
        ).read_text(encoding="utf-8")

    def test_contract_is_valid_json(self):
        self.assertEqual(self.contract["openapi"], "3.1.0")
        self.assertIn("paths", self.contract)

    def test_expected_paths_are_present(self):
        self.assertEqual(set(self.contract["paths"]), self.EXPECTED_PATHS)

    def test_paths_match_the_gateway_route_table(self):
        """The Rust-served paths in the spec must equal the .route(...) table in lib.rs."""
        routed_paths = set(
            re.findall(r'\.route\(\s*"([^"]+)"', self.gateway_source)
        )
        self.assertTrue(routed_paths, "no .route(...) calls found in lib.rs")

        rust_served_spec_paths = {
            path
            for path, item in self.contract["paths"].items()
            for operation in item.values()
            if "tls-lb-static" not in operation.get("tags", [])
        }
        self.assertEqual(rust_served_spec_paths, routed_paths)


if __name__ == "__main__":
    unittest.main()
