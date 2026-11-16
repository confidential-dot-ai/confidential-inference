import ast
import copy
import hashlib
import json
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
        cls.source_lock = load(ROOT / "images/sglang-confidential/source.lock")

    def test_source_lock_has_required_immutable_pins(self):
        lock = self.source_lock
        self.assertRegex(lock["source"]["commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(lock["source"]["upstream"]["commit"], r"^[0-9a-f]{40}$")
        for image in (lock["image"], lock["uv"]):
            self.assertRegex(image["digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(lock["deploymentImage"], {
            "reference": "ghcr.io/confidential-dot-ai/confidential-inference/sglang-confidential",
        })
        self.assertEqual(lock["python"]["requirementsLockSha256"], hashlib.sha256(
            (ROOT / "images/sglang-confidential/requirements.lock").read_bytes()).hexdigest())


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
        cls.gateway_source = (ROOT / "services/gateway/gateway/app.py").read_text(encoding="utf-8")
        cls.key_source = (ROOT / "services/gateway/gateway/keys.py").read_text(encoding="utf-8")

    def test_contract_is_valid_json(self):
        self.assertEqual(self.contract["openapi"], "3.1.0")
        self.assertIn("paths", self.contract)

    def test_key_limit_errors_are_documented(self):
        """The 429 response lists the per-key limit codes that the key policy emits."""
        capacity = self.contract["components"]["responses"]["InferenceCapacity"]
        codes = {
            example["value"]["error"]["code"]
            for example in capacity["content"]["application/json"]["examples"].values()
        }
        for code in ("rate_limit_exceeded", "insufficient_quota"):
            self.assertIn(code, codes)
            self.assertIn(f'"{code}"', self.key_source)

    def test_expected_paths_are_present(self):
        self.assertEqual(set(self.contract["paths"]), self.EXPECTED_PATHS)

    def test_paths_match_the_gateway_route_table(self):
        """Public application routes must equal the non-C8s paths in the API."""
        routed_paths = {
            node.args[0].value
            for node in ast.walk(ast.parse(self.gateway_source))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "web"
            and node.func.attr in ("get", "post", "put") and node.args
            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
            and not node.args[0].value.startswith("/admin/")
        }
        self.assertTrue(routed_paths)
        served_spec_paths = {
            path
            for path, item in self.contract["paths"].items()
            for operation in item.values()
            if "tls-lb-static" not in operation.get("tags", [])
        }
        self.assertEqual(served_spec_paths, routed_paths)



if __name__ == "__main__":
    unittest.main()
