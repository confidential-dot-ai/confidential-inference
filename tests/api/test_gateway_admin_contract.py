import copy
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "api" / "gateway-admin.openapi.json"
GATEWAY_ADMIN_ROUTES = ROOT / "services" / "gateway" / "src" / "api_keys.rs"
HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
KEY_SNAPSHOT_PULL = ("/api/gateway/key-snapshot", "get")


def load_contract():
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def resolve_ref(document, value):
    if not isinstance(value, dict) or "$ref" not in value:
        return value
    ref = value["$ref"]
    if not ref.startswith("#/"):
        raise AssertionError(f"external reference is not permitted: {ref}")
    target = document
    for part in ref[2:].split("/"):
        target = target[part.replace("~1", "/").replace("~0", "~")]
    return target


def operations(document):
    for path, path_item in document["paths"].items():
        for method, operation in path_item.items():
            if method in HTTP_METHODS:
                yield path, method, operation


def property_names(document, schema, seen=None):
    seen = set() if seen is None else seen
    if isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if ref in seen:
            return set()
        seen.add(ref)
        return property_names(document, resolve_ref(document, schema), seen)
    if isinstance(schema, dict):
        names = set(schema.get("properties", {}))
        for value in schema.values():
            names.update(property_names(document, value, seen))
        return names
    if isinstance(schema, list):
        names = set()
        for value in schema:
            names.update(property_names(document, value, seen))
        return names
    return set()


ADMIN_SECURITY = [{"adminApiKey": []}, {"adminSignedRequest": []}]


def validate_security(document):
    """Every gateway route requires an admin API key or the v1 request
    signature. The one route the admin serves (the key snapshot pull)
    requires the gateway bearer token."""
    schemes = document["components"]["securitySchemes"]
    signed = schemes.get("adminSignedRequest", {})
    if signed.get("type") != "apiKey" or signed.get("name") != "X-Admin-Signature":
        raise AssertionError("the admin API must define the v1 request signature")
    if schemes.get("adminApiKey", {}).get("scheme") != "bearer":
        raise AssertionError("the admin API must define the admin API key")
    if schemes.get("gatewayBearerToken", {}).get("scheme") != "bearer":
        raise AssertionError("the key snapshot pull must require a bearer token")
    if document.get("security") != ADMIN_SECURITY:
        raise AssertionError("the contract must require admin authentication globally")
    for path, method, operation in operations(document):
        expected = (
            [{"gatewayBearerToken": []}]
            if (path, method) == KEY_SNAPSHOT_PULL
            else ADMIN_SECURITY
        )
        if operation.get("security", document["security"]) != expected:
            raise AssertionError(f"{method} {path} does not require {expected}")
        if "401" not in operation["responses"]:
            raise AssertionError(f"{method} {path} omits the authentication error response")


def validate_response_secret_boundaries(document):
    """No response carries a plaintext key, the pepper or another secret. The
    snapshot rows carry `keyHash`, the peppered HMAC the gateway verifies
    against; it is not a secret on its own."""
    forbidden = {"apikey", "plaintext", "plaintextkey", "secret", "pepper", "token", "salt"}
    for path, method, operation in operations(document):
        for status, raw_response in operation["responses"].items():
            response = resolve_ref(document, raw_response)
            content = response.get("content", {}).get("application/json")
            if not content:
                continue
            names = property_names(document, content["schema"])
            normalized = {"".join(c.lower() for c in name if c.isalnum()) for name in names}
            leaked = normalized & forbidden
            if leaked:
                raise AssertionError(f"{method} {path} {status} exposes {sorted(leaked)}")


class GatewayAdminContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = load_contract()

    def test_contract_is_openapi_31_json(self):
        self.assertEqual(self.contract["openapi"], "3.1.0")
        self.assertEqual(
            self.contract["jsonSchemaDialect"],
            "https://json-schema.org/draft/2020-12/schema",
        )
        self.assertEqual(self.contract["x-state-authority"], "admin-key-registry")
        self.assertEqual(self.contract["x-non-authoritative-systems"], ["gateway"])

    def test_gateway_routes_use_the_c8s_tls_lb_entry_point(self):
        self.assertEqual(
            self.contract["servers"],
            [{"url": "https://api.example.invalid", "description": "The c8s tls-lb entry point"}],
        )
        pull = self.contract["paths"][KEY_SNAPSHOT_PULL[0]]
        self.assertEqual(pull["servers"][0]["url"], "https://admin.example.invalid")

    def test_security(self):
        validate_security(self.contract)

    def test_gateway_paths_match_the_gateway_admin_router(self):
        source = GATEWAY_ADMIN_ROUTES.read_text(encoding="utf-8")
        routed = set(re.findall(r'\.route\(\s*"([^"]+)",\s*(get|put|post|delete)\(', source))
        self.assertTrue(routed, "no .route(...) calls found in api_keys.rs")
        served = {
            (path, method)
            for path, method, _ in operations(self.contract)
            if (path, method) != KEY_SNAPSHOT_PULL
        }
        self.assertEqual(served, routed)

    def test_pull_and_push_carry_the_same_snapshot(self):
        pull = self.contract["paths"][KEY_SNAPSHOT_PULL[0]]["get"]["responses"]["200"]
        push = self.contract["paths"]["/admin/v1/api-keys/snapshot"]["put"]["requestBody"]
        self.assertEqual(
            pull["content"]["application/json"]["schema"],
            push["content"]["application/json"]["schema"],
        )

    def test_the_snapshot_carries_no_second_signature(self):
        snapshot = self.contract["components"]["schemas"]["KeyRegistrySnapshot"]
        self.assertNotIn("signature", snapshot["properties"])
        self.assertFalse(snapshot["additionalProperties"])
        self.assertEqual(
            snapshot["properties"]["schemaVersion"]["const"],
            "confidential.ai/key-registry-snapshot/v1",
        )

    def test_the_snapshot_never_carries_a_plaintext_key(self):
        key = self.contract["components"]["schemas"]["KeyRegistrySnapshotKey"]
        self.assertFalse(key["additionalProperties"])
        self.assertNotIn("apiKey", key["properties"])
        self.assertNotIn("plaintextKey", key["properties"])
        self.assertIn("keyHash", key["required"])

    def test_the_source_route_reports_the_drift_probe_fields(self):
        status = self.contract["components"]["schemas"]["RegistrySourceStatus"]
        for field in ("cachedRevision", "pepperFingerprint"):
            self.assertIn(field, status["required"])
        self.assertNotIn("mode", status["properties"])

    def test_no_response_schema_leaks_secrets(self):
        validate_response_secret_boundaries(self.contract)

    def test_security_regression_is_detected(self):
        altered = copy.deepcopy(self.contract)
        altered["security"] = []
        with self.assertRaises(AssertionError):
            validate_security(altered)

        altered = copy.deepcopy(self.contract)
        altered["paths"]["/admin/v1/health"]["get"]["security"] = []
        with self.assertRaises(AssertionError):
            validate_security(altered)

    def test_secret_leak_regression_is_detected(self):
        altered = copy.deepcopy(self.contract)
        status = altered["components"]["schemas"]["RegistrySourceStatus"]
        status["properties"]["pepper"] = {"type": "string"}
        with self.assertRaises(AssertionError):
            validate_response_secret_boundaries(altered)


if __name__ == "__main__":
    unittest.main()
