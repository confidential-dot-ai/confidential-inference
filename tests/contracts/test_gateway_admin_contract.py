import copy
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "contracts" / "gateway-admin.openapi.json"
HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
MUTATIONS = {
    ("/admin/v1/api-keys", "post"),
    ("/admin/v1/api-keys/{keyId}/revoke", "post"),
    ("/admin/v1/api-keys/{keyId}", "delete"),
    ("/admin/v1/api-keys/import", "post"),
    ("/admin/v1/api-keys/freeze", "post"),
    ("/admin/v1/api-keys/unfreeze", "post"),
}


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


def parameter_names(document, operation):
    names = set()
    for parameter in operation.get("parameters", []):
        resolved = resolve_ref(document, parameter)
        names.add((resolved["in"], resolved["name"], resolved.get("required", False)))
    return names


def response_schema(document, operation, status):
    response = resolve_ref(document, operation["responses"][status])
    media = response["content"]["application/json"]
    return resolve_ref(document, media["schema"])


def request_schema(document, operation):
    media = operation["requestBody"]["content"]["application/json"]
    return resolve_ref(document, media["schema"])


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


def validate_mtls_security(document):
    schemes = document["components"]["securitySchemes"]
    signed = schemes.get("adminSignedRequest", {})
    if signed.get("type") != "apiKey" or signed.get("name") != "X-Admin-Signature":
        raise AssertionError("the admin API must require signed requests")
    if document.get("security") != [{"adminSignedRequest": []}]:
        raise AssertionError("the contract must require signed requests globally")
    for path, method, operation in operations(document):
        effective = operation.get("security", document["security"])
        if effective != [{"adminSignedRequest": []}]:
            raise AssertionError(f"{method} {path} does not require only signed requests")
        if "401" not in operation["responses"] or "403" not in operation["responses"]:
            raise AssertionError(f"{method} {path} omits an authentication error response")


def validate_response_secret_boundaries(document):
    forbidden = {"plaintext", "secret", "verifier", "keyhash", "hash", "salt"}
    for path, method, operation in operations(document):
        for status, raw_response in operation["responses"].items():
            response = resolve_ref(document, raw_response)
            content = response.get("content", {}).get("application/json")
            if not content:
                continue
            names = property_names(document, content["schema"])
            normalized = {"".join(character.lower() for character in name if character.isalnum()) for name in names}
            leaked = normalized & forbidden
            if leaked:
                raise AssertionError(f"{method} {path} {status} exposes {sorted(leaked)}")
            if "apiKey" in names and (path, method, status) != (
                "/admin/v1/api-keys",
                "post",
                "201",
            ):
                raise AssertionError(f"{method} {path} {status} exposes the API key")


class GatewayAdminContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = load_contract()

    def test_contract_is_openapi_31_json(self):
        self.assertEqual(self.contract["openapi"], "3.1.0")
        self.assertEqual(
            self.contract["jsonSchemaDialect"],
            "https://json-schema.org/draft/2020-12/schema",
        )
        self.assertEqual(self.contract["x-state-authority"], "unencrypted-persistent-ext4-state-disk")
        self.assertIn("admin-client", self.contract["x-non-authoritative-systems"])

    def test_server_uses_the_c8s_tls_lb_entry_point(self):
        self.assertEqual(
            self.contract["servers"],
            [
                {
                    "url": "https://api.example.invalid",
                    "description": "The c8s tls-lb entry point",
                }
            ],
        )

    def test_every_operation_requires_mtls(self):
        validate_mtls_security(self.contract)

    def test_required_operations_exist(self):
        expected = {
            ("/admin/v1/health", "get"),
            ("/admin/v1/api-keys", "post"),
            ("/admin/v1/api-keys", "get"),
            ("/admin/v1/api-keys/{keyId}/revoke", "post"),
            ("/admin/v1/api-keys/{keyId}", "delete"),
            ("/admin/v1/api-keys/export", "get"),
            ("/admin/v1/api-keys/import", "post"),
            ("/admin/v1/api-keys/freeze", "post"),
            ("/admin/v1/api-keys/unfreeze", "post"),
            ("/admin/v1/api-keys/source", "get"),
            ("/admin/v1/api-keys/snapshot", "put"),
        }
        actual = {(path, method) for path, method, _ in operations(self.contract)}
        self.assertEqual(actual, expected)

    def test_the_snapshot_push_carries_no_second_signature(self):
        """The admin request signature already binds the pushed body. A
        second signature field would add a trust root the gateway does not
        need."""
        snapshot = self.contract["components"]["schemas"]["KeyRegistrySnapshot"]
        self.assertNotIn("signature", snapshot["properties"])
        self.assertFalse(snapshot["additionalProperties"])
        self.assertEqual(
            snapshot["properties"]["schemaVersion"]["const"],
            "confidential.ai/key-registry-snapshot/v1",
        )

    def test_the_snapshot_never_carries_a_plaintext_key(self):
        """The admin VM stores only the peppered hash. No snapshot field
        may hold a plaintext key."""
        key = self.contract["components"]["schemas"]["KeyRegistrySnapshotKey"]
        self.assertFalse(key["additionalProperties"])
        self.assertNotIn("apiKey", key["properties"])
        self.assertNotIn("plaintextKey", key["properties"])
        self.assertIn("keyHash", key["required"])

    def test_the_source_route_reports_the_drift_probe_fields(self):
        """The admin VM reads this route once a minute. It pushes only on
        drift, so the route must report the revision and the pepper
        fingerprint."""
        status = self.contract["components"]["schemas"]["RegistrySourceStatus"]
        for field in ("mode", "cachedRevision", "pepperFingerprint"):
            self.assertIn(field, status["required"])

    def test_create_returns_plaintext_once(self):
        create = self.contract["paths"]["/admin/v1/api-keys"]["post"]
        schema = response_schema(self.contract, create, "201")
        self.assertEqual(set(schema["properties"]), {"apiKey", "metadata"})
        self.assertTrue(schema["properties"]["apiKey"]["x-sensitive"])
        self.assertTrue(schema["properties"]["apiKey"]["x-one-time-response"])
        self.assertIn("apiKey", schema["required"])
        replay_schema = response_schema(self.contract, create, "200")
        self.assertNotIn("apiKey", property_names(self.contract, replay_schema))
        replay = resolve_ref(self.contract, create["responses"]["200"])
        self.assertIn("Idempotency-Replayed", replay["headers"])

        for path, method, operation in operations(self.contract):
            for status in operation["responses"]:
                if (path, method, status) == ("/admin/v1/api-keys", "post", "201"):
                    continue
                response = resolve_ref(self.contract, operation["responses"][status])
                content = response.get("content", {}).get("application/json")
                if content:
                    names = property_names(self.contract, content["schema"])
                    self.assertNotIn("apiKey", names, (path, method, status))

    def test_list_returns_metadata_without_secret_fields(self):
        list_keys = self.contract["paths"]["/admin/v1/api-keys"]["get"]
        names = property_names(self.contract, response_schema(self.contract, list_keys, "200"))
        forbidden = {"apiKey", "plaintext", "secret", "verifier", "keyHash", "salt"}
        self.assertTrue({"id", "name", "prefix", "status", "version"}.issubset(names))
        self.assertFalse(names & forbidden, names & forbidden)

    def test_no_response_schema_leaks_secret_storage_fields(self):
        validate_response_secret_boundaries(self.contract)

    def test_mutations_require_idempotency_and_audit_context(self):
        for path, method in MUTATIONS:
            operation = self.contract["paths"][path][method]
            with self.subTest(path=path, method=method):
                self.assertIn(("header", "Idempotency-Key", True), parameter_names(self.contract, operation))
                schema = request_schema(self.contract, operation)
                if schema is self.contract["components"]["schemas"]["AuditContext"]:
                    audit = schema
                else:
                    self.assertIn("audit", schema["required"])
                    audit = resolve_ref(self.contract, schema["properties"]["audit"])
                self.assertTrue({"actor", "reason"}.issubset(audit["required"]))
                self.assertIn("409", operation["responses"])

    def test_updates_require_optimistic_versions(self):
        update_operations = (
            self.contract["paths"]["/admin/v1/api-keys/{keyId}/revoke"]["post"],
            self.contract["paths"]["/admin/v1/api-keys/{keyId}"]["delete"],
        )
        for operation in update_operations:
            with self.subTest(operation=operation["operationId"]):
                self.assertIn(("header", "If-Match", True), parameter_names(self.contract, operation))
                self.assertIn("412", operation["responses"])
                success = resolve_ref(self.contract, operation["responses"]["200"])
                self.assertIn("ETag", success["headers"])

        for schema_name in ("ApiKeyMetadata",):
            schema = self.contract["components"]["schemas"][schema_name]
            self.assertIn("version", schema["required"])

    def test_health_reports_canonical_disk_readiness(self):
        health = self.contract["paths"]["/admin/v1/health"]["get"]
        schema = response_schema(self.contract, health, "200")
        self.assertEqual(schema["properties"]["status"]["const"], "ready")
        self.assertEqual(
            schema["properties"]["stateAuthority"]["const"],
            "unencrypted-persistent-ext4-state-disk",
        )
        self.assertEqual(schema["properties"]["stateDisk"]["const"], "ready")
        self.assertIn("503", health["responses"])

    def test_security_regression_is_detected(self):
        altered = copy.deepcopy(self.contract)
        altered["security"] = []
        with self.assertRaises(AssertionError):
            validate_mtls_security(altered)

        altered = copy.deepcopy(self.contract)
        altered["paths"]["/admin/v1/health"]["get"]["security"] = []
        with self.assertRaises(AssertionError):
            validate_mtls_security(altered)

    def test_secret_leak_regression_is_detected(self):
        altered = copy.deepcopy(self.contract)
        metadata = altered["components"]["schemas"]["ApiKeyMetadata"]
        metadata["properties"]["verifier"] = {"type": "string"}
        with self.assertRaises(AssertionError):
            validate_response_secret_boundaries(altered)


if __name__ == "__main__":
    unittest.main()
