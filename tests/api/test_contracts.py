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
        cls.release_schema = load(ROOT / "api/release-bundle.schema.json")
        cls.release = load(FIXTURES / "release-bundle.valid.json")
        cls.production_release = load(ROOT / "releases/production/release-bundle.json")
        cls.source_lock = load(ROOT / "images/sglang/source.lock")

        jsonschema.Draft202012Validator.check_schema(cls.release_schema)

    def test_valid_release_bundle(self):
        release = self.production_release
        validate(release, self.release_schema)

        names = [workload["name"] for workload in release["workloads"]]
        self.assertEqual(len(names), len(set(names)))
        for workload in release["workloads"]:
            if workload["name"].startswith("inference-worker-"):
                self.assertEqual(
                    workload["modelDmVerityRoot"], release["model"]["dmVerityRoot"]
                )

    def test_staging_allowlist_reproduces_from_the_committed_policy(self):
        """Staging moved to operator mode on c8s v0.20.4: no sealed release
        bundle is committed yet (the release flow builds and signs it), but
        the generated allowlist must still match the committed policy."""
        allowlist_path = ROOT / "c8s/allowlists/staging.json"
        policy = load(ROOT / "c8s/staging-policy.json")
        self.assertEqual(policy["environment"], "staging")
        self.assertEqual(policy["c8s"]["cvmMode"], "bare-metal")
        digest = "sha256:" + hashlib.sha256(
            allowlist_path.read_bytes().rstrip(b"\n")
        ).hexdigest()
        self.assertTrue(digest.startswith("sha256:"))

    def test_the_source_lock_keeps_production_as_the_default_node_image(self):
        """An older reader of `nodeImage` still gets production's image."""
        per_environment = self.source_lock.get("nodeImages")
        self.assertIsInstance(per_environment, dict)
        self.assertEqual(
            sorted(per_environment),
            ["candidate", "conf-inference-prod", "production", "staging"],
        )
        self.assertEqual(self.source_lock["nodeImage"], per_environment["production"])

    def test_release_rejects_tag_in_place_of_digest(self):
        for digest in ("latest", "sha256:" + "A" * 64, "sha256:" + "a" * 63, "sha512:" + "a" * 64):
            with self.subTest(digest=digest):
                altered = copy.deepcopy(self.release)
                altered["workloads"][0]["image"]["digest"] = digest
                with self.assertRaises(jsonschema.ValidationError):
                    validate(altered, self.release_schema)

    def test_release_rejects_tagged_or_digest_qualified_reference(self):
        for reference in (
            "docker.io/lmsysorg/sglang:latest",
            "docker.io/lmsysorg/sglang@sha256:" + "a" * 64,
        ):
            with self.subTest(reference=reference):
                altered = copy.deepcopy(self.release)
                altered["workloads"][1]["image"]["reference"] = reference
                with self.assertRaises(jsonschema.ValidationError):
                    validate(altered, self.release_schema)

    def test_schemas_reject_missing_required_fields(self):
        for field in ("schemaVersion", "release", "source", "node", "c8s", "allowlistDigest", "model", "workloads"):
            with self.subTest(contract="release", field=field):
                altered = copy.deepcopy(self.release)
                del altered[field]
                with self.assertRaises(jsonschema.ValidationError):
                    validate(altered, self.release_schema)

        nested_cases = (
            (self.release, self.release_schema, ("node", "evidenceArtifactDigest")),
            (self.release, self.release_schema, ("model", "dmVerityRoot")),
            (self.release, self.release_schema, ("c8s", "operatorKeySetSha256")),
            (self.release, self.release_schema, ("c8s", "frontDoorWorkload")),
        )
        for instance, schema, (parent, field) in nested_cases:
            with self.subTest(parent=parent, field=field):
                altered = copy.deepcopy(instance)
                del altered[parent][field]
                with self.assertRaises(jsonschema.ValidationError):
                    validate(altered, schema)

        gpu_case = copy.deepcopy(self.release)
        gpu_case["workloads"][0]["gpu"] = {
            "required": True, "deviceCount": 1, "architectures": ["BLACKWELL"]
        }
        for field in ("required", "deviceCount", "architectures"):
            with self.subTest(parent="workloads[0].gpu", field=field):
                altered = copy.deepcopy(gpu_case)
                del altered["workloads"][0]["gpu"][field]
                with self.assertRaises(jsonschema.ValidationError):
                    validate(altered, self.release_schema)

    def test_source_lock_has_required_immutable_pins(self):
        lock = load(ROOT / "images/sglang/source.lock")
        self.assertRegex(lock["source"]["commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(lock["model"]["revision"], r"^[0-9a-f]{40}$")
        self.assertRegex(lock["image"]["digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            lock["deploymentImage"],
            {"reference": "ghcr.io/confidential-dot-ai/confidential-inference/sglang"},
        )
        self.assertRegex(lock["nodeImage"]["digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(
            lock["nodeEvidenceArtifact"]["digest"], r"^sha256:[0-9a-f]{64}$"
        )
        self.assertEqual(
            set(lock["nodeEvidenceArtifacts"]),
            {"candidate", "conf-inference-prod", "production", "staging"},
        )
        for artifact in lock["nodeEvidenceArtifacts"].values():
            self.assertRegex(artifact["digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            set(lock["roles"]),
            {"sglang-router", "inference-worker-0", "inference-worker-1"},
        )
        for role in lock["roles"].values():
            self.assertEqual(set(role), {"argv"})
            self.assertTrue(role["argv"])

    def test_source_lock_matches_rendered_production_argv(self):
        output = subprocess.run(
            [
                "helm",
                "template",
                "v0",
                str(ROOT / "helm/confidential-inference"),
                "--namespace",
                "confidential-inference",
                "-f",
                str(ROOT / "tests/api/values-sglang.yaml"),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        documents = [document for document in yaml.safe_load_all(output) if document]
        router = next(
            document for document in documents
            if document.get("kind") == "Deployment" and document["metadata"]["name"] == "sglang-router"
        )
        workers = {
            document["metadata"]["name"]: document
            for document in documents
            if document.get("kind") == "StatefulSet"
            and document["metadata"]["name"] in {"inference-worker-0", "inference-worker-1"}
        }
        rendered = {
            "sglang-router": router["spec"]["template"]["spec"]["containers"][0],
            "inference-worker-0": workers["inference-worker-0"]["spec"]["template"]["spec"]["containers"][0],
            "inference-worker-1": workers["inference-worker-1"]["spec"]["template"]["spec"]["containers"][0],
        }
        self.assertEqual(set(rendered), set(self.source_lock["roles"]))
        for name, role in self.source_lock["roles"].items():
            container = rendered[name]
            self.assertEqual(container.get("command", []) + container.get("args", []), role["argv"])


class WorkloadAttestationFixtureTests(unittest.TestCase):
    """Both c8s protocol shapes must validate against the one shared schema."""

    @classmethod
    def setUpClass(cls):
        cls.schema = load(ROOT / "api/workload-attestation.schema.json")
        jsonschema.Draft202012Validator.check_schema(cls.schema)

    def test_production_fixture_is_valid(self):
        # Old protocol (c8s 079aeb48, still running conf-inference-prod
        # today): session_pubkey receipts, a digests-bearing allowlist
        # document, and a release-matched operator key set.
        fixture = load(FIXTURES / "workload-attestation.valid.json")
        validate(fixture, self.schema)
        self.assertNotIn("attestationProtocol", fixture["c8s"])
        self.assertIn("digests", fixture["c8s"]["activeAllowlist"]["document"])

    def test_v0_20_4_fixture_is_valid(self):
        # New protocol (c8s 466ce79 / 2ef376a8): xwing receipts, a folded
        # allowlist document with no digests key, and the honest
        # requires-attested-cds-read operator status.
        fixture = load(FIXTURES / "workload-attestation.v0-20-4.valid.json")
        validate(fixture, self.schema)
        self.assertEqual(fixture["c8s"]["attestationProtocol"], "c8s/attest-pq/v1+xwing")
        self.assertNotIn("digests", fixture["c8s"]["activeAllowlist"]["document"])
        self.assertEqual(
            fixture["c8s"]["operatorTrust"]["activeKeySetStatus"],
            "requires-attested-cds-read",
        )
        self.assertEqual(fixture["gpuEvidence"]["status"], "not-exposed-by-c8s")

    def test_v3_metadata_fixture_is_valid(self):
        fixture = load(FIXTURES / "workload-attestation.v3.valid.json")
        validate(fixture, self.schema)
        self.assertEqual(set(fixture), {"schemaVersion", "release", "c8s"})
        self.assertEqual(set(fixture["c8s"]), {"activeAllowlist", "discovery", "operatorKeys"})

    def test_v3_rejects_removed_fields_and_missing_sources(self):
        fixture = load(FIXTURES / "workload-attestation.v3.valid.json")
        for field in ("nonce", "receipts", "scope", "operationalStatus", "gpuEvidence", "tls"):
            with self.subTest(field=field):
                changed = copy.deepcopy(fixture)
                changed[field] = []
                with self.assertRaises(jsonschema.ValidationError):
                    validate(changed, self.schema)
        for field in ("activeAllowlist", "discovery", "operatorKeys"):
            with self.subTest(missing=field):
                changed = copy.deepcopy(fixture)
                del changed["c8s"][field]
                with self.assertRaises(jsonschema.ValidationError):
                    validate(changed, self.schema)


class GatewayInferenceContractTests(unittest.TestCase):
    """Checks api/gateway-inference.openapi.json against the gateway source."""

    EXPECTED_PATHS = {
        "/health",
        "/ready",
        "/v1/models",
        "/v1/chat/completions",
        "/v1/completions",
        "/attestation",
        "/v1/attestation",
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
