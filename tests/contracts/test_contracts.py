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


def source_lock_node_image(source_lock: dict, environment: str) -> dict:
    """Return the node image the source lock pins for one environment.

    Each environment seals its own allowlist into its own measured node image.
    `nodeImage` stays as the production entry for an older reader.
    """
    per_environment = source_lock.get("nodeImages")
    if isinstance(per_environment, dict) and per_environment:
        selected = per_environment.get(environment)
        if not isinstance(selected, dict):
            raise ValueError(f"the source lock pins no node image for {environment}")
        return selected
    return source_lock["nodeImage"]


def verify_release_against_source_lock(release: dict, source_lock: dict) -> None:
    node = release["node"]
    pinned = source_lock_node_image(source_lock, release["release"]["environment"])
    if node["image"] != {
        "reference": pinned["reference"],
        "digest": pinned["digest"],
    }:
        raise ValueError("the node image pin does not match the source lock")
    if node["sourceCommit"] != pinned["sourceCommit"]:
        raise ValueError("the node source commit does not match the source lock")
    if node["evidenceArtifactDigest"] != source_lock["nodeEvidenceArtifact"]["digest"]:
        raise ValueError("the node evidence pin does not match the source lock")
    if release["model"]["repository"] != source_lock["model"]["repository"]:
        raise ValueError("the model repository does not match the source lock")
    if release["model"]["revision"] != source_lock["model"]["revision"]:
        raise ValueError("the model revision does not match the source lock")
    if release["model"]["mountVerification"] != source_lock["model"]["mountVerification"]:
        raise ValueError("the model mount verification does not match the source lock")

    workloads = {workload["name"]: workload for workload in release["workloads"]}
    if len(workloads) != len(release["workloads"]):
        raise ValueError("the release contains duplicate workload names")
    for name, role in source_lock["roles"].items():
        workload = workloads.get(name)
        if workload is None:
            raise ValueError(f"the release omits the {name} workload")
        if workload["image"]["reference"] != source_lock["deploymentImage"]["reference"]:
            raise ValueError(f"the {name} image repository does not match the source lock")
        if workload["argv"] != role["argv"]:
            raise ValueError(f"the {name} argv does not match the source lock")


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release_schema = load(ROOT / "contracts/release-bundle.schema.json")
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
        verify_release_against_source_lock(release, self.source_lock)

    def test_each_release_pins_its_own_environment_node_image(self):
        """One node image per environment, because each seals one allowlist."""
        pins = {}
        for environment in ("production", "integration-staging"):
            with self.subTest(environment=environment):
                release = load(ROOT / f"releases/{environment}/release-bundle.json")
                self.assertEqual(release["release"]["environment"], environment)
                pinned = source_lock_node_image(self.source_lock, environment)
                self.assertEqual(release["node"]["image"], {
                    "reference": pinned["reference"],
                    "digest": pinned["digest"],
                })
                self.assertEqual(release["node"]["sourceCommit"], pinned["sourceCommit"])
                pins[environment] = release["node"]["image"]["digest"]
        self.assertNotEqual(pins["production"], pins["integration-staging"])

    def test_the_staging_release_uses_static_c8s_policy(self):
        """Staging seals its allowlist, so it carries no operator commitment."""
        release = load(ROOT / "releases/integration-staging/release-bundle.json")
        self.assertEqual(release["c8s"]["policyMode"], "static")
        for field in ("meshCa", "operatorPublicKeySha256", "operatorKeySetSha256"):
            self.assertNotIn(field, release["c8s"])
        allowlist_path = ROOT / "c8s/allowlists/integration-staging.json"
        digest = "sha256:" + hashlib.sha256(
            allowlist_path.read_bytes().rstrip(b"\n")
        ).hexdigest()
        self.assertEqual(release["allowlistDigest"], digest)

    def test_the_source_lock_keeps_production_as_the_default_node_image(self):
        """An older reader of `nodeImage` still gets production's image."""
        per_environment = self.source_lock.get("nodeImages")
        self.assertIsInstance(per_environment, dict)
        self.assertEqual(
            sorted(per_environment),
            ["conf-inference-prod", "integration-staging", "production"],
        )
        self.assertEqual(self.source_lock["nodeImage"], per_environment["production"])

    def test_front_door_workload_is_pinned_in_trusted_allowlist(self):
        """The c8s TLS-LB receipt must resolve in the trusted policy file."""
        expected_image = (
            "nginxinc/nginx-unprivileged@sha256:"
            "11f3f6249b4ae3d7a4ec2a51797060107b88ead52b33b6ed3c6c33f55ca96200"
        )
        for environment in ("production", "integration-staging"):
            with self.subTest(environment=environment):
                release = load(ROOT / f"releases/{environment}/release-bundle.json")
                allowlist_path = ROOT / f"c8s/allowlists/{environment}.json"
                allowlist = load(allowlist_path)
                allowlist_bytes = allowlist_path.read_bytes()
                self.assertTrue(allowlist_bytes.endswith(b"\n"))
                name = release["c8s"]["frontDoorWorkload"]
                self.assertEqual(name, "c8s-tls-lb")
                actual_workload = dict(allowlist["workloads"].get(name, {}))
                # Current c8s binds the certificate to the exact allowlist
                # workload name. It does not use the removed custom identity
                # field.
                actual_workload.pop("identity", None)
                self.assertTrue(actual_workload.get("containers"))
                if environment == "production":
                    self.assertIn(
                        expected_image,
                        [container["image"] for container in actual_workload["containers"]],
                    )
                for container in actual_workload["containers"]:
                    self.assertEqual(
                        container["image"].split("@", 1)[1],
                        container["digest"],
                    )
                self.assertEqual(
                    "sha256:" + hashlib.sha256(
                        allowlist_bytes[:-1]
                    ).hexdigest(),
                    release["allowlistDigest"],
                )

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

    def test_source_lock_mismatch_is_rejected(self):
        altered = copy.deepcopy(self.production_release)
        workload = next(
            item for item in altered["workloads"] if item["name"] == "sglang-router"
        )
        workload["argv"] = ["python3", "untrusted.py"]
        with self.assertRaisesRegex(ValueError, "argv"):
            verify_release_against_source_lock(altered, self.source_lock)

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
                str(ROOT / "tests/contracts/values-sglang.yaml"),
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


class GatewayInferenceContractTests(unittest.TestCase):
    """Checks contracts/gateway-inference.openapi.json against the gateway source."""

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
        cls.contract = load(ROOT / "contracts/gateway-inference.openapi.json")
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
