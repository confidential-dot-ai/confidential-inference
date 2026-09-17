import hashlib
import json
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/build-release-bundle.py"
CONFIGS = ROOT / "tests/release-v0/image-configs.fixture.json"
INSTALL = ROOT / "tests/release-v0/c8s-install.fixture.json"
VALUES = ROOT / "tests/contracts/values-sglang.yaml"


class ReleaseBundleTests(unittest.TestCase):
    @staticmethod
    def proxy_policy(peer: str) -> dict:
        return {
            "containers": [{
                "command": {"policy": "exact", "argv": ["/workload-proxy"]},
                "args": {"policy": "exact", "argv": ["--peer-workload=" + peer]},
            }],
        }

    def proxy_bindings(self) -> tuple[dict, list[dict]]:
        policies = {
            "gateway-release": self.proxy_policy("router-release"),
            "router-release": self.proxy_policy("gateway-release"),
        }
        targets = [
            {"target": "gateway", "workload": "gateway-release", "identity": "gateway-release"},
            {"target": "sglang-router", "workload": "router-release", "identity": "router-release"},
        ]
        return policies, targets

    def test_install_digest_excludes_allowlist_source_locators(self) -> None:
        module = runpy.run_path(str(SCRIPT))
        install = json.loads(INSTALL.read_text())
        first = module["install_input_digest"](install)
        install["allowlist"]["publicRelease"] = {
            "repository": "https://example.invalid/public.git",
            "commit": "1" * 40,
            "path": "policy.json",
        }
        self.assertEqual(first, module["install_input_digest"](install))
        install["allowlist"]["file"] = "another-reviewed-copy.json"
        self.assertEqual(first, module["install_input_digest"](install))
        install["allowlist"]["digest"] = "sha256:" + "2" * 64
        self.assertNotEqual(first, module["install_input_digest"](install))

    def test_public_release_allowlist_resolves_inside_public_repository(self) -> None:
        module = runpy.run_path(str(SCRIPT))
        install = json.loads(INSTALL.read_text())
        install["allowlist"].pop("file")
        install["allowlist"]["publicRelease"] = {
            "repository": "https://github.com/confidential-dot-ai/confidential-inference",
            "commit": "1" * 40,
            "path": "c8s/allowlists/production.json",
        }
        self.assertEqual(
            module["install_allowlist_path"](install, INSTALL),
            (ROOT / "c8s/allowlists/production.json").resolve(),
        )

    def generated_allowlist_fixture(self) -> tuple[str, dict, dict, dict]:
        module = runpy.run_path(str(SCRIPT))
        install = json.loads(INSTALL.read_text())
        configs = json.loads(CONFIGS.read_text())["images"]
        rendered = subprocess.run(
            [
                "helm", "template", "test", str(ROOT / "helm/confidential-inference"),
                "--namespace", "confidential-inference", "-f", str(VALUES),
                "--set", "gateway.state.enabled=true",
            ], cwd=ROOT, text=True, capture_output=True, check=True,
        ).stdout
        floor_records = {
            item["image"].rpartition("@")[2]: item["image"]
            for item in install["systemFloor"]
        }
        floor = set(floor_records)
        records = module["rendered_mapping_records"](
            rendered, install["workloadMappings"], configs, floor, False,
        )
        workloads = {}
        for name, value in records.items():
            candidates = value["containers"] or value["initContainers"]
            workloads[name] = {
                "label": sorted(candidates, key=module["allowlist_shape"])[0]["image"],
                "initContainers": value["initContainers"],
                "containers": value["containers"],
            }
        return rendered, install, {
            "digests": floor_records, "workloads": workloads,
        }, module

    def run_tool(self, *extra: str) -> tuple[subprocess.CompletedProcess[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "release.json"
        command = [
            "python3", str(SCRIPT), "--release-name", "v0-test",
            "--output", str(output), "--image-configs", str(CONFIGS),
            "--c8s-install-input", str(INSTALL), "--values", str(VALUES),
            "--environment", "production", *extra,
        ]
        return subprocess.run(command, cwd=ROOT, text=True, capture_output=True), output

    def attested_values(self, count: int) -> Path:
        source = VALUES.read_text()
        variant_text = source.replace(
            "gpusPerReplica: 4", f"gpusPerReplica: 4\n  attestedGpuCount: {count}", 1
        )
        self.assertNotEqual(source, variant_text)
        temporary = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        self.addCleanup(lambda: Path(temporary.name).unlink(missing_ok=True))
        with temporary:
            temporary.write(variant_text)
        return Path(temporary.name)

    def test_attested_gpu_count_annotation_overrides_the_allocation(self) -> None:
        values = self.attested_values(8)
        result, output = self.run_tool("--values", str(values), "--fixture")
        self.assertEqual(result.returncode, 0, result.stderr)
        bundle = json.loads(output.read_text())
        workloads = {item["name"]: item for item in bundle["workloads"]}
        self.assertEqual(
            workloads["inference-worker-0"]["gpu"],
            {"required": True, "deviceCount": 8, "architectures": ["BLACKWELL"]},
        )
        # The pod allocation itself is unchanged: tensor parallelism stays at 4.
        self.assertIn("--tp=4", workloads["inference-worker-0"]["argv"])

    def test_attested_gpu_count_below_the_allocation_is_rejected(self) -> None:
        values = self.attested_values(2)
        result, _ = self.run_tool("--values", str(values), "--fixture")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("below the allocated GPU count", result.stderr)

    def test_fixture_bundle_is_deterministic_and_valid(self) -> None:
        first, first_path = self.run_tool("--fixture")
        self.assertEqual(first.returncode, 0, first.stderr)
        first_bytes = first_path.read_bytes()
        second, second_path = self.run_tool("--fixture")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first_bytes, second_path.read_bytes())

        bundle = json.loads(first_bytes)
        schema = json.loads((ROOT / "contracts/release-bundle.schema.json").read_text())
        jsonschema.Draft202012Validator(schema).validate(bundle)
        workloads = {item["name"]: item for item in bundle["workloads"]}
        self.assertEqual(
            set(workloads),
            {
                "gateway", "inference-worker-0",
                "inference-worker-1", "kube-state-metrics",
                "metrics-collector", "sglang-router",
                "gateway-cds-attest", "sglang-router-cds-attest",
                "gateway-router-workload-proxy", "sglang-router-gateway-workload-proxy",
                "inference-worker-0-cds-attest",
                "inference-worker-1-cds-attest",
                "metrics-collector-cds-attest",
                "kube-state-metrics-cds-attest",
            },
        )
        self.assertEqual(workloads["gateway"]["argv"], ["/usr/local/bin/confidential-gateway"])
        self.assertEqual(
            workloads["gateway"]["build"]["dockerfile"],
            "images/gateway/Dockerfile",
        )
        self.assertEqual(
            workloads["inference-worker-0"]["build"]["platform"],
            "linux/amd64",
        )
        self.assertEqual(workloads["sglang-router"]["argv"][:3], ["python3", "-m", "sglang_router.launch_router"])
        self.assertEqual(
            workloads["gateway-router-workload-proxy"]["argv"],
            [
                "/c8s",
                "workload-proxy",
                "--mode=client",
                "--listen=127.0.0.1:30001",
                "--upstream=sglang-router:9443",
                "--peer-workload=sglang-router",
                "--cert-file=/etc/c8s/certs/tls.crt",
                "--key-file=/etc/c8s/certs/tls.key",
                "--ca-file=/etc/c8s/certs/ca.crt",
            ],
        )
        self.assertEqual(
            workloads["sglang-router-gateway-workload-proxy"]["argv"],
            [
                "/c8s",
                "workload-proxy",
                "--mode=server",
                "--listen=0.0.0.0:9443",
                "--upstream=127.0.0.1:30000",
                "--peer-workload=gateway",
                "--cert-file=/etc/c8s/certs/tls.crt",
                "--key-file=/etc/c8s/certs/tls.key",
                "--ca-file=/etc/c8s/certs/ca.crt",
            ],
        )
        self.assertEqual(workloads["inference-worker-0"]["modelDmVerityRoot"], "8" * 64)
        self.assertEqual(
            workloads["inference-worker-0"]["gpu"],
            {"required": True, "deviceCount": 4, "architectures": ["BLACKWELL"]},
        )
        verification = bundle["model"]["mountVerification"]
        self.assertEqual("/models/dsv4", verification["path"])
        self.assertEqual(900, verification["timeoutSeconds"])
        self.assertEqual(
            "6c8f3d2d3b48707541b88f32f22ef3f0f8a6b57d8523281e2b8d3cdb0ae9a023",
            verification["expectedFiles"]["config.json"],
        )
        self.assertEqual("/usr/local/bin/wait-for-model", workloads["inference-worker-0"]["argv"][0])
        self.assertEqual(bundle["c8s"]["sourceCommit"], "615bf738bb44a48f3f249aefd2fe823868e035a7")
        install = json.loads(INSTALL.read_text())
        manifest_value = install["nodeImage"]["manifest"]
        self.assertTrue(manifest_value.startswith("repo://"))
        manifest = json.loads((ROOT / manifest_value.removeprefix("repo://")).read_text())
        self.assertEqual(bundle["c8s"]["measurements"]["rtmr2"], manifest["tdx"]["rtmr2"])
        self.assertEqual(bundle["c8s"]["meshCa"]["certificateSecretName"], "C8S_MESH_CA_CERT_PEM")

    def test_version_one_bundle_remains_valid_without_build_metadata(self) -> None:
        bundle = json.loads(
            (ROOT / "tests/contracts/fixtures/release-bundle.valid.json").read_text()
        )
        bundle["schemaVersion"] = 1
        for workload in bundle["workloads"]:
            workload.pop("build", None)
        schema = json.loads((ROOT / "contracts/release-bundle.schema.json").read_text())
        jsonschema.Draft202012Validator(schema).validate(bundle)

    def test_static_c8s_release_omits_operator_key_commitments(self) -> None:
        module = runpy.run_path(str(SCRIPT))
        install = json.loads(INSTALL.read_text())
        install["c8s"]["policyMode"] = "static"
        allowlist_digest = "sha256:" + hashlib.sha256(
            (ROOT / "tests/release-v0/allowlist.fixture.json").read_bytes().rstrip(b"\n")
        ).hexdigest()
        install["allowlist"]["digest"] = allowlist_digest
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        install_path = Path(temporary.name) / "install.json"
        install_path.write_text(json.dumps(install))
        result = module["c8s_release_input"](
            install_path,
            ROOT / "tests/release-v0/allowlist.fixture.json",
            allowlist_digest,
            "sha256:" + "6" * 64,
            False,
            "production",
        )
        self.assertEqual(result["policyMode"], "static")
        self.assertNotIn("operatorPublicKeySha256", result)
        self.assertNotIn("operatorKeySetSha256", result)
        self.assertNotIn("meshCa", result)

    def test_release_schema_static_mode_forbids_operator_commitments(self) -> None:
        bundle = json.loads(
            (ROOT / "tests/contracts/fixtures/release-bundle.valid.json").read_text()
        )
        bundle["c8s"]["policyMode"] = "static"
        bundle["c8s"].pop("operatorPublicKeySha256")
        bundle["c8s"].pop("operatorKeySetSha256")
        bundle["c8s"].pop("meshCa")
        schema = json.loads((ROOT / "contracts/release-bundle.schema.json").read_text())
        jsonschema.Draft202012Validator(schema).validate(bundle)

        bundle["c8s"]["operatorPublicKeySha256"] = "sha256:" + "4" * 64
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(bundle)

    def test_release_digest_uses_c8s_canonical_bytes(self) -> None:
        canonical_digest = runpy.run_path(str(SCRIPT))["c8s_allowlist_digest"]
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        canonical = b'{"schema":"c8s.allowlist/v1","digests":{},"workloads":{}}'
        allowlist = directory / "allowlist.json"
        allowlist.write_text(
            '{\n  "workloads": {}, "schema": "c8s.allowlist/v1", "digests": {}\n}\n'
        )
        c8s = directory / "c8s"
        c8s.write_text(
            "#!/bin/sh\nprintf '%s' '" + canonical.decode("ascii") + "'\n"
        )
        c8s.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "differs from c8s canonical bytes"):
            canonical_digest(allowlist, str(c8s))
        allowlist.write_bytes(canonical + b"\n")
        self.assertEqual(
            canonical_digest(allowlist, str(c8s)),
            "sha256:" + hashlib.sha256(canonical).hexdigest(),
        )

    def test_real_release_bundles_hash_the_committed_canonical_bytes(self) -> None:
        for environment in ("production", "conf-inference-prod"):
            with self.subTest(environment=environment):
                allowlist = (
                    ROOT / "c8s/allowlists" / f"{environment}.json"
                ).read_bytes()
                self.assertTrue(allowlist.endswith(b"\n"))
                canonical = allowlist[:-1]
                release = json.loads(
                    (
                        ROOT / "releases" / environment / "release-bundle.json"
                    ).read_text()
                )
                self.assertEqual(
                    release["allowlistDigest"],
                    "sha256:" + hashlib.sha256(canonical).hexdigest(),
                )

    def test_attestation_target_uses_the_exact_policy_name(self) -> None:
        c8s_release_input = runpy.run_path(str(SCRIPT))["c8s_release_input"]
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        install = json.loads(INSTALL.read_text())
        gateway = next(
            item for item in install["workloadMappings"]
            if item.get("confidentialWorkloadId") == "gateway"
        )
        gateway["allowlistName"] = "gateway-release-2"
        path = Path(temporary.name) / "install.json"
        path.write_text(json.dumps(install))
        allowlist = Path(temporary.name) / "allowlist.json"
        policy = json.loads(
            (ROOT / "tests/release-v0/allowlist.fixture.json").read_text()
        )
        policy["workloads"]["gateway"]["containers"] = [{
            "command": {"argv": ["/workload-proxy"]},
            "args": {"argv": ["--peer-workload=sglang-router"]},
        }]
        policy["workloads"]["sglang-router"]["containers"] = [{
            "command": {"argv": ["/workload-proxy"]},
            "args": {"argv": ["--peer-workload=gateway-release-2"]},
        }]
        policy["workloads"]["gateway-release-2"] = policy["workloads"].pop("gateway")
        allowlist.write_text(json.dumps(policy))

        result = c8s_release_input(
            path,
            allowlist,
            install["allowlist"]["digest"],
            "sha256:" + "ab" * 32,
            False,
            "production",
        )

        self.assertIn(
            {
                "target": "gateway",
                "workload": "gateway-release-2",
                "identity": "gateway-release-2",
            },
            result["attestationTargets"],
        )

    def test_gateway_proxy_identity_mismatch_fails_closed(self) -> None:
        validate = runpy.run_path(str(SCRIPT))["validate_proxy_identity_bindings"]
        policies, targets = self.proxy_bindings()
        policies["gateway-release"]["containers"][0]["args"]["argv"] = [
            "--peer-workload=wrong-router"
        ]
        with self.assertRaisesRegex(ValueError, "gateway proxy peer workload"):
            validate(policies, targets)

    def test_router_proxy_identity_mismatch_fails_closed(self) -> None:
        validate = runpy.run_path(str(SCRIPT))["validate_proxy_identity_bindings"]
        policies, targets = self.proxy_bindings()
        policies["router-release"]["containers"][0]["args"]["argv"] = [
            "--peer-workload=wrong-gateway"
        ]
        with self.assertRaisesRegex(ValueError, "sglang-router proxy peer workload"):
            validate(policies, targets)

    def test_gateway_target_identity_mismatch_fails_closed(self) -> None:
        validate = runpy.run_path(str(SCRIPT))["validate_proxy_identity_bindings"]
        policies, targets = self.proxy_bindings()
        targets[0]["identity"] = "wrong-gateway"
        with self.assertRaisesRegex(ValueError, "gateway receipt identity"):
            validate(policies, targets)

    def test_router_target_identity_mismatch_fails_closed(self) -> None:
        validate = runpy.run_path(str(SCRIPT))["validate_proxy_identity_bindings"]
        policies, targets = self.proxy_bindings()
        targets[1]["identity"] = "wrong-router"
        with self.assertRaisesRegex(ValueError, "sglang-router receipt identity"):
            validate(policies, targets)

    def test_proxy_target_absence_fails_closed(self) -> None:
        validate = runpy.run_path(str(SCRIPT))["validate_proxy_identity_bindings"]
        policies, targets = self.proxy_bindings()
        targets.pop()
        with self.assertRaisesRegex(ValueError, "missing=.*sglang-router"):
            validate(policies, targets)

    def test_rendered_target_identity_mismatch_fails_closed(self) -> None:
        validate = runpy.run_path(str(SCRIPT))["validate_proxy_identity_bindings"]
        policies, targets = self.proxy_bindings()
        rendered = {"gateway": "wrong-gateway", "sglang-router": "sglang-router"}
        with self.assertRaisesRegex(ValueError, "gateway attestation target identity"):
            validate(policies, targets, rendered)

    def test_rendered_proxy_identity_mismatch_fails_closed(self) -> None:
        validate = runpy.run_path(str(SCRIPT))["validate_proxy_identity_bindings"]
        policies, targets = self.proxy_bindings()
        rendered = [
            {"argv": ["/workload-proxy", "--mode=client", "--peer-workload=wrong-router"]},
            {"argv": ["/workload-proxy", "--mode=server", "--peer-workload=gateway-release"]},
        ]
        with self.assertRaisesRegex(ValueError, "rendered gateway proxy peer workload"):
            validate(policies, targets, rendered_workloads=rendered)

    def test_peer_identity_argument_fails_closed(self) -> None:
        validate = runpy.run_path(str(SCRIPT))["validate_proxy_identity_bindings"]
        policies, targets = self.proxy_bindings()
        policies["gateway-release"]["containers"][0]["args"]["argv"] = [
            "--peer-identity=sglang-router"
        ]
        with self.assertRaisesRegex(ValueError, "must pin one peer workload"):
            validate(policies, targets)

    def test_rendered_image_drift_fails_against_generated_allowlist(self) -> None:
        rendered, install, allowlist, module = self.generated_allowlist_fixture()
        gateway = allowlist["workloads"]["gateway"]["containers"][0]
        gateway["image"] = gateway["image"].replace("133348", "233348", 1)
        gateway["digest"] = "sha256:" + "2" * 64
        with self.assertRaisesRegex(ValueError, "rendered gateway containers"):
            module["validate_rendered_allowlist"](
                rendered, install, allowlist,
                json.loads(CONFIGS.read_text())["images"], False,
            )

    def test_rendered_command_drift_fails_against_generated_allowlist(self) -> None:
        rendered, install, allowlist, module = self.generated_allowlist_fixture()
        gateway = allowlist["workloads"]["gateway"]["containers"][0]
        gateway["command"]["argv"] = ["/usr/local/bin/changed-gateway"]
        with self.assertRaisesRegex(ValueError, "rendered gateway containers"):
            module["validate_rendered_allowlist"](
                rendered, install, allowlist,
                json.loads(CONFIGS.read_text())["images"], False,
            )

    def test_extra_generated_allowlist_policy_fails_closed(self) -> None:
        rendered, install, allowlist, module = self.generated_allowlist_fixture()
        allowlist["workloads"]["unexpected-workload"] = {
            "label": "example.invalid/unexpected@sha256:" + "3" * 64,
            "initContainers": [],
            "containers": [],
        }
        with self.assertRaisesRegex(ValueError, "extra=.*unexpected-workload"):
            module["validate_rendered_allowlist"](
                rendered, install, allowlist,
                json.loads(CONFIGS.read_text())["images"], False,
            )

    def test_declared_c8s_chart_workload_is_not_an_application_extra(self) -> None:
        rendered, install, allowlist, module = self.generated_allowlist_fixture()
        install["externalWorkloadMappings"] = [{
            "allowlistName": "c8s-tls-lb",
            "confidentialWorkloadId": "c8s-tls-lb",
            "controller": "Deployment/c8s-tls-lb",
            "source": {"type": "c8s-chart"},
        }]
        allowlist["workloads"]["c8s-tls-lb"] = {
            "label": "example.invalid/c8s@sha256:" + "3" * 64,
            "initContainers": [],
            "containers": [],
        }
        module["validate_rendered_allowlist"](
            rendered, install, allowlist,
            json.loads(CONFIGS.read_text())["images"], False,
        )

    def test_workload_label_can_select_any_rendered_container(self) -> None:
        # A synthetic two-real-container pod, deliberately not sharing any
        # digest with the c8s floor: neither container is one c8s injects
        # (see validate_rendered_allowlist's floor-digest exclusion), so both
        # are expected main containers and the label may name either.
        module = runpy.run_path(str(SCRIPT))
        app_image = "ghcr.io/confidential-dot-ai/confidential-inference/gateway@sha256:" + "1" * 64
        sidecar_image = "example.invalid/sidecar@sha256:" + "2" * 64
        rendered = json.dumps({
            "kind": "Deployment",
            "metadata": {"name": "gateway"},
            "spec": {"template": {"metadata": {"annotations": {"confidential.ai/cw": "gateway"}}, "spec": {
                "containers": [
                    {"image": app_image, "command": ["/usr/local/bin/confidential-gateway"], "args": []},
                    {"image": sidecar_image, "command": ["/sidecar"], "args": ["--role=aux"]},
                ],
            }}},
        })
        install = json.loads(INSTALL.read_text())
        install["workloadMappings"] = [{
            "allowlistName": "gateway",
            "confidentialWorkloadId": "gateway",
            "controllers": ["Deployment/gateway"],
        }]
        configs = json.loads(CONFIGS.read_text())["images"]
        floor = set(item["image"].rpartition("@")[2] for item in install["systemFloor"])
        records = module["rendered_mapping_records"](
            rendered, install["workloadMappings"], configs, floor, False,
        )
        gateway_records = records["gateway"]["containers"]
        self.assertEqual(len(gateway_records), 2)
        allowlist = {
            "digests": {item["image"].rpartition("@")[2]: item["image"] for item in install["systemFloor"]},
            "workloads": {"gateway": {
                "label": gateway_records[-1]["image"],
                "initContainers": [],
                "containers": gateway_records,
            }},
        }
        module["validate_rendered_allowlist"](rendered, install, allowlist, configs, False)

    def test_extra_rendered_attestation_target_fails_closed(self) -> None:
        validate = runpy.run_path(str(SCRIPT))["validate_proxy_identity_bindings"]
        policies, targets = self.proxy_bindings()
        rendered = {"gateway": "gateway", "sglang-router": "sglang-router", "extra": "extra"}
        with self.assertRaisesRegex(ValueError, "extra=.*extra"):
            validate(policies, targets, rendered)

    def test_node_socket_capability_is_required(self) -> None:
        require = runpy.run_path(str(SCRIPT))["require_node_workload_claims"]
        install = json.loads(INSTALL.read_text())
        install["c8s"]["sourceCommit"] = "d" * 40
        for field, value in (
            ("cvmMode", "kata"),
            ("workloadClaimsHostDir", "/wrong"),
            ("workloadClaimsSocket", "workload-claims.sock"),
            ("capabilities", []),
        ):
            candidate = json.loads(json.dumps(install))
            if field == "cvmMode":
                candidate["cluster"][field] = value
            else:
                candidate["c8s"][field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "node-CVM|workload-claims|baked-node-socket"):
                    require(candidate)

    def test_strict_mode_rejects_an_unready_source(self) -> None:
        result, _ = self.run_tool(
            "--strict", "--allowlist-digest", "sha256:" + "a1" * 32,
            "--model-dm-verity-root", "b2" * 32,
            "--mesh-ca-sha256", "sha256:" + "c3" * 32,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(
            "worktree is not clean" in result.stderr
            or "placeholder digest" in result.stderr
            or "verified image configuration" in result.stderr
            or "strict mode needs --allowlist" in result.stderr,
            result.stderr,
        )

    def test_strict_image_parser_rejects_a_placeholder_digest(self) -> None:
        image_pin = runpy.run_path(str(SCRIPT))["image_pin"]
        with self.assertRaisesRegex(ValueError, "placeholder digest"):
            image_pin("ghcr.io/example/gateway@sha256:" + "1" * 64, True)

    def test_tagged_image_always_fails(self) -> None:
        result, _ = self.run_tool(
            "--fixture", "--helm-set", "images.gateway=ghcr.io/example/gateway:latest"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(
            "uses a tag" in result.stderr or "does not match pattern" in result.stderr.lower(),
            result.stderr,
        )

    def test_sglang_command_change_fails_the_source_lock(self) -> None:
        result, _ = self.run_tool(
            "--fixture", "--helm-set", "router.port=31000"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("argv does not match", result.stderr)

    def test_new_owned_digest_requires_build_provenance(self) -> None:
        image = (
            "ghcr.io/confidential-dot-ai/confidential-inference/sglang@sha256:"
            + "ab" * 32
        )
        result, _ = self.run_tool(
            "--fixture",
            "--helm-set", f"images.sglang={image}",
            "--helm-set", f"images.sglangWorker={image}",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("'build' is a required property", result.stderr)

    def test_wrong_sglang_repository_fails_the_source_lock(self) -> None:
        image = "ghcr.io/example/sglang@sha256:" + "ab" * 32
        result, _ = self.run_tool(
            "--fixture",
            "--helm-set", f"images.sglang={image}",
            "--helm-set", f"images.sglangWorker={image}",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("image repository does not match", result.stderr)

    def test_missing_image_configuration_fails(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        configs = Path(temporary.name) / "empty.json"
        configs.write_text('{"images": {}}\n')
        output = Path(temporary.name) / "release.json"
        result = subprocess.run(
            ["python3", str(SCRIPT), "--fixture", "--release-name", "v0-test",
             "--output", str(output), "--image-configs", str(configs),
             "--c8s-install-input", str(INSTALL), "--values", str(VALUES),
             "--environment", "production"],
            cwd=ROOT, text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("image configuration is missing", result.stderr)

    def test_release_rejects_an_allowlist_outside_the_c8s_input(self) -> None:
        result, _ = self.run_tool(
            "--fixture", "--allowlist-digest", "sha256:" + "9" * 64
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the c8s install input", result.stderr)


if __name__ == "__main__":
    unittest.main()


class SourceLockNodeImageTests(unittest.TestCase):
    """The source lock pins one measured node image per environment."""

    @staticmethod
    def select(lock: dict, environment: str):
        module = runpy.run_path(str(SCRIPT))
        return module["source_lock_node_image"](lock, environment)

    def entry(self, digest_character: str) -> dict:
        return {
            "reference": "ghcr.io/example/node-guest-base",
            "digest": "sha256:" + digest_character * 64,
            "sourceCommit": "a" * 40,
        }

    def test_a_per_environment_entry_wins(self):
        lock = {
            "nodeImage": self.entry("1"),
            "nodeImages": {
                "production": self.entry("1"),
                "staging": self.entry("2"),
            },
        }
        self.assertEqual(self.select(lock, "production"), self.entry("1"))
        self.assertEqual(self.select(lock, "staging"), self.entry("2"))

    def test_an_old_lock_without_per_environment_entries_still_reads(self):
        lock = {"nodeImage": self.entry("3")}
        self.assertEqual(self.select(lock, "production"), self.entry("3"))
        self.assertEqual(self.select(lock, "staging"), self.entry("3"))

    def test_an_unpinned_environment_fails_closed(self):
        lock = {
            "nodeImage": self.entry("1"),
            "nodeImages": {"production": self.entry("1")},
        }
        with self.assertRaises(Exception):
            self.select(lock, "staging")

    def test_a_lock_with_no_node_image_fails_closed(self):
        with self.assertRaises(Exception):
            self.select({}, "production")

    def test_the_committed_lock_pins_both_environments(self):
        lock = json.loads((ROOT / "images/sglang/source.lock").read_text())
        production = self.select(lock, "production")
        staging = self.select(lock, "staging")
        self.assertNotEqual(production["digest"], staging["digest"])
        self.assertEqual(production, lock["nodeImage"])
