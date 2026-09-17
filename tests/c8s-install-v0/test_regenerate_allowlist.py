from __future__ import annotations

import json
from pathlib import Path
import runpy
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/regenerate-c8s-allowlist.py"
POLICY_PATH = ROOT / "c8s/production-policy.json"
STAGING_POLICY_PATH = ROOT / "c8s/staging-policy.json"


class RegenerateAllowlistTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = runpy.run_path(str(SCRIPT))
        cls.policy = cls.module["load_policy"](POLICY_PATH)
        cls.staging_policy = cls.module["load_policy"](STAGING_POLICY_PATH)

    def test_public_policy_is_repository_local(self) -> None:
        self.assertEqual(self.policy["output"], "c8s/allowlists/production.json")
        self.assertEqual(self.policy["chart"]["values"], "c8s/production-values.yaml")
        self.assertNotIn("private", SCRIPT.read_text().lower())
        self.assertNotIn("internal", SCRIPT.read_text().lower())

    def test_public_binding_rejects_staging_output(self) -> None:
        error = self.module["RegenerationError"]
        with self.assertRaisesRegex(error, "--output"):
            self.module["validate_binding"](
                self.policy, ROOT / "c8s/allowlists/staging.json"
            )

    def test_staging_policy_is_repository_local(self) -> None:
        self.assertEqual(
            self.staging_policy["output"], "c8s/allowlists/staging.json"
        )
        self.assertEqual(
            self.staging_policy["chart"]["values"], "c8s/staging-values.yaml"
        )
        self.assertEqual(self.staging_policy["environment"], "staging")

    def test_staging_binding_rejects_production_output(self) -> None:
        error = self.module["RegenerationError"]
        with self.assertRaisesRegex(error, "--output"):
            self.module["validate_binding"](
                self.staging_policy, ROOT / "c8s/allowlists/production.json"
            )

    def test_config_allowlist_rejects_an_arbitrary_path(self) -> None:
        error = self.module["RegenerationError"]
        with self.assertRaisesRegex(error, "--config must be one of"):
            self.module["load_policy"](ROOT / "c8s/production-policy.schema.json")

    def test_config_allowlist_accepts_both_public_policies(self) -> None:
        for path in (POLICY_PATH, STAGING_POLICY_PATH):
            with self.subTest(path=path):
                loaded = self.module["load_policy"](path)
                self.assertIn(loaded["environment"], ("production", "staging"))

    def test_parse_args_leaves_output_unset_by_default(self) -> None:
        argv = sys.argv
        sys.argv = ["regenerate-c8s-allowlist.py", "--c8s", "/tmp/pinned-c8s"]
        try:
            args = self.module["parse_args"]()
        finally:
            sys.argv = argv
        self.assertIsNone(args.output)
        self.assertEqual(args.config, POLICY_PATH)

    def test_generate_defaults_output_from_the_policy_when_omitted(self) -> None:
        module_globals = self.module["generate"].__globals__
        seen: dict[str, Path] = {}
        real_validate_binding = self.module["validate_binding"]

        def spy_validate_binding(policy, output):
            seen["output"] = output
            raise self.module["RegenerationError"]("stop after binding check")

        with mock.patch.dict(module_globals, {"validate_binding": spy_validate_binding}):
            with self.assertRaises(self.module["RegenerationError"]):
                self.module["generate"](STAGING_POLICY_PATH, None, Path("/tmp/pinned-c8s"))
        self.assertEqual(
            seen["output"], (ROOT / "c8s/allowlists/staging.json").resolve()
        )

    def test_application_policy_has_no_identity_and_keeps_exact_peer_names(self) -> None:
        docs = [{
            "kind": "Deployment",
            "metadata": {"name": "gateway"},
            "spec": {"template": {"metadata": {"annotations": {}}, "spec": {
                "containers": [{
                    "image": "ghcr.io/confidential-dot-ai/confidential-inference/gateway@sha256:" + "1" * 64,
                    "command": ["/usr/local/bin/confidential-gateway"],
                    "args": [],
                }],
            }}},
            "spec": {"template": {"metadata": {"annotations": {}}, "spec": {
                "containers": [{
                    "image": "ghcr.io/confidential-dot-ai/confidential-inference/gateway@sha256:" + "1" * 64,
                    "command": ["/usr/local/bin/confidential-gateway"],
                    "args": [],
                }],
            }}},
        }]
        # Use a small policy to isolate workload derivation.
        policy = {
            "systemImages": {},
            "workloads": [{"name": "gateway", "controller": "Deployment/gateway"}],
            "imageConfigs": {
                docs[0]["spec"]["template"]["spec"]["containers"][0]["image"]: [{
                    "command": ["/usr/local/bin/confidential-gateway"], "args": []
                }]
            },
        }
        result = self.module["application_allowlist"](policy, docs)
        self.assertNotIn("identity", result["workloads"]["gateway"])
        self.assertEqual(
            result["workloads"]["gateway"]["containers"][0]["command"]["argv"],
            ["/usr/local/bin/confidential-gateway"],
        )

    def test_application_policy_drops_the_c8s_attestation_sidecar(self) -> None:
        # cds-attest runs on a floor image (c8s-operator, admitted under any
        # argv by the system floor) with argv[0] == "/c8s", one of c8s's
        # InjectedEntrypoints. c8s's own WorkloadContainers drops such a
        # container before workload matching runs, so a tenant workload entry
        # must not declare it as a main container either -- declaring it
        # there makes the entry permanently unmatchable (ErrNoMatch), because
        # the container c8s reports never includes it. See the 2026-09-17
        # staging mesh diagnosis deployment receipt.
        sidecar_image = "example.invalid/c8s-operator@sha256:" + "2" * 64
        app_image = "example.invalid/gateway@sha256:" + "3" * 64
        sidecar_args = ["cds-attest", "--expected-workload=gateway"]
        docs = [{
            "kind": "Deployment",
            "metadata": {"name": "gateway"},
            "spec": {"template": {"metadata": {"annotations": {}}, "spec": {
                "containers": [
                    {"image": app_image, "command": ["/usr/local/bin/gateway"], "args": []},
                    {"image": sidecar_image, "command": ["/c8s"], "args": sidecar_args},
                ],
            }}},
        }]
        policy = {
            "systemImages": {sidecar_image: sidecar_image},
            "workloads": [{"name": "gateway", "controller": "Deployment/gateway"}],
            "imageConfigs": {
                sidecar_image: [{"command": ["/c8s"], "args": sidecar_args}],
                app_image: [{"command": ["/usr/local/bin/gateway"], "args": []}],
            },
        }
        result = self.module["application_allowlist"](policy, docs)
        containers = result["workloads"]["gateway"]["containers"]
        self.assertEqual(len(containers), 1)
        self.assertEqual(containers[0]["image"], app_image)

    def test_application_policy_keeps_a_sidecar_sharing_a_floor_image_when_not_injected(self) -> None:
        # A container on a floor image whose command is not one of c8s's
        # InjectedEntrypoints (for example the mesh's workload-proxy) is never
        # dropped by WorkloadContainers, so it must stay a declared main
        # container.
        image = "example.invalid/c8s-operator@sha256:" + "4" * 64
        args = ["--mode=server", "--listen=0.0.0.0:9443"]
        docs = [{
            "kind": "Deployment",
            "metadata": {"name": "gateway"},
            "spec": {"template": {"metadata": {"annotations": {}}, "spec": {
                "containers": [{"image": image, "command": ["/workload-proxy"], "args": args}],
            }}},
        }]
        policy = {
            "systemImages": {image: image},
            "workloads": [{"name": "gateway", "controller": "Deployment/gateway"}],
            "imageConfigs": {image: [{"command": ["/workload-proxy"], "args": args}]},
        }
        result = self.module["application_allowlist"](policy, docs)
        containers = result["workloads"]["gateway"]["containers"]
        self.assertEqual(len(containers), 1)
        self.assertEqual(containers[0]["args"]["argv"], args)

    def test_composer_uses_render_allowlist_and_canonicalizer(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command: list[str], _cwd: Path = ROOT) -> bytes:
            calls.append(command)
            if command[1] == "render-allowlist":
                return b'{"schema":"c8s.allowlist/v1","digests":{},"workloads":{}}'
            return b'{"schema":"c8s.allowlist/v1","digests":{},"workloads":{}}'

        with mock.patch.dict(self.module["compose"].__globals__, {"run_bytes": fake_run}):
            output = self.module["compose"](
                self.policy, Path("/tmp/pinned-c8s"), b'{"schema":"c8s.allowlist/v1","digests":{},"workloads":{}}'
            )
        self.assertEqual(json.loads(output)["schema"], "c8s.allowlist/v1")
        self.assertEqual(calls[0][1:3], ["render-allowlist", "--cvm-mode"])
        self.assertIn("--bootstrap-allowlist", calls[0])
        self.assertIn("--kube-version", calls[0])
        self.assertEqual(calls[0][calls[0].index("--kube-version") + 1], "1.32.0")
        self.assertEqual(calls[1][1:3], ["allowlist", "canonicalize"])

    def test_tls_lb_policy_covers_the_complete_attested_pod(self) -> None:
        policy = {
            "systemImages": self.policy["systemImages"],
            "workloads": [],
            "imageConfigs": {},
            "systemWorkloads": {
                "c8s-tls-lb": self.policy["systemWorkloads"]["c8s-tls-lb"]
            },
        }
        workload = self.module["application_allowlist"](policy, [])["workloads"]["c8s-tls-lb"]
        self.assertEqual(len(workload["initContainers"]), 3)
        self.assertEqual(len(workload["containers"]), 3)
        commands = [
            record["command"]["argv"] + record["args"].get("argv", [])
            for field in ("initContainers", "containers")
            for record in workload[field]
        ]
        self.assertIn(["/c8s", "acme", "--domains=api.confidential.ai", "--challenge-port=8402", "--http-port=8080", "--cert-dir=/etc/c8s-acme-tls"], commands)
        self.assertTrue(any(argv[:2] == ["/c8s", "cds-attest"] for argv in commands))
        self.assertTrue(any(argv[:2] == ["/c8s", "allowlist-proxy"] for argv in commands))
        self.assertTrue(any(argv[:1] == ["/docker-entrypoint.sh"] for argv in commands))

    def test_composed_identity_is_rejected(self) -> None:
        error = self.module["RegenerationError"]
        composed = json.dumps({
            "schema": "c8s.allowlist/v1", "digests": {},
            "workloads": {"gateway": {"identity": "gateway"}},
        }).encode()
        with self.assertRaisesRegex(error, "identity"):
            self.module["validate_composed"](
                {"systemImages": {}},
                {"workloads": {"gateway": {"initContainers": [], "containers": []}}},
                composed,
            )

    def test_update_output_check_mode_does_not_mutate(self) -> None:
        error = self.module["RegenerationError"]
        output = ROOT / "c8s/allowlists/production.json"
        original = output.read_bytes()
        with self.assertRaisesRegex(error, "policy drift"):
            self.module["update_output"](output, b'{"policy":"different"}', False)
        self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
