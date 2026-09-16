#!/usr/bin/env python3
"""Tests for the v0 public-source boundary validator."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "scripts" / "validate-source-boundary.py"
TEST_ONLY_API_KEY = "sk-" + "proj-abcdefghijklmnopqrstuvwxyz123456"
TEST_ONLY_PRIVATE_KEY_HEADER = "-----BEGIN PRIVATE " + "KEY-----"
# The validator scans this repository, and this file is part of it. Every
# fixture below is assembled at run time so that no fixture line matches the
# rule it tests. This keeps the fixtures out of the exact-line allowlist.
TEST_ONLY_PRIVATE_IP = "10." + "77.3.4"
TEST_ONLY_SHARED_ADDRESS = "100." + "80.3.4"
# The older rule name, assembled so that this file does not match it.
SHARED_ADDRESS_RULE = "[tail" + "net-service-traffic]"
TEST_ONLY_DOCUMENTATION_IP = "192." + "0.2.7"
TEST_ONLY_HOME_PATH = "/home" + "/someone/checkout"
TEST_ONLY_MAC_HOME_PATH = "/Users" + "/someone/checkout"
TEST_ONLY_HOST_NAMES = (
    "conf-inference-" + "prod-control-plane",
    "conf-inference-" + "staging-inference-0",
    "confidential-inference-" + "production-gateway",
    "tdx-" + "node-3",
    "b300-" + "node-1",
    "b200-" + "host-2",
    "west-" + "gh-runner",
    "kettle-" + "build-01",
    "lunal-" + "host-9",
)


class SourceBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, content: str = "safe\n") -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def run_validator(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(VALIDATOR), "--root", str(self.root), *arguments],
            text=True,
            capture_output=True,
            check=False,
        )

    def track(self, *relative_paths: str) -> None:
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "add", "--", *relative_paths],
            check=True,
        )

    def assert_rule(self, relative: str, content: str, rule: str) -> None:
        self.write(relative, content)
        result = self.run_validator()
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn(f"[{rule}]", result.stdout)

    def test_safe_public_files_pass(self) -> None:
        self.write("services/gateway/main.py", "API_KEY = get_secret()\n")
        self.write("images/gateway/Dockerfile", "FROM python@sha256:" + "a" * 64 + "\n")
        self.write(".github/workflows/v0-check.yml", "    uses: actions/checkout@" + "b" * 40 + "\n")
        result = self.run_validator()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_private_path_fails(self) -> None:
        self.assert_rule("services/candidate-private-router/main.py", "safe\n", "private-optimization-path")

    def test_infisical_local_config_fails(self) -> None:
        self.assert_rule("services/.infisical.json", "{}\n", "infisical-local-config")

    def test_tracked_root_infisical_config_fails(self) -> None:
        self.write(".infisical.json", "{}\n")
        self.track(".infisical.json")
        result = self.run_validator()
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("[infisical-local-config]", result.stdout)

    def test_untracked_root_infisical_config_stays_local(self) -> None:
        self.write("README.md", "safe\n")
        self.write(".infisical.json", "{}\n")
        self.track("README.md")
        result = self.run_validator()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_tracked_root_kube_directory_fails(self) -> None:
        self.write(".kube/config", "local operator settings\n")
        self.track(".kube/config")
        result = self.run_validator()
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("[kubeconfig]", result.stdout)

    def test_tracked_secret_artifact_fails(self) -> None:
        self.write("operator.private.pem", "deliberately opaque fixture\n")
        self.track("operator.private.pem")
        result = self.run_validator()
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("[secret-artifact]", result.stdout)

    def test_scripts_are_in_scope(self) -> None:
        self.assert_rule(
            "scripts/download.sh",
            "curl https://example.test/tool\n",
            "unpinned-remote-artifact",
        )

    def test_kubeconfig_data_fails(self) -> None:
        content = "clusters:\n- cluster: {}\ncontexts:\n- context: {}\ncurrent-context: prod\nusers:\n"
        self.assert_rule("c8s/export.yaml", content, "kubeconfig")

    def test_plaintext_api_key_and_pem_fail(self) -> None:
        content = f'API_KEY = "{TEST_ONLY_API_KEY}"\n{TEST_ONLY_PRIVATE_KEY_HEADER}\n'
        self.write("services/gateway/secrets.py", content)
        result = self.run_validator()
        self.assertEqual(1, result.returncode)
        self.assertIn("[plaintext-api-key]", result.stdout)
        self.assertIn("[pem-private-key]", result.stdout)

    def test_key_vault_runtime_dependency_fails(self) -> None:
        self.assert_rule("services/gateway/secrets.py", "from azure.keyvault.secrets import SecretClient\n", "azure-key-vault-runtime")

    def test_tailnet_service_traffic_fails(self) -> None:
        self.assert_rule("helm/chart/values.yaml", "upstream: https://worker.tail123.ts.net\n", "tailnet-service-traffic")

    def test_tailscale_reference_fails(self) -> None:
        self.assert_rule(
            "c8s/README.md",
            "The application uses a Tailscale proxy for service traffic.\n",
            "tailnet-service-traffic",
        )

    def test_tailnet_network_policy_exclusion_passes(self) -> None:
        self.write(
            "helm/chart/templates/network-policy.yaml",
            "ipBlock:\n  cidr: 0.0.0.0/0\n  except:\n    - 100.64.0.0/10\n",
        )
        self.assertEqual(0, self.run_validator().returncode)

    def test_tailnet_network_policy_destination_still_fails(self) -> None:
        self.assert_rule(
            "helm/chart/templates/network-policy.yaml",
            "ipBlock:\n  cidr: 100.64.0.0/10\n",
            "tailnet-service-traffic",
        )

    def test_other_azure_vm_systemd_unit_fails(self) -> None:
        self.assert_rule(
            "images/unreviewed/unreviewed.service",
            "[Unit]\nDescription=Unreviewed\n[Service]\nExecStart=/bin/true\n",
            "systemd-unit",
        )

    def test_systemd_unit_fails(self) -> None:
        self.assert_rule("services/gateway/conf/gateway.service", "[Service]\nExecStart=/app\n", "systemd-unit")

    def test_image_tag_fails_and_digest_passes(self) -> None:
        self.assert_rule("helm/chart/values.yaml", "image: example/gateway:v0\n", "image-tag")
        self.write("helm/chart/values.yaml", "image: example/gateway@sha256:" + "c" * 64 + "\n")
        self.assertEqual(0, self.run_validator().returncode)

    def test_unpinned_action_and_download_fail(self) -> None:
        self.write(".github/workflows/v0-check.yml", "    uses: actions/checkout@v4\n")
        self.write("images/gateway/Dockerfile", "RUN curl -o tool https://example.test/tool\n")
        result = self.run_validator()
        self.assertEqual(1, result.returncode)
        self.assertGreaterEqual(result.stdout.count("[unpinned-remote-artifact]"), 2)

    def test_loopback_container_checks_pass(self) -> None:
        self.write(
            "services/mock/tests/check.sh",
            "curl --fail http://127.0.0.1:1080/health\n",
        )
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_all_source_paths_are_in_scope(self) -> None:
        self.write("legacy/private-optimization/key.pem", TEST_ONLY_PRIVATE_KEY_HEADER + "\n")
        self.write(".github/workflows/legacy.yml", "uses: actions/checkout@v4\n")
        result = self.run_validator()
        self.assertEqual(1, result.returncode)
        self.assertIn("[private-optimization-path]", result.stdout)
        self.assertIn("[pem-private-key]", result.stdout)
        self.assertIn("[unpinned-remote-artifact]", result.stdout)

    def test_generated_dependency_and_build_trees_are_out_of_scope(self) -> None:
        self.write("services/admin-web/node_modules/package/key.pem", TEST_ONLY_PRIVATE_KEY_HEADER + "\n")
        self.write("services/admin-web/dist/bundle.js", "API_KEY = 'test-secret-value-1234'\n")
        self.write("services/gateway/target/debug/build.txt", "curl https://example.test/tool\n")
        self.write("services/admin-backend/__pycache__/app.pyc", "opaque build output\n")
        self.assertEqual(0, self.run_validator().returncode)

    def test_exact_line_allowlist_supports_negative_fixtures(self) -> None:
        line = f'API_KEY = "{TEST_ONLY_API_KEY}"'
        self.write("services/fixtures/negative.py", line + "\n")
        allowlist = self.write(
            "fixture-allowlist.json",
            json.dumps({
                "version": 1,
                "entries": [{
                    "rule": "plaintext-api-key",
                    "path": "services/fixtures/negative.py",
                    "line_sha256": hashlib.sha256(line.encode()).hexdigest(),
                    "reason": "This line is a deliberate negative fixture.",
                }],
            }),
        )
        result = self.run_validator("--allowlist", str(allowlist))
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_private_address_fails(self) -> None:
        self.assert_rule(
            "deploy/notes.md", f"the node answers on {TEST_ONLY_PRIVATE_IP}\n",
            "private-ip-address",
        )

    def test_a_shared_address_space_address_is_reported_exactly_once(self) -> None:
        # The RFC 6598 range is in the private-address data, and an older rule
        # covers the same range. The private-address rule defers to that older
        # rule, so one line gives one finding.
        self.write("deploy/hosts.yaml", f"address: {TEST_ONLY_SHARED_ADDRESS}\n")
        result = self.run_validator()
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn(SHARED_ADDRESS_RULE, result.stdout)
        self.assertNotIn("[private-ip-address]", result.stdout)

    def test_documentation_address_passes(self) -> None:
        self.write("deploy/example.yaml", f"address: {TEST_ONLY_DOCUMENTATION_IP}\n")
        result = self.run_validator()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_home_directory_paths_fail(self) -> None:
        self.assert_rule(
            "tests/example_test.py", f'ROOT = "{TEST_ONLY_HOME_PATH}"\n',
            "home-directory-path",
        )
        self.assert_rule(
            "tests/example_test.py", f'ROOT = "{TEST_ONLY_MAC_HOME_PATH}"\n',
            "home-directory-path",
        )

    def test_every_known_host_name_shape_fails(self) -> None:
        for name in TEST_ONLY_HOST_NAMES:
            with self.subTest(host=name):
                self.assert_rule(
                    "c8s/example-values.yaml", f"  nodeName: {name}\n",
                    "infrastructure-host-name",
                )

    def test_a_longer_name_that_contains_a_fragment_passes(self) -> None:
        # The rule needs a whole token. A release name or an image tag that
        # merely contains a fragment is not a host name.
        self.write(
            "c8s/example-values.yaml",
            "releaseId: conf-inference-" + "prod-v1\n"
            "secretName: conf-inference-" + "prod-gateway-admin-mtls\n"
            "baseTag: rke2-" + "tdx-079aeb4\n",
        )
        result = self.run_validator()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
