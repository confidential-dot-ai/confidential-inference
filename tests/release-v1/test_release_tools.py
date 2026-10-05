"""Unit tests for the v0.14.0 release tools in scripts/.

These tests use no network, no cluster, and no c8s binary. They cover the
parts of the tools that decide the allowlist and the manifest content.
"""

from __future__ import annotations

import functools
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GEN = load("generate_release_allowlist", "scripts/generate-release-allowlist.py")
MAN = load("build_release_manifest", "scripts/build-release-manifest.py")
NODE = load("fetch_node_manifest", "scripts/fetch-node-manifest.py")
PROFILES = sys.modules["release_profiles"]
PRODUCTION = PROFILES.for_directory(ROOT / "release")
STAGING = PROFILES.for_directory(ROOT / "release/staging")


@functools.cache
def rendered(profile) -> list[dict]:
    """The chart rendered with the profile values and its policy settings. Do not change it."""
    return MAN.render_chart(MAN.CHART, profile, MAN.read_allowlist_policy(profile.policy)["chart"])


def rendered_workers(profile) -> list[dict]:
    return [item for item in rendered(profile) if item.get("kind") == "StatefulSet"
            and item.get("metadata", {}).get("name", "").startswith("inference-worker-")]

DIGEST = "sha256:" + "a" * 64
IMAGE = f"ghcr.io/example/app@{DIGEST}"
CORE = f"ghcr.io/confidential-dot-ai/c8s-operator@sha256:{'b' * 64}"
POLICY = {"chart": {"namespace": "confidential-inference"}, "kubernetes": {"serviceHost": "10.53.0.1"}}


def controller(kind="StatefulSet", name="worker", container=None, volumes=None, annotations=None, **pod):
    spec = {"enableServiceLinks": False, "containers": [container or {"name": "app", "image": IMAGE}]}
    spec.update(pod)
    if volumes is not None:
        spec["volumes"] = volumes
    return {
        "kind": kind,
        "metadata": {"name": name},
        "spec": {"replicas": 1, "template": {"metadata": {"annotations": annotations or {}}, "spec": spec}},
    }


class EnvironmentTests(unittest.TestCase):
    def env(self, obj, configs=None, cdi=None):
        container = obj["spec"]["template"]["spec"]["containers"][0]
        configs = configs or {IMAGE: {"env": ["PATH=/usr/bin", "PATH=/bin", "A=1"], "entrypoint": ["/a"], "cmd": []}}
        return GEN.container_env(obj, container, configs, POLICY, cdi)

    def test_image_env_last_value_wins_and_platform_values_are_added(self):
        values = self.env(controller())
        self.assertEqual(values["PATH"], "/bin")
        self.assertEqual(values["HOSTNAME"], "worker-0")
        self.assertEqual(values["KUBERNETES_SERVICE_HOST"], "10.53.0.1")
        self.assertEqual(values["KUBERNETES_PORT_443_TCP"], "tcp://10.53.0.1:443")

    def test_pod_env_expands_earlier_names_and_field_refs(self):
        container = {"name": "app", "image": IMAGE, "env": [
            {"name": "B", "value": "x"},
            {"name": "C", "value": "$(B)-y-$$(B)"},
            {"name": "POD", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
        ]}
        values = self.env(controller(container=container))
        self.assertEqual(values["C"], "x-y-$(B)")
        self.assertEqual(values["POD"], "worker-0")

    def test_node_specific_values_are_refused(self):
        container = {"name": "app", "image": IMAGE, "env": [
            {"name": "HOST_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.hostIP"}}}]}
        with self.assertRaisesRegex(GEN.GenerationError, "differs per node"):
            self.env(controller(container=container))

    def test_service_links_and_random_pod_names_are_refused(self):
        obj = controller()
        obj["spec"]["template"]["spec"]["enableServiceLinks"] = True
        with self.assertRaisesRegex(GEN.GenerationError, "enableServiceLinks"):
            self.env(obj)
        with self.assertRaisesRegex(GEN.GenerationError, "HOSTNAME"):
            self.env(controller(kind="Deployment"))
        self.assertEqual(self.env(controller(kind="Deployment", hostname="gateway"))["HOSTNAME"], "gateway")

    def test_gpu_container_needs_the_cdi_record(self):
        container = {"name": "app", "image": IMAGE, "resources": {"limits": {"nvidia.com/gpu": 4}}}
        with self.assertRaisesRegex(GEN.GenerationError, "CDI record is absent"):
            self.env(controller(container=container))
        cdi = {"env": {"NVIDIA_VISIBLE_DEVICES": "void"}, "mounts": []}
        self.assertEqual(self.env(controller(container=container), cdi=cdi)["NVIDIA_VISIBLE_DEVICES"], "void")


class MountTests(unittest.TestCase):
    def test_rules_follow_volume_class_and_c8s_injection(self):
        container = {"name": "app", "image": IMAGE, "volumeMounts": [
            {"name": "tmp", "mountPath": "/tmp"},
            {"name": "config", "mountPath": "/mnt/c8s-data/config", "readOnly": True},
        ]}
        obj = controller(
            container=container,
            volumes=[{"name": "tmp", "emptyDir": {}}, {"name": "config", "configMap": {"name": "c"}}],
            annotations={
                "confidential.ai/cw": "worker",
                "confidential.ai/c8s-secrets": "P=/p",
                "confidential.ai/c8s-volumes": "dsv4=/v/dsv4",
                "confidential.ai/c8s-volume-dir": "/mnt/c8s-data/models",
            },
        )
        rules = GEN.container_mounts(obj, container, None)
        self.assertEqual(rules, [
            {"destination": "/etc/c8s/certs", "kind": "emptyDir"},
            {"destination": "/mnt/c8s-data/config", "kind": "data"},
            {"destination": "/mnt/c8s-data/models/dsv4", "kind": "data"},
            {"destination": "/run/c8s/secrets", "kind": "emptyDir"},
            {"destination": "/tmp", "kind": "emptyDir"},
        ])

    def test_data_outside_the_data_root_is_refused(self):
        container = {"name": "app", "image": IMAGE, "volumeMounts": [{"name": "config", "mountPath": "/etc/app"}]}
        obj = controller(container=container, volumes=[{"name": "config", "configMap": {"name": "c"}}])
        with self.assertRaisesRegex(GEN.GenerationError, "below /mnt/c8s-data/"):
            GEN.container_mounts(obj, container, None)

    def test_host_path_pins_source_and_mode(self):
        container = {"name": "app", "image": IMAGE, "volumeMounts": [{"name": "proc", "mountPath": "/host/proc", "readOnly": True}]}
        obj = controller(container=container, volumes=[{"name": "proc", "hostPath": {"path": "/proc"}}])
        self.assertEqual(GEN.container_mounts(obj, container, None),
                         [{"destination": "/host/proc", "kind": "host", "source": "/proc", "readOnly": True}])


class ProcessTests(unittest.TestCase):
    config = {"entrypoint": ["/entry"], "cmd": ["--default"]}

    def test_runtime_merge_of_command_and_args(self):
        base = {"name": "app", "image": IMAGE}
        self.assertEqual(GEN.effective_process(base, self.config)["command"], ["/entry"])
        self.assertEqual(GEN.effective_process(base, self.config)["args"], ["--default"])
        with_args = GEN.effective_process({**base, "args": ["--x"]}, self.config)
        self.assertEqual((with_args["command"], with_args["args"]), (["/entry"], ["--x"]))
        with_command = GEN.effective_process({**base, "command": ["/other"]}, self.config)
        self.assertEqual(with_command["command"], ["/other"])
        self.assertNotIn("args", with_command)

    def test_c8s_carve_out_matches_cds(self):
        core = {GEN.split_image(CORE)[1]}
        self.assertTrue(GEN.is_carved_out({"image": CORE, "command": ["/c8s"]}, core))
        self.assertFalse(GEN.is_carved_out({"image": CORE, "command": ["/other"]}, core))
        self.assertFalse(GEN.is_carved_out({"image": IMAGE, "command": ["/c8s"]}, core))

    def test_floor_entry_name_mirrors_c8s(self):
        name, entry = GEN.floor_entry(CORE)
        self.assertEqual(name, "c8s-operator-" + "b" * 12)
        self.assertEqual(entry["containers"][0]["env"], {"policy": "any"})


class AcceptedFindingTests(unittest.TestCase):
    LINE = ('error: workload "{entry}" container sha256:' + "c" * 64 + ' pins PATH to a search path '
            'overlapping host mount "{path}"; operator-supplied content could be loaded as code')

    def lint_with(self, lines, accepted, code=1):
        class Result:
            returncode = code
            stdout = ("\n".join(lines) + "\n").encode()
            stderr = b""
        original = GEN.subprocess.run
        GEN.subprocess.run = lambda *a, **k: Result()
        try:
            GEN.lint(Path("c8s"), Path("allowlist.json"), accepted)
        finally:
            GEN.subprocess.run = original

    def key(self, entry, path):
        return (entry, "search-path-overlaps-mount", "PATH", "host", path)

    def test_the_committed_file_accepts_exactly_four_findings(self):
        accepted = GEN.read_accepted_findings(ROOT / "release/accepted-lint-findings.json")
        self.assertEqual(len(accepted), 4)
        self.assertEqual({key[4] for key in accepted}, {"/usr/bin/nvidia-smi", "/usr/bin/nvidia-persistenced"})

    def test_accepted_findings_pass(self):
        self.lint_with([self.LINE.format(entry="w", path="/usr/bin/a"), "1 lint error(s)"], {self.key("w", "/usr/bin/a")})

    def test_a_new_finding_fails(self):
        with self.assertRaisesRegex(GEN.GenerationError, "not accepted"):
            self.lint_with([self.LINE.format(entry="w", path="/usr/bin/b"), "1 lint error(s)"], {self.key("w", "/usr/bin/a")})

    def test_a_vanished_finding_fails(self):
        with self.assertRaisesRegex(GEN.GenerationError, "no longer appears"):
            self.lint_with([], {self.key("w", "/usr/bin/a")}, code=0)

    def test_an_unknown_line_fails(self):
        with self.assertRaisesRegex(GEN.GenerationError, "not an accepted finding"):
            self.lint_with(["warning: something else", self.LINE.format(entry="w", path="/usr/bin/a"), "2 lint warning(s) with --strict"],
                           {self.key("w", "/usr/bin/a")})


class ManifestTests(unittest.TestCase):
    def test_the_committed_spec_is_valid(self):
        MAN.read_spec(PRODUCTION)
        staging = MAN.read_spec(STAGING)
        self.assertEqual(staging["version"], "v0.14.2-staging")

    def test_release_candidate_versions_are_refused(self):
        spec = MAN.read_spec(PRODUCTION)
        for version, profile in (("v0.14.0-rc.1", PRODUCTION), ("v0.14.0-staging", PRODUCTION),
                                 ("v0.14.0", STAGING)):
            with self.subTest(version=version), self.assertRaisesRegex(MAN.ManifestError, "version must be"):
                MAN.validate_spec({**spec, "version": version}, profile)

    def test_image_source_boundary_allows_only_later_non_image_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            gateway = repo / "images/gateway/Dockerfile"
            gateway.parent.mkdir(parents=True)
            gateway.write_text("FROM scratch\n")
            release_values = repo / "release/values.yaml"
            release_values.parent.mkdir(parents=True)
            release_values.write_text("version: first\n")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "image source"], cwd=repo, check=True)
            image_source = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()

            release_values.write_text("version: pinned\n")
            subprocess.run(["git", "commit", "-qam", "pin release"], cwd=repo, check=True)
            release_source = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()
            MAN.verify_image_source_boundary(image_source, release_source, repo)

            gateway.write_text("FROM scratch\nLABEL changed=yes\n")
            subprocess.run(["git", "commit", "-qam", "change image"], cwd=repo, check=True)
            changed_source = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()
            with self.assertRaisesRegex(MAN.ManifestError, "gateway"):
                MAN.verify_image_source_boundary(image_source, changed_source, repo)

    def test_image_source_boundary_rejects_a_changed_selector(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            selector = repo / "scripts/affected-release-images.py"
            selector.parent.mkdir(parents=True)
            selector.write_text("selector = 1\n")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "image source"], cwd=repo, check=True)
            image_source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            selector.write_text("selector = 2\n")
            subprocess.run(["git", "commit", "-qam", "change selector"], cwd=repo, check=True)
            release_source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            with self.assertRaisesRegex(MAN.ManifestError, "selector changed"):
                MAN.verify_image_source_boundary(image_source, release_source, repo)

    def test_staging_manifest_uses_the_staging_profile(self):
        values = PROFILES.read_values(STAGING)
        image_source_commit = MAN.read_spec(STAGING)["imageSourceCommit"]
        release_source_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        records = {}
        for value in values["images"].values():
            if value.startswith("ghcr.io/confidential-dot-ai/confidential-inference/"):
                name, digest = value.split("@", 1)
                records[name] = digest
        publication = {
            "schema": "confidential.ai/image-publication-manifest/v2",
            "source": {
                "repository": "https://github.com/confidential-dot-ai/confidential-inference",
                "commit": image_source_commit,
                "baseRef": "v0.13.28-rc.2",
                "baseRefCommit": "a54319a2ebb2ae51f161d7c2085bffcca02e082c",
            },
            "images": [
                {"name": name, "digest": digest}
                for name, digest in sorted(records.items())
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            publication_path = Path(temporary) / "publication.json"
            publication_path.write_text(json.dumps(publication))
            with mock.patch.object(MAN, "verify_image_source_boundary"):
                manifest = MAN.build(
                    ROOT / "release/staging",
                    ROOT / "helm/confidential-inference",
                    ROOT / "contracts/c8s-admission-source-lock.json",
                    release_source_commit,
                    publication_path,
                )
        self.assertEqual(manifest["release"], {"name": "v0.14.2-staging", "environment": "staging"})
        self.assertEqual(manifest["allowlist"]["path"], "release/staging/allowlist.json")
        self.assertEqual(manifest["source"]["commit"], release_source_commit)
        self.assertEqual(manifest["imagePublication"]["sourceCommit"], image_source_commit)

    def test_staging_workers_verify_the_model_before_the_simulator(self):
        workers = rendered_workers(STAGING)
        self.assertEqual(len(workers), 2)
        for worker in workers:
            pod = worker["spec"]["template"]
            container = pod["spec"]["containers"][0]
            self.assertEqual(container["command"], ["/usr/local/bin/wait-for-model"])
            self.assertIn("python3", container["args"])
            self.assertIn("sglang_simulator.simulation.sglang.launch_server", container["args"])
            self.assertIn("confidential.ai/c8s-volumes", pod["metadata"]["annotations"])
            self.assertEqual(container["resources"]["requests"]["memory"], "16Gi")

        allowlist = json.loads((ROOT / "release/staging/allowlist.json").read_text())
        zero_digest = "sha256:" + "0" * 64
        for name in ("inference-worker-0", "inference-worker-1"):
            policy = allowlist["workloads"][name]["containers"][0]
            self.assertEqual(policy["command"]["argv"], ["/usr/local/bin/wait-for-model"])
            self.assertIn("sglang_simulator.simulation.sglang.launch_server", policy["args"]["argv"])
        self.assertNotIn(zero_digest, (ROOT / "release/staging/allowlist.json").read_text())

    def test_manifest_refuses_model_values_that_differ_from_the_spec(self):
        spec = MAN.read_spec(STAGING)
        values = PROFILES.read_values(STAGING)
        MAN.require_model_agreement(spec, values)
        cases = [
            ("name", "different/model", "repository"),
            ("revision", "a" * 40, "revision"),
        ]
        for field, value, message in cases:
            changed = json.loads(json.dumps(values))
            changed["inference"]["model"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(MAN.ManifestError, message):
                MAN.require_model_agreement(spec, changed)

    def test_manifest_refuses_a_rendered_byte_manifest_that_differs_from_the_spec(self):
        spec = MAN.read_spec(STAGING)
        MAN.require_model_files(spec, rendered(STAGING))
        changed = json.loads(json.dumps(rendered(STAGING)))
        for worker in changed:
            if worker.get("kind") == "StatefulSet" and worker["metadata"]["name"].startswith("inference-worker-"):
                container = worker["spec"]["template"]["spec"]["containers"][0]
                container["args"] = [arg.replace(spec["model"]["byteManifestSha256"], "0" * 64)
                                     for arg in container["args"]]
        with self.assertRaisesRegex(MAN.ManifestError, "byte manifest"):
            MAN.require_model_files(spec, changed)

    @staticmethod
    def expected_file_args(profile) -> list[list[str]]:
        return [[arg.removeprefix("--expected-file=")
                 for arg in worker["spec"]["template"]["spec"]["containers"][0]["args"]
                 if arg.startswith("--expected-file=")]
                for worker in rendered_workers(profile)]

    def test_production_workers_check_the_expected_files_map(self):
        verification = PROFILES.read_values(PRODUCTION)["inference"]["model"]["mountVerification"]
        expected = [f"{name}={digest}" for name, digest in sorted(verification["expectedFiles"].items())]
        for arguments in self.expected_file_args(PRODUCTION):
            self.assertEqual(arguments, expected)

    def test_staging_workers_check_only_the_staging_model_files(self):
        verification = PROFILES.read_values(STAGING)["inference"]["model"]["mountVerification"]
        expected = sorted(f"{item['path']}={item['sha256']}" for item in verification["expectedFileList"])
        for arguments in self.expected_file_args(STAGING):
            self.assertEqual(arguments, expected)

    def test_manifest_refuses_publication_evidence_for_an_unrendered_digest(self):
        publication = {
            "schema": "confidential.ai/image-publication-manifest/v2",
            "source": {
                "repository": "https://github.com/confidential-dot-ai/confidential-inference",
                "commit": "b" * 40,
                "baseRef": "v0.13.28-rc.2",
                "baseRefCommit": "c" * 40,
            },
            "images": [{
                "name": "ghcr.io/confidential-dot-ai/confidential-inference/gateway",
                "digest": "sha256:" + "0" * 64,
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "publication.json"
            path.write_text(json.dumps(publication))
            with self.assertRaisesRegex(MAN.ManifestError, "differs from the rendered release"):
                MAN.image_publication(
                    path,
                    source_commit="b" * 40,
                    release_images={
                        "gateway": "ghcr.io/confidential-dot-ai/confidential-inference/gateway@sha256:" + "1" * 64,
                    },
                )

    def test_manifest_records_a_published_image_outside_the_application_chart(self):
        publication = {
            "schema": "confidential.ai/image-publication-manifest/v2",
            "source": {
                "repository": "https://github.com/confidential-dot-ai/confidential-inference",
                "commit": "b" * 40,
                "baseRef": "v0.13.28-rc.2",
                "baseRefCommit": "c" * 40,
            },
            "images": [{
                "name": "ghcr.io/confidential-dot-ai/confidential-inference/maintenance-gateway",
                "digest": "sha256:" + "2" * 64,
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "publication.json"
            path.write_text(json.dumps(publication))
            result = MAN.image_publication(
                path,
                source_commit="b" * 40,
                release_images={
                    "gateway": "ghcr.io/confidential-dot-ai/confidential-inference/gateway@sha256:" + "1" * 64,
                },
            )
        self.assertEqual(
            result["images"]["ghcr.io/confidential-dot-ai/confidential-inference/maintenance-gateway"],
            "sha256:" + "2" * 64,
        )

    def test_manifest_refuses_publication_from_another_source_commit(self):
        publication = {
            "schema": "confidential.ai/image-publication-manifest/v2",
            "source": {
                "repository": "https://github.com/confidential-dot-ai/confidential-inference",
                "commit": "a" * 40,
                "baseRef": "v0.13.28-rc.2",
                "baseRefCommit": "c" * 40,
            },
            "images": [{
                "name": "ghcr.io/confidential-dot-ai/confidential-inference/gateway",
                "digest": "sha256:" + "1" * 64,
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "publication.json"
            path.write_text(json.dumps(publication))
            with self.assertRaisesRegex(MAN.ManifestError, "source commit differs"):
                MAN.image_publication(
                    path,
                    source_commit="b" * 40,
                    release_images={
                        "gateway": "ghcr.io/confidential-dot-ai/confidential-inference/gateway@sha256:" + "1" * 64,
                    },
                )

    def test_staging_policy_uses_its_exact_render_and_allowlist_namespace(self):
        spec = MAN.read_spec(STAGING)
        policy = MAN.read_allowlist_policy(STAGING.policy)
        core = spec["c8s"]["coreImages"]
        documents = rendered(STAGING)
        allowlist = json.loads(STAGING.allowlist.read_text())
        configs = json.loads(PROFILES.IMAGE_CONFIG.read_text())
        MAN.require_allowlist_contract(allowlist, policy, core, documents, configs)
        router = next(item for item in documents if item.get("kind") == "Deployment"
                      and item.get("metadata", {}).get("name") == "sglang-router")
        args = router["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertIn("--service-discovery-namespace=confidential-inference-staging", args)
        changed = json.loads(json.dumps(allowlist))
        changed["workloads"].pop("inference-worker-1")
        with self.assertRaisesRegex(MAN.ManifestError, "entries differ"):
            MAN.require_allowlist_contract(changed, policy, core, documents, configs)
        changed = json.loads(json.dumps(allowlist))
        changed["workloads"]["sglang-router"]["containers"][0]["args"]["argv"][1] = \
            "--service-discovery-namespace=wrong"
        with self.assertRaisesRegex(MAN.ManifestError, "process differs"):
            MAN.require_allowlist_contract(changed, policy, core, documents, configs)

    def test_each_node_manifest_belongs_to_the_layer_that_pins_c8s(self):
        for profile in PROFILES.load():
            with self.subTest(profile=profile.name):
                if (profile.directory / "node-manifest.json").exists():
                    self.assertEqual(PROFILES.node_manifest(profile), profile.directory / "node-manifest.json")
                self.assertFalse((profile.directory / "inputs/image-config.json").exists()
                                 and profile.directory / "inputs/image-config.json" != PROFILES.IMAGE_CONFIG)

    def test_the_source_lock_pins_the_spec_commit(self):
        lock = json.loads((ROOT / "contracts/c8s-admission-source-lock.json").read_text())
        for profile in PROFILES.load():
            with self.subTest(profile=profile.name):
                spec = MAN.read_spec(profile)
                entry = MAN.source_lock_entry(lock, spec["c8s"]["sourceCommit"])
                self.assertEqual(entry["tag"], spec["c8s"]["release"])
                self.assertEqual(
                    entry["nodeImage"],
                    spec["c8s"]["nodeImage"]["reference"]
                    + "@"
                    + spec["c8s"]["nodeImage"]["digest"],
                )

    def test_the_node_manifest_matches_the_pinned_artifact_layer(self):
        for profile in PROFILES.load():
            with self.subTest(profile=profile.name):
                data = PROFILES.node_manifest(profile).read_bytes()
                pinned = MAN.read_spec(profile)["c8s"]["nodeManifestArtifact"]["manifestJson"]
                self.assertEqual(MAN.sha256(data), pinned)
                NODE.check_measurements(json.loads(data))

    def test_the_schema_refuses_deployment_values(self):
        schema = json.loads((ROOT / "contracts/release-manifest.schema.json").read_text())
        properties = set(schema["properties"])
        for forbidden in ("meshCa", "operatorPublicKeySha256", "operatorKeySetSha256", "target"):
            self.assertNotIn(forbidden, properties)
        self.assertFalse(schema["additionalProperties"])
        jsonschema.Draft202012Validator.check_schema(schema)


if __name__ == "__main__":
    unittest.main()
