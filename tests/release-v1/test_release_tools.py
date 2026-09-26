"""Unit tests for the v0.14.0 release tools in scripts/.

These tests use no network, no cluster, and no c8s binary. They cover the
parts of the tools that decide the allowlist and the manifest content.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
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
    def spec(self, **changes):
        value = yaml.safe_load((ROOT / "release/spec.yaml").read_text())
        value.update(changes)
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            yaml.safe_dump(value, handle)
        return Path(handle.name)

    def test_the_committed_spec_is_valid(self):
        MAN.read_spec(ROOT / "release/spec.yaml")

    def test_release_candidate_versions_are_refused(self):
        with self.assertRaisesRegex(MAN.ManifestError, "no release-candidate"):
            MAN.read_spec(self.spec(version="v0.14.0-rc.1"))

    def test_the_source_lock_pins_the_spec_commit(self):
        spec = MAN.read_spec(ROOT / "release/spec.yaml")
        lock = json.loads((ROOT / "contracts/c8s-admission-source-lock.json").read_text())
        entry = MAN.source_lock_entry(lock, spec["c8s"]["sourceCommit"])
        self.assertEqual(entry["tag"], spec["c8s"]["release"])
        self.assertEqual(entry["nodeImage"], spec["c8s"]["nodeImage"]["reference"] + "@" + spec["c8s"]["nodeImage"]["digest"])

    def test_the_node_manifest_matches_the_pinned_artifact_layer(self):
        data = (ROOT / "release/node-manifest.json").read_bytes()
        self.assertEqual(MAN.sha256(data), "sha256:64dfb7a7eca5f51385150a1743ca0611d4b37099ad53d41c4c697570a338e4d2")
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
