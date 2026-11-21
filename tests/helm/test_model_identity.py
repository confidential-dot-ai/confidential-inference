"""Model identity pins survive both download and pre-attached model paths."""

import json
import hashlib
from pathlib import Path
import subprocess
import shlex
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
PIN = "1" * 64


class ModelIdentityTests(unittest.TestCase):
    def render(self, override=None, success=True):
        values = {
            "modelIdentity": {"enabled": True},
            "images": {"confidentialSglangEngine": f"example.invalid/engine@sha256:{'2' * 64}"},
            "inference": {"mode": "model", "engineImage": "confidentialSglangEngine", "speculativeAlgorithm": "", "model": {
                "mountVerification": {"expectedFileList": [
                    {"path": ".model-lock-local-manifest.json", "sha256": PIN}]}}},
        }
        def merge(target, changes):
            for key, value in changes.items():
                if isinstance(value, dict) and isinstance(target.get(key), dict):
                    merge(target[key], value)
                else:
                    target[key] = value
        merge(values, override or {})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "values.yaml"
            path.write_text(yaml.safe_dump(values))
            result = subprocess.run(["helm", "template", "model-policy", str(ROOT / "helm/confidential-inference"),
                                     "-f", str(path)], capture_output=True, text=True)
        if not success:
            self.assertNotEqual(0, result.returncode)
            return result.stderr
        self.assertEqual(0, result.returncode, result.stderr)
        return {item["metadata"]["name"]: item for item in yaml.safe_load_all(result.stdout)
                if item and item["kind"] in ("Deployment", "StatefulSet")}

    def test_pins_the_complete_model_path(self):
        documents = self.render()
        containers = {name: obj["spec"]["template"]["spec"]["containers"][0]
                      for name, obj in documents.items()}
        gateway = {e["name"]: e.get("value") for e in containers["gateway"]["env"]}
        router = {e["name"]: e.get("value") for e in containers["sglang-router"]["env"]}
        self.assertEqual("sglang-router", gateway["C8S_MESH_PEER_WORKLOADS"])
        self.assertEqual("inference-worker", router["C8S_MESH_PEER_WORKLOADS"])
        self.assertIn(f"--model-manifest-sha256={PIN}", containers["inference-worker"]["args"])
        self.assertEqual({"example/model": ["example/model"]}, json.loads(router["CI_ROUTER_MODEL_ROUTES"])["routes"])

    def test_alias_cannot_select_another_model(self):
        error = self.render({"runtimeConfig": {"modelRoutes": {"alias": ["other/model"]}}}, success=False)
        self.assertIn("select only inference.model.name", error)

    def test_simulator_cannot_claim_model_verification(self):
        self.assertIn("not a simulator", self.render({"inference": {"mode": "simulator"}}, success=False))

    def test_duplicate_identity_and_missing_manifest_are_refused(self):
        for override in ({"router": {"attestedWorkload": "inference-worker"}},
                         {"inference": {"model": {"mountVerification": {
                             "expectedFileList": [{"path": "other", "sha256": PIN}], "expectedFiles": {}}}}}):
            self.render(override, success=False)

    def test_feature_is_opt_in(self):
        documents = self.render({"modelIdentity": {"enabled": False}})
        for obj in documents.values():
            for container in obj["spec"]["template"]["spec"]["containers"]:
                self.assertFalse(any(e["name"] == "C8S_MESH_PEER_WORKLOADS" for e in container.get("env", [])))
                self.assertFalse(any(a.startswith("--model-manifest-sha256=") for a in container.get("args", [])))

    def test_override_cannot_remove_the_model_pin(self):
        error = self.render({"workloadOverridesEnabled": True, "workloadOverrides": {
            "StatefulSet/inference-worker": {"spec": {"template": {"spec": {
                "containers": [{"name": "sglang", "args": []}]}}}}}}, success=False)
        self.assertIn("does not permit workloadOverridesEnabled", error)

    def test_alternate_model_sources_are_refused(self):
        for inference in ({"workerExtraArgs": ["--model-path=/other/model"]},
                          {"workerExtraArgs": ["--load-format=dummy"]},
                          {"workerExtraArgs": ["--enable-lora"]},
                          {"speculativeAlgorithm": "EAGLE"}):
            self.assertIn("unverified speculative model inputs", self.render({"inference": inference}, success=False))

    def test_download_source_is_a_literal_shell_argument(self):
        manifest = "{}"
        name = "vendor/model'$(printf must-not-run)"
        documents = self.render({"inference": {"model": {"name": name,
            "mountVerification": {"expectedFileList": [{"path": ".model-lock-local-manifest.json",
                "sha256": hashlib.sha256(manifest.encode()).hexdigest()}]},
            "download": {"enabled": True, "manifest": manifest,
                "hosts": [{"address": "192.0.2.10", "serverName": "models.internal"}]}}}})
        command = documents["inference-worker"]["spec"]["template"]["spec"]["containers"][0]["command"]
        self.assertIn("--repository=" + name, shlex.split(command[2]))


if __name__ == "__main__":
    unittest.main()
