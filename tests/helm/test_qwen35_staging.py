"""The Qwen3.5-0.8B staging layer runs the staging image: one worker, one GPU.

Adapted from confidential-inference#299, for the image that this repository
builds (images/sglang-qwen35-0.8b).
"""
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "helm/confidential-inference"
DEPLOYMENTS = ROOT / "tests/fixtures/deployments"
RELEASE_VALUES = ROOT / "tests/release-v1/fixtures/release-values.yaml"
SERVE = ROOT / "images/sglang-qwen35-0.8b/serve.sh"
MODEL = "Qwen/Qwen3.5-0.8B"
REVISION = "2fc06364715b967f1860aea9cf38778875588b17"
MANIFEST_SHA256 = "625963f6a7f159fd2a3e8ad97642a11ac275d1735adaadca8df39452b9fbd8fa"
IMAGE_MODEL_PATH = "/opt/confidential-inference/models/qwen35-0.8b"
STAGING_WORKER = yaml.safe_load(RELEASE_VALUES.read_text())["images"]["sglangQwen35"]


def render(*layers: str, extra: tuple[str, ...] = (), check: bool = True) -> subprocess.CompletedProcess:
    files = [arg for layer in ("production-values.yaml", "staging-values.yaml", *layers)
             for arg in ("--values", str(DEPLOYMENTS / layer))]
    return subprocess.run(["helm", "template", "example", str(CHART), "--namespace", "confidential-inference",
                           *files, "--values", str(RELEASE_VALUES), "--set", "environment=staging",
                           "--set", "frameworkRelease.name=v0.14.18", *extra],
                          text=True, capture_output=True, check=check)


def documents(result: subprocess.CompletedProcess) -> list[dict]:
    return [item for item in yaml.safe_load_all(result.stdout) if item]


def workers(found: list[dict]) -> list[dict]:
    return [item for item in found if item["kind"] == "StatefulSet"
            and item["metadata"]["name"].startswith("inference-worker-")]


def sglang(worker: dict) -> dict:
    return next(c for c in worker["spec"]["template"]["spec"]["containers"] if c["name"] == "sglang")


class Qwen35StagingTests(unittest.TestCase):
    def setUp(self):
        self.documents = documents(render("qwen35-staging-values.yaml"))

    def test_release_names_the_repository_image(self):
        spec = yaml.safe_load((ROOT / "release/spec.yaml").read_text())["images"]
        # The release build adds the digest that the Release images run published.
        self.assertEqual("ghcr.io/confidential-dot-ai/confidential-inference/sglang-qwen35-0.8b",
                         spec["sglangQwen35"])
        self.assertTrue(STAGING_WORKER.startswith(spec["sglangQwen35"] + "@sha256:"))
        configs = json.loads((ROOT / "release/inputs/image-config.json").read_text())
        self.assertFalse(any("sglang-qwen35-0.8b" in image for image in configs))

    def test_one_worker_runs_qwen_on_one_gpu(self):
        found = workers(self.documents)
        self.assertEqual(["inference-worker-0"], [w["metadata"]["name"] for w in found])
        worker = found[0]
        template = worker["spec"]["template"]
        container = sglang(worker)
        self.assertEqual(STAGING_WORKER, container["image"])
        self.assertEqual("1", template["metadata"]["annotations"]["confidential.ai/attested-gpu-count"])
        self.assertEqual(1, int(container["resources"]["limits"]["nvidia.com/gpu"]))
        args = container["args"]
        self.assertEqual(["/usr/local/bin/wait-for-model"], container["command"])
        self.assertIn(f"--expected-repository={MODEL}", args)
        self.assertIn(f"--expected-revision={REVISION}", args)
        self.assertIn(f"--expected-file=.model-lock-local-manifest.json={MANIFEST_SHA256}", args)

    def test_worker_argv_is_the_image_helper_argv(self):
        container = sglang(workers(self.documents)[0])
        args = container["args"]
        path = next(a for a in args if a.startswith("--path=")).removeprefix("--path=")
        server = args[args.index("--") + 1:]
        self.assertEqual(["python3", "-m", "sglang.launch_server"], server[:3])
        helper = subprocess.run(["bash", str(SERVE), "args"], env={"MODEL_PATH": path, "PATH": "/usr/bin:/bin"},
                                check=True, capture_output=True, text=True).stdout.split()
        # The staging trace flags are telemetry, not part of the helper's argv.
        self.assertEqual(helper, [a for a in server[3:] if not a.startswith(
            ("--enable-trace", "--trace-modules", "--otlp-traces-endpoint"))])
        self.assertFalse(any("dsv4" in a and not a.startswith("--model-path") for a in server))

    def test_router_sends_to_the_one_worker(self):
        router = next(item for item in self.documents if item["kind"] == "Deployment"
                      and item["metadata"]["name"] == "sglang-router")
        args = router["spec"]["template"]["spec"]["containers"][0]["args"]
        urls = args[args.index("--worker-urls") + 1:args.index("--policy=cache_aware")]
        self.assertEqual(["http://inference-worker-0-0.inference-workers:30000"], urls)

    def test_model_files_are_in_the_image(self):
        worker = workers(self.documents)[0]
        template = worker["spec"]["template"]
        container = sglang(worker)
        args = container["args"]
        self.assertEqual(["/usr/local/bin/wait-for-model"], container["command"])
        self.assertIn(f"--path={IMAGE_MODEL_PATH}", args)
        self.assertIn("--image-files", args)
        self.assertNotIn("--plain-cache", args)
        self.assertIn(f"--model-path={IMAGE_MODEL_PATH}", args)
        # No download, no egress, no init container, no model volume.
        self.assertNotIn("confidential.ai/c8s-volumes", template["metadata"]["annotations"])
        self.assertNotIn("confidential.ai/c8s-volume-dir", template["metadata"]["annotations"])
        self.assertNotIn("hostAliases", template["spec"])
        self.assertNotIn("initContainers", template["spec"])
        self.assertEqual(["shm"], [volume["name"] for volume in template["spec"]["volumes"]])
        self.assertEqual(["shm"], [mount["name"] for mount in container["volumeMounts"]])
        self.assertFalse(any("fetch-model" in part for part in container["command"] + args))
        names = {(item["kind"], item["metadata"]["name"]) for item in self.documents}
        self.assertNotIn(("ConfigMap", "model-manifest"), names)
        self.assertNotIn(("NetworkPolicy", "inference-worker-model-download"), names)

    def test_wait_for_model_pins_the_image_manifest(self):
        args = sglang(workers(self.documents)[0])["args"]
        manifest = (ROOT / "images/sglang-qwen35-0.8b/model-manifest.json").read_bytes()
        self.assertEqual(MANIFEST_SHA256, hashlib.sha256(manifest).hexdigest())
        self.assertIn(f"--expected-file=.model-lock-local-manifest.json={MANIFEST_SHA256}", args)
        files = {entry["path"]: entry["content_sha256"] for entry in json.loads(manifest)["files"]}
        self.assertIn(f"--expected-file=config.json={files['config.json']}", args)
        self.assertIn(f"--expected-file=tokenizer_config.json={files['tokenizer_config.json']}", args)

    def test_image_model_path_is_the_image_layer(self):
        dockerfile = (ROOT / "images/sglang-qwen35-0.8b/Dockerfile").read_text()
        self.assertIn(f'LABEL ai.confidential.model.path="{IMAGE_MODEL_PATH}"', dockerfile)

    def test_image_model_excludes_download(self):
        result = render("qwen35-staging-values.yaml", extra=("--set", "inference.model.download.enabled=true"),
                        check=False)
        self.assertNotEqual(0, result.returncode)

    def test_image_model_needs_model_mode(self):
        result = render("qwen35-staging-values.yaml", extra=("--set", "inference.mode=simulator",
                                                              "--set", "inference.gpusPerReplica=0"), check=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("inference.mode=model", result.stderr)

    def test_image_model_needs_an_image_path(self):
        for value in ("", "/mnt/c8s-data/models/qwen", "/opt/../etc"):
            result = render("qwen35-staging-values.yaml", extra=("--set", f"inference.model.imagePath={value}"),
                            check=False)
            self.assertNotEqual(0, result.returncode, value)

    def test_default_source_is_the_mount(self):
        found = workers(documents(render()))
        self.assertTrue(found)
        for worker in found:
            self.assertNotIn("--image-files", sglang(worker)["args"])

    def test_gateway_serves_the_model(self):
        gateway = next(item for item in self.documents if item["kind"] == "Deployment"
                       and item["metadata"]["name"] == "gateway")
        env = next(c for c in gateway["spec"]["template"]["spec"]["containers"] if c["name"] == "gateway")["env"]
        settings = json.loads(next(e["value"] for e in env if e["name"] == "GATEWAY_RUNTIME_CONFIG"))
        self.assertEqual([MODEL], settings["catalogModelIds"])
        self.assertEqual([MODEL], settings["inferenceModelIds"])

    def test_default_worker_image_is_the_production_image(self):
        found = workers(documents(render()))
        expected = yaml.safe_load(RELEASE_VALUES.read_text())["images"]["sglangDsv41Flash"]
        self.assertTrue(found)
        self.assertEqual({expected}, {sglang(worker)["image"] for worker in found})

    def test_selecting_an_unset_image_fails(self):
        result = render("qwen35-staging-values.yaml", extra=("--set", "images.sglangQwen35=null"), check=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("sglangQwen35", result.stderr)

    def test_pd_cannot_be_enabled(self):
        result = render(extra=("--set", "inference.pd.enabled=true"), check=False)
        self.assertNotEqual(0, result.returncode)


if __name__ == "__main__":
    unittest.main()
