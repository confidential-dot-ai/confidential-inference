"""The Qwen3.5-0.8B staging layer runs the staging worker image on one GPU."""
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
MODEL = "Qwen/Qwen3.5-0.8B"
REVISION = "2fc06364715b967f1860aea9cf38778875588b17"
MANIFEST_SHA256 = "625963f6a7f159fd2a3e8ad97642a11ac275d1735adaadca8df39452b9fbd8fa"
# The image that release/spec.yaml pins for sglangStagingWorker.
STAGING_WORKER = yaml.safe_load((ROOT / "release/spec.yaml").read_text())["images"]["sglangStagingWorker"]


def render(*layers: str, extra: tuple[str, ...] = (), check: bool = True) -> subprocess.CompletedProcess:
    files = [arg for layer in ("production-values.yaml", "staging-values.yaml", *layers)
             for arg in ("--values", str(DEPLOYMENTS / layer))]
    return subprocess.run(["helm", "template", "example", str(CHART), "--namespace", "confidential-inference",
                           *files, "--values", str(RELEASE_VALUES), "--set", "environment=staging",
                           "--set", "frameworkRelease.name=v0.14.18", *extra],
                          text=True, capture_output=True, check=check)


def workers(documents: list[dict]) -> list[dict]:
    return [item for item in documents if item["kind"] == "StatefulSet"
            and item["metadata"]["name"].startswith("inference-worker-")]


def sglang(worker: dict) -> dict:
    return next(c for c in worker["spec"]["template"]["spec"]["containers"] if c["name"] == "sglang")


class Qwen35StagingTests(unittest.TestCase):
    def setUp(self):
        result = render("qwen35-staging-values.yaml")
        self.documents = [item for item in yaml.safe_load_all(result.stdout) if item]

    def test_release_pins_a_digest(self):
        self.assertRegex(STAGING_WORKER, r"^ghcr\.io/confidential-dot-ai/sglang-qwen35-0\.8b@sha256:[a-f0-9]{64}$")
        configs = json.loads((ROOT / "release/inputs/image-config.json").read_text())
        self.assertIn(STAGING_WORKER, configs)
        # The release fixture names the same image as the spec.
        self.assertEqual(STAGING_WORKER, yaml.safe_load(RELEASE_VALUES.read_text())["images"]["sglangStagingWorker"])

    def test_workers_run_qwen_on_one_gpu(self):
        found = workers(self.documents)
        self.assertEqual(2, len(found))
        for index, worker in enumerate(found):
            template = worker["spec"]["template"]
            container = sglang(worker)
            self.assertEqual(STAGING_WORKER, container["image"])
            self.assertEqual("1", template["metadata"]["annotations"]["confidential.ai/attested-gpu-count"])
            self.assertEqual(1, int(container["resources"]["limits"]["nvidia.com/gpu"]))
            args = container["args"]
            self.assertEqual("/usr/local/bin/wait-for-model", args[0])
            self.assertIn(f"--expected-repository={MODEL}", args)
            self.assertIn(f"--expected-revision={REVISION}", args)
            self.assertIn(f"--expected-file=.model-lock-local-manifest.json={MANIFEST_SHA256}", args)
            path = f"/mnt/c8s-data/models/{['dsv4', 'dsv4-1'][index]}"
            # recipes/qwen35-0.8b `serve.sh args` in confidential-sglang, plus
            # the staging trace flags.
            server = args[args.index("--") + 1:]
            self.assertEqual(["python3", "-m", "sglang.launch_server",
                              f"--model-path={path}", f"--served-model-name={MODEL}", f"--revision={REVISION}",
                              "--tool-call-parser=qwen3_coder", "--reasoning-parser=qwen3", "--tp=1",
                              "--moe-runner-backend=auto", "--mem-fraction-static=0.90",
                              "--chunked-prefill-size=4096", "--swa-full-tokens-ratio=0.1",
                              "--enable-metrics", "--enable-cache-report"],
                             [a for a in server if not a.startswith(("--enable-trace", "--trace-modules", "--otlp-",
                                                                     "--host=", "--port="))])
            self.assertFalse(any("dsv4" in a and not a.startswith("--model-path") for a in server))

    def test_download_manifest_is_the_pinned_manifest(self):
        config = next(item for item in self.documents if item["kind"] == "ConfigMap"
                      and item["metadata"]["name"] == "model-manifest")
        manifest = config["data"]["manifest.json"].encode()
        self.assertEqual(MANIFEST_SHA256, hashlib.sha256(manifest).hexdigest())
        self.assertEqual(f"{MODEL}@{REVISION}", json.loads(manifest)["immutable_ref"])

    def test_gateway_serves_the_model(self):
        gateway = next(item for item in self.documents if item["kind"] == "Deployment"
                       and item["metadata"]["name"] == "gateway")
        env = next(c for c in gateway["spec"]["template"]["spec"]["containers"] if c["name"] == "gateway")["env"]
        settings = json.loads(next(e["value"] for e in env if e["name"] == "GATEWAY_RUNTIME_CONFIG"))
        self.assertEqual([MODEL], settings["catalogModelIds"])
        self.assertEqual([MODEL], settings["inferenceModelIds"])

    def test_default_worker_image_is_unchanged(self):
        documents = [item for item in yaml.safe_load_all(render().stdout) if item]
        expected = yaml.safe_load(RELEASE_VALUES.read_text())["images"]["sglangWorker"]
        self.assertTrue(workers(documents))
        self.assertEqual({expected}, {sglang(worker)["image"] for worker in workers(documents)})

    def test_selecting_an_unset_image_fails(self):
        result = render("qwen35-staging-values.yaml", extra=("--set", "images.sglangStagingWorker=null"), check=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("sglangStagingWorker", result.stderr)


if __name__ == "__main__":
    unittest.main()
