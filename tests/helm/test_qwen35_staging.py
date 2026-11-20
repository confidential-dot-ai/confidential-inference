"""The Qwen3.5-0.8B staging recipe: values only, on the confidential-sglang engine image.

Two workers, one GPU each. Each worker downloads the model at start from a
model server (inference.model.download, plain HTTP on an internal address)
and checks every byte against the pinned byte manifest. No model is in an
image.
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
MANIFEST = DEPLOYMENTS / "qwen35-0.8b-model-manifest.json"
MODEL = "Qwen/Qwen3.5-0.8B"
REVISION = "2fc06364715b967f1860aea9cf38778875588b17"
MANIFEST_SHA256 = "625963f6a7f159fd2a3e8ad97642a11ac275d1735adaadca8df39452b9fbd8fa"
ENGINE = yaml.safe_load(RELEASE_VALUES.read_text())["images"]["confidentialSglangEngine"]


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
            and item["metadata"]["name"] == "inference-worker"]


def sglang(worker: dict) -> dict:
    return next(c for c in worker["spec"]["template"]["spec"]["containers"] if c["name"] == "sglang")


def named(found: list[dict], kind: str, name: str) -> dict:
    return next(item for item in found if item["kind"] == kind and item["metadata"]["name"] == name)


class Qwen35StagingTests(unittest.TestCase):
    def setUp(self):
        self.documents = documents(render("qwen35-staging-values.yaml"))

    def test_release_names_one_engine_image(self):
        # The engine comes from the confidential-sglang record (release/spec.yaml
        # confidentialSglang), never from the spec's own images.
        spec = yaml.safe_load((ROOT / "release/spec.yaml").read_text())
        self.assertEqual([], [key for key, value in spec["images"].items() if "sglang" in value])
        self.assertRegex(spec["confidentialSglang"]["record"], r"^images-[0-9a-f]{12}$")
        self.assertTrue(ENGINE.startswith("ghcr.io/confidential-dot-ai/confidential-sglang/engine@sha256:"))

    def test_two_workers_run_qwen_on_one_gpu_each(self):
        found = workers(self.documents)
        self.assertEqual(1, len(found))
        self.assertEqual(2, found[0]["spec"]["replicas"])
        for worker in found:
            template = worker["spec"]["template"]
            container = sglang(worker)
            self.assertEqual(ENGINE, container["image"])
            self.assertEqual("1", template["metadata"]["annotations"]["confidential.ai/attested-gpu-count"])
            self.assertEqual(1, int(container["resources"]["limits"]["nvidia.com/gpu"]))
            args = container["args"]
            self.assertIn(f"--expected-repository={MODEL}", args)
            self.assertIn(f"--expected-revision={REVISION}", args)
            self.assertIn(f"--expected-file=.model-lock-local-manifest.json={MANIFEST_SHA256}", args)

    def test_worker_argv_uses_the_qwen_parsers(self):
        for worker in workers(self.documents):
            args = sglang(worker)["args"]
            server = args[args.index("--") + 1:]
            self.assertEqual(["python3", "-m", "sglang.launch_server"], server[:3])
            self.assertIn(f"--served-model-name={MODEL}", server)
            self.assertIn(f"--revision={REVISION}", server)
            self.assertIn("--tool-call-parser=qwen3_coder", server)
            self.assertIn("--reasoning-parser=qwen3", server)
            self.assertIn("--tp=1", server)
            self.assertIn("--moe-runner-backend=auto", server)
            self.assertFalse(any(a.startswith("--speculative-algorithm") for a in server))
            self.assertFalse(any("dsv4" in a or "deepseek" in a for a in server))

    def test_router_discovers_the_workers(self):
        router = named(self.documents, "Deployment", "sglang-router")
        args = router["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertNotIn("--worker-urls", args)
        self.assertIn("--service-discovery", args)
        self.assertIn("--service-discovery-namespace=confidential-inference", args)
        self.assertIn("--selector=app.kubernetes.io/component=inference-worker", args)

    def test_model_comes_from_the_model_server_over_plain_http(self):
        for worker in workers(self.documents):
            template = worker["spec"]["template"]
            container = sglang(worker)
            fetch = container["command"][2]
            self.assertIn("/usr/local/bin/fetch-model --endpoint=http://models.example.invalid fetch", fetch)
            self.assertIn(f"--manifest-sha256={MANIFEST_SHA256}", fetch)
            self.assertIn("--plain-cache", container["args"])
            self.assertEqual([{"ip": "192.0.2.20", "hostnames": ["models.example.invalid"]}],
                             template["spec"]["hostAliases"])
            # The model server, not a C8s volume and not the image.
            self.assertNotIn("confidential.ai/c8s-volumes", template["metadata"]["annotations"])
        policy = named(self.documents, "NetworkPolicy", "inference-worker-model-download")
        self.assertEqual([{"to": [{"ipBlock": {"cidr": "192.0.2.20/32"}}], "ports": [{"protocol": "TCP", "port": 80}]}],
                         policy["spec"]["egress"])

    def test_download_manifest_is_the_pinned_manifest_file(self):
        data = MANIFEST.read_bytes()
        self.assertEqual(MANIFEST_SHA256, hashlib.sha256(data).hexdigest())
        manifest = json.loads(data)
        self.assertEqual(f"{MODEL}@{REVISION}", manifest["immutable_ref"])
        config = named(self.documents, "ConfigMap", "model-manifest")
        self.assertEqual(data.decode(), config["data"]["manifest.json"])
        args = sglang(workers(self.documents)[0])["args"]
        files = {entry["path"]: entry["content_sha256"] for entry in manifest["files"]}
        self.assertIn(f"--expected-file=config.json={files['config.json']}", args)
        self.assertIn(f"--expected-file=tokenizer_config.json={files['tokenizer_config.json']}", args)

    def test_gateway_serves_the_model(self):
        gateway = named(self.documents, "Deployment", "gateway")
        env = next(c for c in gateway["spec"]["template"]["spec"]["containers"] if c["name"] == "gateway")["env"]
        settings = json.loads(next(e["value"] for e in env if e["name"] == "GATEWAY_RUNTIME_CONFIG"))
        self.assertEqual([MODEL], settings["catalogModelIds"])
        self.assertEqual([MODEL], settings["inferenceModelIds"])

    def test_every_environment_runs_the_engine_image(self):
        for layers in ((), ("qwen35-staging-values.yaml",)):
            found = workers(documents(render(*layers)))
            self.assertTrue(found)
            self.assertEqual({ENGINE}, {sglang(worker)["image"] for worker in found})

    def test_removed_settings_fail(self):
        for extra in (("--set", "inference.workerImage=sglangQwen35"),
                      ("--set", "inference.model.source=image"),
                      ("--set", "inference.model.imagePath=/opt/confidential-inference/models/qwen35-0.8b"),
                      ("--set", "images.sglangQwen35=ghcr.io/confidential-dot-ai/confidential-inference/x@sha256:" + "5" * 64)):
            result = render("qwen35-staging-values.yaml", extra=extra, check=False)
            self.assertNotEqual(0, result.returncode, extra)

    def test_engine_image_is_required(self):
        result = render("qwen35-staging-values.yaml", extra=("--set", "images.confidentialSglangEngine=null"),
                        check=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("confidentialSglangEngine", result.stderr)

    def test_the_removed_engine_and_router_keys_fail(self):
        for key in ("sglangConfidential", "sglangRouter"):
            image = f"ghcr.io/confidential-dot-ai/confidential-inference/{key}@sha256:" + "5" * 64
            result = render("qwen35-staging-values.yaml", extra=("--set", f"images.{key}={image}"), check=False)
            self.assertNotEqual(0, result.returncode, key)
        result = render("qwen35-staging-values.yaml", extra=("--set", "inference.engineImage=sglangConfidential"),
                        check=False)
        self.assertNotEqual(0, result.returncode)

    def test_pd_cannot_be_enabled(self):
        result = render(extra=("--set", "inference.pd.enabled=true"), check=False)
        self.assertNotEqual(0, result.returncode)


if __name__ == "__main__":
    unittest.main()
