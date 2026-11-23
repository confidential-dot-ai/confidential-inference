"""inference.layout pair: the recipe deepseek-v41-flash-262k-4xb200 on the chart.

Each replica is one pair pod (inference-pair-<i>: prefill and decode of the
engine image's launch plan dsv41-262k in one sglang-pair container) and one
PD router pod (pd-router-<i>). The cache-aware router routes between the PD
routers. The values are the recipe's (scripts/recipe-values.py), then the
environment's (tests/fixtures/deployments/dsv41-pair-environment-values.yaml),
then the release's, the order a deployment applies them.
"""
from __future__ import annotations

import importlib.util
import json
import re
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "helm/confidential-inference"
RECIPE = ROOT / "recipes/deepseek-v41-flash-262k-4xb200/recipe.yaml"
ENVIRONMENT = ROOT / "tests/fixtures/deployments/dsv41-pair-environment-values.yaml"
RELEASE_VALUES = ROOT / "tests/release-v1/fixtures/release-values.yaml"
NAMESPACE = "confidential-inference"
ENGINE = "ghcr.io/confidential-dot-ai/confidential-sglang/engine@sha256:" + "e" * 64
ROUTER = "ghcr.io/confidential-dot-ai/confidential-sglang/router@sha256:" + "f" * 64
MODEL = "deepseek-ai/DeepSeek-V4.1-Flash-1017"
MODEL_PATH = "/mnt/c8s-data/models/dsv41"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RV = load("recipe_values_pair", ROOT / "scripts/recipe-values.py")


def recipe_values() -> dict:
    return RV.recipe_values(RV.load(RECIPE), RV.release_image_keys(None))


def render(*extra: str, values: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as temporary:
        recipe = Path(temporary) / "recipe-values.yaml"
        recipe.write_text(RV.dump(values or recipe_values()))
        images = Path(temporary) / "images.yaml"
        images.write_text(yaml.safe_dump({"images": {"confidentialSglangEngine": ENGINE,
                                                     "confidentialSglangRouter": ROUTER}}))
        return subprocess.run(["helm", "template", "example", str(CHART), "--namespace", NAMESPACE,
                               "--values", str(recipe), "--values", str(ENVIRONMENT),
                               "--values", str(RELEASE_VALUES), "--values", str(images), *extra],
                              text=True, capture_output=True, check=check)


def documents(result: subprocess.CompletedProcess) -> list[dict]:
    return [item for item in yaml.safe_load_all(result.stdout) if item]


def named(found: list[dict], kind: str, name: str) -> dict:
    return next(item for item in found if item["kind"] == kind and item["metadata"]["name"] == name)


def pair_config(found: list[dict]) -> dict:
    container = named(found, "StatefulSet", "inference-pair")["spec"]["template"]["spec"]["containers"][0]
    args = container["args"]
    return json.loads(args[args.index("--config-json") + 1])


class PairLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.values = recipe_values()
        cls.documents = documents(render())
        cls.two = documents(render("--set", "inference.replicas=2"))

    def test_one_statefulset_of_identical_pairs_and_no_worker(self):
        for found, replicas in ((self.documents, 1), (self.two, 2)):
            pairs = named(found, "StatefulSet", "inference-pair")
            self.assertEqual(pairs["spec"]["replicas"], replicas)
            self.assertFalse([item for item in found if item["metadata"]["name"] == "inference-worker"])
            routers = sorted(item["metadata"]["name"] for item in found
                             if item["kind"] == "Deployment" and item["metadata"]["name"].startswith("pd-router-"))
            self.assertEqual(routers, [f"pd-router-{index}" for index in range(replicas)])

    def test_the_pair_pod_runs_one_container_with_four_gpus(self):
        template = named(self.documents, "StatefulSet", "inference-pair")["spec"]["template"]
        containers = template["spec"]["containers"]
        self.assertEqual([c["name"] for c in containers], ["sglang-pair"])
        self.assertNotIn("initContainers", template["spec"])
        container = containers[0]
        self.assertEqual(container["image"], ENGINE)
        self.assertEqual(container["command"], ["/opt/dsv41/bin/python", "/usr/local/bin/sglang-pair"])
        self.assertEqual(container["resources"]["limits"]["nvidia.com/gpu"], 4)
        self.assertEqual(container["resources"]["requests"]["nvidia.com/gpu"], 4)
        # The environment's requests, not the chart's.
        self.assertEqual((container["resources"]["requests"]["cpu"], container["resources"]["requests"]["memory"]),
                         ("32", "400Gi"))
        annotations = template["metadata"]["annotations"]
        self.assertEqual(annotations["confidential.ai/cw"], "inference-pair")
        self.assertEqual(annotations["confidential.ai/attested-gpu-count"], "4")
        self.assertEqual(annotations["confidential.ai/gpu-architectures"], "BLACKWELL")
        self.assertNotIn("confidential.ai/c8s-volumes", annotations)
        # The model download: one emptyDir and the manifest, no per-pair model disk.
        volumes = {volume["name"]: volume for volume in template["spec"]["volumes"]}
        self.assertEqual(sorted(volumes), ["model-download", "model-manifest", "scratch", "shm"])
        self.assertIn("emptyDir", volumes["model-download"])
        self.assertEqual(template["spec"]["hostAliases"], [{"ip": "192.0.2.20", "hostnames": ["models.example.invalid"]}])
        probes = {kind: container[kind]["httpGet"]["path"] for kind in ("startupProbe", "readinessProbe", "livenessProbe")}
        self.assertEqual(probes, {"startupProbe": "/startupz", "readinessProbe": "/readyz", "livenessProbe": "/livez"})

    def test_the_model_gate_downloads_checks_and_holds_the_engram(self):
        gate = pair_config(self.documents)["modelGate"]
        self.assertEqual(gate[:2], ["/bin/sh", "-c"])
        self.assertIn("/usr/local/bin/fetch-model --endpoint=http://models.example.invalid:8080 fetch", gate[2])
        self.assertIn("--manifest-sha256=eb73a3749d5c99994b018a6063068c2ca28871900415fc364fbbfe1b07300629", gate[2])
        check = gate[gate.index("/usr/local/bin/wait-for-model"):]
        self.assertIn(f"--path={MODEL_PATH}", check)
        self.assertIn(f"--expected-repository={MODEL}", check)
        self.assertIn("--expected-revision=1bae0e1088993b9b82de08f59de5be5a34e42170", check)
        self.assertIn("--expected-file=model.safetensors.index.json="
                      "74b0686a3d2891980d5e303251b075a3bccae2c2ff650747db2620a649b98fa8", check)
        self.assertEqual(check[check.index("--") + 1:], [
            "/opt/dsv41/bin/python", "/opt/sglang/recipes/deepseek-v41/launcher/hold_engram_cache.py",
            "--model", MODEL_PATH, "--ready-file", "/run/dsv41/engram.ready"])

    def test_both_workers_run_the_plan_with_the_chart_flags_and_the_warmup(self):
        config = pair_config(self.documents)
        self.assertEqual(set(config), {"workers", "modelGate", "statusPort", "progressTimeoutSeconds",
                                       "startupTimeoutSeconds", "shutdownTimeoutSeconds"})
        workers = config["workers"]
        self.assertEqual([w["role"] for w in workers], ["prefill", "decode"])
        for worker in workers:
            plan = self.values["inference"]["pair"][worker["role"]]
            self.assertEqual((worker["gpus"], worker["ranks"], worker["port"]), (2, 2, plan["port"]))
            self.assertEqual(worker["command"], [
                "/opt/dsv41/bin/python", "-m", "sglang.launch_server", f"--model-path={MODEL_PATH}",
                f"--served-model-name={MODEL}", "--host=0.0.0.0", "--warmups=confidential_cold_path", *plan["args"]])
            self.assertEqual(worker["env"], {**plan["env"], "HF_HUB_OFFLINE": "1",
                                             "SGLANG_ENABLE_HEALTH_ENDPOINT_GENERATION": "false"})
            self.assertIn("MC_INTRANODE_NVLINK", worker["env"])
            self.assertNotIn("CUDA_VISIBLE_DEVICES", worker["env"])

    def test_each_pd_router_reaches_only_its_own_pair(self):
        router = self.values["inference"]["pair"]["router"]
        for index in range(2):
            deployment = named(self.two, "Deployment", f"pd-router-{index}")
            template = deployment["spec"]["template"]
            self.assertEqual(template["metadata"]["annotations"]["confidential.ai/cw"], f"pd-router-{index}")
            self.assertEqual(template["metadata"]["labels"]["app.kubernetes.io/component"], "pd-router")
            self.assertEqual(template["spec"]["hostname"], f"pd-router-{index}")
            self.assertNotIn("hostAliases", template["spec"])
            container = template["spec"]["containers"][0]
            self.assertEqual(container["image"], ROUTER)
            host = f"inference-pair-{index}.inference-pairs.{NAMESPACE}.svc.cluster.local"
            self.assertEqual(container["args"][:6], ["--pd-disaggregation", "--prefill", f"http://{host}:8041", "8999",
                                                     "--decode", f"http://{host}:8042"])
            self.assertEqual(container["args"][6:6 + len(router["args"])], router["args"])
            self.assertIn("--port=8040", container["args"])

    def test_the_cache_aware_router_routes_between_the_pd_routers(self):
        container = named(self.two, "Deployment", "sglang-router")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(container["image"], ROUTER)
        args = container["args"]
        self.assertIn("--policy=cache_aware", args)
        self.assertIn("--selector=app.kubernetes.io/component=pd-router", args)
        self.assertIn("--service-discovery-port=8040", args)
        self.assertNotIn("--selector=app.kubernetes.io/component=inference-worker", args)

    def test_no_control_plane_address_is_in_the_chart_or_the_recipe(self):
        """The router's API server address is a deploy-time value: the render uses the one it is given."""
        kubeconfig = yaml.safe_load(named(documents(render(
            "--set", "router.discovery.apiServer.address=192.0.2.77")), "ConfigMap",
            "sglang-router-kubeconfig")["data"]["kubeconfig"])
        self.assertEqual(kubeconfig["clusters"][0]["cluster"]["server"], "https://192.0.2.77:6443")
        default = yaml.safe_load((CHART / "values.yaml").read_text())["router"]["discovery"]["apiServer"]["address"]
        self.assertTrue(default.startswith("192.0.2."), "the chart default must be a documentation address")
        # No IPv4 address in the pair template or the recipe.
        for path in (RECIPE, CHART / "templates/inference-pairs.yaml"):
            self.assertIsNone(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", path.read_text().replace("0.0.0.0", "")), path)
        self.assertNotIn("apiServer", json.dumps(self.values))
        # Only the cache-aware router talks to the API server; the pairs and PD routers do not.
        for item in self.two:
            if item["kind"] in ("Deployment", "StatefulSet") and item["metadata"]["name"] != "sglang-router":
                self.assertNotIn("kubernetes-api", json.dumps(item))

    def test_network_policies_open_only_the_pair_paths(self):
        policies = {item["metadata"]["name"]: item["spec"] for item in self.documents if item["kind"] == "NetworkPolicy"}
        ports = lambda rule: sorted(port["port"] for port in rule["ports"])  # noqa: E731
        router = policies["router-paths"]["egress"][0]
        self.assertEqual(router["to"][0]["podSelector"]["matchLabels"], {"app.kubernetes.io/component": "pd-router"})
        self.assertEqual(ports(router), [8040])
        self.assertEqual(ports(policies["pd-router-paths"]["egress"][0]), [8041, 8042])
        self.assertEqual(ports(policies["pd-router-paths"]["ingress"][0]), [8040])
        self.assertEqual(ports(policies["pair-ingress"]["ingress"][0]), [8041, 8042])
        # The KV bootstrap port stays inside the pod (loopback).
        self.assertNotIn(8999, [port["port"] for spec in policies.values()
                                for rule in spec.get("ingress", []) + spec.get("egress", [])
                                for port in rule.get("ports", [])])
        download = policies["inference-worker-model-download"]
        self.assertIn("inference-pair", download["podSelector"]["matchExpressions"][0]["values"])
        cds = policies["workloads-to-c8s-cds"]["podSelector"]["matchExpressions"][0]["values"]
        self.assertTrue({"inference-pair", "pd-router"} <= set(cds))

    def test_c8s_admission_accepts_every_pod(self):
        admission = runpy.run_path(str(ROOT / "scripts/check-c8s-admission.py"))
        for found in (render(), render("--set", "inference.replicas=2", "--set", "telemetry.enabled=false")):
            self.assertEqual(admission["refusals"](documents(found)), [])

    def test_the_chart_refuses_a_pair_it_cannot_run(self):
        values = recipe_values()
        cases = {
            "--host, which the chart sets": lambda v: v["inference"]["pair"]["prefill"]["args"].append("--host=1.2.3.4"),
            "--warmups, which the chart sets": lambda v: v["inference"]["pair"]["decode"]["args"].append("--warmup"),
            "which sglang-pair sets": lambda v: v["inference"]["pair"]["decode"]["env"].update(CUDA_VISIBLE_DEVICES="0"),
            "not the pair's 4 GPUs": lambda v: v["inference"].update(gpusPerReplica=8),
            "needs inference.pair.plan": lambda v: v["inference"]["pair"].update(prefill={}),
            "ports must differ": lambda v: v["inference"]["pair"]["decode"].update(port=8041),
        }
        for message, edit in cases.items():
            with self.subTest(message=message):
                changed = json.loads(json.dumps(values))
                edit(changed)
                result = render(values=changed, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_node_loss_tolerations_default_to_kubernetes_and_follow_the_environment(self):
        """The routers and pairs tolerate an unreachable or not-ready node for
        scheduling.nodeLossTolerationSeconds: 300 by default, as Kubernetes would."""
        def tolerations(found: list[dict]) -> dict[str, list]:
            names = ["inference-pair", "sglang-router", "pd-router-0", "pd-router-1"]
            return {item["metadata"]["name"]: item["spec"]["template"]["spec"].get("tolerations")
                    for item in found if item["kind"] in ("StatefulSet", "Deployment")
                    and item["metadata"]["name"] in names}

        def expected(seconds: int) -> list[dict]:
            return [{"key": key, "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": seconds}
                    for key in ("node.kubernetes.io/unreachable", "node.kubernetes.io/not-ready")]
        found = tolerations(self.two)
        self.assertEqual(sorted(found), ["inference-pair", "pd-router-0", "pd-router-1", "sglang-router"])
        self.assertEqual(found, {name: expected(300) for name in found})
        longer = tolerations(documents(render("--set", "inference.replicas=2",
                                              "--set", "scheduling.nodeLossTolerationSeconds=1800")))
        self.assertEqual(longer, {name: expected(1800) for name in found})
        # The aggregated workers (inference.layout worker) too.
        for seconds in (300, 1800):
            result = subprocess.run(["helm", "template", "example", str(CHART), "--namespace", NAMESPACE,
                                     "--values", str(ROOT / "tests/fixtures/deployments/production-values.yaml"),
                                     "--values", str(RELEASE_VALUES),
                                     "--set", f"scheduling.nodeLossTolerationSeconds={seconds}"],
                                    text=True, capture_output=True, check=True)
            workers = named(documents(result), "StatefulSet", "inference-worker")
            self.assertEqual(workers["spec"]["template"]["spec"]["tolerations"], expected(seconds))
        for bad in ("-1", "86401"):
            with self.subTest(value=bad):
                result = render("--set", f"scheduling.nodeLossTolerationSeconds={bad}", check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("nodeLossTolerationSeconds", result.stderr)

    def test_the_worker_layout_renders_as_before(self):
        """Without inference.layout, no pair object renders and the router finds the workers."""
        result = subprocess.run(["helm", "template", "example", str(CHART), "--namespace", NAMESPACE,
                                 "--values", str(ROOT / "tests/fixtures/deployments/production-values.yaml"),
                                 "--values", str(RELEASE_VALUES)], text=True, capture_output=True, check=True)
        found = documents(result)
        names = {item["metadata"]["name"] for item in found}
        self.assertIn("inference-worker", names)
        self.assertFalse({"inference-pair", "pd-router-0", "pd-router-paths", "pair-ingress"} & names)
        router = named(found, "Deployment", "sglang-router")["spec"]["template"]["spec"]["containers"][0]
        self.assertIn("--selector=app.kubernetes.io/component=inference-worker", router["args"])


if __name__ == "__main__":
    unittest.main()
