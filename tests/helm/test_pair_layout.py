"""inference.layout pair: the recipe deepseek-v41-flash-262k-4xb200 on the chart.

Each replica is one pair pod (inference-pair-<i>: prefill and decode of the
engine image's launch plan dsv41-262k in one sglang-pair container) and one
PD router pod (pd-router-<i>). The cache-aware router routes between the PD
routers. The values are the recipe's (scripts/recipe-values.py), then the
environment's (tests/fixtures/deployments/dsv41-pair-environment-values.yaml),
then the release's, the order a deployment applies them.
"""
from __future__ import annotations

import hashlib
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
# The C8s model volume of a deployment without a download: the GPU worker's
# `persistent` disk, opened from this CDS path.
VOLUME_SOURCE = "/confidential-inference/volumes/persistent"
VOLUME = ("--set", "inference.model.download.enabled=false", "--set-string",
          f"inference.model.c8sVolumeSource={VOLUME_SOURCE}", "--set-json", 'inference.model.volumeNames=["persistent"]',
          "--set-json", 'scheduling.inferenceNodeNames=["gpu-0"]')
SEED_HOST = {"serverName": "models-seed.example.invalid", "address": "198.51.100.7"}


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RV = load("recipe_values_pair", ROOT / "scripts/recipe-values.py")
KCM = runpy.run_path(str(ROOT / "scripts/kernel-cache-manifest.py"))


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

    def test_the_gateway_settings_carry_the_unsupported_parameters(self):
        container = named(self.documents, "Deployment", "gateway")["spec"]["template"]["spec"]["containers"][0]
        env = {item["name"]: item.get("value") for item in container["env"]}
        settings = json.loads(env["GATEWAY_RUNTIME_CONFIG"])
        self.assertEqual(settings["unsupportedParameters"], [
            {"name": "n", "allowed": [1]},
            {"name": "best_of", "allowed": [1]},
            {"name": "min_p", "allowed": [0]},
            {"name": "logprobs", "allowed": [False]},
            {"name": "top_logprobs", "allowed": [0]},
        ])
        # The chart schema checks the shape.
        bad = {**self.values, "gateway": {"unsupportedParameters": [{"name": "n", "when": 2}]}}
        result = render(values=bad, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupportedParameters", result.stderr)

    def test_flashinfer_jit_is_off_only_when_the_values_say_so(self):
        values = {**self.values, "inference": {**self.values["inference"], "flashinferDisableJit": False}}
        for worker in pair_config(documents(render(values=values)))["workers"]:
            self.assertNotIn("FLASHINFER_DISABLE_JIT", worker["env"])

    def test_parallel_start_is_on_by_default_and_absent_when_off(self):
        self.assertIs(True, pair_config(self.documents)["parallelStart"])
        self.assertNotIn("parallelStart", pair_config(documents(render("--set", "inference.pair.parallelStart=false"))))

    def test_both_workers_run_the_plan_with_the_chart_flags_and_the_warmup(self):
        config = pair_config(self.documents)
        self.assertEqual(set(config), {"workers", "modelGate", "statusPort", "progressTimeoutSeconds",
                                       "startupTimeoutSeconds", "shutdownTimeoutSeconds", "parallelStart"})
        workers = config["workers"]
        self.assertEqual([w["role"] for w in workers], ["prefill", "decode"])
        for worker in workers:
            plan = self.values["inference"]["pair"][worker["role"]]
            self.assertEqual((worker["gpus"], worker["ranks"], worker["port"]), (2, 2, plan["port"]))
            self.assertEqual(worker["command"], [
                "/opt/dsv41/bin/python", "-m", "sglang.launch_server", f"--model-path={MODEL_PATH}",
                f"--served-model-name={MODEL}", "--host=0.0.0.0", "--warmups=confidential_cold_path", *plan["args"]])
            # The recipe's engine.flashinferDisableJit: true.
            self.assertEqual(worker["env"], {**plan["env"], "HF_HUB_OFFLINE": "1",
                                             "SGLANG_ENABLE_HEALTH_ENDPOINT_GENERATION": "false",
                                             "FLASHINFER_DISABLE_JIT": "1"})
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

    def test_the_router_memory_gauges_leave_from_both_router_jobs(self):
        """confidential-sglang#29: the router launcher adds ci_router_memory_{current,peak}_bytes, unlabeled,
        to the cache-aware router's and each PD router's metrics. No name filter and no label filter of
        the collector may drop them."""
        telemetry = ("--set", "telemetry.enabled=true", "--set", "telemetry.deployment=test-deployment",
                     "--set", "telemetry.relay.serverName=relay.example.com",
                     "--set", "telemetry.relay.address=203.0.113.7",
                     "--set", "telemetry.metrics.tenantId=00000000-0000-0000-0000-000000000001",
                     "--set", "telemetry.metrics.clientId=00000000-0000-0000-0000-000000000002",
                     "--set", "telemetry.metrics.dataCollectionRule=dcr-" + "0" * 32)
        collector = named(documents(render(*telemetry)), "Deployment", "telemetry-collector")
        (argument,) = collector["spec"]["template"]["spec"]["containers"][0]["args"]
        config = json.loads(argument.removeprefix("--config=yaml:"))
        jobs = {job["job_name"]: job for job in
                config["receivers"]["prometheus"]["config"]["scrape_configs"]}
        for name in ("sglang-router", "pd-router"):
            job = jobs[name]
            for rule in job.get("metric_relabel_configs", []):
                # Only label filters: no rule keeps or drops series by name.
                self.assertEqual(rule["action"], "labelkeep", (name, rule))
                for label in ("__name__", "job", "instance", "component"):
                    self.assertRegex(label, f"^(?:{rule['regex']})$", (name, rule))
        # The second gate keeps labels only; it never removes a series.
        statements = config["processors"]["transform/metrics"]["metric_statements"]
        self.assertTrue(all(item.startswith("keep_keys(datapoint.attributes, ") for item in statements), statements)
        contract = yaml.safe_load((ROOT / "docs/observability-metrics.yaml").read_text())
        sources = {rule["source"] for rule in contract["recordingRules"]}
        self.assertTrue({"ci_router_memory_peak_bytes", "ci_router_memory_current_bytes"} <= sources)

    def seed_values(self, *, image: str = ENGINE, plan: str = "dsv41-262k", repository: str = "confidential-ai/kernel-cache",
                    files: list | None = None) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            (cache / "triton/abc").mkdir(parents=True)
            (cache / "triton/abc/kernel.cubin").write_bytes(b"cubin")
            (cache / "inductor/locks").mkdir(parents=True)
            (cache / "inductor/locks/a.lock").write_bytes(b"")
            manifest = KCM["manifest"](cache, repository, image, plan).decode()
        if files is not None:
            changed = json.loads(manifest)
            changed["files"] = files
            manifest = json.dumps(changed)
        values = recipe_values()
        values["inference"]["pair"]["kernelCache"]["seed"] = {"enabled": True, "manifest": manifest}
        return values

    def seed_gate(self, *extra: str) -> list[str]:
        return pair_config(documents(render(*extra, values=self.seed_values())))["modelGate"]

    def test_the_kernel_cache_seed_is_off_by_default(self):
        found = self.documents
        self.assertFalse([item for item in found if item["metadata"]["name"] == "kernel-cache-manifest"])
        template = named(found, "StatefulSet", "inference-pair")["spec"]["template"]["spec"]
        self.assertNotIn("kernel-cache-manifest", [volume["name"] for volume in template["volumes"]])
        self.assertNotIn("kernel-cache-manifest", json.dumps(pair_config(found)["modelGate"]))
        self.assertNotIn("volumeClaimTemplates", named(found, "StatefulSet", "inference-pair")["spec"])

    def test_the_kernel_cache_seed_fills_the_plan_cache_before_the_model_gate(self):
        values = self.seed_values()
        manifest = values["inference"]["pair"]["kernelCache"]["seed"]["manifest"]
        found = documents(render(values=values))
        self.assertEqual(named(found, "ConfigMap", "kernel-cache-manifest")["data"]["manifest.json"], manifest)
        self.assertEqual(json.loads(manifest)["immutable_revision"], "sha256-" + "e" * 64 + "-dsv41-262k")
        self.assertEqual([item["path"] for item in json.loads(manifest)["files"]], ["triton/abc/kernel.cubin"])
        gate = pair_config(found)["modelGate"]
        self.assertEqual(gate[:2], ["/bin/sh", "-c"])
        self.assertEqual(gate[3], "sh")
        self.assertIn("for e in http://models.example.invalid:8080; do /usr/local/bin/fetch-model --endpoint=$e fetch "
                      "--path=/tmp/dsv41/kernel-cache --manifest=/mnt/c8s-data/kernel-cache-manifest/manifest.json "
                      f"--manifest-sha256={hashlib.sha256(manifest.encode()).hexdigest()} "
                      "--revision-metadata=.kernel-cache-manifest.json", gate[2])
        self.assertTrue(gate[2].endswith('exec "$@"'))
        # Then the model gate, unchanged.
        self.assertEqual(gate[4:], pair_config(self.documents)["modelGate"])
        pod = named(found, "StatefulSet", "inference-pair")["spec"]["template"]["spec"]
        self.assertIn({"name": "kernel-cache-manifest", "configMap": {"name": "kernel-cache-manifest"}}, pod["volumes"])
        self.assertIn({"name": "kernel-cache-manifest", "mountPath": "/mnt/c8s-data/kernel-cache-manifest", "readOnly": True},
                      pod["containers"][0]["volumeMounts"])
        # The workers keep the plan's cache paths: the seed lands where they look.
        for worker in pair_config(found)["workers"]:
            self.assertEqual(worker["env"]["TRITON_CACHE_DIR"], "/tmp/dsv41/kernel-cache/triton")
        admission = runpy.run_path(str(ROOT / "scripts/check-c8s-admission.py"))
        self.assertEqual(admission["refusals"](found), [])

    def test_the_recipe_renders_the_plan_kernel_cache_directory(self):
        self.assertEqual(recipe_values()["inference"]["pair"]["kernelCache"], {"planDirectory": "/tmp/dsv41/kernel-cache"})
        layout = RV.release_layout("dsv41-262k", None)
        for directory in ("kernel-cache", "/var/cache/kernels", "/tmp/../etc"):
            with self.subTest(directory=directory):
                changed = json.loads(json.dumps(layout))
                changed["paths"]["kernel_cache_dir"] = directory
                with self.assertRaisesRegex(RV.RecipeError, "kernel_cache_dir"):
                    RV.values(RV.load(RECIPE), RV.release_image_keys(None), changed)

    def test_the_kernel_cache_seed_is_the_plan_whole_cache_tree(self):
        """planDirectory must be the workers' SGLANG_CACHE_DIR, and every compiler cache must be below it."""
        cases = {}
        for directory in ("/tmp/dsv41/kernel-cache/triton", "/tmp/dsv41/other"):
            values = self.seed_values()
            values["inference"]["pair"]["kernelCache"]["planDirectory"] = directory
            cases[directory] = (values, "is not the prefill worker's SGLANG_CACHE_DIR")
        values = self.seed_values()
        values["inference"]["pair"]["decode"]["env"]["TRITON_CACHE_DIR"] = "/tmp/triton"
        cases["decode triton"] = (values, "inference.pair.decode.env TRITON_CACHE_DIR /tmp/triton is not below")
        values = self.seed_values()
        values["inference"]["pair"]["prefill"]["env"]["CUDA_CACHE_PATH"] = "/tmp/dsv41/kernel-cache-nv"
        cases["sibling prefix"] = (values, "inference.pair.prefill.env CUDA_CACHE_PATH")
        values = self.seed_values()
        del values["inference"]["pair"]["prefill"]["env"]["SGLANG_CACHE_DIR"]
        cases["unset"] = (values, "SGLANG_CACHE_DIR (unset)")
        for name, (values, message) in cases.items():
            with self.subTest(case=name):
                result = render(values=values, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
        # A trailing slash is the same directory.
        values = self.seed_values()
        values["inference"]["pair"]["kernelCache"]["planDirectory"] = "/tmp/dsv41/kernel-cache/"
        self.assertIn("--path=/tmp/dsv41/kernel-cache ", pair_config(documents(render(values=values)))["modelGate"][2])

    def test_the_kernel_cache_seed_tries_each_download_host_in_order(self):
        hosts = [{"serverName": "cache.example.invalid", "address": "10.95.0.80"},
                 {"serverName": "models.example.invalid", "address": "192.0.2.20"}]
        script = self.seed_gate("--set-json", f"inference.model.download.hosts={json.dumps(hosts)}")[2]
        self.assertIn("for e in http://cache.example.invalid:8080 http://models.example.invalid:8080; do "
                      "/usr/local/bin/fetch-model --endpoint=$e fetch ", script)
        self.assertIn('if wait $f; then f=; break; fi; echo "kernel cache seed: $e failed" >&2; done; '
                      '[ -z "$f" ] || echo ', script)
        self.assertTrue(script.endswith('trap - TERM INT; exec "$@"'))
        self.assertNotRegex(script, r"exit 1(?![0-9])")

    def test_the_rendered_kernel_cache_seed_runs_failover_and_goes_on_cold(self):
        """Run the rendered seed shell with a fetch-model stub: the hosts go in order, the first success
        stops the loop, and when every host fails the model gate still runs (a cold cache, not a failed
        pair). TERM stops the running fetch at once, without the next host or the model gate."""
        import os
        import signal
        import time
        hosts = [{"serverName": "cache.example.invalid", "address": "10.95.0.80"},
                 {"serverName": "models.example.invalid", "address": "192.0.2.20"}]
        two = self.seed_gate("--set-json", f"inference.model.download.hosts={json.dumps(hosts)}")
        one = self.seed_gate()
        cache, server = "http://cache.example.invalid:8080", "http://models.example.invalid:8080"
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "log"
            stub = Path(temporary) / "fetch-model"
            stub.write_text('#!/bin/sh\nendpoint=${1#--endpoint=}\necho "fetch $endpoint $3" >> "$LOG"\n'
                            'case " $FAIL " in *" $endpoint "*) exit 7;; esac\n'
                            '[ -n "$SLEEP" ] && exec sleep "$SLEEP"\nexit 0\n')
            stub.chmod(0o755)
            gate = ["sh", "-c", f'echo "gate $*" >> "{log}"', "sh", "--model-gate-arg"]

            def command(rendered: list[str], model_gate: list[str] = gate) -> list[str]:
                self.assertEqual(rendered[:2], ["/bin/sh", "-c"])
                return ["/bin/sh", "-c", rendered[2].replace("/usr/local/bin/fetch-model", str(stub)), rendered[3],
                        *model_gate]

            def run(rendered: list[str], fail: str = "") -> tuple[int, list[str], str]:
                log.write_text("")
                done = subprocess.run(command(rendered), env={**os.environ, "LOG": str(log), "FAIL": fail, "SLEEP": ""},
                                      capture_output=True, text=True, timeout=30)
                return done.returncode, log.read_text().split("\n")[:-1], done.stderr

            path = "--path=/tmp/dsv41/kernel-cache"
            self.assertEqual(run(two)[:2], (0, [f"fetch {cache} {path}", "gate --model-gate-arg"]))
            code, lines, stderr = run(two, fail=cache)
            self.assertEqual((code, lines), (0, [f"fetch {cache} {path}", f"fetch {server} {path}", "gate --model-gate-arg"]))
            self.assertIn(f"kernel cache seed: {cache} failed", stderr)
            self.assertNotIn("no source gave it", stderr)
            code, lines, stderr = run(two, fail=f"{cache} {server}")
            self.assertEqual((code, lines), (0, [f"fetch {cache} {path}", f"fetch {server} {path}", "gate --model-gate-arg"]))
            self.assertIn("kernel cache seed: no source gave it; the workers compile their kernels", stderr)
            # One host: the loop runs once and the pair goes on cold (the model download would exit 1).
            code, lines, stderr = run(one, fail=server)
            self.assertEqual((code, lines), (0, [f"fetch {server} {path}", "gate --model-gate-arg"]))
            self.assertIn("no source gave it", stderr)
            # The model gate's own exit code is the gate's.
            log.write_text("")
            failing = command(two, ["sh", "-c", "exit 3", "sh"])
            self.assertEqual(subprocess.run(failing, env={**os.environ, "LOG": str(log), "FAIL": "", "SLEEP": ""},
                                            capture_output=True, timeout=30).returncode, 3)
            # TERM during a fetch: 143 at once, no next host, no model gate.
            log.write_text("")
            process = subprocess.Popen(command(two), env={**os.environ, "LOG": str(log), "FAIL": "", "SLEEP": "30"},
                                       stderr=subprocess.DEVNULL)
            for _ in range(200):
                if log.read_text():
                    break
                time.sleep(0.05)
            time.sleep(0.2)
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=10), 143)
            self.assertEqual(log.read_text().split("\n")[:-1], [f"fetch {cache} {path}"])

    def test_the_chart_refuses_a_kernel_cache_seed_of_another_image_or_plan(self):
        other = "ghcr.io/confidential-dot-ai/confidential-sglang/engine@sha256:" + "d" * 64
        cases = {
            "not of this engine image and plan": self.seed_values(image=other),
            "not of this engine image and plan ": self.seed_values(plan="dsv41"),
            "names no repository or no file": self.seed_values(files=[]),
        }
        not_json = self.seed_values()
        not_json["inference"]["pair"]["kernelCache"]["seed"]["manifest"] = "not a manifest"
        cases["is not a fetch-model byte manifest"] = not_json
        empty = self.seed_values()
        empty["inference"]["pair"]["kernelCache"]["seed"]["manifest"] = ""
        cases["seed.manifest is required"] = empty
        for message, values in cases.items():
            with self.subTest(message=message):
                result = render(values=values, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message.strip(), result.stderr)
        # The environment's model download comes last; turn it off there. Without
        # it the seed needs its own hosts.
        result = render(*VOLUME, values=self.seed_values(), check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("needs seed.hosts, or inference.model.download", result.stderr)

    def volume_seed_values(self) -> dict:
        values = self.seed_values()
        values["inference"]["pair"]["kernelCache"]["seed"]["hosts"] = [SEED_HOST]
        return values

    def test_the_pair_reads_the_c8s_model_volume(self):
        """Download off: the pair reads the C8s volume `persistent`, checked in place, and nothing is fetched."""
        found = documents(render(*VOLUME))
        template = named(found, "StatefulSet", "inference-pair")["spec"]["template"]
        annotations = template["metadata"]["annotations"]
        self.assertEqual(annotations["confidential.ai/c8s-volumes"], f"persistent={VOLUME_SOURCE}")
        self.assertEqual(annotations["confidential.ai/c8s-volume-dir"], "/mnt/c8s-data/models")
        spec = template["spec"]
        # Pinned to the node that holds the disk, no exit, no download objects.
        self.assertEqual(spec["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
                         ["nodeSelectorTerms"][0]["matchExpressions"][0]["values"], ["gpu-0"])
        self.assertNotIn("nodeSelector", spec)
        self.assertNotIn("hostAliases", spec)
        self.assertEqual(sorted(volume["name"] for volume in spec["volumes"]), ["scratch", "shm"])
        names = {item["metadata"]["name"] for item in found}
        self.assertFalse({"model-manifest", "inference-worker-model-download", "inference-pair-kernel-cache-seed"} & names)
        gate = pair_config(found)["modelGate"]
        self.assertEqual(gate[0], "/usr/local/bin/wait-for-model")
        self.assertIn("--path=/mnt/c8s-data/models/persistent", gate)
        # The dm-verity mount, not a plain cache, and no fetch-model.
        self.assertNotIn("--plain-cache", gate)
        self.assertNotIn("fetch-model", json.dumps(gate))
        self.assertIn("--revision-metadata=.model-lock-local-manifest.json", gate)
        for worker in pair_config(found)["workers"]:
            self.assertIn("--model-path=/mnt/c8s-data/models/persistent", worker["command"])
        admission = runpy.run_path(str(ROOT / "scripts/check-c8s-admission.py"))
        self.assertEqual(admission["refusals"](found), [])

    def test_the_volume_consumer_allowlist_rules(self):
        """The allowlist generator gives the pair the volume's `data` mount rule and `secrets` grant,
        and one exit per seed address (C8s v0.101.9 docs/volumes.md "The mount policy")."""
        gen = load("generate_release_allowlist_pair", ROOT / "scripts/generate-release-allowlist.py")
        found = documents(render(*VOLUME, values=self.volume_seed_values()))
        pair = named(found, "StatefulSet", "inference-pair")
        container = pair["spec"]["template"]["spec"]["containers"][0]
        rules = gen.container_mounts(pair, container, {"mounts": []}, c8s_release="v0.101.9")
        self.assertIn({"destination": "/mnt/c8s-data/models/persistent", "kind": "data"}, rules)
        self.assertFalse([rule for rule in rules if rule["kind"] == "host"])
        self.assertEqual(gen.volume_reads(pair), [VOLUME_SOURCE])
        exits = gen.declared_egress(pair, {"controller": "StatefulSet/inference-pair", "egress": {"port": 443}})
        self.assertEqual(exits, [{"cidr": f"{SEED_HOST['address']}/32", "port": 443}])

    def test_the_kernel_cache_seed_comes_from_its_own_hosts_with_the_model_volume(self):
        found = documents(render(*VOLUME, values=self.volume_seed_values()))
        spec = named(found, "StatefulSet", "inference-pair")["spec"]["template"]["spec"]
        self.assertEqual(spec["hostAliases"], [{"ip": SEED_HOST["address"], "hostnames": [SEED_HOST["serverName"]]}])
        self.assertIn("kernel-cache-manifest", [volume["name"] for volume in spec["volumes"]])
        gate = pair_config(found)["modelGate"]
        self.assertEqual(gate[:2], ["/bin/sh", "-c"])
        # https on 443 by default, not the download's http on 8080.
        self.assertIn(f"for e in https://{SEED_HOST['serverName']}; do /usr/local/bin/fetch-model", gate[2])
        self.assertEqual(gate[4], "/usr/local/bin/wait-for-model")
        self.assertNotIn("--plain-cache", gate)
        policy = named(found, "NetworkPolicy", "inference-pair-kernel-cache-seed")["spec"]
        self.assertEqual(policy["podSelector"], {"matchLabels": {"app.kubernetes.io/component": "inference-pair"}})
        self.assertEqual(policy["egress"], [{"to": [{"ipBlock": {"cidr": f"{SEED_HOST['address']}/32"}}],
                                             "ports": [{"protocol": "TCP", "port": 443}]}])
        self.assertNotIn("inference-worker-model-download", {item["metadata"]["name"] for item in found})
        admission = runpy.run_path(str(ROOT / "scripts/check-c8s-admission.py"))
        self.assertEqual(admission["refusals"](found), [])

    def test_seed_hosts_add_to_the_download_hosts(self):
        """With the download on, seed.hosts are extra sources: both are aliases, the seed tries only its own."""
        found = documents(render(values=self.volume_seed_values()))
        spec = named(found, "StatefulSet", "inference-pair")["spec"]["template"]["spec"]
        self.assertEqual(spec["hostAliases"], [{"ip": "192.0.2.20", "hostnames": ["models.example.invalid"]},
                                               {"ip": SEED_HOST["address"], "hostnames": [SEED_HOST["serverName"]]}])
        gate = pair_config(found)["modelGate"]
        self.assertIn(f"for e in https://{SEED_HOST['serverName']}; do", gate[2])
        self.assertNotIn("models.example.invalid", gate[2])
        # A seed host that is also a download host is one alias.
        values = self.seed_values()
        values["inference"]["pair"]["kernelCache"]["seed"]["hosts"] = [
            {"serverName": "models.example.invalid", "address": "192.0.2.20", "scheme": "http", "port": 8080}]
        spec = named(documents(render(values=values)), "StatefulSet", "inference-pair")["spec"]["template"]["spec"]
        self.assertEqual(spec["hostAliases"], [{"ip": "192.0.2.20", "hostnames": ["models.example.invalid"]}])

    def test_the_kernel_cache_manifest_tool(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            (cache / "nv").mkdir()
            (cache / "nv/index").write_bytes(b"index")
            (cache / "x.partial").write_bytes(b"")
            (cache / ".kernel-cache-manifest.json").write_bytes(b"{}")
            manifest = json.loads(KCM["manifest"](cache, "confidential-ai/kernel-cache", ENGINE, "dsv41-262k"))
            self.assertEqual(manifest["files"], [{"path": "nv/index", "size": 5,
                                                  "content_sha256": hashlib.sha256(b"index").hexdigest()}])
            self.assertEqual(manifest["schema"], "confidential-benchmark/local-model-byte-manifest/v1")
            self.assertEqual(manifest["repository"], "confidential-ai/kernel-cache")
            (cache / "link").symlink_to(cache / "nv/index")
            with self.assertRaisesRegex(KCM["ManifestError"], "symbolic link"):
                KCM["manifest"](cache, "confidential-ai/kernel-cache", ENGINE, "dsv41-262k")
            (cache / "link").unlink()
            with self.assertRaisesRegex(KCM["ManifestError"], "digest-pinned"):
                KCM["manifest"](cache, "confidential-ai/kernel-cache", "engine:latest", "dsv41-262k")

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
