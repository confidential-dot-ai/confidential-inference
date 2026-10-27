#!/usr/bin/env python3
"""Verify the prefill/decode (PD) layout of the chart against the launcher's plan.

fixtures/dsv41-launch-plan-8gpu-2p2d.json holds the worker and router
processes the DeepSeek-V4.1 launcher generates (--dry-run). The chart must
render exactly those argv and environments, except for the substitutions
below, each of which a Kubernetes pod needs.
"""

from __future__ import annotations

import copy
import json
import runpy
import subprocess
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "helm/confidential-inference"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
PLAN = json.loads((FIXTURES / "dsv41-launch-plan-8gpu-2p2d.json").read_text())
VALUES = FIXTURES / "dsv41-pd-values.yaml"
admission = runpy.run_path(str(ROOT / "scripts/check-c8s-admission.py"))

MODEL_NAME = "example/DeepSeek-V4.1-Flash-1017-NVFP4"
MODEL_PATH = "/mnt/c8s-data/models/dsv41"
CACHE = "/var/cache/dsv41"
PYTHON = "/opt/dsv41/bin/python"
POD_HOST = "inference-pd-0.inference-pd"

# Every difference between the launcher's processes and the chart's.
ARG_SUBSTITUTIONS = {
    # The c8s model volume, not the host checkpoint directory.
    "--model-path": ("/data0/DeepSeek-V4.1-Flash-1017-NVFP4", MODEL_PATH),
    # The router reaches the workers from its own pod.
    "--host": ("127.0.0.1", "0.0.0.0"),
    # The release's model name, which the gateway's model routes use.
    "--served-model-name": ("dsv41", MODEL_NAME),
}
# The device plugin assigns each container its GPUs, numbered from 0.
ENV_REMOVED = {"CUDA_VISIBLE_DEVICES"}
# The kernel cache is a pod emptyDir, never a host directory.
ENV_PREFIX = ("/data/dsv41-bringup/container-cache/dsv41-pd-b300", CACHE)
# The router starts with the pod, not after the workers are healthy as the
# launcher starts it, so it must wait out their whole startup.
ROUTER_ADDED = ["--worker-startup-timeout-secs=7200"]
# Not in the plan: pod resource requests (calibration pending).
RESOURCES = {"prefill": {"cpu": "16", "memory": "160Gi"}, "decode": {"cpu": "16", "memory": "64Gi"}}
# Not in the plan: the gateway admits as many inference requests as the decode
# workers run (the chart refuses fewer), and queues a burst for its 2 s timeout
# instead of answering 503 at once.
GATEWAY_QUEUE = 64


def flag_values(argv: list[str]) -> dict[str, str]:
    return {argv[i]: argv[i + 1] for i in range(len(argv) - 1)
            if argv[i].startswith("--") and not argv[i + 1].startswith("--")}


def worker_args(command: list[str]) -> list[str]:
    assert command[1:3] == ["-m", "sglang.launch_server"], command
    args = list(command[3:])
    for flag, (old, new) in ARG_SUBSTITUTIONS.items():
        index = args.index(flag)
        assert args[index + 1] == old, (flag, args[index + 1])
        args[index + 1] = new
    return args


def worker_env(env: dict[str, str]) -> dict[str, str]:
    old, new = ENV_PREFIX
    return {name: value.replace(old, new) for name, value in env.items() if name not in ENV_REMOVED}


def router_args(command: list[str]) -> list[str]:
    """The router argv after the worker list, without the listen flags the chart sets."""
    args = command[command.index("sglang_router.launch_router") + 1:]
    kept, index = [], 0
    while index < len(args):
        arg = args[index]
        if arg == "--pd-disaggregation":
            index += 1
        elif arg == "--prefill":
            index += 3
        elif arg in {"--decode", "--host", "--port", "--prometheus-port"}:
            index += 2
        else:
            kept.append(arg)
            index += 1
    return kept + ROUTER_ADDED


def decode_slots(plan: dict) -> int:
    """The requests all decode workers run at once (--max-running-requests)."""
    flags = [flag_values(worker["command"]) for worker in plan["workers"]]
    return sum(int(f["--max-running-requests"]) for f in flags if f["--disaggregation-mode"] == "decode")


def derive_values(plan: dict) -> dict:
    workers = []
    for worker in plan["workers"]:
        flags = flag_values(worker["command"])
        role = flags["--disaggregation-mode"]
        entry = {
            "name": worker["name"],
            "role": role,
            "gpus": len(worker["env"]["CUDA_VISIBLE_DEVICES"].split(",")),
            "port": int(worker["url"].rsplit(":", 1)[1]),
        }
        if role == "prefill":
            entry["bootstrapPort"] = worker["bootstrap_port"]
        entry.update(args=worker_args(worker["command"]), env=worker_env(worker["env"]),
                     resources=RESOURCES[role])
        workers.append(entry)
    return {
        "images": {"sglangPd": "ghcr.io/confidential-dot-ai/confidential-inference/sglang-dsv41@sha256:" + "0" * 64},
        "inference": {
            "mode": "model",
            "gpuArchitectures": ["BLACKWELL"],
            "model": {
                "name": MODEL_NAME,
                "revision": "0" * 40,
                "c8sVolumeSource": "/confidential-inference/volumes/dsv41",
                "volumeNames": ["dsv41"],
            },
            "pd": {"enabled": True, "python": PYTHON, "cacheDirectory": CACHE,
                   "workers": workers, "routerArgs": router_args(plan["router"]["command"])},
        },
        "gateway": {"protection": {"inferenceConcurrency": decode_slots(plan), "inferenceQueue": GATEWAY_QUEUE}},
    }


def render(values: dict, *arguments: str, success: bool = True):
    """The rendered documents, or for an expected failure, Helm's error text."""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as handle:
        yaml.safe_dump(values, handle)
        handle.flush()
        result = subprocess.run(["helm", "template", "example", str(CHART), "--values", handle.name, *arguments],
                                cwd=ROOT, text=True, capture_output=True, check=False)
    if (result.returncode == 0) != success:
        raise AssertionError(result.stderr or "the render unexpectedly succeeded")
    return [item for item in yaml.safe_load_all(result.stdout) if item] if success else result.stderr


def by_name(documents: list[dict], kind: str, name: str) -> dict:
    return next(item for item in documents if item["kind"] == kind and item["metadata"]["name"] == name)


def check_values_file_is_the_plan() -> dict:
    """The checked-in example values are the plan plus the documented substitutions."""
    values = yaml.safe_load(VALUES.read_text())
    assert values == derive_values(PLAN), "regenerate fixtures/dsv41-pd-values.yaml from the plan"
    return values


def check_render(values: dict) -> None:
    documents = render(values)
    names = {(item["kind"], item["metadata"]["name"]) for item in documents}
    # PD replaces the aggregated workers.
    assert not any(kind == "StatefulSet" and name.startswith("inference-worker-") for kind, name in names)
    assert ("Service", "inference-workers") not in names
    stateful = by_name(documents, "StatefulSet", "inference-pd")
    template = stateful["spec"]["template"]
    pod = template["spec"]
    annotations = template["metadata"]["annotations"]
    assert annotations["confidential.ai/cw"] == "inference-pd-0"
    assert annotations["confidential.ai/c8s-volumes"] == "dsv41=/confidential-inference/volumes/dsv41"
    assert annotations["confidential.ai/attested-gpu-count"] == "8"
    # Least privilege: the pod asks for no host namespace and no privilege.
    for field in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"):
        assert not pod.get(field), field
    containers = pod["containers"]
    assert [item["name"] for item in containers] == ["engram-holder"] + [w["name"] for w in PLAN["workers"]]
    for container in containers:
        context = container["securityContext"]
        assert context == {"allowPrivilegeEscalation": False, "runAsNonRoot": True, "runAsUser": 1001,
                           "runAsGroup": 1001, "capabilities": {"drop": ["ALL"]}}, container["name"]
    holder = containers[0]
    assert holder["command"] == ["/usr/local/bin/wait-for-model"]
    assert holder["args"][-6:] == [PYTHON, "/opt/sglang/recipes/deepseek-v41/launcher/hold_engram_cache.py",
                                   "--model", MODEL_PATH, "--ready-file", "/run/dsv41/engram.ready"]
    assert f"--path={MODEL_PATH}" in holder["args"] and f"--expected-repository={MODEL_NAME}" in holder["args"]
    ports_before: list[str] = []
    for worker, container in zip(PLAN["workers"], containers[1:]):
        # The exact launcher argv, after the documented substitutions.
        assert container["args"] == [PYTHON, "-m", "sglang.launch_server", *worker_args(worker["command"])]
        env = {item["name"]: item["value"] for item in container["env"]}
        assert env == {"HOME": f"{CACHE}/home", **worker_env(worker["env"])}
        gpus = len(worker["env"]["CUDA_VISIBLE_DEVICES"].split(","))
        assert container["resources"]["limits"] == {"nvidia.com/gpu": gpus}
        # Workers start one at a time, after the holder, as the launcher starts them.
        script = container["command"][2]
        assert container["command"][:2] == ["/bin/sh", "-c"] and container["command"][3] == "sh"
        assert script.startswith("until [ -s /run/dsv41/engram.ready ]")
        assert f"for port in {' '.join(ports_before)}; do" in script and script.endswith('exec "$@"')
        ports_before.append(worker["url"].rsplit(":", 1)[1])
        mounts = {item["mountPath"]: item for item in container["volumeMounts"]}
        assert set(mounts) == {"/dev/shm", CACHE, "/run/dsv41"} and mounts["/run/dsv41"]["readOnly"]
    volumes = {item["name"]: item for item in pod["volumes"]}
    assert volumes["shm"]["emptyDir"]["medium"] == "Memory"
    assert "medium" not in volumes["kernel-cache"]["emptyDir"]
    assert not any("hostPath" in volume for volume in pod["volumes"])
    # The router: PD mode with the plan's policy and admission flags.
    router = by_name(documents, "Deployment", "sglang-router")["spec"]["template"]["spec"]["containers"][0]
    expected = ["--pd-disaggregation"]
    for worker in PLAN["workers"]:
        if "bootstrap_port" in worker:
            expected += ["--prefill", f"http://{POD_HOST}:{worker['url'].rsplit(':', 1)[1]}", str(worker["bootstrap_port"])]
    for worker in PLAN["workers"]:
        if "bootstrap_port" not in worker:
            expected += ["--decode", f"http://{POD_HOST}:{worker['url'].rsplit(':', 1)[1]}"]
    expected += router_args(PLAN["router"]["command"])
    expected += ["--health-check-timeout-secs=5", "--health-failure-threshold=3"]
    expected += ["--host=0.0.0.0", "--port=30000", "--prometheus-host=0.0.0.0", "--prometheus-port=29000"]
    assert router["args"] == expected, router["args"]
    for flag in ("--reject-video", "--max-concurrent-requests", "--max-images-per-request", "--max-inflight-images"):
        assert flag in router["args"]
    # The router reaches every worker port; the pod reaches itself.
    worker_ports = [{"protocol": "TCP", "port": int(w["url"].rsplit(":", 1)[1])} for w in PLAN["workers"]]
    assert by_name(documents, "NetworkPolicy", "router-paths")["spec"]["egress"][0]["ports"] == worker_ports
    assert by_name(documents, "NetworkPolicy", "worker-ingress")["spec"]["ingress"][0]["ports"] == worker_ports
    internal = by_name(documents, "NetworkPolicy", "inference-pd-internal")["spec"]
    assert internal["podSelector"]["matchLabels"]["app.kubernetes.io/instance"] == "inference-pd"
    # The gateway admits a request for every decode slot and queues a burst.
    gateway = by_name(documents, "Deployment", "gateway")["spec"]["template"]["spec"]["containers"][0]
    env = {item["name"]: item.get("value") for item in gateway["env"]}
    settings = json.loads(env["GATEWAY_RUNTIME_CONFIG"])
    assert (settings["inferenceConcurrency"], settings["inferenceQueue"]) == (decode_slots(PLAN), GATEWAY_QUEUE)
    # The c8s webhook admits the pod (scripts/check-c8s-admission.py).
    assert admission["refusals"](documents) == []


def check_refusals(values: dict) -> None:
    """A values file that breaks the layout fails the render."""
    def broken(change, reason: str) -> None:
        edited = copy.deepcopy(values)
        change(edited)
        error = render(edited, success=False)
        assert reason in error, (reason, error)

    def set_arg(flag: str, value: str):
        def change(edited: dict) -> None:
            args = edited["inference"]["pd"]["workers"][0]["args"]
            args[args.index(flag) + 1] = value
        return change

    broken(set_arg("--model-path", "/data0/DeepSeek-V4.1-Flash-1017-NVFP4"), "args must set --model-path")
    broken(set_arg("--host", "127.0.0.1"), "args must set --host 0.0.0.0")
    broken(set_arg("--port", "9999"), "args must set --port 8041")
    broken(set_arg("--served-model-name", "dsv41"), "args must set --served-model-name")
    broken(set_arg("--disaggregation-bootstrap-port", "9001"), "args must set --disaggregation-bootstrap-port 8999")
    broken(lambda edited: edited["inference"]["pd"]["workers"][0]["env"].update(CUDA_VISIBLE_DEVICES="0,1"),
           "remove CUDA_VISIBLE_DEVICES")
    broken(lambda edited: edited["images"].pop("sglangPd"), "inference.pd requires images.sglangPd")
    broken(lambda edited: edited["inference"].update(mode="simulator"), "inference.pd requires inference.mode=model")
    broken(lambda edited: edited["inference"]["pd"].update(
        workers=[w for w in edited["inference"]["pd"]["workers"] if w["role"] == "prefill"]),
        "needs at least one prefill and one decode worker")
    broken(lambda edited: edited["inference"]["pd"]["workers"][1].update(port=8041), "duplicate port 8041")
    slots = decode_slots(PLAN)
    broken(lambda edited: edited["gateway"]["protection"].update(inferenceConcurrency=slots - 1),
           f"gateway.protection.inferenceConcurrency {slots - 1} is below the {slots} requests the decode workers run")
    # A decode worker has no bootstrap port (values.schema.json).
    broken(lambda edited: edited["inference"]["pd"]["workers"][2].update(bootstrapPort=9001), "/inference/pd/workers/2")
    telemetry = ("--set", "telemetry.enabled=true", "--set", "telemetry.deployment=d",
                 "--set", "telemetry.relay.serverName=r.example.com", "--set", "telemetry.relay.address=203.0.113.7",
                 "--set", "telemetry.metrics.tenantId=00000000-0000-0000-0000-000000000001",
                 "--set", "telemetry.metrics.clientId=00000000-0000-0000-0000-000000000002",
                 "--set", "telemetry.metrics.dataCollectionRule=dcr-" + "0" * 32)
    # Telemetry scrapes the gateway and the router, not the PD workers (no metrics port yet).
    documents = render(values, *telemetry)
    (argument,) = by_name(documents, "Deployment", "telemetry-collector")["spec"]["template"]["spec"]["containers"][0]["args"]
    jobs = [job["job_name"] for job in json.loads(argument.removeprefix("--config=yaml:"))["receivers"]["prometheus"]["config"]["scrape_configs"]]
    assert not any(job.startswith("inference-") for job in jobs), jobs


def check_off_by_default() -> None:
    documents = render({"inference": {"mode": "simulator"}})
    assert not any(item["metadata"]["name"].startswith("inference-pd") for item in documents)
    router = by_name(documents, "Deployment", "sglang-router")["spec"]["template"]["spec"]["containers"][0]
    assert router["args"][0] == "--worker-urls" and "--pd-disaggregation" not in router["args"]


# The staging layer for one 8-GPU B200 node (release/staging/b200/values.yaml):
# the plan's layout with the per-worker limits of the B200 1p1d tuning run
# (1 PP2 prefill + 1 TP2 decode on 4 B200, 180 GB HBM). Every other flag and
# variable is the plan's.
B200_LAYER = ROOT / "release/staging/b200/values.yaml"
B200_FLAGS = {
    "prefill": {
        "--context-length": "131072",
        "--max-running-requests": "16",
        "--max-total-tokens": "1572864",
        "--cuda-graph-config": '{"prefill": {"backend": "breakable", "bs": [256, 512, 1024, 2048, 4096, 8192, 12288],'
                               ' "max_seq_len": 65536}, "decode": {"backend": "disabled"}}',
    },
    "decode": {
        "--context-length": "131072",
        "--max-total-tokens": "4194304",
        "--cuda-graph-config": '{"prefill": {"backend": "disabled"}, "decode": {"backend": "breakable",'
                               ' "bs": [1, 2, 4, 8, 10, 12, 14, 16, 32, 64]}}',
    },
}
# The host cache is 4 times the device KV pool, not a fixed size.
B200_REPLACED = {"prefill": {"--hicache-size": ("--hicache-ratio", "4.0")}}
B200_ADDED = {"decode": ["--disaggregation-decode-polling-interval", "2"]}
B200_MODEL = {
    "name": "deepseek-ai/DeepSeek-V4.1-Flash",
    "revision": "5254448103b6254fc646dacbca1cbbf20e9216c1",
    "manifestSha256": "a0d3a3c29654399bcddf018c3a00de4528238399182d400427287d790798f41b",
    "c8sVolumeSource": "/confidential-inference/model-updates/b200-dsv41",
}


def b200_args(args: list[str], role: str) -> list[str]:
    args = [B200_MODEL["name"] if index and args[index - 1] == "--served-model-name" else arg
            for index, arg in enumerate(args)]
    for flag, value in B200_FLAGS[role].items():
        args[args.index(flag) + 1] = value
    for flag, (new_flag, value) in B200_REPLACED.get(role, {}).items():
        index = args.index(flag)
        args[index:index + 2] = [new_flag, value]
    return args + B200_ADDED.get(role, [])


def derive_b200_layer(plan: dict) -> dict:
    values = derive_values(plan)
    for worker in values["inference"]["pd"]["workers"]:
        worker["args"] = b200_args(worker["args"], worker["role"])
    model = B200_MODEL
    return {
        "inference": {
            **values["inference"],
            "model": {
                "name": model["name"],
                "revision": model["revision"],
                "c8sVolumeSource": model["c8sVolumeSource"],
                "volumeNames": ["dsv41"],
                "mountVerification": {"expectedFileList": [
                    {"path": ".model-lock-local-manifest.json", "sha256": model["manifestSha256"]}]},
            },
        },
        "gateway": {
            **values["gateway"],
            "usage": {"models": {model["name"]: {"served_model": model["name"], "model_revision": model["revision"]}}},
        },
        "telemetry": {"enabled": False},
    }


def check_b200_layer() -> None:
    """The B200 layer is the plan with the B200 limits, and renders on top of staging."""
    layer = yaml.safe_load(B200_LAYER.read_text())
    assert layer == derive_b200_layer(PLAN), "regenerate release/staging/b200/values.yaml (derive_b200_layer)"
    image = "ghcr.io/confidential-dot-ai/confidential-inference/sglang-dsv41@sha256:" + "0" * 64
    result = subprocess.run(["helm", "template", "example", str(CHART), "--namespace", "confidential-inference",
                             "--values", "release/values.yaml", "--values", "release/staging/values.yaml",
                             "--values", str(B200_LAYER), "--values", "tests/release-v1/fixtures/release-values.yaml",
                             "--set", "attestationReceipts.releaseId=v0.14.18-staging",
                             "--set", f"images.sglangPd={image}"],
                            cwd=ROOT, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    documents = [item for item in yaml.safe_load_all(result.stdout) if item]
    template = by_name(documents, "StatefulSet", "inference-pd")["spec"]["template"]
    assert template["metadata"]["annotations"]["confidential.ai/attested-gpu-count"] == "8"
    containers = template["spec"]["containers"]
    holder = containers[0]
    assert f"--expected-repository={B200_MODEL['name']}" in holder["args"]
    assert f"--expected-file=.model-lock-local-manifest.json={B200_MODEL['manifestSha256']}" in holder["args"]
    for worker, container in zip(PLAN["workers"], containers[1:]):
        role = flag_values(worker["command"])["--disaggregation-mode"]
        assert container["args"] == [PYTHON, "-m", "sglang.launch_server", *b200_args(worker_args(worker["command"]), role)]
    assert not any(item["kind"] == "StatefulSet" and item["metadata"]["name"].startswith("inference-worker-")
                   for item in documents)
    assert admission["refusals"](documents) == []


def main() -> None:
    values = check_values_file_is_the_plan()
    check_render(values)
    check_refusals(values)
    check_off_by_default()
    check_b200_layer()
    print("PD layout checks passed")


if __name__ == "__main__":
    main()
