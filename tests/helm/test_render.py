#!/usr/bin/env python3
"""Verify the neutral Helm chart defaults and safety rules."""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "helm/confidential-inference"
PINNED = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
# The chart has no default for inference.mode. Every render must state the
# mode. This constant marks a render that only needs a chart to succeed, not
# a specific mode, so it picks the GPU-free simulator backend.
NEUTRAL_MODE = ("--set", "inference.mode=simulator")


def helm(*arguments: str, success: bool = True) -> str:
    result = subprocess.run(
        ["helm", *arguments], cwd=ROOT, text=True, capture_output=True, check=False
    )
    if (result.returncode == 0) != success:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout


def main() -> None:
    helm("lint", str(CHART), *NEUTRAL_MODE)
    documents = [
        item for item in yaml.safe_load_all(
            helm("template", "example", str(CHART), "--namespace", "inference", *NEUTRAL_MODE)
        ) if item
    ]
    workloads = [
        item for item in documents
        if item["kind"] in {"Deployment", "StatefulSet", "DaemonSet"}
    ]
    names = {item["metadata"]["name"] for item in workloads}
    assert {"gateway", "sglang-router", "inference-worker-0", "inference-worker-1"}.issubset(names)
    assert not any(item["kind"] == "PersistentVolume" for item in documents)
    for workload in workloads:
        containers = workload["spec"]["template"]["spec"]["containers"]
        attest = [item for item in containers if item["name"] == "cds-attest"]
        assert len(attest) == 1
        attest = attest[0]
        assert "--attestation-api-url=http://$(HOST_IP):8400" in attest["args"]
        assert any(item["name"] == "HOST_IP" for item in attest.get("env", []))
        assert not any(
            item["name"] == "c8s-workload-claims"
            for item in attest.get("volumeMounts", [])
        )
        assert not any(
            item["name"] == "c8s-workload-claims"
            for item in workload["spec"]["template"]["spec"].get("volumes", [])
        )
        for container in containers:
            if container is not attest:
                assert not any(
                    item["name"] == "c8s-workload-claims"
                    for item in container.get("volumeMounts", [])
                )
    assert not any(
        item["kind"] == "Service"
        and item["spec"].get("type", "ClusterIP") in {"LoadBalancer", "NodePort"}
        for item in documents
    )
    gateway = next(
        item for item in documents
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "gateway"
    )
    gateway_container = next(
        item for item in gateway["spec"]["template"]["spec"]["containers"]
        if item["name"] == "gateway"
    )
    gateway_env = {item["name"]: item["value"] for item in gateway_container["env"]}
    assert gateway_env["GATEWAY_ENDPOINT_DRAIN_SECONDS"] == "35"
    assert gateway_env["GATEWAY_EXPECTED_OPERATOR_KEY_SET_SHA256"].startswith("sha256:")
    assert gateway_container["readinessProbe"]["httpGet"]["path"] == "/ready"
    assert gateway_container["livenessProbe"]["httpGet"]["path"] == "/health"
    assert gateway["spec"]["template"]["spec"]["terminationGracePeriodSeconds"] == 960
    for workload in workloads:
        for container in workload["spec"]["template"]["spec"]["containers"]:
            assert PINNED.fullmatch(container["image"]), container["image"]
            security = container["securityContext"]
            assert security["allowPrivilegeEscalation"] is False
            assert "ALL" in security["capabilities"]["drop"]
    rendered = yaml.safe_dump_all(documents)
    assert "nvidia.com/gpu" not in rendered

    # The gateway state is a c8s mutable encrypted volume. The chart creates
    # no host storage, no cluster-scoped storage objects, and no admission
    # policy for it.
    stateful = [
        item for item in yaml.safe_load_all(
            helm(
                "template", "example", str(CHART), "--namespace", "inference",
                *NEUTRAL_MODE, "--set", "gateway.state.enabled=true",
            )
        ) if item
    ]
    assert not {
        "PersistentVolume", "PersistentVolumeClaim", "StorageClass",
        "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding",
    } & {item["kind"] for item in stateful}
    assert not any(item["kind"] == "DaemonSet" and "state" in item["metadata"]["name"] for item in stateful)
    stateful_gateway = next(
        item for item in stateful
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "gateway"
    )
    assert stateful_gateway["spec"]["strategy"] == {"type": "Recreate"}
    annotations = stateful_gateway["spec"]["template"]["metadata"]["annotations"]
    assert annotations["confidential.ai/c8s-volumes"] == "gwstate=/confidential-inference/volumes/gwstate"
    assert annotations["confidential.ai/c8s-volume-dir"] == "/mnt/c8s-data"
    stateful_env = {
        item["name"]: item["value"]
        for item in stateful_gateway["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert stateful_env["GATEWAY_STATE_VOLUME"] == "c8s"
    assert stateful_env["GATEWAY_STATE_VOLUME_NAME"] == "gwstate"
    assert stateful_env["GATEWAY_STATE_DATABASE"] == "/mnt/c8s-data/gwstate/gateway.sqlite3"
    assert not any(
        "persistentVolumeClaim" in volume
        for volume in stateful_gateway["spec"]["template"]["spec"]["volumes"]
    )
    helm(
        "template", "example", str(CHART), *NEUTRAL_MODE,
        "--set", "gateway.state.enabled=true",
        "--set", "gateway.state.databasePath=/mnt/c8s-data/other/gateway.sqlite3",
        success=False,
    )
    helm(
        "lint", str(CHART), *NEUTRAL_MODE, "--set-string",
        "images.gateway=example.invalid/gateway:latest", success=False,
    )
    helm(
        "lint", str(CHART), *NEUTRAL_MODE, "--set", "gateway.service.type=LoadBalancer",
        success=False,
    )
    helm(
        "template", "example", str(CHART), "--namespace", "inference", *NEUTRAL_MODE,
        "--set", "gateway.terminationGracePeriodSeconds=935",
        success=False,
    )
    helm(
        "template", "example", str(CHART), "--namespace", "inference", *NEUTRAL_MODE,
        "--set", "inference.replicas=1",
        "--set", "inference.gpusPerReplica=1",
        "--set", "inference.gpuArchitectures=[]",
        success=False,
    )

    inference_documents = [
        item for item in yaml.safe_load_all(
            helm(
                "template", "example", str(CHART), "--namespace", "inference",
                "--values", str(ROOT / "tests/contracts/values-sglang.yaml"),
            )
        ) if item
    ]
    router = next(
        item for item in inference_documents
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "sglang-router"
    )
    router_args = next(
        container["args"]
        for container in router["spec"]["template"]["spec"]["containers"]
        if container["name"] == "sglang-router"
    )
    assert "--selector=app.kubernetes.io/component=inference-worker" in router_args
    assert router["spec"]["strategy"]["rollingUpdate"] == {
        "maxUnavailable": 0,
        "maxSurge": 1,
    }
    router_service = next(
        item for item in inference_documents
        if item["kind"] == "Service" and item["metadata"]["name"] == "sglang-router"
    )
    assert "publishNotReadyAddresses" not in router_service["spec"]
    router_role = next(
        item for item in inference_documents
        if item["kind"] == "Role" and item["metadata"]["name"] == "sglang-router-pods"
    )
    assert router_role["rules"] == [{
        "apiGroups": [""],
        "resources": ["pods"],
        "verbs": ["get", "list", "watch"],
    }]

    # The attested GPU count annotation defaults to the per-pod allocation and
    # can be overridden when several workers share one node's GPUs.
    worker = next(
        item for item in inference_documents
        if item["metadata"]["name"] == "inference-worker-0"
        and item["kind"] in {"Deployment", "StatefulSet"}
    )
    worker_annotations = worker["spec"]["template"]["metadata"]["annotations"]
    assert worker_annotations["confidential.ai/attested-gpu-count"] == "4"
    override_documents = [
        item for item in yaml.safe_load_all(
            helm(
                "template", "example", str(CHART), "--namespace", "inference",
                "--values", str(ROOT / "tests/contracts/values-sglang.yaml"),
                "--set", "inference.attestedGpuCount=8",
            )
        ) if item
    ]
    override_worker = next(
        item for item in override_documents
        if item["metadata"]["name"] == "inference-worker-0"
        and item["kind"] in {"Deployment", "StatefulSet"}
    )
    override_annotations = override_worker["spec"]["template"]["metadata"]["annotations"]
    assert override_annotations["confidential.ai/attested-gpu-count"] == "8"
    router_network_policy = next(
        item for item in inference_documents
        if item["kind"] == "NetworkPolicy" and item["metadata"]["name"] == "router-paths"
    )
    router_egress_ports = {
        port["port"]
        for rule in router_network_policy["spec"]["egress"]
        for port in rule.get("ports", [])
    }
    assert {443, 6443}.issubset(router_egress_ports)

    workers = [
        item for item in inference_documents
        if item["kind"] == "StatefulSet"
        and item["metadata"]["name"].startswith("inference-worker-")
    ]
    assert len(workers) == 2
    for worker in workers:
        worker_index = worker["metadata"]["name"].removeprefix("inference-worker-")
        worker_pod = worker["spec"]["template"]
        sglang_args = next(
            container["args"]
            for container in worker_pod["spec"]["containers"]
            if container["name"] == "sglang"
        )
        assert sglang_args.count("--tool-call-parser=deepseekv4") == 1
        cds_attest_args = next(
            container["args"]
            for container in worker_pod["spec"]["containers"]
            if container["name"] == "cds-attest"
        )
        assert f"--expected-workload=inference-worker-{worker_index}" in cds_attest_args
        assert "--nvidia-gpu-evidence" in cds_attest_args
        cds_attest = next(
            container
            for container in worker_pod["spec"]["containers"]
            if container["name"] == "cds-attest"
        )
        assert "--attestation-api-url=http://$(HOST_IP):8400" in cds_attest["args"]
        assert not any(
            item["name"] == "c8s-workload-claims"
            for item in cds_attest.get("volumeMounts", [])
        )
        assert (
            worker["spec"]["template"]["metadata"]["annotations"]["confidential.ai/cw"]
            == f"inference-worker-{worker_index}"
        )

    no_gpu_flag_documents = [
        item for item in yaml.safe_load_all(
            helm(
                "template", "example", str(CHART), "--namespace", "inference",
                "--values", str(ROOT / "tests/contracts/values-sglang.yaml"),
                "--set", "attestationReceipts.gpuEvidenceFlagEnabled=false",
            )
        ) if item
    ]
    no_gpu_flag_workers = [
        item for item in no_gpu_flag_documents
        if item["kind"] == "StatefulSet"
        and item["metadata"]["name"].startswith("inference-worker-")
    ]
    assert len(no_gpu_flag_workers) == 2
    for worker in no_gpu_flag_workers:
        cds_attest_args = next(
            container["args"]
            for container in worker["spec"]["template"]["spec"]["containers"]
            if container["name"] == "cds-attest"
        )
        assert "--nvidia-gpu-evidence" not in cds_attest_args

    simulator_documents = [
        item for item in yaml.safe_load_all(
            helm(
                "template", "example", str(CHART), "--namespace", "inference",
                "--values", str(ROOT / "tests/contracts/values-sglang-simulator.yaml"),
            )
        ) if item
    ]
    simulator_workers = [
        item for item in simulator_documents
        if item["kind"] == "StatefulSet"
        and item["metadata"]["name"].startswith("inference-worker-")
    ]
    assert len(simulator_workers) == 2
    for worker in simulator_workers:
        worker_index = worker["metadata"]["name"].removeprefix("inference-worker-")
        pod = worker["spec"]["template"]
        assert "confidential.ai/c8s-volumes" not in pod["metadata"]["annotations"]
        container = next(
            item for item in pod["spec"]["containers"] if item["name"] == "sglang"
        )
        assert container["command"] == ["python3"]
        assert "sglang_simulator.simulation.sglang.launch_server" in container["args"]
        assert "--chat-template=chatml" in container["args"]
        assert f"--random-seed={worker_index}" in container["args"]
        assert "nvidia.com/gpu" not in container["resources"].get("requests", {})
        assert "nvidia.com/gpu" not in container["resources"].get("limits", {})
        environment = {item["name"]: item["value"] for item in container["env"]}
        assert environment["CUDA_VISIBLE_DEVICES"] == ""
        assert environment["SGLANG_USE_CPU_ENGINE"] == "1"

    worker_transition_documents = [
        item for item in yaml.safe_load_all(
            helm(
                "template", "example", str(CHART), "--namespace", "inference",
                "--values", str(ROOT / "tests/contracts/values-sglang.yaml"),
                "--set-string", "inference.attestedWorkloads[0]=inference-worker-0-release-2",
                "--set-string", "inference.attestedWorkloads[1]=inference-worker-1-release-2",
            )
        ) if item
    ]
    transition_workers = [
        item for item in worker_transition_documents
        if item["kind"] == "StatefulSet"
        and item["metadata"]["name"].startswith("inference-worker-")
    ]
    for worker in transition_workers:
        worker_index = worker["metadata"]["name"].removeprefix("inference-worker-")
        cds_attest_args = next(
            container["args"]
            for container in worker["spec"]["template"]["spec"]["containers"]
            if container["name"] == "cds-attest"
        )
        assert (
            f"--expected-workload=inference-worker-{worker_index}-release-2"
            in cds_attest_args
        )
        assert "--nvidia-gpu-evidence" in cds_attest_args
        assert (
            worker["spec"]["template"]["metadata"]["annotations"]["confidential.ai/cw"]
            == f"inference-worker-{worker_index}"
        )

    non_worker_attest_args = []
    for document in inference_documents:
        if document["kind"] != "Deployment":
            continue
        for container in document["spec"]["template"]["spec"]["containers"]:
            if container["name"] == "cds-attest":
                non_worker_attest_args.extend(container.get("args", []))
    assert "--nvidia-gpu-evidence" not in non_worker_attest_args

    default_documents = [
        item for item in yaml.safe_load_all(
            helm("template", "example", str(CHART), "--namespace", "inference", *NEUTRAL_MODE)
        ) if item
    ]
    default_attest_args = []
    for document in default_documents:
        if document["kind"] not in {"Deployment", "StatefulSet"}:
            continue
        for container in document["spec"]["template"]["spec"]["containers"]:
            if container["name"] == "cds-attest":
                default_attest_args.extend(container.get("args", []))
    assert "--nvidia-gpu-evidence" not in default_attest_args

    transition_documents = [
        item for item in yaml.safe_load_all(
            helm(
                "template", "example", str(CHART), "--namespace", "inference", *NEUTRAL_MODE,
                "--set-string", "gateway.attestedWorkload=gateway-release-2",
                "--set-string", "router.attestedWorkload=router-release-2",
                "--set-string", "metricsCollector.attestedWorkload=metrics-collector-release-2",
                "--set-string", "kubeStateMetrics.attestedWorkload=kube-state-metrics-release-2",
            )
        ) if item
    ]
    expected = {
        "gateway": "--expected-workload=gateway-release-2",
        "sglang-router": "--expected-workload=router-release-2",
        "metrics-collector": "--expected-workload=metrics-collector-release-2",
        "kube-state-metrics": "--expected-workload=kube-state-metrics-release-2",
    }
    for deployment_name, expected_argument in expected.items():
        deployment = next(
            item for item in transition_documents
            if item["kind"] == "Deployment"
            and item["metadata"]["name"] == deployment_name
        )
        cds_attest = next(
            container
            for container in deployment["spec"]["template"]["spec"]["containers"]
            if container["name"] == "cds-attest"
        )
        assert expected_argument in cds_attest["args"]
        assert (
            deployment["spec"]["template"]["metadata"]["annotations"]
            ["confidential.ai/cw"] == deployment_name
        )

    # The chart has no default for inference.mode, so a values file that
    # omits the field must fail the render, not silently pick a backend.
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as mode_absent_values:
        yaml.safe_dump({"inference": {"enabled": True}}, mode_absent_values)
        mode_absent_values.flush()
        result = subprocess.run(
            [
                "helm", "template", "example", str(CHART), "--namespace", "inference",
                "--values", mode_absent_values.name,
            ],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
    assert result.returncode != 0, "a render with no inference.mode must fail"
    assert "inference" in result.stderr
    assert "mode" in result.stderr

    # Each committed environment values file must state its own mode, since
    # the chart will not choose one for it.
    production_values = yaml.safe_load(
        (ROOT / "c8s/production-values.yaml").read_text()
    )
    assert production_values["inference"]["mode"] == "model"
    assert production_values["inference"]["reasoningParser"] == "deepseek-v4"
    production_documents = [
        item for item in yaml.safe_load_all(
            helm(
                "template", "production", str(CHART),
                "--namespace", "confidential-inference",
                "--values", str(ROOT / "c8s/production-values.yaml"),
            )
        ) if item
    ]
    production_workers = [
        item for item in production_documents
        if item["kind"] == "StatefulSet"
        and item["metadata"]["name"].startswith("inference-worker-")
    ]
    assert len(production_workers) == 2
    for worker in production_workers:
        sglang_args = next(
            container["args"]
            for container in worker["spec"]["template"]["spec"]["containers"]
            if container["name"] == "sglang"
        )
        assert sglang_args.count("--reasoning-parser=deepseek-v4") == 1
        assert sglang_args.count("--tool-call-parser=deepseekv4") == 1
    staging_values = yaml.safe_load(
        (ROOT / "c8s/staging-values.yaml").read_text()
    )
    assert staging_values["inference"]["mode"] == "simulator"

    # The cds-attest sidecar must read TEE evidence from the same attestation
    # API that c8s injects into its own get-cert and get-secret sidecars. A
    # c8s install with no in-cluster attestation-api Deployment serves the
    # node HTTP endpoint only, and the Unix socket then has no server behind
    # it: the sidecar answers 502 and /attestation answers 503.
    node_api_documents = default_documents
    node_api_sidecars = [
        container
        for document in node_api_documents
        if document["kind"] in {"Deployment", "StatefulSet"}
        for container in document["spec"]["template"]["spec"]["containers"]
        if container["name"] == "cds-attest"
    ]
    assert node_api_sidecars
    for container in node_api_sidecars:
        assert "--attestation-api-url=http://$(HOST_IP):8400" in container["args"]
        assert [
            item for item in container.get("env", []) if item["name"] == "HOST_IP"
        ], "the node attestation API URL needs the HOST_IP field reference"
        assert not any(
            item["name"] == "c8s-workload-claims"
            for item in container.get("volumeMounts", [])
        )

    print("Helm neutral-default and safety tests passed.")


if __name__ == "__main__":
    main()
