#!/usr/bin/env python3
"""Verify the neutral Helm chart defaults and safety rules."""

from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
from pathlib import Path

import json
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


def render(*arguments: str) -> list[dict]:
    """The documents of `helm template example CHART` with the neutral mode and arguments."""
    output = helm("template", "example", str(CHART), *NEUTRAL_MODE, *arguments)
    return [item for item in yaml.safe_load_all(output) if item]


class Gateway:
    """The gateway Deployment of rendered documents, its container, env and release identity ConfigMap."""

    def __init__(self, documents: list[dict]) -> None:
        self.deployment = next(
            item for item in documents
            if item["kind"] == "Deployment" and item["metadata"]["name"] == "gateway"
        )
        self.container = next(
            item for item in self.deployment["spec"]["template"]["spec"]["containers"]
            if item["name"] == "gateway"
        )
        self.env = {item["name"]: item["value"] for item in self.container["env"]}
        self.identity_data = next(
            item for item in documents
            if item["kind"] == "ConfigMap" and item["metadata"]["name"] == "gateway-release-identity"
        )["data"]
        self.identity = json.loads(self.identity_data["release-identity.json"])


def check_cds_policy_pins(url_only: Gateway) -> None:
    """The CDS origin and the policy paths are environment (so allowlist input);
    the policy bytes and their pins travel in the release identity ConfigMap."""
    url = "attestationReceipts.cds.url=https://c8s-cds.c8s-system.svc:8443"
    assert url_only.env["GATEWAY_C8S_CDS_URL"] == "https://c8s-cds.c8s-system.svc:8443"
    assert url_only.env["GATEWAY_C8S_IMAGE_POLICY"] == "/mnt/c8s-data/release-identity/..data/cds-image-policy.json"
    assert url_only.env["GATEWAY_C8S_SERVED_IMAGE_POLICY"] == "/mnt/c8s-data/release-identity/..data/served-image-policy.json"
    assert "cds-image-policy.json" not in url_only.identity_data
    assert "cdsImagePolicySha256" not in url_only.identity
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "target.json"
        served = Path(directory) / "served.json"
        target.write_text('{"target": 1}\n')
        served.write_text('{"served": 2}\n')
        files = (
            "--set-file", f"attestationReceipts.cds.imagePolicy={target}",
            "--set-file", f"attestationReceipts.cds.servedImagePolicy={served}",
        )
        pinned = Gateway(render("--set", url, *files))
        assert pinned.identity_data["cds-image-policy.json"] == target.read_text()
        assert pinned.identity_data["served-image-policy.json"] == served.read_text()
        assert pinned.identity["cdsImagePolicySha256"] == "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest()
        assert pinned.identity["cdsServedImagePolicySha256"] == "sha256:" + hashlib.sha256(served.read_bytes()).hexdigest()
        # The pins are in the file, not the environment.
        assert "GATEWAY_C8S_IMAGE_POLICY_SHA256" not in pinned.env
        # One document alone, or documents without the origin, is a mistake.
        helm("template", "example", str(CHART), *NEUTRAL_MODE, "--set", url, *files[:2], success=False)
        helm("template", "example", str(CHART), *NEUTRAL_MODE, *files, success=False)


def main() -> None:
    # The production release must route to a real Service and use the same
    # C8s identity in the gateway controller and its evidence sidecar.
    production = [item for item in yaml.safe_load_all(helm('template', 'confidential-inference', str(CHART),
        '--namespace', 'confidential-inference', '-f', str(ROOT/'release/values.yaml'),
        '-f', str(ROOT/'tests/release-v1/fixtures/release-values.yaml'),
        '--set', 'attestationReceipts.releaseId=v0.14.18')) if item]
    gateway = next(d for d in production if d['kind'] == 'Deployment' and d['metadata']['name'] == 'gateway-v0-14-18')
    assert gateway['spec']['template']['metadata']['annotations']['confidential.ai/cw'] == gateway['metadata']['name']
    main_container = next(c for c in gateway['spec']['template']['spec']['containers'] if c['name'] == 'gateway')
    gateway_environment = {item['name']: item['value'] for item in main_container['env']}
    for name in ('GATEWAY_C8S_IMAGE_POLICY_SHA256', 'GATEWAY_C8S_SERVED_IMAGE_POLICY_SHA256',
                 'GATEWAY_C8S_EVIDENCE_BASE_URL', 'GATEWAY_C8S_EVIDENCE_CONNECT_HOST'):
        assert name not in gateway_environment
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / 'target.json'
        served = Path(directory) / 'served.json'
        target.write_text('{"target": 1}\n')
        served.write_text('{"served": 2}\n')
        pinned = [item for item in yaml.safe_load_all(helm('template', 'confidential-inference', str(CHART),
            '--namespace', 'confidential-inference', '-f', str(ROOT/'release/values.yaml'),
            '-f', str(ROOT/'tests/release-v1/fixtures/release-values.yaml'),
            '--set', 'attestationReceipts.releaseId=v0.14.18',
            '--set-file', f'attestationReceipts.cds.imagePolicy={target}',
            '--set-file', f'attestationReceipts.cds.servedImagePolicy={served}')) if item]
        trust = next(item['data'] for item in pinned if item['kind'] == 'ConfigMap'
                     and item['metadata']['name'] == 'gateway-release-identity')
        identity = json.loads(trust['release-identity.json'])
        assert identity['cdsImagePolicySha256'] == 'sha256:' + hashlib.sha256(target.read_bytes()).hexdigest()
        assert identity['cdsServedImagePolicySha256'] == 'sha256:' + hashlib.sha256(served.read_bytes()).hexdigest()
        assert trust['cds-image-policy.json'] == target.read_text()
        assert trust['served-image-policy.json'] == served.read_text()
        pinned_gateway = next(item for item in pinned if item['kind'] == 'Deployment'
                              and item['metadata']['name'] == gateway['metadata']['name'])
        assert pinned_gateway['spec']['template'] == gateway['spec']['template']
    assert gateway_environment['GATEWAY_INFERENCE_URL'] == 'http://router-v0-14-18.confidential-inference.svc.cluster.local:30000'
    evidence = next(c for c in gateway['spec']['template']['spec']['containers'] if c['name'] == 'cds-attest')
    assert '--expected-workload='+gateway['metadata']['name'] in evidence['args']
    service = next(d for d in production if d['kind'] == 'Service' and d['metadata']['name'] == 'router-v0-14-18')
    router = next(d for d in production if d['kind'] == 'Deployment' and d['metadata']['name'] == 'router-v0-14-18')
    assert all(router['spec']['template']['metadata']['labels'].get(k) == v for k, v in service['spec']['selector'].items())
    # One model definition produces both views. A release metadata change
    # must not change the pod templates or add a third gateway identity.
    runtime_documents = render("--set", "runtimeConfig.enabled=true", "--set",
        "attestationReceipts.releaseId=v0.14.18-transition", "--set-json",
        'runtimeConfig.modelRoutes={"public-a":["backend-a"],"public-b":["backend-b"]}')
    runtime_gateway = Gateway(runtime_documents)
    maps = {item['metadata']['name']: item for item in runtime_documents if item['kind'] == 'ConfigMap'}
    settings = json.loads(maps['gateway-runtime']['data']['settings.json'])
    routes = json.loads(maps['router-model-routes']['data']['routes.json'])
    assert settings['catalogModelIds'] == settings['inferenceModelIds'] == sorted(routes['routes'])
    assert settings['revision'] == routes['revision'] == 1
    assert settings['routerService'] == 'router-v0-14-18'
    router_slot = next(item for item in runtime_documents if item['kind'] == 'Service' and item['metadata']['name'] == settings['routerService'])
    assert router_slot['spec']['clusterIP'] == 'None'
    assert routes['routes']['public-a'] == ['backend-a']
    assert settings['evidence'] == {'baseUrl': 'https://api.example.invalid'}
    assert 'GATEWAY_C8S_EVIDENCE_BASE_URL' not in runtime_gateway.env
    assert 'GATEWAY_C8S_EVIDENCE_CONNECT_HOST' not in runtime_gateway.env
    promoted_documents = render("--set", "runtimeConfig.enabled=true", "--set",
        "attestationReceipts.releaseId=v0.14.18-transition", "--set-json",
        'runtimeConfig.modelRoutes={"public-a":["backend-a"],"public-b":["backend-b"]}',
        "--set", "attestationReceipts.evidenceBaseUrl=https://api.example.test",
        "--set", "attestationReceipts.evidenceConnectHost=c8s-router.c8s-system.svc.cluster.local",
        "--set", "runtimeConfig.revision=2")
    promoted_maps = {item['metadata']['name']: item for item in promoted_documents if item['kind'] == 'ConfigMap'}
    promoted_settings = json.loads(promoted_maps['gateway-runtime']['data']['settings.json'])
    assert promoted_settings['evidence'] == {'baseUrl': 'https://api.example.test',
        'connectHost': 'c8s-router.c8s-system.svc.cluster.local'}
    assert promoted_settings['revision'] == 2
    assert Gateway(promoted_documents).deployment['spec']['template'] == runtime_gateway.deployment['spec']['template']
    assert runtime_gateway.env['GATEWAY_RUNTIME_CONFIG_FILE'] == '/mnt/c8s-data/runtime/settings.json'
    assert runtime_gateway.env['GATEWAY_RELEASE_SELECTION_FILE'] == '/mnt/c8s-data/release-selection/releases.json'
    for removed in ('GATEWAY_MODEL', 'GATEWAY_RELEASE_ID', 'GATEWAY_INFERENCE_CONCURRENCY',
                    'GATEWAY_MAXIMUM_BODY_BYTES', 'GATEWAY_UPSTREAM_TIMEOUT_SECONDS'):
        assert removed not in runtime_gateway.env
    assert 'releaseBundleSha256' not in runtime_gateway.identity
    assert 'gateway-release-selection' not in maps
    assert not any('subPath' in mount for mount in runtime_gateway.container['volumeMounts'])
    final_documents = render("--set", "runtimeConfig.enabled=true", "--set",
        "attestationReceipts.releaseId=v0.14.18", "--set-json",
        'runtimeConfig.modelRoutes={"public-a":["backend-a"],"public-b":["backend-b"]}')
    assert Gateway(final_documents).deployment['spec']['template'] == runtime_gateway.deployment['spec']['template']
    runtime_router = next(item for item in runtime_documents if item['kind'] == 'Deployment'
                          and item['metadata']['name'] == 'sglang-router')
    private_router = next(item for item in runtime_documents if item['kind'] == 'Service'
                          and item['metadata']['name'] == 'router-v0-14-18')
    assert private_router['spec']['clusterIP'] == 'None'
    assert all(runtime_router['spec']['template']['metadata']['labels'].get(key) == value
               for key, value in private_router['spec']['selector'].items())
    final_private_router = next(item for item in final_documents if item['kind'] == 'Service'
                                and item['metadata']['name'] == 'router-v0-14-18')
    assert private_router == final_private_router
    router_container = next(item for item in runtime_router['spec']['template']['spec']['containers']
                            if item['name'] == 'sglang-router')
    assert router_container['env'] == [{'name':'CI_ROUTER_MODEL_ROUTES_FILE',
                                     'value':'/mnt/c8s-data/model-routes/routes.json'}]
    assert router_container['volumeMounts'][0]['readOnly'] is True
    assert 'subPath' not in router_container['volumeMounts'][0]
    helm("lint", str(CHART), *NEUTRAL_MODE)
    documents = render("--namespace", "inference")
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
    gateway = Gateway(documents)
    assert gateway.env["GATEWAY_ENDPOINT_DRAIN_SECONDS"] == "35"
    assert "GATEWAY_C8S_EVIDENCE_CONNECT_HOST" not in gateway.env
    local = Gateway(render(
        "--set", "attestationReceipts.evidenceBaseUrl=https://api.example.test",
        "--set", "attestationReceipts.evidenceConnectHost=c8s-router.c8s-system.svc.cluster.local",
        "--set", "attestationReceipts.cds.url=https://c8s-cds.c8s-system.svc:8443",
    ))
    assert local.env["GATEWAY_C8S_EVIDENCE_BASE_URL"] == "https://api.example.test"
    assert local.env["GATEWAY_C8S_EVIDENCE_CONNECT_HOST"] == "c8s-router.c8s-system.svc.cluster.local"
    # The release identity reaches the gateway through a mounted ConfigMap,
    # not environment variables, so the allowlist can pin the environment.
    assert "GATEWAY_EXPECTED_OPERATOR_KEY_SET_SHA256" not in gateway.env
    assert gateway.identity["expectedOperatorKeySetSha256"].startswith("sha256:")
    assert gateway.env["GATEWAY_RELEASE_IDENTITY_FILE"] == "/mnt/c8s-data/release-identity/..data/release-identity.json"
    # Without a CDS origin the chart sets no policy metadata settings.
    assert "GATEWAY_C8S_CDS_URL" not in gateway.env
    check_cds_policy_pins(local)
    assert gateway.container["readinessProbe"]["httpGet"]["path"] == "/ready"
    assert gateway.container["livenessProbe"]["httpGet"]["path"] == "/health"
    assert gateway.deployment["spec"]["template"]["spec"]["terminationGracePeriodSeconds"] == 960
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
    stateful = render("--namespace", "inference", "--set", "gateway.state.enabled=true")
    assert not {
        "PersistentVolume", "PersistentVolumeClaim", "StorageClass",
        "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding",
    } & {item["kind"] for item in stateful}
    assert not any(item["kind"] == "DaemonSet" and "state" in item["metadata"]["name"] for item in stateful)
    stateful_gateway = Gateway(stateful)
    assert stateful_gateway.deployment["spec"]["strategy"] == {"type": "Recreate"}
    annotations = stateful_gateway.deployment["spec"]["template"]["metadata"]["annotations"]
    assert annotations["confidential.ai/c8s-volumes"] == "gwstate=/confidential-inference/volumes/gwstate"
    assert annotations["confidential.ai/c8s-volume-dir"] == "/mnt/c8s-data"
    stateful_env = stateful_gateway.env
    assert stateful_env["GATEWAY_STATE_VOLUME"] == "c8s"
    assert stateful_env["GATEWAY_STATE_VOLUME_NAME"] == "gwstate"
    assert stateful_env["GATEWAY_STATE_DATABASE"] == "/mnt/c8s-data/gwstate/gateway.sqlite3"
    assert not any(
        "persistentVolumeClaim" in volume
        for volume in stateful_gateway.deployment["spec"]["template"]["spec"]["volumes"]
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

    # The staging layer clears production model routes and loads live files.
    staging_documents = render("--values", "release/values.yaml", "--values",
                               "release/staging/values.yaml", "--values",
                               "tests/release-v1/fixtures/release-values.yaml")
    maps = {item["metadata"]["name"]: item for item in staging_documents
            if item["kind"] == "ConfigMap"}
    model = "hf-internal-testing/tiny-random-LlamaForCausalLM"
    settings = json.loads(maps["gateway-runtime"]["data"]["settings.json"])
    routes = json.loads(maps["router-model-routes"]["data"]["routes.json"])
    assert settings["catalogModelIds"] == [model]
    assert settings["inferenceModelIds"] == [model]
    assert settings["evidence"]["connectHost"] == "c8s-router.c8s-system.svc.cluster.local"
    router_slot = next(item for item in staging_documents if item["kind"] == "Service" and item["metadata"]["name"] == settings["routerService"])
    assert router_slot["spec"]["clusterIP"] == "None"
    assert routes["routes"] == {model: [model]}
    assert "gateway-release-selection" not in maps, "deployment owns verified release selection"
    sidecars = []
    for document in staging_documents:
        if document["kind"] not in {"Deployment", "StatefulSet"}:
            continue
        pod = document["spec"]["template"]["spec"]
        for container in pod["containers"]:
            if container["name"] == "cds-attest":
                sidecars.append(container)
                assert "--attestation-api-url=unix:///run/c8s/workload-claims/attestation-api.sock" in container["args"]
                assert not any(item["name"] == "HOST_IP" for item in container.get("env", []))
                assert not container.get("volumeMounts"), "C8s NRI adds the platform socket mount"
    assert len(sidecars) == 6
    agent = next(item for item in staging_documents if item["kind"] == "Deployment"
                 and item["metadata"]["name"] == "gateway-update-agent")
    assert agent["spec"]["replicas"] == 1 and agent["spec"]["strategy"]["type"] == "Recreate"
    client = agent["spec"]["template"]["spec"]["containers"][0]
    assert client["image"] == yaml.safe_load((ROOT / "tests/release-v1/fixtures/release-values.yaml").read_text())["images"]["rolloutClient"]
    assert client["args"] == ["-u", "-c", (CHART / "files/staging-validation-agent.py").read_text()]
    client_env = {item["name"]: item.get("value") for item in client["env"]}
    assert json.loads(client_env["UPDATE_ROUTER_HOSTS"]) == [settings["routerService"] + ".default.svc.cluster.local"]
    assert client["securityContext"]["runAsNonRoot"] is True
    assert client["securityContext"]["readOnlyRootFilesystem"] is True
    assert agent["spec"]["template"]["spec"]["serviceAccountName"] == "gateway-update-agent"
    role = next(item for item in staging_documents if item["kind"] == "Role"
                and item["metadata"]["name"] == "gateway-update-agent")
    assert role["rules"] == [{"apiGroups": [""], "resources": ["secrets"],
                              "resourceNames": ["gateway-update-task"], "verbs": ["get"]}]
    assert not any(item["kind"] == "Deployment" and item["metadata"]["name"] == "gateway-update-agent"
                   for item in production_documents)
    helm("template", "example", str(CHART), *NEUTRAL_MODE,
         "--set", "stagingValidation.enabled=true", success=False)

    print("Helm neutral-default and safety tests passed.")


if __name__ == "__main__":
    main()
