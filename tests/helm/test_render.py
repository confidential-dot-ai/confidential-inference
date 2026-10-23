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


def check_override_replaces_strategy() -> None:
    """A Recreate override drops the chart's rollingUpdate, which the API server refuses with Recreate."""
    with tempfile.TemporaryDirectory() as directory:
        values = Path(directory) / "values.yaml"
        values.write_text(yaml.safe_dump({"workloadOverridesEnabled": True, "workloadOverrides": {
            "Deployment/sglang-router": {"spec": {"strategy": {"type": "Recreate"}}}}}))
        router = next(item for item in render("-f", str(values))
                      if item["kind"] == "Deployment" and item["metadata"]["name"] == "sglang-router")
    assert router["spec"]["strategy"] == {"type": "Recreate"}


def check_plain_http_behind_the_mesh() -> None:
    """c8s >= v0.64 (C8s #809): the per-pod mesh carries every pod-to-pod hop
    over mutual TLS and refuses its cert directory in app containers. The
    gateway serves plain HTTP on 9443 only, and no app container uses
    /etc/c8s/certs."""
    documents = render()
    gateway = Gateway(documents)
    assert gateway.env["GATEWAY_LISTEN"] == "0.0.0.0:9443"
    assert "GATEWAY_TLS_LISTEN" not in gateway.env
    assert "GATEWAY_C8S_RECEIPT_TARGETS" not in gateway.env
    policy = next(item for item in documents if item["kind"] == "NetworkPolicy"
                  and item["metadata"]["name"] == "gateway-ingress")
    assert [port["port"] for port in policy["spec"]["ingress"][0]["ports"]] == [9443]
    for document in documents:
        if document["kind"] not in {"Deployment", "StatefulSet", "DaemonSet"}:
            continue
        for container in document["spec"]["template"]["spec"]["containers"]:
            assert container["name"] not in {"cds-attest", "router-workload-proxy", "gateway-workload-proxy"}
            assert "/etc/c8s/certs" not in json.dumps(container), (document["metadata"]["name"], container["name"])
            # The mesh forwards only HTTP probes.
            for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
                assert not {"tcpSocket", "grpc"} & set(container.get(probe, {})), (document["metadata"]["name"], probe)

def check_front_door_namespace() -> None:
    # From c8s v0.66.0 the router runs in its own namespace, c8s-router.
    documents = [item for item in yaml.safe_load_all(helm('template', 'confidential-inference', str(CHART),
        '--namespace', 'confidential-inference', '-f', str(ROOT/'release/values.yaml'),
        '-f', str(ROOT/'tests/release-v1/fixtures/release-values.yaml'),
        '--set', 'attestationReceipts.releaseId=v0.14.18', '--set', 'c8s.frontDoorNamespace=c8s-router')) if item]
    policies = {d['metadata']['name']: d for d in documents if d['kind'] == 'NetworkPolicy'}
    peer = policies['gateway-ingress']['spec']['ingress'][0]['from'][0]
    assert peer['namespaceSelector']['matchLabels'] == {'kubernetes.io/metadata.name': 'c8s-router'}
    assert any(peer.get('namespaceSelector', {}).get('matchLabels') == {'kubernetes.io/metadata.name': 'c8s-router'}
               for rule in policies['gateway-to-router']['spec']['egress'] for peer in rule.get('to', []))


def check_cds_nodeport_and_probe_budget() -> None:
    # c8s >= v0.66: credential clients dial the node's CDS NodePort, and the
    # per-pod mesh gives every probe 5 s (C8s #1027).
    documents = [item for item in yaml.safe_load_all(helm('template', 'confidential-inference', str(CHART),
        '--namespace', 'confidential-inference', '-f', str(ROOT/'release/values.yaml'),
        '-f', str(ROOT/'release/staging/values.yaml'),
        '-f', str(ROOT/'tests/release-v1/fixtures/release-values.yaml'),
        '--set', 'attestationReceipts.releaseId=v0.14.18-staging')) if item]
    policies = {d['metadata']['name']: d for d in documents if d['kind'] == 'NetworkPolicy'}
    for name in ('workloads-to-c8s-cds', 'gateway-update-agent'):
        assert any('to' not in rule and {'protocol': 'TCP', 'port': 30808} in rule['ports']
                   for rule in policies[name]['spec']['egress']), name
    for document in documents:
        if document['kind'] not in {'Deployment', 'StatefulSet'}:
            continue
        pod = document['spec']['template']['spec']
        for container in pod.get('initContainers', []) + pod['containers']:
            for probe in ('startupProbe', 'readinessProbe', 'livenessProbe'):
                if probe in container:
                    assert container[probe].get('timeoutSeconds', 1) <= 5, (document['metadata']['name'], container['name'], probe)


TELEMETRY = (
    "--set", "telemetry.enabled=true",
    "--set", "telemetry.deployment=test-deployment",
    "--set", "telemetry.relay.serverName=relay.example.com",
    "--set", "telemetry.relay.address=203.0.113.7",
    "--set", "telemetry.metrics.tenantId=00000000-0000-0000-0000-000000000001",
    "--set", "telemetry.metrics.clientId=00000000-0000-0000-0000-000000000002",
    "--set", "telemetry.metrics.dataCollectionRule=dcr-" + "0" * 32,
)


def collector_config(documents: list[dict]) -> dict:
    """The telemetry collector's pipeline, which is its one argument."""
    collector = next(item for item in documents
                     if item["kind"] == "Deployment" and item["metadata"]["name"] == "telemetry-collector")
    (argument,) = collector["spec"]["template"]["spec"]["containers"][0]["args"]
    assert argument.startswith("--config=yaml:")
    return json.loads(argument.removeprefix("--config=yaml:"))


def check_telemetry_collector() -> None:
    """One stock collector is the only pod with an exit, and its argument pins what leaves."""
    assert not any(item["metadata"]["name"].startswith("telemetry-") for item in render())
    helm("template", "example", str(CHART), *NEUTRAL_MODE, "--set", "telemetry.enabled=true", success=False)

    documents = render(*TELEMETRY, "--set", "telemetry.traces.enabled=true")
    pods = {item["metadata"]["name"]: item["spec"]["template"]["spec"] for item in documents
            if item["kind"] in {"Deployment", "StatefulSet"}}
    # The collector and (stateless, #223) the gateway are the only pods with
    # an exit; each exit is a hostAliases address and its one ipBlock.
    exits = {name for name, pod in pods.items() if pod.get("hostAliases")}
    assert "telemetry-collector" in exits and exits <= {"telemetry-collector", "gateway"}, exits
    collector = pods["telemetry-collector"]
    assert collector["hostAliases"] == [{"ip": "203.0.113.7", "hostnames": ["relay.example.com"]}]
    assert PINNED.match(collector["containers"][0]["image"])
    assert "env" not in collector["containers"][0]
    assert collector["automountServiceAccountToken"] is False
    # C8s #1049: an entry with egress has no host mount and a fixed argv.
    assert not any("hostPath" in volume for volume in collector.get("volumes", []))
    assert all("args" in container for container in collector["containers"])
    for pod in (collector, pods["gateway"]):
        # Per-pod mesh: no app container mounts the c8s certificate volume.
        assert not any(mount["mountPath"] == "/etc/c8s/certs"
                       for container in pod["containers"] for mount in container.get("volumeMounts", []))
    policies = {item["metadata"]["name"]: item for item in documents if item["kind"] == "NetworkPolicy"}
    blocks = [peer["ipBlock"]["cidr"] for policy in policies.values()
              for rule in policy["spec"].get("egress", []) for peer in rule.get("to", []) if "ipBlock" in peer]
    addresses = {alias["ip"] + "/32" for name in exits for alias in pods[name]["hostAliases"]}
    assert sorted(blocks) == sorted(addresses) and "203.0.113.7/32" in blocks, blocks

    config = collector_config(documents)
    relay = "https://relay.example.com/"
    assert config["exporters"]["prometheusremotewrite"]["endpoint"].startswith(relay + "prometheus/")
    assert config["exporters"]["otlphttp/loki"]["logs_endpoint"] == relay + "otlp/v1/logs"
    assert config["extensions"]["oauth2client"]["token_url"].startswith(relay + "entra/")
    jobs = config["receivers"]["prometheus"]["config"]["scrape_configs"]
    assert [job["job_name"] for job in jobs] == ["gateway", "sglang-router", "inference-worker-0", "inference-worker-1"]
    for job in jobs:
        (keep,) = job["metric_relabel_configs"]
        assert keep["action"] == "labelkeep"
        assert "__name__" in keep["regex"] and "prompt" not in keep["regex"]
    targets = [target for job in jobs for static in job.get("static_configs", []) for target in static["targets"]]
    targets += [name for job in jobs for sd in job.get("dns_sd_configs", []) for name in sd["names"]]
    services = {item["metadata"]["name"]: item for item in documents if item["kind"] == "Service"}
    # The mesh connects pods: every target is a pod address of a headless Service.
    for target in targets:
        host = target.split(":")[0].split(".")
        service = services[host[1] if host[0].startswith("inference-worker-") else host[0]]
        assert service["spec"]["clusterIP"] == "None", target
    processors = config["processors"]
    assert "keep_keys(spanevent.attributes, [])" in processors["transform/traces"]["trace_statements"]
    assert not any("gen_ai.request.id" in statement for statement in processors["transform/traces"]["trace_statements"])
    assert "keep_keys(log.attributes, [])" in processors["transform/logs"]["log_statements"]
    assert config["service"]["pipelines"]["traces"]["exporters"] == ["spanmetrics"]

    # C8s's platform kube-state-metrics: off without a target, then one job
    # with a name filter and a port-only egress rule, no hostAliases exit.
    assert "kube-state-metrics" not in [job["job_name"] for job in jobs]
    with_ksm = render(*TELEMETRY, "--set", "telemetry.kubeStateMetrics.target=192.0.2.5:30809")
    (ksm,) = [job for job in collector_config(with_ksm)["receivers"]["prometheus"]["config"]["scrape_configs"]
              if job["job_name"] == "kube-state-metrics"]
    assert ksm["static_configs"][0]["targets"] == ["192.0.2.5:30809"]
    assert ksm["metric_relabel_configs"][0]["action"] == "keep"
    assert "namespace" in ksm["metric_relabel_configs"][1]["regex"]
    egress = next(item for item in with_ksm if item["kind"] == "NetworkPolicy"
                  and item["metadata"]["name"] == "telemetry-collector-paths")["spec"]["egress"]
    assert {"ports": [{"protocol": "TCP", "port": 30809}]} in egress
    assert not next(item for item in with_ksm if item["kind"] == "Deployment"
                    and item["metadata"]["name"] == "telemetry-collector")["spec"]["template"]["spec"]["hostAliases"][1:]
    gateway = Gateway(documents)
    assert gateway.env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] == "http://telemetry-collector.default.svc.cluster.local:4318/v1/logs"
    assert "RUST_LOG" not in gateway.env
    model = [item for item in yaml.safe_load_all(helm(
        "template", "example", str(CHART), "--values", str(ROOT / "tests/contracts/values-sglang.yaml"),
        *TELEMETRY, "--set", "telemetry.traces.enabled=true")) if item]
    # GPU metrics: the worker image serves them (wait-for-model --gpu-metrics-port).
    gpu_jobs = [job["job_name"] for job in collector_config(model)["receivers"]["prometheus"]["config"]["scrape_configs"]
                if job["job_name"].startswith("inference-gpu-")]
    assert gpu_jobs == ["inference-gpu-0", "inference-gpu-1"], gpu_jobs
    worker = next(item for item in model if item["kind"] == "StatefulSet")["spec"]["template"]["spec"]["containers"][0]
    assert "--enable-trace" in worker["args"] and "--otlp-traces-endpoint=telemetry-collector.default.svc.cluster.local:4317" in worker["args"]
    assert not any(arg.startswith("--log-requests") for arg in worker["args"])


def main() -> None:
    # The production release must route to a real Service.
    production = [item for item in yaml.safe_load_all(helm('template', 'confidential-inference', str(CHART),
        '--namespace', 'confidential-inference', '-f', str(ROOT/'release/values.yaml'),
        '-f', str(ROOT/'tests/release-v1/fixtures/release-values.yaml'),
        '--set', 'attestationReceipts.releaseId=v0.14.18')) if item]
    # One gateway workload and state volume per deployment: a release change
    # replaces the pod (Recreate) and reopens the same key database.
    gateway = next(d for d in production if d['kind'] == 'Deployment' and d['metadata']['name'] == 'gateway')
    assert gateway['spec']['strategy'] == {'type': 'Recreate'}
    gateway_annotations = gateway['spec']['template']['metadata']['annotations']
    assert gateway_annotations['confidential.ai/cw'] == 'gateway'
    assert gateway_annotations['confidential.ai/c8s-volumes'] == 'gwstate=/confidential-inference/volumes/gwstate'
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
    assert gateway_environment['GATEWAY_STATE_VOLUME_NAME'] == 'gwstate'
    assert gateway_environment['GATEWAY_STATE_DATABASE'] == '/mnt/c8s-data/gwstate/gateway.sqlite3'
    assert gateway_environment['GATEWAY_INFERENCE_URL'] == 'http://router-v0-14-18.confidential-inference.svc.cluster.local:30000'
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
    with tempfile.TemporaryDirectory() as directory:
        bundle = Path(directory) / 'release-bundle.json'
        bundle.write_text('{"schema": "confidential.ai/release-manifest/v1"}\n')
        selected = {item['metadata']['name']: item for item in render(
            "--set", "runtimeConfig.enabled=true", "--set", "attestationReceipts.releaseId=v0.14.18",
            "--set-file", f"runtimeConfig.releaseBundle={bundle}") if item['kind'] == 'ConfigMap'}
        selection = json.loads(selected['gateway-release-selection']['data']['releases.json'])
        assert selection == {'schemaVersion': 1, 'revision': 1, 'releaseBundles': [bundle.read_text()],
            'selectedBundleSha256': 'sha256:' + hashlib.sha256(bundle.read_bytes()).hexdigest()}
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
    assert not any(container["name"] == "cds-attest" for workload in workloads
                   for container in workload["spec"]["template"]["spec"]["containers"])
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
    assert router_args[:3] == ["--worker-urls", "http://inference-worker-0-0.inference-workers:30000",
                               "http://inference-worker-1-0.inference-workers:30000"]
    assert not any(arg.startswith("--service-discovery") for arg in router_args)
    assert router["spec"]["strategy"]["rollingUpdate"] == {
        "maxUnavailable": 0,
        "maxSurge": 1,
    }
    router_service = next(
        item for item in inference_documents
        if item["kind"] == "Service" and item["metadata"]["name"] == "sglang-router"
    )
    assert "publishNotReadyAddresses" not in router_service["spec"]
    assert not any(item["kind"] in {"Role", "RoleBinding"} and item["metadata"]["name"] == "sglang-router-pods"
                   for item in inference_documents)

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
    assert router_egress_ports == {30000}

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
        assert (
            worker["spec"]["template"]["metadata"]["annotations"]["confidential.ai/cw"]
            == f"inference-worker-{worker_index}"
        )

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
    staging_values = yaml.safe_load(
        (ROOT / "c8s/staging-values.yaml").read_text()
    )
    assert staging_values["inference"]["mode"] == "simulator"

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
    assert not any(container["name"] == "cds-attest" for document in staging_documents
                   if document["kind"] in {"Deployment", "StatefulSet"}
                   for container in document["spec"]["template"]["spec"]["containers"])
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
                   for item in production)
    helm("template", "example", str(CHART), *NEUTRAL_MODE,
         "--set", "stagingValidation.enabled=true", success=False)

    check_plain_http_behind_the_mesh()
    check_override_replaces_strategy()
    check_front_door_namespace()
    check_cds_nodeport_and_probe_budget()
    check_telemetry_collector()
    print("Helm neutral-default and safety tests passed.")


if __name__ == "__main__":
    main()
