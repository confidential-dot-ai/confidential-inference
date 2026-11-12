#!/usr/bin/env python3
"""Verify the neutral Helm chart defaults and safety rules."""

from __future__ import annotations

import re
import runpy
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


def environment_args(arguments: tuple[str, ...]) -> tuple[str, ...]:
    """The environment name that scripts/render-allowlist.py sets for an example environment.

    The example values files do not set `environment`: the render sets it
    from its --environment argument, after the values files.
    """
    files = [arg for arg in arguments if "tests/fixtures/deployments/" in arg]
    if not files:
        return ()
    name = "staging" if any(arg.endswith("staging-values.yaml") for arg in files) else "production"
    return ("--set", f"environment={name}")


def helm(*arguments: str, success: bool = True) -> str:
    result = subprocess.run(
        ["helm", *arguments, *environment_args(arguments)], cwd=ROOT, text=True, capture_output=True, check=False
    )
    if (result.returncode == 0) != success:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout


def render(*arguments: str) -> list[dict]:
    """The documents of `helm template example CHART` with the neutral mode and arguments."""
    mode = () if any(arg.endswith(("tests/fixtures/deployments/production-values.yaml", "tests/api/values-sglang.yaml")) for arg in arguments) else NEUTRAL_MODE
    output = helm("template", "example", str(CHART), *mode, *arguments)
    return [item for item in yaml.safe_load_all(output) if item]


class Gateway:
    """The gateway Deployment of rendered documents, its container, env and settings."""

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
        self.settings = json.loads(self.env["GATEWAY_RUNTIME_CONFIG"])


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

def g7_violations(documents: list[dict], secret_reads: dict[str, list[str]]) -> list[str]:
    """Controllers that mount a hostPath volume and read c8s secrets.

    c8s allowlist rule G7 refuses a secrets grant on an entry with a host
    mount. An entry reads secrets through the c8s-volumes or c8s-secrets
    annotation, or through secretReads in its workload policy.
    """
    found = []
    for item in documents:
        if item["kind"] not in {"Deployment", "StatefulSet", "DaemonSet"}:
            continue
        controller = f"{item['kind']}/{item['metadata']['name']}"
        template = item["spec"]["template"]
        pod = template["spec"]
        host = {volume["name"] for volume in pod.get("volumes", []) if "hostPath" in volume}
        mounted = any(mount["name"] in host for field in ("initContainers", "containers")
                      for container in pod.get(field, []) for mount in container.get("volumeMounts", []))
        annotations = template.get("metadata", {}).get("annotations", {})
        reads = (secret_reads.get(controller) or "confidential.ai/c8s-volumes" in annotations
                 or "confidential.ai/c8s-secrets" in annotations)
        if mounted and reads:
            found.append(controller)
    return found


def check_model_cache() -> None:
    """The C8s v0.99.29 worker mounts the plain models disk read-only, so the chart refuses the plain cache."""
    for name, cache, error in (
            ("enabled", {"enabled": True}, "inference.model.cache is unsupported"),
            ("old cache setting", {"enabled": False, "hostPath": "/var/lib/models/model"}, "hostPath")):
        result = subprocess.run(["helm", "template", "example", str(CHART), *NEUTRAL_MODE,
                                 "--set-json", f"inference.model.cache={json.dumps(cache)}"],
                                cwd=ROOT, text=True, capture_output=True, check=False)
        assert result.returncode != 0 and error in result.stderr, (name, result.stderr)
    templates = "".join(path.read_text() for path in (CHART / "templates").glob("*.yaml"))
    for stale in ("cache.hostPath", "$cache.hostPath", "model-cache"):
        assert stale not in templates, stale


MANIFEST = '{"schema":"confidential-benchmark/local-model-byte-manifest/v1"}\n'
DOWNLOAD_HOSTS = [{"serverName": "models.example.invalid", "address": "192.0.2.20"},
                  {"serverName": "cdn.example.invalid", "address": "192.0.2.21"}]


def download_values(**download) -> dict:
    """Values that turn on inference.model.download, with the manifest pinned by its SHA-256."""
    import hashlib
    return {"inference": {"replicas": 1, "simulator": {"validateModelMount": True}, "model": {
        "volumeNames": ["model"],
        "mountVerification": {"expectedFiles": {
            ".model-lock-local-manifest.json": hashlib.sha256(MANIFEST.encode()).hexdigest()}},
        "download": {"enabled": True, "hosts": DOWNLOAD_HOSTS, "manifest": MANIFEST, **download}}}}


def render_values(values: dict, *arguments: str, success: bool = True):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "values.yaml"
        path.write_text(yaml.safe_dump(values))
        if success:
            return render("-f", str(path), *arguments)
        result = subprocess.run(["helm", "template", "example", str(CHART), *NEUTRAL_MODE, "-f", str(path), *arguments],
                                cwd=ROOT, text=True, capture_output=True, check=False)
        assert result.returncode != 0, "the render unexpectedly succeeded"
        return result.stderr


def check_model_download() -> None:
    """inference.model.download: the worker downloads the model at each start into an emptyDir
    on its encrypted scratch disk, verifies it read-only, and reaches only the pinned source."""
    import hashlib
    admission = runpy.run_path(str(ROOT / "scripts/check-c8s-admission.py"))
    pin = hashlib.sha256(MANIFEST.encode()).hexdigest()
    for mode in ("simulator", "model"):
        documents = render_values(download_values(), "--set", f"inference.mode={mode}",
                                  "--set", "inference.gpusPerReplica=1", "--set", "inference.gpuArchitectures={BLACKWELL}")
        worker = next(item for item in documents if item["kind"] == "StatefulSet"
                      and item["metadata"]["name"] == "inference-worker-0")
        template = worker["spec"]["template"]
        pod = template["spec"]
        assert "confidential.ai/c8s-volumes" not in template["metadata"]["annotations"], mode
        assert pod["hostAliases"] == [{"ip": host["address"], "hostnames": [host["serverName"]]}
                                      for host in DOWNLOAD_HOSTS], mode
        assert "initContainers" not in pod, "the C8s worker grants the exits only to running main containers"
        container = pod["containers"][0]
        shell, flag, script, name = container["command"]
        assert (shell, flag, name) == ("/bin/sh", "-c", "sh")
        assert ("/usr/local/bin/fetch-model --endpoint=https://models.example.invalid fetch "
                f"--path=/mnt/c8s-data/model-download --manifest=/mnt/c8s-data/model-manifest/manifest.json "
                f"--manifest-sha256={pin} --revision-metadata=.model-lock-local-manifest.json &") in script
        assert script.endswith('exec "$@"')
        assert container["args"][:3] == ["/usr/local/bin/wait-for-model", "--path=/mnt/c8s-data/models/model",
                                         "--plain-cache"], container["args"][:3]
        assert container["volumeMounts"][1:] == [
            {"name": "model-download", "mountPath": "/mnt/c8s-data/model-download"},
            {"name": "model-download", "mountPath": "/mnt/c8s-data/models/model", "readOnly": True},
            {"name": "model-manifest", "mountPath": "/mnt/c8s-data/model-manifest", "readOnly": True}]
        volumes = {volume["name"]: volume for volume in pod["volumes"]}
        # A default-medium emptyDir: the worker places it on its encrypted scratch disk.
        assert volumes["model-download"] == {"name": "model-download", "emptyDir": {"sizeLimit": "512Gi"}}
        assert volumes["model-manifest"]["configMap"] == {"name": "model-manifest"}
        manifest = next(item for item in documents if item["kind"] == "ConfigMap"
                        and item["metadata"]["name"] == "model-manifest")
        assert manifest["data"] == {"manifest.json": MANIFEST}
        policy = next(item for item in documents if item["kind"] == "NetworkPolicy"
                      and item["metadata"]["name"] == "inference-worker-model-download")["spec"]
        assert policy["egress"] == [{"to": [{"ipBlock": {"cidr": "192.0.2.20/32"}}, {"ipBlock": {"cidr": "192.0.2.21/32"}}],
                                     "ports": [{"protocol": "TCP", "port": 443}]}]
        assert admission["refusals"](documents) == [], mode
    # Off by default: no download object renders.
    plain = render()
    assert not any(item["metadata"]["name"] in {"model-manifest", "inference-worker-model-download"} for item in plain)
    for name, values, error in (
            ("manifest pin", download_values(manifest=MANIFEST + " "), "does not match the pinned SHA-256"),
            ("no source", download_values(hosts=[]), "hosts"),
            ("no manifest", download_values(manifest=""), "manifest"),
            ("too many exits", download_values(hosts=[{"serverName": f"h{i}.example.invalid", "address": f"192.0.2.{i}"}
                                                      for i in range(9)]), "hosts"),
            ("not an address", download_values(hosts=[{"serverName": "models.example.invalid", "address": "models"}]), "address"),
            ("size", download_values(sizeLimit="512G"), "sizeLimit")):
        assert error in render_values(values, success=False), name


def check_front_door_namespace() -> None:
    # From c8s v0.66.0 the router runs in its own namespace, c8s-router.
    documents = [item for item in yaml.safe_load_all(helm('template', 'confidential-inference', str(CHART),
        '--namespace', 'confidential-inference', '-f', str(ROOT/'tests/fixtures/deployments/production-values.yaml'),
        '-f', str(ROOT/'tests/release-v1/fixtures/release-values.yaml'),
        '--set', 'frameworkRelease.name=v0.14.18', '--set', 'c8s.frontDoorNamespace=c8s-router')) if item]
    policies = {d['metadata']['name']: d for d in documents if d['kind'] == 'NetworkPolicy'}
    peer = policies['gateway-ingress']['spec']['ingress'][0]['from'][0]
    assert peer['namespaceSelector']['matchLabels'] == {'kubernetes.io/metadata.name': 'c8s-router'}
    assert any(peer.get('namespaceSelector', {}).get('matchLabels') == {'kubernetes.io/metadata.name': 'c8s-router'}
               for rule in policies['gateway-to-router']['spec']['egress'] for peer in rule.get('to', []))


def check_c8s_admission() -> None:
    """Every example deployment renders pods C8s worker admission accepts (scripts/check-c8s-admission.py)."""
    admission = runpy.run_path(str(ROOT / "scripts/check-c8s-admission.py"))
    release = ("--namespace", "confidential-inference", "-f", "tests/fixtures/deployments/production-values.yaml",
               "-f", "tests/release-v1/fixtures/release-values.yaml",
               "--set", "frameworkRelease.name=v0.14.18")
    for profile in ((), release, (*release, "-f", "tests/fixtures/deployments/staging-values.yaml"),
                    ("--values", "tests/api/values-sglang.yaml"),
                    ("--set", "dcgmExporter.enabled=true",
                     "--set", "nodeExporter.enabled=true", "--set", "c8s.cds.cidrs={198.51.100.4/32}")):
        found = admission["refusals"](render(*profile))
        assert found == [], (profile, found)

    def pod(container: dict, spec: dict | None = None) -> dict:
        return {"kind": "Pod", "metadata": {"name": "p", "annotations": {"confidential.ai/cw": "p"}},
                "spec": {**(spec or {}), "containers": [{"name": "app", **container}]}}

    user = {"securityContext": {"runAsUser": 1001}}
    tests = {
        # The refusals of 2026-10-22 staging.
        "tcpSocket probe": (pod({**user, "readinessProbe": {"tcpSocket": {"port": 1}}}), ["tcpSocket"]),
        "slow probe": (pod({**user, "livenessProbe": {"httpGet": {"port": 8080, "path": "/health"},
                                                     "timeoutSeconds": 10}}), ["timeoutSeconds 10"]),
        "credential mount": (pod({**user, "volumeMounts": [{"name": "certs", "mountPath": "/etc/c8s/certs"}]}),
                             ["/etc/c8s/certs"]),
        "privileged": (pod({"securityContext": {"runAsUser": 1001, "privileged": True}}), ["privileged: true"]),
        "privilege escalation": (pod({"securityContext": {"runAsUser": 1001, "allowPrivilegeEscalation": True}}),
                                 ["allowPrivilegeEscalation: true"]),
        "undeclarable capability": (pod({"securityContext": {"runAsUser": 1001, "capabilities": {"add": ["net_raw"]}}}),
                                    ["capability net_raw"]),
        "declarable capability": (pod({"securityContext": {"runAsUser": 1001, "capabilities": {"add": ["SYS_ADMIN"]}}}),
                                  []),
        "container root": (pod({"securityContext": {"runAsUser": 0}}), ["runAsUser: 0"]),
        "pod root": (pod({}, {"securityContext": {"runAsUser": 0}}), ["runAsUser: 0"]),
        "container overrides pod root": (pod(user, {"securityContext": {"runAsUser": 0}}), []),
        "no user": (pod({}), ["sets no runAsUser"]),
        "reserved gid": (pod({"securityContext": {"runAsUser": 1001, "runAsGroup": 1338}}), ["runAsGroup 1338"]),
        "reserved pod uid": (pod({}, {"securityContext": {"runAsUser": 1337}}), ["runAsUser 1337"]),
        "container overrides reserved pod ids": (
            pod({"securityContext": {"runAsUser": 1001, "runAsGroup": 1001}},
                {"securityContext": {"runAsUser": 1337, "runAsGroup": 1338}}), []),
        "reserved fsGroup":(pod(user, {"securityContext": {"fsGroup": 1337}}), ["fsGroup 1337"]),
        "exec probe": (pod({**user, "readinessProbe": {"exec": {"command": ["true"]}}}), ["exec probes"]),
        "exec hook": (pod({**user, "lifecycle": {"preStop": {"exec": {"command": ["true"]}}}}), ["exec lifecycle hook"]),
        "terminal": (pod({**user, "tty": True}), ["tty: true"]),
        "stdin": (pod({**user, "stdin": True, "stdinOnce": True}), ["stdin: true"]),
        "init container stdin": (pod(user, {"initContainers": [{"name": "init", **user, "stdin": True}]}),
                                 ["container init: sets stdin: true"]),
        "terminal and stdin off": (pod({**user, "tty": False, "stdin": False}), []),
    }
    for name, (document, expected) in tests.items():
        found = admission["refusals"]([document])
        assert len(found) == len(expected) and all(want in line for want, line in zip(expected, found)), (name, found)

    deny = {"kind": "NetworkPolicy", "metadata": {"name": "deny"},
            "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{"ports": [{"port": 443}]}]}}
    cds = {"kind": "NetworkPolicy", "metadata": {"name": "cds"},
           "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [
               {"to": [{"ipBlock": {"cidr": "198.51.100.4/32"}}], "ports": [{"protocol": "TCP", "port": 8443}]}]}}
    restricted = pod(user)
    found = admission["refusals"]([restricted, deny])
    assert len(found) == 1 and "CDS on TCP 8443" in found[0], found
    assert admission["refusals"]([restricted, deny, cds]) == []
    assert len(admission["refusals"]([restricted, deny, cds], 9443)) == 1

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
    # an exit; each exit is a hostAliases address and its one ipBlock. The
    # CDS rule on TCP 8443 is the only other ipBlock.
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
              for rule in policy["spec"].get("egress", []) if {"protocol": "TCP", "port": 8443} not in rule.get("ports", [])
              for peer in rule.get("to", []) if "ipBlock" in peer]
    addresses = {alias["ip"] + "/32" for name in exits for alias in pods[name]["hostAliases"]}
    assert sorted(blocks) == sorted(addresses) and "203.0.113.7/32" in blocks, blocks

    config = collector_config(documents)
    relay = "https://relay.example.com/"
    assert config["exporters"]["prometheusremotewrite"]["endpoint"].startswith(relay + "prometheus/")
    assert config["exporters"]["otlphttp/loki"]["logs_endpoint"] == relay + "otlp/v1/logs"
    assert config["extensions"]["oauth2client"]["token_url"].startswith(relay + "entra/")
    jobs = config["receivers"]["prometheus"]["config"]["scrape_configs"]
    assert [job["job_name"] for job in jobs] == ["gateway", "sglang-router", "inference-worker-0", "inference-worker-1",
                                                 "otelcol"]
    # The collector scrapes its own otelcol_* metrics on loopback; every
    # series carries `cluster` (kube-state-metrics has its own `deployment`).
    assert jobs[-1]["static_configs"][0]["targets"] == ["127.0.0.1:8888"]
    assert config["service"]["telemetry"]["metrics"]["readers"][0]["pull"]["exporter"]["prometheus"] == {
        "host": "127.0.0.1", "port": 8888}
    labels = config["exporters"]["prometheusremotewrite"]["external_labels"]
    assert labels["cluster"] == "test-deployment" and "deployment" not in labels
    for job in jobs:
        (keep,) = job["metric_relabel_configs"]
        assert keep["action"] == "labelkeep"
        assert "__name__" in keep["regex"] and "prompt" not in keep["regex"]
    targets = [target for job in jobs[:-1] for static in job.get("static_configs", []) for target in static["targets"]]
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
    assert "owner_kind" in ksm["metric_relabel_configs"][-1]["regex"] and "uid" not in ksm["metric_relabel_configs"][-1]["regex"]
    egress = next(item for item in with_ksm if item["kind"] == "NetworkPolicy"
                  and item["metadata"]["name"] == "telemetry-collector-paths")["spec"]["egress"]
    assert {"ports": [{"protocol": "TCP", "port": 30809}]} in egress
    assert not next(item for item in with_ksm if item["kind"] == "Deployment"
                    and item["metadata"]["name"] == "telemetry-collector")["spec"]["template"]["spec"]["hostAliases"][1:]
    gateway = Gateway(documents)
    assert gateway.env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] == "http://telemetry-collector.default.svc.cluster.local:4318/v1/logs"
    assert "RUST_LOG" not in gateway.env
    model = [item for item in yaml.safe_load_all(helm(
        "template", "example", str(CHART), "--values", str(ROOT / "tests/api/values-sglang.yaml"),
        *TELEMETRY, "--set", "telemetry.traces.enabled=true")) if item]
    # GPU metrics: dcgm-exporter in the worker image (wait-for-model --gpu-metrics-port).
    gpu_jobs = [job["job_name"] for job in collector_config(model)["receivers"]["prometheus"]["config"]["scrape_configs"]
                if job["job_name"].startswith("inference-gpu-")]
    assert gpu_jobs == ["inference-gpu-0", "inference-gpu-1"], gpu_jobs
    worker = next(item for item in model if item["kind"] == "StatefulSet")["spec"]["template"]["spec"]["containers"][0]
    assert "--enable-trace" in worker["args"] and "--otlp-traces-endpoint=telemetry-collector.default.svc.cluster.local:4317" in worker["args"]
    assert not any(arg.startswith("--log-requests") for arg in worker["args"])


def main() -> None:
    # The production release must route to a real Service.
    production = [item for item in yaml.safe_load_all(helm('template', 'confidential-inference', str(CHART),
        '--namespace', 'confidential-inference', '-f', str(ROOT/'tests/fixtures/deployments/production-values.yaml'),
        '-f', str(ROOT/'tests/release-v1/fixtures/release-values.yaml'),
        '--set', 'frameworkRelease.name=v0.14.18')) if item]
    # The gateway keeps no state: it rolls with one extra pod, and c8s gives
    # it the pepper and the admin client configuration, no volume.
    gateway = next(d for d in production if d['kind'] == 'Deployment' and d['metadata']['name'] == 'gateway')
    assert gateway['spec']['strategy'] == {'type': 'RollingUpdate', 'rollingUpdate': {'maxUnavailable': 0, 'maxSurge': 1}}
    gateway_annotations = gateway['spec']['template']['metadata']['annotations']
    assert gateway_annotations['confidential.ai/cw'] == 'gateway'
    assert gateway_annotations['confidential.ai/c8s-secrets'] == (
        'GATEWAY_API_KEY_PEPPER=/confidential-inference/gateway/api-key-pepper,'
        'product-usage=/confidential-inference/gateway/product-usage')
    assert not any(name.startswith('confidential.ai/c8s-volume') for name in gateway_annotations)
    main_container = next(c for c in gateway['spec']['template']['spec']['containers'] if c['name'] == 'gateway')
    gateway_environment = {item['name']: item['value'] for item in main_container['env']}
    # The gateway reads no ConfigMap: its settings are pinned environment, and
    # only the per-deployment admin Secrets are mounted.
    gateway_volumes = gateway['spec']['template']['spec']['volumes']
    assert not any('configMap' in volume for volume in gateway_volumes)
    assert {mount['mountPath'] for mount in main_container['volumeMounts']} == {
        '/mnt/c8s-data/admin-auth', '/mnt/c8s-data/admin-api-key', '/run/confidential-gateway', '/tmp'}
    assert not any(name.startswith(('GATEWAY_C8S_', 'GATEWAY_RELEASE_')) for name in gateway_environment)
    production_settings = json.loads(gateway_environment['GATEWAY_RUNTIME_CONFIG'])
    assert production_settings['maximumBodyBytes'] == 2097152
    # Refuse a chart value that the published gateway cannot start with.
    too_large = subprocess.run(['helm', 'template', 'body-limit-test', str(CHART),
        '--set', 'inference.mode=simulator',
        '--set', 'gateway.protection.maximumBodyBytes=8388609'],
        capture_output=True, text=True)
    assert too_large.returncode != 0 and 'maximumBodyBytes' in too_large.stderr
    assert production_settings['bodyTimeoutSeconds'] == 10
    assert production_settings['upstreamTimeoutSeconds'] == 900
    assert production_settings['streamIdleTimeoutSeconds'] == 60
    production_workers = [item for item in production if item['kind'] == 'StatefulSet'
                          and item['metadata']['name'].startswith('inference-worker-')]
    assert len(production_workers) == 2
    for worker in production_workers:
        container = worker['spec']['template']['spec']['containers'][0]
        context_args = [arg for arg in container['args'] if arg.startswith('--context-length')]
        assert context_args == ['--context-length=131072'], context_args
        sampling_args = [arg for arg in container['args'] if arg.startswith('--sampling-backend')]
        assert sampling_args == ['--sampling-backend=pytorch'], sampling_args
    model = 'deepseek-ai/DeepSeek-V4.1-Flash-1017'
    public_models = [model]
    assert production_settings['catalogModelIds'] == public_models
    assert production_settings['inferenceModelIds'] == public_models
    production_values = yaml.safe_load((ROOT / 'tests/fixtures/deployments/production-values.yaml').read_text())
    assert production_values['runtimeConfig']['modelRoutes'] == {
        model: [model]}
    bindings = production_values['gateway']['usage']['models']
    assert set(bindings) == set(public_models)
    assert bindings[model] == {
        'served_model': model,
        'model_revision': '1bae0e1088993b9b82de08f59de5be5a34e42170'}
    # Values that bin/deploy sets per deployment do not reach the pod.
    deployed = [item for item in yaml.safe_load_all(helm('template', 'confidential-inference', str(CHART),
        '--namespace', 'confidential-inference', '-f', str(ROOT/'tests/fixtures/deployments/production-values.yaml'),
        '-f', str(ROOT/'tests/release-v1/fixtures/release-values.yaml'),
        '--set', 'frameworkRelease.name=v0.14.18',
        '--set', 'attestationReceipts.evidenceBaseUrl=https://candidate.example.test',
        '--set', 'attestationReceipts.evidenceConnectHost=c8s-router.c8s-router.svc.cluster.local',
        '--set', 'runtimeConfig.releaseBundle={}')) if item]
    deployed_gateway = next(item for item in deployed if item['kind'] == 'Deployment'
                            and item['metadata']['name'] == 'gateway')
    assert deployed_gateway['spec']['template'] == gateway['spec']['template']
    assert not any(item['kind'] == 'ConfigMap' and item['metadata']['name'].startswith('gateway-')
                   for item in deployed)
    assert gateway_environment['GATEWAY_ADMIN_CONFIG_FILE'] == '/run/c8s/secrets/product-usage'
    assert not any(name.startswith('GATEWAY_STATE_') for name in gateway_environment)
    assert gateway_environment['GATEWAY_INFERENCE_URL'] == 'http://sglang-router:30000'
    # The router Deployment and Service keep their names across releases, so
    # an upgrade rolls the router behind the same address. Its c8s workload is
    # per release: the old and the new pod each match their own allowlist entry.
    service = next(d for d in production if d['kind'] == 'Service' and d['metadata']['name'] == 'router-headless')
    router = next(d for d in production if d['kind'] == 'Deployment' and d['metadata']['name'] == 'sglang-router')
    assert all(router['spec']['template']['metadata']['labels'].get(k) == v for k, v in service['spec']['selector'].items())
    router_container = next(c for c in router['spec']['template']['spec']['containers']
                            if c['name'] == 'sglang-router')
    router_env = {item['name']: item['value'] for item in router_container['env']}
    assert json.loads(router_env['CI_ROUTER_MODEL_ROUTES']) == {
        'schemaVersion': 1, 'routes': {model: [model]}}
    assert router['spec']['selector']['matchLabels'] == {'app.kubernetes.io/part-of': 'confidential-inference',
                                                         'app.kubernetes.io/component': 'sglang-router'}
    assert router['spec']['strategy']['rollingUpdate'] == {'maxUnavailable': 0, 'maxSurge': 1}
    assert router['spec']['template']['metadata']['annotations']['confidential.ai/cw'] == 'sglang-router'
    # One model definition produces both views, each in its pod's pinned
    # environment: the gateway settings and the router routes.
    routes_json = 'runtimeConfig.modelRoutes={"public-a":["backend-a"],"public-b":["backend-b"]}'
    runtime_documents = render("--set", "frameworkRelease.name=v0.14.17",
        "--set-json", routes_json)
    runtime_gateway = Gateway(runtime_documents)
    settings = runtime_gateway.settings
    runtime_router = next(item for item in runtime_documents if item['kind'] == 'Deployment'
                          and item['metadata']['name'] == 'sglang-router')
    router_container = next(item for item in runtime_router['spec']['template']['spec']['containers']
                            if item['name'] == 'sglang-router')
    assert [item['name'] for item in router_container['env']] == ['CI_ROUTER_MODEL_ROUTES']
    routes = json.loads(router_container['env'][0]['value'])
    assert routes == {'schemaVersion': 1, 'routes': {'public-a': ['backend-a'], 'public-b': ['backend-b']}}
    assert settings['catalogModelIds'] == settings['inferenceModelIds'] == sorted(routes['routes'])
    assert settings['routerService'] == 'router-headless'
    router_slot = next(item for item in runtime_documents if item['kind'] == 'Service' and item['metadata']['name'] == settings['routerService'])
    assert router_slot['spec']['clusterIP'] == 'None'
    assert not any(item['kind'] == 'ConfigMap' for item in runtime_documents)
    assert 'volumeMounts' not in router_container
    for removed in ('GATEWAY_MODEL', 'GATEWAY_INFERENCE_CONCURRENCY',
                    'GATEWAY_MAXIMUM_BODY_BYTES', 'GATEWAY_UPSTREAM_TIMEOUT_SECONDS'):
        assert removed not in runtime_gateway.env
    assert not any('subPath' in mount for mount in runtime_gateway.container['volumeMounts'])
    final_documents = render("--set", "frameworkRelease.name=v0.14.18", "--set-json", routes_json)
    private_router = next(item for item in runtime_documents if item['kind'] == 'Service'
                          and item['metadata']['name'] == 'router-headless')
    assert private_router['spec']['clusterIP'] == 'None'
    assert all(runtime_router['spec']['template']['metadata']['labels'].get(key) == value
               for key, value in private_router['spec']['selector'].items())
    final_private_router = next(item for item in final_documents if item['kind'] == 'Service'
                                and item['metadata']['name'] == 'router-headless')
    assert private_router == final_private_router
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
    # Deployment-time attestation values reach no pod.
    local_documents = render(
        "--set", "attestationReceipts.evidenceBaseUrl=https://api.example.test",
        "--set", "attestationReceipts.evidenceConnectHost=c8s-router.c8s-system.svc.cluster.local",
        "--set", "attestationReceipts.cds.url=https://198.51.100.4:8443",
    )
    assert Gateway(local_documents).deployment == Gateway(render()).deployment
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

    # The gateway reaches the admin only at its pinned address (also its
    # allowlist exit), and what it sends is environment, so allowlist input.
    with_admin = render("--namespace", "inference", "--set", "gateway.usage.enabled=true",
                        "--set", "gateway.admin.url=https://relay.example.com/api/usage/ingest",
                        "--set", "gateway.admin.address=203.0.113.7",
                        "--set", "gateway.usage.models.m.served_model=m",
                        "--set", "gateway.usage.models.m.model_revision=r1")
    admin = Gateway(with_admin)
    assert admin.env["GATEWAY_USAGE_ENABLED"] == "true"
    assert admin.env["GATEWAY_ADMIN_ENDPOINT"] == "https://relay.example.com/api/usage/ingest"
    assert json.loads(admin.env["GATEWAY_USAGE_MODELS"]) == {"m": {"served_model": "m", "model_revision": "r1"}}
    assert admin.deployment["spec"]["template"]["spec"]["hostAliases"] == [
        {"ip": "203.0.113.7", "hostnames": ["relay.example.com"]}]
    # C8s #1049: an entry with egress has no host mount and no open argv
    # (the gateway runs its image entrypoint with no args: args deny).
    gateway_pod = admin.deployment["spec"]["template"]["spec"]
    assert not any("hostPath" in volume for volume in gateway_pod.get("volumes", []))
    assert not any(container.get("args") for container in gateway_pod["containers"])
    # Per-pod mesh: the gateway does not mount the c8s certificate volume.
    assert not any(mount["mountPath"] == "/etc/c8s/certs"
                   for container in gateway_pod["containers"] for mount in container.get("volumeMounts", []))
    egress = next(item for item in with_admin if item["kind"] == "NetworkPolicy"
                  and item["metadata"]["name"] == "gateway-to-router")["spec"]["egress"]
    blocks = [peer["ipBlock"]["cidr"] for rule in egress for peer in rule.get("to", []) if "ipBlock" in peer]
    assert blocks == ["203.0.113.7/32"], blocks
    assert "GATEWAY_USAGE_ENABLED" not in Gateway(render("--namespace", "inference")).env
    helm("template", "example", str(CHART), *NEUTRAL_MODE,
         "--set", "gateway.admin.url=http://relay.example.com/x", success=False)
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
                "--values", str(ROOT / "tests/api/values-sglang.yaml"),
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
                "--values", str(ROOT / "tests/api/values-sglang.yaml"),
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
                "--values", str(ROOT / "tests/api/values-sglang-simulator.yaml"),
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

    # Each deployment must state its own mode, since
    # the chart will not choose one for it.
    production_values = yaml.safe_load(
        (ROOT / "tests/fixtures/deployments/production-values.yaml").read_text()
    )
    assert production_values["inference"]["mode"] == "model"
    staging_values = yaml.safe_load(
        (ROOT / "tests/fixtures/deployments/staging-values.yaml").read_text()
    )
    assert staging_values["inference"]["mode"] == "simulator"

    # The staging layer clears production model routes and loads live files.
    staging_documents = render("--values", "tests/fixtures/deployments/production-values.yaml", "--values",
                               "tests/fixtures/deployments/staging-values.yaml", "--values",
                               "tests/release-v1/fixtures/release-values.yaml")
    model = "hf-internal-testing/tiny-random-LlamaForCausalLM"
    settings = Gateway(staging_documents).settings
    staging_router = next(item for item in staging_documents if item["kind"] == "Deployment"
                          and item["metadata"]["name"] == "sglang-router")
    routes = json.loads(staging_router["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"])
    assert settings["catalogModelIds"] == [model]
    assert settings["inferenceModelIds"] == [model]
    router_slot = next(item for item in staging_documents if item["kind"] == "Service" and item["metadata"]["name"] == settings["routerService"])
    assert router_slot["spec"]["clusterIP"] == "None"
    assert routes["routes"] == {model: [model]}
    # The only ConfigMap is the byte manifest of the staging model download.
    assert [item["metadata"]["name"] for item in staging_documents if item["kind"] == "ConfigMap"] == ["model-manifest"]
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
    check_model_cache()
    check_model_download()
    check_front_door_namespace()
    check_c8s_admission()
    check_telemetry_collector()
    print("Helm neutral-default and safety tests passed.")


if __name__ == "__main__":
    main()
