#!/usr/bin/env python3
"""Check the named c8s proxy wiring and its public launch policy."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "helm/confidential-inference"
# The internal staging values file lives in the confidential-inference-internal
# repository. Set CONFIDENTIAL_INFERENCE_INTERNAL to the path of a checkout of
# that repository. There is no default path: a maintainer path must not become
# a default in this repository. The overlay test below skips when the variable
# is unset.
INTERNAL_REPO_ENV = "CONFIDENTIAL_INFERENCE_INTERNAL"
INTERNAL_VALUES_RELATIVE_PATH = "environments/values-staging.yaml"


def internal_staging_values() -> Path | None:
    """Return the internal staging values file, or None when it is absent."""
    configured = os.environ.get(INTERNAL_REPO_ENV)
    if not configured:
        return None
    candidate = Path(configured) / INTERNAL_VALUES_RELATIVE_PATH
    return candidate if candidate.is_file() else None
# The chart has no default for inference.mode. This constant marks a render
# that only needs a chart to succeed, not a specific mode, so it picks the
# GPU-free simulator backend.
NEUTRAL_MODE = ("--set", "inference.mode=simulator")
PROXY_ARGS = {
    "client": [
        "--mode=client",
        "--listen=127.0.0.1:30001",
        "--upstream=sglang-router:9443",
        "--peer-workload=sglang-router",
        "--cert-file=/etc/c8s/certs/tls.crt",
        "--key-file=/etc/c8s/certs/tls.key",
        "--ca-file=/etc/c8s/certs/ca.crt",
    ],
    "server": [
        "--mode=server",
        "--listen=0.0.0.0:9443",
        "--upstream=127.0.0.1:30000",
        "--peer-workload=gateway",
        "--cert-file=/etc/c8s/certs/tls.crt",
        "--key-file=/etc/c8s/certs/tls.key",
        "--ca-file=/etc/c8s/certs/ca.crt",
    ],
}


def rendered(*arguments: str) -> list[dict]:
    result = subprocess.run(
        [
            "helm", "template", "example", str(CHART), "--namespace", "inference",
            *NEUTRAL_MODE, "--set", "namedWorkloadProxy.enabled=true", *arguments,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [item for item in yaml.safe_load_all(result.stdout) if item]


def container(workload: dict, name: str) -> dict:
    return next(
        item
        for item in workload["spec"]["template"]["spec"]["containers"]
        if item["name"] == name
    )


def test_proxy_is_on_by_default() -> None:
    # Production's allowlist carries gateway and router workload-proxy
    # sidecars, so the chart must enable the proxy without any override.
    result = subprocess.run(
        ["helm", "template", "example", str(CHART), "--namespace", "inference", *NEUTRAL_MODE],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    documents = [item for item in yaml.safe_load_all(result.stdout) if item]
    gateway = next(
        item for item in documents
        if item.get("kind") == "Deployment" and item["metadata"]["name"] == "gateway"
    )
    router = next(
        item for item in documents
        if item.get("kind") == "Deployment" and item["metadata"]["name"] == "sglang-router"
    )
    proxy = container(gateway, "router-workload-proxy")
    assert proxy["command"] == ["/c8s"] and proxy["args"][0] == "workload-proxy"
    assert proxy["args"] == ["workload-proxy", *PROXY_ARGS["client"]]
    assert container(router, "gateway-workload-proxy")["args"] == ["workload-proxy", *PROXY_ARGS["server"]]
    env = {item["name"]: item["value"] for item in container(gateway, "gateway")["env"]}
    assert env["GATEWAY_INFERENCE_URL"] == "http://127.0.0.1:30001"


def test_proxy_can_be_disabled_explicitly() -> None:
    # A cluster running a c8s release without /workload-proxy can opt out.
    result = subprocess.run(
        [
            "helm", "template", "example", str(CHART), "--namespace", "inference",
            *NEUTRAL_MODE, "--set", "namedWorkloadProxy.enabled=false",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    documents = [item for item in yaml.safe_load_all(result.stdout) if item]
    gateway = next(
        item for item in documents
        if item.get("kind") == "Deployment" and item["metadata"]["name"] == "gateway"
    )
    router = next(
        item for item in documents
        if item.get("kind") == "Deployment" and item["metadata"]["name"] == "sglang-router"
    )
    gateway_names = {item["name"] for item in gateway["spec"]["template"]["spec"]["containers"]}
    router_names = {item["name"] for item in router["spec"]["template"]["spec"]["containers"]}
    assert "router-workload-proxy" not in gateway_names
    assert "gateway-workload-proxy" not in router_names
    env = {item["name"]: item["value"] for item in container(gateway, "gateway")["env"]}
    assert env["GATEWAY_INFERENCE_URL"] == "http://sglang-router:30000"


def test_gateway_uses_only_loopback_proxy() -> None:
    documents = rendered()
    gateway = next(
        item
        for item in documents
        if item.get("kind") == "Deployment" and item["metadata"]["name"] == "gateway"
    )
    app = container(gateway, "gateway")
    env = {item["name"]: item["value"] for item in app["env"]}
    assert env["GATEWAY_INFERENCE_URL"] == "http://127.0.0.1:30001"
    assert "sglang-router" not in env["GATEWAY_INFERENCE_URL"]
    proxy = container(gateway, "router-workload-proxy")
    assert proxy["command"] == ["/c8s"] and proxy["args"][0] == "workload-proxy"
    assert proxy["args"] == ["workload-proxy", *PROXY_ARGS["client"]]
    # The proxy intentionally listens only on pod loopback. Kubelet TCP probes
    # target the pod IP and would restart a healthy proxy. The gateway's own
    # readiness probe checks this complete loopback path instead.
    assert "readinessProbe" not in proxy
    assert "livenessProbe" not in proxy


def test_router_service_targets_authenticated_proxy_and_health_stays_loopback() -> None:
    documents = rendered()
    service = next(
        item
        for item in documents
        if item.get("kind") == "Service" and item["metadata"]["name"] == "sglang-router"
    )
    openai = next(item for item in service["spec"]["ports"] if item["name"] == "openai")
    assert openai["port"] == 9443
    assert openai["targetPort"] == "proxy-tls"
    assert all(item["port"] != 30000 for item in service["spec"]["ports"])

    network_policy = next(
        item
        for item in documents
        if item.get("kind") == "NetworkPolicy"
        and item["metadata"]["name"] == "router-paths"
    )
    gateway_ingress = next(
        rule
        for rule in network_policy["spec"]["ingress"]
        if rule.get("from", [{}])[0].get("podSelector", {}).get("matchLabels", {}).get(
            "app.kubernetes.io/component"
        )
        == "gateway"
    )
    gateway_ports = {item["port"] for item in gateway_ingress["ports"]}
    assert gateway_ports == {9443}

    gateway_egress_policy = next(
        item
        for item in documents
        if item.get("kind") == "NetworkPolicy"
        and item["metadata"]["name"] == "gateway-to-router"
    )
    gateway_egress = next(
        rule
        for rule in gateway_egress_policy["spec"]["egress"]
        if rule.get("to", [{}])[0].get("podSelector", {}).get("matchLabels", {}).get(
            "app.kubernetes.io/component"
        )
        == "sglang-router"
    )
    assert {item["port"] for item in gateway_egress["ports"]} == {9443}

    router = next(
        item
        for item in documents
        if item.get("kind") == "Deployment"
        and item["metadata"]["name"] == "sglang-router"
    )
    app = container(router, "sglang-router")
    proxy = container(router, "gateway-workload-proxy")
    assert next(
        port for port in proxy["ports"] if port["name"] == "proxy-tls"
    )["containerPort"] == 9443
    assert "--host=127.0.0.1" in app["args"]
    assert "http://127.0.0.1:30000/readiness" in app["readinessProbe"]["exec"]["command"][-1]
    assert "http://127.0.0.1:30000/health" in app["livenessProbe"]["exec"]["command"][-1]
    assert proxy["command"] == ["/c8s"] and proxy["args"][0] == "workload-proxy"
    assert proxy["args"] == ["workload-proxy", *PROXY_ARGS["server"]]
    assert proxy["readinessProbe"] == {
        "tcpSocket": {"port": "proxy-tls"},
        "periodSeconds": 10,
        "timeoutSeconds": 3,
        "failureThreshold": 3,
    }
    assert proxy["livenessProbe"] == {
        "tcpSocket": {"port": "proxy-tls"},
        "periodSeconds": 30,
        "timeoutSeconds": 3,
        "failureThreshold": 3,
    }


def test_proxy_uses_exact_c8s_workload_names_when_policy_names_change() -> None:
    documents = rendered(
        "--set-string", "gateway.attestedWorkload=gateway-db0b6ee",
        "--set-string", "router.attestedWorkload=sglang-router-684393d",
    )
    gateway = next(
        item for item in documents
        if item.get("kind") == "Deployment" and item["metadata"]["name"] == "gateway"
    )
    router = next(
        item for item in documents
        if item.get("kind") == "Deployment" and item["metadata"]["name"] == "sglang-router"
    )
    assert container(gateway, "router-workload-proxy")["args"] == [
        "workload-proxy",
        *PROXY_ARGS["client"][:3],
        "--peer-workload=sglang-router-684393d",
        *PROXY_ARGS["client"][4:],
    ]
    assert container(router, "gateway-workload-proxy")["args"] == [
        "workload-proxy",
        *PROXY_ARGS["server"][:3],
        "--peer-workload=gateway-db0b6ee",
        *PROXY_ARGS["server"][4:],
    ]


def test_environment_overlay_uses_production_policy_names() -> None:
    result = subprocess.run(
        [
            "helm",
            "template",
            "production",
            str(CHART),
            "--namespace",
            "inference",
            *NEUTRAL_MODE,
            "--set",
            "namedWorkloadProxy.enabled=true",
            "--set",
            "gateway.attestedWorkload=gateway-db0b6ee",
            "--set",
            "router.attestedWorkload=sglang-router-684393d",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    documents = [item for item in yaml.safe_load_all(result.stdout) if item]
    gateway = next(
        item for item in documents
        if item.get("kind") == "Deployment" and item["metadata"]["name"] == "gateway"
    )
    router = next(
        item for item in documents
        if item.get("kind") == "Deployment" and item["metadata"]["name"] == "sglang-router"
    )
    assert container(gateway, "router-workload-proxy")["args"] == [
        "workload-proxy",
        *PROXY_ARGS["client"][:3],
        "--peer-workload=sglang-router-684393d",
        *PROXY_ARGS["client"][4:],
    ]
    assert container(router, "gateway-workload-proxy")["args"] == [
        "workload-proxy",
        *PROXY_ARGS["server"][:3],
        "--peer-workload=gateway-db0b6ee",
        *PROXY_ARGS["server"][4:],
    ]


def test_prechange_allowlists_are_retained_by_canonical_digest() -> None:
    # Only production keeps prechange allowlist history right now. Staging
    # pruned its old entries down to the current release; a new entry lands
    # here the next time staging's allowlist changes.
    expected = {
        "production": "3124e2150c64094865988c8ca05a61d860cb312c4de87e5770461f5cf2006be3",
    }
    for environment, digest in expected.items():
        path = ROOT / "c8s/allowlists/history" / environment / f"sha256-{digest}.json"
        assert path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        json.loads(path.read_text())


def test_active_staging_allowlist_uses_one_simulator_worker() -> None:
    # Staging moved to c8s v0.21.2 and one inference node (no GPU): a single
    # inference-worker-0, unlike the old two-worker staging cluster.
    workloads = json.loads(
        (ROOT / "c8s/allowlists/staging.json").read_text()
    )["workloads"]
    assert "inference-worker-1" not in workloads
    containers = workloads["inference-worker-0"]["containers"]
    # The c8s runtime injects an attestation sidecar ahead of the app
    # container, so find the sglang container by its command instead of
    # by a fixed index.
    policy = next(
        item for item in containers if item["command"]["argv"] == ["python3"]
    )
    argv = policy["command"]["argv"] + policy["args"]["argv"]
    assert argv[:3] == ["python3", "-m", "sglang_simulator.simulation.sglang.launch_server"]
    assert "--random-seed=0" in argv


def test_internal_volume_overlay_renders_if_present() -> None:
    values = internal_staging_values()
    if values is None:
        print(
            f"skip: no internal staging values; set {INTERNAL_REPO_ENV} to the "
            "path of a confidential-inference-internal checkout"
        )
        return
    result = subprocess.run(
        ["helm", "template", "staging", str(CHART), "--namespace", "inference", "--values", str(values)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def main() -> None:
    test_proxy_is_on_by_default()
    test_proxy_can_be_disabled_explicitly()
    test_gateway_uses_only_loopback_proxy()
    test_router_service_targets_authenticated_proxy_and_health_stays_loopback()
    test_proxy_uses_exact_c8s_workload_names_when_policy_names_change()
    test_environment_overlay_uses_production_policy_names()
    test_prechange_allowlists_are_retained_by_canonical_digest()
    test_active_staging_allowlist_uses_one_simulator_worker()
    test_internal_volume_overlay_renders_if_present()


if __name__ == "__main__":
    main()
