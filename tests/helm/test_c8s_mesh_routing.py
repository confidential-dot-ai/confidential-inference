#!/usr/bin/env python3
"""Check mesh egress scope and direct service discovery."""
from pathlib import Path
import subprocess
import yaml

ROOT = Path(__file__).resolve().parents[2]


def render(*flags):
    result = subprocess.run([
        "helm", "template", "example", str(ROOT / "helm/confidential-inference"),
        "--namespace", "inference", "--set", "inference.mode=simulator",
        "--set", "metricsCollector.enabled=true", "--set", "kubeStateMetrics.enabled=true",
        *flags,
    ], capture_output=True, text=True, check=True)
    return {(item["kind"], item["metadata"]["name"]): item
            for item in yaml.safe_load_all(result.stdout) if item}


def main():
    before = render()
    after = render("--set", "network.c8sMeshNodeCidrs[0]=172.20.0.0/24",
                   "--set", "network.c8sMeshNodeCidrs[1]=172.20.2.0/24")
    key = ("NetworkPolicy", "workloads-to-c8s-mesh")
    assert key not in before
    policy = after[key]["spec"]
    assert policy["policyTypes"] == ["Egress"]
    assert policy["egress"] == [{
        "to": [{"ipBlock": {"cidr": "172.20.0.0/24"}}, {"ipBlock": {"cidr": "172.20.2.0/24"}}],
        "ports": [{"protocol": "TCP", "port": 15001}],
    }]
    for name in ("sglang-router", "metrics-collector", "kube-state-metrics"):
        key = ("Service", name)
        assert "clusterIP" not in before[key]["spec"]
        assert after[key]["spec"]["clusterIP"] == "None"
    assert after[("Service", "sglang-router")]["spec"]["publishNotReadyAddresses"] is True
    assert "publishNotReadyAddresses" not in before[("Service", "sglang-router")]["spec"]
    for key, item in before.items():
        if item["kind"] in ("Deployment", "StatefulSet", "DaemonSet"):
            assert item == after[key], f"Mesh routing changed pod definitions: {key}"
    print("C8s mesh routing checks passed.")


if __name__ == "__main__":
    main()
