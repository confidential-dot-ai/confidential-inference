from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "helm/confidential-inference"
CONTRACT = ROOT / "docs/network-ports.yaml"
# The chart has no default for inference.mode. This constant marks a render
# that only needs a chart to succeed, not a specific mode, so it picks the
# GPU-free simulator backend.
NEUTRAL_MODE = ("--set", "inference.mode=simulator")


def named(documents: list[dict], kind: str, name: str) -> dict:
    return next(
        item for item in documents
        if item["kind"] == kind and item["metadata"]["name"] == name
    )


def selects(selector: dict, labels: dict) -> bool:
    if any(labels.get(key) != value for key, value in selector.get("matchLabels", {}).items()):
        return False
    for expression in selector.get("matchExpressions", []):
        value = labels.get(expression["key"])
        if expression["operator"] == "In" and value not in expression["values"]:
            return False
        if expression["operator"] == "NotIn" and value in expression["values"]:
            return False
        if expression["operator"] == "Exists" and expression["key"] not in labels:
            return False
        if expression["operator"] == "DoesNotExist" and expression["key"] in labels:
            return False
    return True


class NetworkContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = yaml.safe_load(CONTRACT.read_text())
        output = subprocess.run(
            ["helm", "template", "example", str(CHART), *NEUTRAL_MODE], cwd=ROOT,
            check=True, text=True, capture_output=True,
        ).stdout
        cls.documents = [item for item in yaml.safe_load_all(output) if item]

    def port(self, name: str) -> dict:
        return next(item for item in self.contract["ports"] if item["name"] == name)

    def workloads(self) -> list[dict]:
        found = [
            item for item in self.documents
            if item["kind"] in {"Deployment", "StatefulSet", "DaemonSet"}
            and "confidential.ai/cw" in item["spec"]["template"]["metadata"].get("annotations", {})
        ]
        self.assertGreaterEqual(len(found), 5)
        return found

    def test_public_and_c8s_ports_are_explicit(self) -> None:
        public = self.port("public-gateway")
        self.assertEqual((public["externalPort"], public["podPort"]), (443, 9443))
        acme = self.port("public-acme-challenge")
        self.assertEqual((acme["externalPort"], acme["podPort"]), (80, 8080))
        self.assertEqual(
            set(self.contract["publicEntry"]["outerPublicServicePorts"]),
            {80, 443},
        )
        self.assertEqual(self.port("c8s-attestation")["cvmPort"], 8400)
        self.assertEqual(self.port("c8s-credential-release")["cvmPort"], 8443)
        self.assertEqual(self.port("c8s-credential-release")["scope"], "cds-vm")
        self.assertEqual(self.port("c8s-admission-inventory")["cvmPort"], 1019)
        self.assertEqual(self.port("inner-kubernetes-api")["releases"], "before-c8s-v0.99.29")
        api = self.port("control-plane-kubernetes-api")
        self.assertEqual((api["scope"], api["externalPort"], api["releases"]), ("control-plane", 6443, "c8s-v0.99.29"))

    def test_inner_chart_has_no_public_service(self) -> None:
        public = [
            item for item in self.documents
            if item["kind"] == "Service"
            and item["spec"].get("type", "ClusterIP") in {"LoadBalancer", "NodePort"}
        ]
        self.assertEqual(public, [])

    def test_gateway_ingress_accepts_the_front_door_and_metrics_only(self) -> None:
        ingress = named(self.documents, "NetworkPolicy", "gateway-ingress")["spec"]["ingress"]
        self.assertEqual(ingress[0]["ports"], [{"protocol": "TCP", "port": 9443}])
        self.assertEqual(
            ingress[0]["from"][0]["podSelector"]["matchLabels"],
            {"app.kubernetes.io/name": "tls-lb"},
        )
        # The metrics port opens only to the telemetry collector, when it runs.
        self.assertEqual(len(ingress), 1)

    def test_front_door_pod_label_is_a_chart_value(self) -> None:
        """c8s PR #606 renamed the front-door component `tls-lb` to `router`.

        The gateway ingress policy and the gateway evidence egress policy must
        both follow `c8s.frontDoorPodLabelName`. A hard-coded label makes the
        front door -> gateway hop time out on a c8s pin that uses the other
        name, because the namespace default-deny policy drops it.
        """
        output = subprocess.run(
            [
                "helm", "template", "example", str(CHART), *NEUTRAL_MODE,
                "--set", "c8s.frontDoorPodLabelName=router",
            ],
            cwd=ROOT, check=True, text=True, capture_output=True,
        ).stdout
        documents = [item for item in yaml.safe_load_all(output) if item]

        ingress = named(documents, "NetworkPolicy", "gateway-ingress")["spec"]["ingress"]
        self.assertEqual(
            ingress[0]["from"][0]["podSelector"]["matchLabels"],
            {"app.kubernetes.io/name": "router"},
        )

        egress = named(documents, "NetworkPolicy", "gateway-to-router")["spec"]["egress"]
        front_door = [
            peer
            for rule in egress
            for peer in rule.get("to", [])
            if peer.get("podSelector", {}).get("matchLabels", {}).get(
                "app.kubernetes.io/name"
            )
        ]
        self.assertEqual(
            [peer["podSelector"]["matchLabels"] for peer in front_door],
            [{"app.kubernetes.io/name": "router"}],
        )

    def test_pods_reach_attestation_through_the_node_socket_only(self) -> None:
        # The worker binds the attestation API to node loopback; credential
        # clients use the node's attestation socket.
        policies = [item for item in self.documents if item["kind"] == "NetworkPolicy"]
        self.assertFalse(
            any(
                port.get("port") == self.port("c8s-attestation")["cvmPort"]
                for policy in policies
                for rule in policy["spec"].get("egress", [])
                for port in rule.get("ports", [])
            )
        )

    def cds_rules(self, documents: list[dict]) -> dict[str, list[dict]]:
        """The egress rules on the CDS port that select each confidential workload."""
        cds_port = self.port("c8s-credential-release")["cvmPort"]
        policies = [item for item in documents if item["kind"] == "NetworkPolicy"]
        return {
            workload["metadata"]["name"]: [
                rule
                for policy in policies
                if selects(policy["spec"]["podSelector"], workload["spec"]["template"]["metadata"]["labels"])
                for rule in policy["spec"].get("egress", [])
                if any(port.get("port") == cds_port for port in rule.get("ports", []))
            ]
            for workload in self.workloads()
        }

    def test_each_confidential_workload_reaches_only_the_configured_cds(self) -> None:
        output = subprocess.run(
            ["helm", "template", "example", str(CHART), *NEUTRAL_MODE,
             "--set", "c8s.cds.cidrs={198.51.100.4/32}"],
            cwd=ROOT, check=True, text=True, capture_output=True,
        ).stdout
        documents = [item for item in yaml.safe_load_all(output) if item]
        for name, rules in self.cds_rules(documents).items():
            self.assertTrue(rules, name)
            for rule in rules:
                self.assertEqual(rule.get("to"), [{"ipBlock": {"cidr": "198.51.100.4/32"}}], name)

    def test_the_maintenance_gateway_reaches_only_the_configured_cds(self) -> None:
        cds_port = self.port("c8s-credential-release")["cvmPort"]
        for values, peers in ((("--set", "cds.cidrs={198.51.100.4/32}"), [{"ipBlock": {"cidr": "198.51.100.4/32"}}]),
                              ((), None)):
            output = subprocess.run(["helm", "template", "example", str(ROOT / "helm/maintenance-gateway"), *values],
                                    cwd=ROOT, check=True, text=True, capture_output=True).stdout
            rules = [rule for item in yaml.safe_load_all(output) if item and item["kind"] == "NetworkPolicy"
                     for rule in item["spec"].get("egress", [])
                     if any(port.get("port") == cds_port for port in rule.get("ports", []))]
            self.assertEqual([rule.get("to") for rule in rules], [peers], values)

    def test_without_a_cds_address_the_cds_rule_names_no_peer(self) -> None:
        # The CDS address is a deployment value; release profiles leave it unset.
        for name, rules in self.cds_rules(self.documents).items():
            self.assertTrue(rules, name)
            self.assertTrue(all("to" not in rule for rule in rules), name)

    def test_each_confidential_workload_can_reach_the_mesh(self) -> None:
        # ratls-mesh DNATs every connection between confidential workloads to
        # the node's mesh port before the CNI applies egress policy.
        mesh_port = self.port("c8s-mesh-outbound")["cvmPort"]
        policies = [item for item in self.documents if item["kind"] == "NetworkPolicy"]
        for workload in self.workloads():
            labels = workload["spec"]["template"]["metadata"]["labels"]
            allowed = any(
                selects(policy["spec"]["podSelector"], labels)
                and "Egress" in policy["spec"].get("policyTypes", [])
                and any(
                    "to" not in rule
                    and any(port.get("port") == mesh_port for port in rule.get("ports", []))
                    for rule in policy["spec"].get("egress", [])
                )
                for policy in policies
            )
            self.assertTrue(allowed, workload["metadata"]["name"])

    def test_application_limits_match_the_public_contract(self) -> None:
        expected = self.contract["publicProtection"]["application"]
        gateway = named(self.documents, "Deployment", "gateway")["spec"]["template"]["spec"]["containers"][0]
        settings = json.loads(next(item["value"] for item in gateway["env"] if item["name"] == "GATEWAY_RUNTIME_CONFIG"))
        self.assertEqual(settings["inferenceConcurrency"], expected["inferenceConcurrency"])
        self.assertEqual(settings["inferenceQueue"], expected["inferenceQueue"])
        self.assertEqual(settings["attestationConcurrency"], expected["attestationConcurrency"])


if __name__ == "__main__":
    unittest.main()
