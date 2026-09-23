from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "helm/confidential-inference"
CONTRACT = ROOT / "contracts/network-ports.yaml"
# The chart has no default for inference.mode. This constant marks a render
# that only needs a chart to succeed, not a specific mode, so it picks the
# GPU-free simulator backend.
NEUTRAL_MODE = ("--set", "inference.mode=simulator")


def named(documents: list[dict], kind: str, name: str) -> dict:
    return next(
        item for item in documents
        if item["kind"] == kind and item["metadata"]["name"] == name
    )


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
        self.assertEqual(self.port("inner-kubernetes-api")["cvmPort"], 6443)

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
        self.assertEqual(ingress[1]["ports"], [{"protocol": "TCP", "port": 9090}])

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

    def test_node_mode_attestation_can_reach_the_local_cvm_service(self) -> None:
        policies = [item for item in self.documents if item["kind"] == "NetworkPolicy"]
        self.assertNotIn(
            "workload-attestation-egress",
            {item["metadata"]["name"] for item in policies},
        )
        self.assertTrue(
            any(
                port.get("port") == 8400
                for policy in policies
                for rule in policy["spec"].get("egress", [])
                for port in rule.get("ports", [])
            )
        )

    def test_application_limits_match_the_public_contract(self) -> None:
        expected = self.contract["publicProtection"]["application"]
        gateway = named(self.documents, "Deployment", "gateway")
        values = {
            item["name"]: item.get("value")
            for item in gateway["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        self.assertEqual(int(values["GATEWAY_INFERENCE_CONCURRENCY"]), expected["inferenceConcurrency"])
        self.assertEqual(int(values["GATEWAY_INFERENCE_QUEUE"]), expected["inferenceQueue"])
        self.assertEqual(int(values["GATEWAY_ATTESTATION_CONCURRENCY"]), expected["attestationConcurrency"])


if __name__ == "__main__":
    unittest.main()
