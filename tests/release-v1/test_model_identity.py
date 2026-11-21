"""A signed older C8s release cannot silently ignore mesh peer restrictions."""

from pathlib import Path
import runpy
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
GEN = runpy.run_path(str(ROOT / "scripts/generate-release-allowlist.py"))


class PeerWorkloadCapabilityTests(unittest.TestCase):
    def test_refuses_older_pinned_c8s(self):
        render = {"router": {"spec": {"template": {"spec": {"containers": [{"env": [
            {"name": "C8S_MESH_PEER_WORKLOADS", "value": "inference-worker"}]}]}}}}}
        check = GEN["require_peer_workload_support"]
        with patch.dict(check.__globals__, run=lambda command: b"old mesh help"):
            with self.assertRaisesRegex(GEN["GenerationError"], "enforced mesh peer workloads"):
                check(render, Path("c8s"))
        with patch.dict(check.__globals__, run=lambda command: b"C8S_MESH_PEER_WORKLOADS"):
            check(render, Path("c8s"))

    def test_unchanged_deployment_needs_no_new_capability(self):
        check = GEN["require_peer_workload_support"]
        with patch.dict(check.__globals__, run=lambda command: self.fail("must not probe the old CLI")):
            check({}, Path("c8s"))

    def test_discovery_and_direct_gateway_cannot_bypass_the_mesh(self):
        for container in (
            {"args": ["--service-discovery-port=30000"], "env": [
                {"name": "C8S_MESH_PEER_WORKLOADS", "value": "inference-worker"}]},
            {"env": [{"name": "C8S_MESH_PEER_WORKLOADS", "value": "sglang-router"},
                     {"name": "GATEWAY_INFERENCE_URL", "value": "http://sglang-router:30000"}]},
        ):
            with self.assertRaisesRegex(GEN["GenerationError"], "declared egress exit"):
                GEN["refuse_peer_egress"]({"app": container}, [{"cidr": "192.0.2.0/24", "port": 30000}])
            GEN["refuse_peer_egress"]({"app": container}, [{"cidr": "192.0.2.1/32", "port": 6443}])


if __name__ == "__main__":
    unittest.main()
