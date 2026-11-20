#!/usr/bin/env python3
"""The allowlist exit of a policy item comes from its pod's hostAliases (C8s #1047),
or from the ranges of the controller's egress-cidrs annotation."""

from __future__ import annotations

import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEN = runpy.run_path(str(ROOT / "scripts/generate-release-allowlist.py"))


def controller(aliases: list[dict], cidrs: str | None = None) -> dict:
    metadata = {"annotations": {GEN["EGRESS_CIDRS_ANNOTATION"]: cidrs}} if cidrs is not None else {}
    return {"metadata": metadata, "spec": {"template": {"spec": {"hostAliases": aliases}}}}


ROUTER = {"controller": "Deployment/sglang-router", "egress": {"port": 6443}}
# The deploy-time API server address, unknown to the release render.
DEPLOY_ALIAS = [{"ip": "192.0.2.30", "hostnames": ["kubernetes-api"]}]


class DeclaredEgressTests(unittest.TestCase):
    def test_each_host_alias_is_one_exit_on_the_declared_port(self) -> None:
        item = {"controller": "Deployment/telemetry-collector", "egress": {"port": 443}}
        aliases = [{"ip": "203.0.113.9", "hostnames": ["b"]}, {"ip": "203.0.113.7", "hostnames": ["a"]}]
        self.assertEqual(GEN["declared_egress"](controller(aliases), item),
                         [{"cidr": "203.0.113.7/32", "port": 443}, {"cidr": "203.0.113.9/32", "port": 443}])

    def test_an_item_without_egress_has_no_exit(self) -> None:
        self.assertEqual(GEN["declared_egress"](controller([]), {"controller": "Deployment/gateway"}), [])

    def test_host_aliases_without_declared_egress_are_refused(self) -> None:
        # The model download of inference.model.download pins its source with
        # hostAliases; without the exit the node drops every connection to it.
        aliases = [{"ip": "203.0.113.7", "hostnames": ["a"]}]
        with self.assertRaisesRegex(GEN["GenerationError"], "declares no egress"):
            GEN["declared_egress"](controller(aliases), {"controller": "StatefulSet/inference-worker-0"})

    def test_declared_egress_needs_an_address(self) -> None:
        with self.assertRaises(GEN["GenerationError"]):
            GEN["declared_egress"](controller([]), {"controller": "Deployment/x", "egress": {"port": 443}})


    def test_exits_sort_by_address_as_c8s_sorts_them(self) -> None:
        aliases = [{"ip": "203.0.113.10", "hostnames": ["b"]}, {"ip": "203.0.113.9", "hostnames": ["a"]}]
        self.assertEqual(GEN["declared_egress"](controller(aliases), ROUTER),
                         [{"cidr": "203.0.113.9/32", "port": 6443}, {"cidr": "203.0.113.10/32", "port": 6443}])


class EgressRangeTests(unittest.TestCase):
    """router.discovery.apiServer.cidrs: the deployment sets the API server
    address after the release render, so each range is one exit."""

    def test_each_range_is_one_exit_in_place_of_the_host_alias(self) -> None:
        self.assertEqual(GEN["declared_egress"](controller(DEPLOY_ALIAS, "10.48.64.0/18"), ROUTER),
                         [{"cidr": "10.48.64.0/18", "port": 6443}])
        self.assertEqual(GEN["declared_egress"](controller(DEPLOY_ALIAS, "10.49.0.0/16,10.48.64.0/18,10.48.0.9/32"), ROUTER),
                         [{"cidr": "10.48.0.9/32", "port": 6443}, {"cidr": "10.48.64.0/18", "port": 6443},
                          {"cidr": "10.49.0.0/16", "port": 6443}])
        # The ranges need no hostAliases address at render time.
        self.assertEqual(GEN["declared_egress"](controller([], "10.48.64.0/18"), ROUTER),
                         [{"cidr": "10.48.64.0/18", "port": 6443}])

    def test_without_ranges_the_exit_stays_the_exact_address(self) -> None:
        self.assertEqual(GEN["declared_egress"](controller(DEPLOY_ALIAS), ROUTER),
                         [{"cidr": "192.0.2.30/32", "port": 6443}])

    def test_ranges_that_c8s_refuses_are_refused(self) -> None:
        for value in ("10.0.0.0/8", "10.48.0.0/15", "10.48.65.0/18", "10.48.64.0", "10.48.64.0/33",
                      "fd00::/48", "", "10.48.64.0/18,", "127.0.0.0/16", "169.254.0.0/16", "224.0.0.0/16",
                      "10.48.64.0/18,10.48.64.0/18", ",".join(f"10.{i}.0.0/16" for i in range(9))):
            with self.subTest(value=value), self.assertRaises(GEN["GenerationError"]):
                GEN["declared_egress"](controller(DEPLOY_ALIAS, value), ROUTER)

    def test_ranges_without_declared_egress_are_refused(self) -> None:
        with self.assertRaisesRegex(GEN["GenerationError"], "declares no egress"):
            GEN["declared_egress"](controller([], "10.48.64.0/18"), {"controller": "Deployment/sglang-router"})


if __name__ == "__main__":
    unittest.main()
