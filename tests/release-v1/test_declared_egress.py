#!/usr/bin/env python3
"""The allowlist exit of a policy item comes from its pod's hostAliases (C8s #1047)."""

from __future__ import annotations

import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEN = runpy.run_path(str(ROOT / "scripts/generate-release-allowlist.py"))


def controller(aliases: list[dict]) -> dict:
    return {"spec": {"template": {"spec": {"hostAliases": aliases}}}}


class DeclaredEgressTests(unittest.TestCase):
    def test_each_host_alias_is_one_exit_on_the_declared_port(self) -> None:
        item = {"controller": "Deployment/telemetry-collector", "egress": {"port": 443}}
        aliases = [{"ip": "203.0.113.9", "hostnames": ["b"]}, {"ip": "203.0.113.7", "hostnames": ["a"]}]
        self.assertEqual(GEN["declared_egress"](controller(aliases), item),
                         [{"cidr": "203.0.113.7/32", "port": 443}, {"cidr": "203.0.113.9/32", "port": 443}])

    def test_an_item_without_egress_has_no_exit(self) -> None:
        aliases = [{"ip": "203.0.113.7", "hostnames": ["a"]}]
        self.assertEqual(GEN["declared_egress"](controller(aliases), {"controller": "Deployment/gateway"}), [])

    def test_declared_egress_needs_an_address(self) -> None:
        with self.assertRaises(GEN["GenerationError"]):
            GEN["declared_egress"](controller([]), {"controller": "Deployment/x", "egress": {"port": 443}})


if __name__ == "__main__":
    unittest.main()
