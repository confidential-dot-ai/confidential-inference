#!/usr/bin/env python3
"""Tests of harden_dist.py against the pinned SGLang source.

Downloads only the public pinned source files and runs the patched functions
with stubs; never imports SGLang or torch.
"""
import ast
import importlib.util
import os
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("harden_dist", ROOT / "images/sglang/harden_dist.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
PIN = "a7fd2e1158c389c33077bae67fb797efa8dd09bd"


def functions(source, *names, **namespace):
    tree = ast.parse(source)
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "patched", "exec"), namespace)
    return namespace


class NetworkAddress:
    def __init__(self, host, port):
        self.host, self.port = host, port

    @classmethod
    def parse(cls, value):
        host, port = value.rsplit(":", 1)
        return cls(host, int(port))

    def to_tcp(self):
        return f"tcp://{self.host}:{self.port}"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class DistPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {}
        for key, path in policy.PATHS.items():
            url = f"https://raw.githubusercontent.com/sgl-project/sglang/{PIN}/python/sglang/{path}"
            with urlopen(url, timeout=60) as response:
                cls.sources[key] = response.read().decode()
        cls.bootstrap = policy.harden_bootstrap(cls.sources["bootstrap"])
        cls.engine = policy.harden_engine(cls.sources["engine"])

    def test_pinned_source_patches_and_fails_closed_on_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for key, path in policy.PATHS.items():
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(self.sources[key])
            policy.patch(root)
            self.assertEqual(self.bootstrap, (root / policy.PATHS["bootstrap"]).read_text())
            self.assertEqual(self.engine, (root / policy.PATHS["engine"]).read_text())
            with self.assertRaisesRegex(ValueError, "unsupported"):
                policy.patch(root)

    def test_hooks_run_before_listeners_open(self):
        lines = [line.strip() for line in self.bootstrap.splitlines()]
        call = lines.index("dist_init_method = _resolve_dist_init_method(dist_port=dist_port)")
        self.assertEqual("_pin_listeners_to_loopback(dist_port)", lines[call + 1])
        self.assertLess(call, lines.index("_init_parallel_groups("))
        lines = [line.strip() for line in self.engine.splitlines()]
        resolved = lines.index("server_args.resolve_once()")
        self.assertEqual("_refuse_non_local_listeners(resolving_view(server_args))", lines[resolved + 1])
        self.assertLess(resolved, lines.index("port_args = PortArgs.init_new(server_args)"))

    def test_rendezvous_is_loopback_whatever_the_settings(self):
        for host, addr, override in (("0.0.0.0", None, None), ("10.0.0.5", "10.0.0.5:5000", "tcp://0.0.0.0:1")):
            serving = SimpleNamespace(host=host)
            ns = functions(self.bootstrap, "_resolve_dist_init_method", NetworkAddress=NetworkAddress,
                           get_serving=lambda: serving,
                           get_parallel=lambda: SimpleNamespace(dist_init_addr=addr),
                           envs=SimpleNamespace(SGLANG_DISTRIBUTED_INIT_METHOD_OVERRIDE=SimpleNamespace(get=lambda: override)))
            self.assertEqual("tcp://127.0.0.1:23456", ns["_resolve_dist_init_method"](dist_port=23456))

    def test_store_master_listens_on_loopback_only(self):
        stores = []

        class TCPStore:
            def __init__(self, host, port, **kwargs):
                listener = socket.socket(fileno=kwargs.pop("master_listen_fd"))
                stores.append((host, port, listener.getsockname(),
                               listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), kwargs))
                listener.close()

        torch = SimpleNamespace(distributed=SimpleNamespace(TCPStore=TCPStore))
        polluted = {"GLOO_SOCKET_IFNAME": "eth0", "NCCL_SOCKET_IFNAME": "eth0", "NCCL_COMM_ID": "0.0.0.0:1"}
        for tp_rank, pp_rank in ((1, 0), (0, 1), (0, 0)):
            port = free_port()
            ns = functions(self.bootstrap, "_pin_listeners_to_loopback", os=os,
                           get_parallel=lambda: SimpleNamespace(tp_rank=tp_rank, pp_rank=pp_rank))
            with patch.dict(os.environ, polluted), \
                    patch.dict(sys.modules, {"torch": torch, "torch.distributed": torch.distributed}):
                ns["_pin_listeners_to_loopback"](port)
                self.assertEqual("lo", os.environ["GLOO_SOCKET_IFNAME"])
                self.assertEqual("lo", os.environ["NCCL_SOCKET_IFNAME"])
                self.assertNotIn("NCCL_COMM_ID", os.environ)
        self.assertEqual(1, len(stores))
        host, store_port, bound, listening, kwargs = stores[0]
        self.assertEqual(("127.0.0.1", ("127.0.0.1", port), 1), (host, bound, listening))
        self.assertEqual(port, store_port)
        self.assertEqual({"is_master": True, "wait_for_workers": False, "multi_tenant": True}, kwargs)
        self.assertIsNotNone(ns["_LOOPBACK_STORE"])

    def test_launcher_refuses_other_listeners(self):
        safe = dict(nnodes=1, node_rank=0, dist_init_addr=None, gated_launch_port=None,
                    elastic_ep_backend=None, moe_a2a_backend="none", weight_cache_mode="off",
                    remote_instance_weight_loader_start_seed_via_transfer_engine=False)
        unsafe = dict(nnodes=2, node_rank=1, dist_init_addr="10.0.0.5:5000", gated_launch_port=31000,
                      elastic_ep_backend="mooncake", moe_a2a_backend="nixl", weight_cache_mode="daemon",
                      remote_instance_weight_loader_start_seed_via_transfer_engine=True)
        for override in (None, "tcp://0.0.0.0:1"):
            envs = SimpleNamespace(SGLANG_DISTRIBUTED_INIT_METHOD_OVERRIDE=SimpleNamespace(get=lambda o=override: o))
            refuse = functions(self.engine, "_refuse_non_local_listeners", envs=envs)["_refuse_non_local_listeners"]
            if override is None:
                refuse(SimpleNamespace(**safe))
            else:
                with self.assertRaisesRegex(RuntimeError, "single-node"):
                    refuse(SimpleNamespace(**safe))
        envs = SimpleNamespace(SGLANG_DISTRIBUTED_INIT_METHOD_OVERRIDE=SimpleNamespace(get=lambda: None))
        refuse = functions(self.engine, "_refuse_non_local_listeners", envs=envs)["_refuse_non_local_listeners"]
        for field, value in unsafe.items():
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "single-node"):
                refuse(SimpleNamespace(**{**safe, field: value}))
        with self.assertRaisesRegex(RuntimeError, "single-node"):
            refuse(SimpleNamespace(**{**safe, "dist_init_addr": "127.0.0.1:5000"}))


if __name__ == "__main__":
    unittest.main()
