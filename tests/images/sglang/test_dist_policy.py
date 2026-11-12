#!/usr/bin/env python3
"""Tests of harden_dist.py against the pinned SGLang source.

Downloads only the public pinned source files and runs the patched functions
with stubs; never imports SGLang or torch.
"""
import ast
import importlib.util
import json
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
FORK = json.loads((ROOT / "tests/images/sglang/fixtures/legacy-diagnostics/source.lock").read_text())["source"]
PINS = {
    "release": ("sgl-project/sglang", "a7fd2e1158c389c33077bae67fb797efa8dd09bd"),
    "diagnostic-fork": (FORK["repository"].removeprefix("https://github.com/"), FORK["commit"]),
}


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


def method(source, cls, name, **namespace):
    tree = ast.parse(source)
    body = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls).body
    node = next(n for n in body if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), "patched", "exec"), namespace)
    return namespace[name]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class DistPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.trees = {}
        for variant, (repo, rev) in PINS.items():
            cls.trees[variant] = {}
            for key, path in policy.PATHS.items():
                url = f"https://raw.githubusercontent.com/{repo}/{rev}/python/sglang/{path}"
                with urlopen(url, timeout=60) as response:
                    cls.trees[variant][key] = response.read().decode()
        cls.sources = cls.trees["release"]
        cls.bootstrap = policy.harden_bootstrap(cls.sources["bootstrap"])
        cls.engine = policy.harden_engine(cls.sources["engine"])
        cls.network = policy.harden_network(cls.sources["network"])
        cls.disagg_service = policy.harden_text("disagg_service", cls.sources["disagg_service"])
        cls.decode = policy.harden_text("decode", cls.sources["decode"])
        cls.conn = policy.harden_text("conn", cls.sources["conn"])

    def test_pinned_sources_patch_and_fail_closed_on_drift(self):
        self.assertEqual(set(PINS), set(policy.SOURCE_HASHES))
        for variant, sources in self.trees.items():
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for key, path in policy.PATHS.items():
                    (root / path).parent.mkdir(parents=True, exist_ok=True)
                    (root / path).write_text(sources[key])
                policy.patch(root)
                for key, path in policy.PATHS.items():
                    self.assertNotEqual(sources[key], (root / path).read_text(), key)
                if variant == "release":
                    for key in policy.PATHS:
                        self.assertEqual(getattr(self, key), (root / policy.PATHS[key]).read_text())
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
        polluted = {"GLOO_SOCKET_IFNAME": "eth0", "NCCL_SOCKET_IFNAME": "eth0", "NCCL_COMM_ID": "0.0.0.0:1",
                    "NCCL_RAS_ENABLE": "1"}
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
                self.assertEqual("0", os.environ["NCCL_RAS_ENABLE"])
        self.assertEqual(1, len(stores))
        host, store_port, bound, listening, kwargs = stores[0]
        self.assertEqual(("127.0.0.1", ("127.0.0.1", port), 1), (host, bound, listening))
        self.assertEqual(port, store_port)
        self.assertEqual({"is_master": True, "wait_for_workers": False, "multi_tenant": True}, kwargs)
        self.assertIsNotNone(ns["_LOOPBACK_STORE"])

    def test_launcher_refuses_other_listeners(self):
        safe = dict(nnodes=1, node_rank=0, dist_init_addr=None, gated_launch_port=None,
                    elastic_ep_backend=None, moe_a2a_backend="none", weight_cache_mode="off",
                    remote_instance_weight_loader_start_seed_via_transfer_engine=False,
                    kv_events_config=None, forward_pass_metrics_ipc_name=None)
        unsafe = dict(nnodes=2, node_rank=1, dist_init_addr="10.0.0.5:5000", gated_launch_port=31000,
                      elastic_ep_backend="mooncake", moe_a2a_backend="nixl", weight_cache_mode="daemon",
                      remote_instance_weight_loader_start_seed_via_transfer_engine=True,
                      kv_events_config='{"publisher": "zmq"}', forward_pass_metrics_ipc_name="tcp://0.0.0.0:1")
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

    def test_kv_bootstrap_is_loopback_whatever_the_request(self):
        servers = []
        mode = type("DisaggregationMode", (str,), {"PREFILL": "prefill", "NULL": "null"})
        ns = functions(self.disagg_service, "start_disagg_service", DisaggregationMode=mode, TransferBackend=str,
                       get_disagg=lambda: SimpleNamespace(disaggregation_mode="prefill",
                                                          disaggregation_transfer_backend="mooncake",
                                                          enable_pd_role_switch=False,
                                                          disaggregation_bootstrap_port=8999),
                       get_serving=lambda: SimpleNamespace(host="0.0.0.0"),
                       get_kv_class=lambda *_: lambda **kwargs: servers.append(kwargs),
                       KVClassType=SimpleNamespace(BOOTSTRAP_SERVER=None),
                       maybe_create_ascend_config_store=lambda **_: None)
        ns["start_disagg_service"]()
        self.assertEqual([{"host": "127.0.0.1", "port": 8999}], servers)

        class Address(NetworkAddress):
            def to_host_port_str(self):
                return f"{self.host}:{self.port}"

        decode = functions(self.decode, "_bootstrap_addr", NetworkAddress=Address, Req=object)["_bootstrap_addr"]
        for host in ("10.0.0.5", "attacker.example", None):
            request = SimpleNamespace(bootstrap_host=host, bootstrap_port=8999)
            self.assertEqual("127.0.0.1:8999", decode(request))

    def test_prefill_registers_on_loopback_whatever_the_host(self):
        class Address(NetworkAddress):
            def to_url(self):
                return f"http://{self.host}:{self.port}"

        for variant, sources in self.trees.items():
            urls = []
            register = method(policy.harden_text("conn", sources["conn"]), "CommonKVManager",
                              "register_to_bootstrap", NetworkAddress=Address,
                              get_parallel=lambda: SimpleNamespace(enable_cp_tp_group_sharing=False,
                                                                   load_balance_method="round_robin",
                                                                   enable_dsa_cache_layer_split=False),
                              get_serving=lambda: SimpleNamespace(port=30000),
                              get_disagg=lambda: SimpleNamespace(disaggregation_decode_allocation_policy=None),
                              envs=SimpleNamespace(SGLANG_RUST_SERVER=SimpleNamespace(get=lambda: False)))
            for host in ("0.0.0.0", "::", "10.0.0.5"):
                manager = SimpleNamespace(
                    dist_init_addr=None, bootstrap_host=host, bootstrap_port=8999, kv_args=SimpleNamespace(page_size=1),
                    _register_topology_row=lambda url, payload: urls.append(url), **dict.fromkeys(
                        ("attn_tp_size", "attn_tp_rank", "attn_cp_size", "attn_cp_rank", "attn_dp_size",
                         "attn_dp_rank", "pp_size", "pp_rank", "system_dp_size", "system_dp_rank", "local_ip",
                         "rank_port", "kv_cache_dtype_str", "dsv41_spec_layout"), 0))
                register(manager)
            self.assertEqual(["http://127.0.0.1:8999/route"] * 3, urls, variant)

    def test_local_ip_and_port_reservations_are_loopback(self):
        ns = functions(self.network, "get_local_ip_auto", "bind_port", "try_bind_socket", "_get_addrinfos_for_bind",
                       socket=socket, os=os, logger=SimpleNamespace(debug=print, warning=print))
        with patch.dict(os.environ, {"SGLANG_HOST_IP": "10.0.0.5", "HOST_IP": "10.0.0.5"}):
            self.assertEqual("127.0.0.1", ns["get_local_ip_auto"]())
            self.assertEqual("127.0.0.1", ns["get_local_ip_auto"]("0.0.0.0"))
        port = free_port()
        with ns["bind_port"](port) as reserved:
            self.assertEqual(("127.0.0.1", port), reserved.getsockname())
            self.assertEqual(1, reserved.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))
            with socket.socket() as wildcard, self.assertRaises(OSError):
                wildcard.bind(("0.0.0.0", port))


if __name__ == "__main__":
    unittest.main()
