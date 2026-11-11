#!/usr/bin/env python3
"""Build-time loopback-only distributed runtime for the pinned SGLang worker.

The torch.distributed store, gloo and NCCL bootstrap listen on loopback only,
whatever --host, --dist-init-addr or the environment say. Components that bind
or advertise the local IP get 127.0.0.1. The prefill/decode KV bootstrap
server listens on loopback, and decode reaches it on loopback whatever host a
request names: every chart layout runs prefill and decode in one pod. The
launcher refuses multi-node and other settings that open further internal
listeners.
"""
import argparse
import ast
import hashlib
from pathlib import Path

SOURCE_HASHES = {
    "bootstrap": "fc31071a2e6d56b865f8e15b416f3261016583bcd7e55c483f6731215c39a676",
    "engine": "059c29dabd318a2766024ae8cd62d82e4f4c95bd67ebd9aa346ee8ddd6ad5423",
    "network": "335811df5b7125ffa02dd12a206c3f42977b35091fe83618db4b511ad1ad1968",
    "disagg_service": "899392c361d227963544aa805a593fa633c1efca9e1cc7779a957815883f4339",
    "decode": "87c66385b11ac194ea749621b17e9bf134aa7bcd4007d20444445d27708839f7",
}
PATHS = {"bootstrap": "srt/distributed/bootstrap.py", "engine": "srt/entrypoints/engine.py",
         "network": "srt/utils/network.py", "disagg_service": "srt/managers/disagg_service.py",
         "decode": "srt/disaggregation/decode.py"}

RESOLVE = '    return NetworkAddress("127.0.0.1", dist_port).to_tcp()\n'
PIN_CALL = "    _pin_listeners_to_loopback(dist_port)\n"
PIN = '''

_LOOPBACK_STORE = None


def _pin_listeners_to_loopback(dist_port: int) -> None:
    # Assigned, not defaulted: no pod setting moves these listeners off loopback.
    os.environ["GLOO_SOCKET_IFNAME"] = "lo"
    os.environ["NCCL_SOCKET_IFNAME"] = "lo"
    os.environ.pop("NCCL_COMM_ID", None)
    os.environ["NCCL_RAS_ENABLE"] = "0"
    parallel = get_parallel()
    if parallel.tp_rank or parallel.pp_rank:
        return
    import socket

    from torch.distributed import TCPStore

    global _LOOPBACK_STORE
    # A torch store master binds every interface. Hand it a loopback socket;
    # this module reference keeps the server cached for the tcp:// rendezvous.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", dist_port))
    sock.listen(socket.SOMAXCONN)
    _LOOPBACK_STORE = TCPStore(
        "127.0.0.1", dist_port, is_master=True, wait_for_workers=False,
        multi_tenant=True, master_listen_fd=sock.detach(),
    )
'''
REFUSE_CALL = "        _refuse_non_local_listeners(resolving_view(server_args))\n"
REFUSE = '''

def _refuse_non_local_listeners(cfg) -> None:
    if (cfg.nnodes != 1 or cfg.node_rank or cfg.dist_init_addr
            or envs.SGLANG_DISTRIBUTED_INIT_METHOD_OVERRIDE.get()
            or cfg.gated_launch_port or cfg.elastic_ep_backend
            or cfg.moe_a2a_backend == "nixl" or cfg.weight_cache_mode == "daemon"
            or cfg.remote_instance_weight_loader_start_seed_via_transfer_engine
            or cfg.kv_events_config or cfg.forward_pass_metrics_ipc_name):
        raise RuntimeError("This image supports only a single-node worker with loopback internal listeners")
'''

LOCAL_IP = '    return "127.0.0.1"\n'
BIND_PORT = '    return try_bind_socket("127.0.0.1", port, listen=True)\n'
# Exact (old, new) text edits; each old text occurs once in the pinned source.
TEXT_EDITS = {
    "disagg_service": [("            host=get_serving().host,\n", '            host="127.0.0.1",\n')],
    "decode": [("    return NetworkAddress(req.bootstrap_host, req.bootstrap_port).to_host_port_str()\n",
                '    return NetworkAddress("127.0.0.1", req.bootstrap_port).to_host_port_str()\n')],
}


def function(tree, name):
    matches = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(matches) != 1:
        raise ValueError(f"unsupported source: {name}")
    return matches[0]


def statement_line(node, text):
    lines = [s.lineno for s in ast.walk(node) if isinstance(s, ast.stmt) and ast.unparse(s) == text]
    if len(lines) != 1:
        raise ValueError(f"unsupported source: {text}")
    return lines[0]


def body(node):
    """Line span of a function body after its docstring."""
    doc = node.body[0]
    if not (isinstance(doc, ast.Expr) and isinstance(doc.value, ast.Constant)
            and len(node.body) > 1 and doc.lineno > node.lineno):
        raise ValueError(f"unsupported source: {node.name}")
    return doc.end_lineno + 1, node.end_lineno


def splice(source, start, end, replacement):
    """Replace 1-based lines start..end (end = start - 1 inserts before start)."""
    lines = source.splitlines(keepends=True)
    lines[start - 1:end] = [replacement]
    return "".join(lines)


def harden_bootstrap(source):
    tree = ast.parse(source)
    resolve = function(tree, "_resolve_dist_init_method")
    if resolve.body[0].lineno <= resolve.lineno or not source.splitlines()[resolve.lineno - 1].endswith(":"):
        raise ValueError("unsupported source: _resolve_dist_init_method")
    call = statement_line(function(tree, "init_parallel_runtime"),
                          "dist_init_method = _resolve_dist_init_method(dist_port=dist_port)")
    if call > resolve.lineno:
        raise ValueError("unsupported source: init_parallel_runtime order")
    result = splice(source, resolve.lineno + 1, resolve.end_lineno, RESOLVE)
    result = splice(result, call + 1, call, PIN_CALL) + PIN
    compile(result, "hardened_bootstrap", "exec")
    return result


def harden_engine(source):
    tree = ast.parse(source)
    line = statement_line(function(tree, "_launch_subprocesses"), "server_args.resolve_once()")
    result = splice(source, line + 1, line, REFUSE_CALL) + REFUSE
    compile(result, "hardened_engine", "exec")
    return result


def harden_network(source):
    tree = ast.parse(source)
    spans = sorted(((*body(function(tree, name)), text)
                    for name, text in (("get_local_ip_auto", LOCAL_IP), ("bind_port", BIND_PORT))),
                   reverse=True)
    for start, end, text in spans:
        source = splice(source, start, end, text)
    compile(source, "hardened_network", "exec")
    return source


def harden_text(key, source):
    for old, new in TEXT_EDITS[key]:
        if source.count(old) != 1:
            raise ValueError(f"unsupported source: {key}")
        source = source.replace(old, new)
    compile(source, f"hardened_{key}", "exec")
    return source


def patch(root):
    paths = {key: root / path for key, path in PATHS.items()}
    sources = {key: path.read_text() for key, path in paths.items()}
    for key, source in sources.items():
        if hashlib.sha256(source.encode()).hexdigest() != SOURCE_HASHES[key]:
            raise ValueError(f"unsupported {key} source; review the listener policy before building")
    results = {"bootstrap": harden_bootstrap(sources["bootstrap"]), "engine": harden_engine(sources["engine"]),
               "network": harden_network(sources["network"]),
               **{key: harden_text(key, sources[key]) for key in TEXT_EDITS}}
    for key, result in results.items():
        paths[key].write_text(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="sglang Python package directory")
    patch(parser.parse_args().root)
