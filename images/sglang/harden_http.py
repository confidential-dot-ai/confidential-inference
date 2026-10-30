#!/usr/bin/env python3
"""Build-time serving-only HTTP policy for the two pinned SGLang workers.

No runtime switch or credential can restore removed registrations. Source hashes
make upstream changes require another review, including newly included routers.
"""
import argparse
import ast
import hashlib
from pathlib import Path

SOURCE_HASHES = {'ordinary': {'http': '305a02a9238b62da90c9dc90ecbbdc0811ba7725f13056677e3ed7dbbfc81d4e', 'launch': '52a96e6b5b8d9372da3a81c7b02de810dad7958e4dbb92a55c7f2ac03cf9e81c'}, 'pd': {'http': 'fbaa29e4ac7ca7ac9f455dcc7690b1b1aa4da627dd2122c6d7b132f9d6bd3928', 'launch': '374976475a62ee53a3f32454bf17071eb9b18bab7ed293390e2c765e3669a7a2'}}

SERVING_HANDLERS = frozenset(['health_generate', 'ready', 'get_model_info', 'model_info', 'get_server_info', 'server_info', 'get_load', 'generate_request', 'encode_request', 'classify_request', 'parse_function_call_request', 'separate_reasoning_request', 'openai_v1_completions', 'openai_v1_chat_completions', 'openai_v1_embeddings', 'openai_v1_classify', 'openai_v1_tokenize', 'openai_v1_detokenize', 'openai_v1_audio_transcriptions', 'openai_v1_realtime_transcription', 'available_models', 'retrieve_model', 'v1_score_request', 'v1_responses_request', 'v1_retrieve_responses', 'v1_cancel_responses', 'v1_rerank_request', 'ollama_chat', 'ollama_generate', 'ollama_tags', 'ollama_show', 'anthropic_v1_messages', 'anthropic_v1_count_tokens', 'sagemaker_health', 'sagemaker_chat_completions', 'vertex_generate', 'sglang_root', 'ollama_root'])

SERVER_INFO_FIELDS = (
    "model_id", "model_path", "served_model_name", "tp_size", "dp_size",
    "attn_dp_size", "load_balance_method", "disaggregation_mode", "version",
    "max_batch_size", "max_total_tokens", "max_prefill_tokens",
    "max_running_requests", "max_num_reqs",
)


def route_decorators(node):
    return [d for d in node.decorator_list
            if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
            and isinstance(d.func.value, ast.Name) and d.func.value.id == "app"
            and d.func.attr != "exception_handler"]


def apply_edits(source, edits):
    lines = source.splitlines(keepends=True)
    for start, end, replacement in sorted(edits, reverse=True):
        lines[start - 1:end] = [replacement]
    result = "".join(lines)
    compile(result, "hardened_worker", "exec")
    return result


def harden_http(source, variant):
    edits = []
    # Walk the whole module: some routes are registered inside env-gated `if`
    # blocks (for example /dumper/{method} with DUMPER_SERVER_PORT=reuse).
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in route_decorators(node):
                if node.name not in SERVING_HANDLERS:
                    edits.append((decorator.lineno, decorator.end_lineno, ""))
            if node.name == "server_info":
                # Do not serialize launch argv, credentials or live internal state.
                config = ("build_server_info(server_args, _global_state.scheduler_info)"
                          if variant == "pd" else
                          "{**dataclasses.asdict(server_args), **_global_state.scheduler_info}")
                body = (
                    "    server_args = _global_state.tokenizer_manager.server_args\n"
                    f"    info = {config}\n"
                    "    info['version'] = __version__\n"
                    f"    return {{key: info[key] for key in {SERVER_INFO_FIELDS!r} if key in info}}\n"
                )
                edits.append((node.body[0].lineno, node.end_lineno, body))
    marker = "app.include_router(elastic_ep_router)"
    if source.count(marker) != 1:
        raise ValueError("unsupported elastic router registration")
    result = apply_edits(source, edits).replace(marker, "# Administrative elastic EP router is not exposed.")
    # FastAPI's /openapi.json, /docs, /docs/oauth2-redirect and /redoc.
    docs = '    openapi_url=None if get_bool_env_var("DISABLE_OPENAPI_DOC") else "/openapi.json",\n'
    if result.count(docs) != 1:
        raise ValueError("unsupported FastAPI app construction")
    result = result.replace(docs, "    openapi_url=None,\n    docs_url=None,\n    redoc_url=None,\n")
    compile(result, "hardened_worker", "exec")
    return result


def harden_launcher(source):
    tree = ast.parse(source)
    run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_server")
    # These images deploy only the Python HTTP frontend. Alternate listeners
    # have separate route tables and must not bypass this policy.
    # DUMPER_SERVER_PORT starts the debug dumper's own HTTP listener.
    guard = (
        "    import os\n"
        "    from sglang.srt.environ import envs\n"
        "    if (envs.SGLANG_RUST_SERVER.get() or server_args.encoder_only\n"
        "            or server_args.smg_grpc_mode or server_args.grpc_mode\n"
        "            or server_args.grpc_port or envs.SGLANG_GRPC_PORT.get() or server_args.use_ray\n"
        "            or 'DUMPER_SERVER_PORT' in os.environ):\n"
        "        raise RuntimeError('This image supports only the hardened Python HTTP frontend')\n"
    )
    insert = run.body[1].lineno
    return apply_edits(source, [(insert, insert - 1, guard)])


def patch(root, variant):
    paths = {"http": root / "srt/entrypoints/http_server.py", "launch": root / "launch_server.py"}
    sources = {key: path.read_text() for key, path in paths.items()}
    for key, source in sources.items():
        if hashlib.sha256(source.encode()).hexdigest() != SOURCE_HASHES[variant][key]:
            raise ValueError(f"unsupported {variant} {key} source; review HTTP policy before building")
    results = {"http": harden_http(sources["http"], variant), "launch": harden_launcher(sources["launch"])}
    for key, result in results.items():
        paths[key].write_text(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="sglang Python package directory")
    parser.add_argument("--variant", choices=SOURCE_HASHES, required=True)
    args = parser.parse_args()
    patch(args.root, args.variant)
