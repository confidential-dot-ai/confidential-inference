#!/usr/bin/env python3
"""Tests of harden_http.py against both pinned SGLang sources.

Downloads only the public pinned source files; never imports SGLang or runs
models or admin handlers. The synthetic ASGI tests need fastapi and httpx and
are skipped without them.
"""
import ast
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from urllib.request import urlopen

try:
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient
    from starlette.responses import StreamingResponse
except ImportError:
    FastAPI = None

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("harden_http", ROOT / "images/sglang/harden_http.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
PINS = {
    "ordinary": ("sgl-project/sglang", "71de97b264b04dcd514cf904003028aefe9775c8"),
    "pd": ("confidential-dot-ai/Sglang-public", "c2425f9b0a274a9f5c3bf91c7af363e94bdbf548"),
}
# Routes declared in http_server.py that stay after hardening. Outside this
# file, /v1/loads (v1_loads_router) and /metrics (--enable-metrics) also stay.
SERVING_ROUTES = {
    "/", "/health", "/health_generate", "/model_info", "/get_model_info", "/server_info",
    "/get_server_info", "/generate", "/encode", "/classify",
    "/parse_function_call", "/separate_reasoning", "/v1/completions", "/v1/chat/completions",
    "/v1/embeddings", "/v1/classify", "/v1/tokenize", "/tokenize", "/v1/detokenize", "/detokenize",
    "/v1/audio/transcriptions", "/v1/realtime", "/v1/models", "/v1/models/{model:path}", "/v1/score",
    "/v1/responses", "/v1/responses/{response_id}", "/v1/responses/{response_id}/cancel",
    "/v1/rerank", "/api/chat", "/api/generate", "/api/tags", "/api/show", "/v1/messages",
    "/v1/messages/count_tokens", "/ping", "/invocations", "/vertex_generate",
}
RETAINED = {
    "ordinary": SERVING_ROUTES | {"/get_load"},
    "pd": SERVING_ROUTES | {"/ready"},
}


def declarations(source):
    return [(node, d) for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            for d in policy.route_decorators(node)]


def route_path(decorator):
    value = decorator.args[0]
    if isinstance(value, ast.Name):  # _ollama_root_route, unset by default
        return "/"
    return value.value if isinstance(value, ast.Constant) else value.args[1].value


DOC_ROUTES = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


def app_doc_kwargs(source):
    """The constant openapi_url, docs_url and redoc_url of the module's FastAPI(...)."""
    call = next(node.value for node in ast.parse(source).body
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and getattr(node.value.func, "id", None) == "FastAPI")
    return {k.arg: k.value.value for k in call.keywords
            if k.arg in ("openapi_url", "docs_url", "redoc_url") and isinstance(k.value, ast.Constant)}


def synthetic_app(source):
    app = FastAPI(**app_doc_kwargs(source))

    async def echo(request: Request):
        payload = await request.body()
        return StreamingResponse(iter([payload, b"\n[DONE]"]), media_type="text/event-stream")

    for node, decorator in declarations(source):
        # Execute the actual retained decorators, but never the worker handlers.
        d = copy.deepcopy(decorator)
        d.keywords = [k for k in d.keywords if k.arg == "methods"]
        expr = ast.Expression(body=d)
        factory = eval(compile(ast.fix_missing_locations(expr), "routes", "eval"), {"app": app, "os": os, "_ollama_root_route": "/"})
        factory(echo)
    return app


class WorkerHTTPPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {}
        for variant, (repo, rev) in PINS.items():
            cls.sources[variant] = {}
            for key, path in (("http", "srt/entrypoints/http_server.py"), ("launch", "launch_server.py")):
                url = f"https://raw.githubusercontent.com/{repo}/{rev}/python/sglang/{path}"
                with urlopen(url, timeout=60) as response:
                    cls.sources[variant][key] = response.read().decode()

    def test_both_pinned_sources_patch_and_fail_closed_on_drift(self):
        for variant, sources in self.sources.items():
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "srt/entrypoints").mkdir(parents=True)
                (root / "srt/entrypoints/http_server.py").write_text(sources["http"])
                (root / "launch_server.py").write_text(sources["launch"])
                policy.patch(root, variant)
                with self.assertRaises(ValueError):
                    policy.patch(root, variant)

    def test_retained_route_inventory(self):
        for variant, sources in self.sources.items():
            with self.subTest(variant=variant):
                hardened = policy.harden_http(sources["http"], variant)
                self.assertEqual(RETAINED[variant], {route_path(d) for _, d in declarations(hardened)})
                self.assertNotIn("app.include_router(elastic_ep_router)", hardened)
                self.assertIn("app.include_router(v1_loads_router)", hardened)
                self.assertEqual({"openapi_url": None, "docs_url": None, "redoc_url": None},
                                 app_doc_kwargs(hardened))

    @unittest.skipIf(FastAPI is None, "needs fastapi and httpx")
    def test_admin_routes_absent_with_or_without_credentials(self):
        for variant, sources in self.sources.items():
            hardened = policy.harden_http(sources["http"], variant)
            denied = {route_path(d) for node, d in declarations(sources["http"])
                      if node.name not in policy.SERVING_HANDLERS}
            denied.update(("/scale_elastic_ep", "/is_scaling_elastic_ep", *DOC_ROUTES))
            self.assertGreater(len(denied), 35)
            self.assertIn("/dumper/{method}", denied)
            self.assertIn("/abort_request", denied)
            with TestClient(synthetic_app(sources["http"])) as client:
                self.assertEqual(client.get("/openapi.json").status_code, 200)
            with TestClient(synthetic_app(hardened)) as client:
                for path in sorted(denied):
                    for method in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
                        for headers in ({}, {"Authorization": "Bearer synthetic-not-a-secret"}):
                            with self.subTest(variant=variant, path=path, method=method, headers=bool(headers)):
                                self.assertEqual(client.request(method, path, headers=headers).status_code, 404)

    @unittest.skipIf(FastAPI is None, "needs fastapi and httpx")
    def test_serving_streams_and_tool_payloads_unchanged(self):
        payload = b'{"stream":true,"tools":[{"type":"function","function":{"name":"synthetic"}}]}'
        for variant, sources in self.sources.items():
            with TestClient(synthetic_app(policy.harden_http(sources["http"], variant))) as client:
                for path in ("/generate", "/v1/chat/completions", "/v1/completions", "/parse_function_call"):
                    response = client.post(path, content=payload)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.content, payload + b"\n[DONE]")
                for path in ("/health", "/health_generate", "/model_info", "/server_info", "/get_server_info"):
                    self.assertEqual(client.get(path).status_code, 200)
                if variant == "pd":
                    self.assertEqual(client.get("/ready").status_code, 200)

    def test_server_info_only_returns_router_fields(self):
        import asyncio
        from types import SimpleNamespace
        for variant, sources in self.sources.items():
            tree = ast.parse(policy.harden_http(sources["http"], variant))
            node = next(n for n in tree.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "server_info")
            node.decorator_list = []
            info = {key: 1 for key in policy.SERVER_INFO_FIELDS}
            info.update(api_key="synthetic", launch_command="synthetic", internal_states=["synthetic"])
            namespace = {
                "_global_state": SimpleNamespace(tokenizer_manager=SimpleNamespace(server_args=object()), scheduler_info={}),
                "__version__": "test", "build_server_info": lambda *args: info,
                "dataclasses": SimpleNamespace(asdict=lambda _: info),
            }
            exec(compile(ast.Module(body=[node], type_ignores=[]), "server_info", "exec"), namespace)
            result = asyncio.run(namespace["server_info"]())
            self.assertEqual(set(result), set(policy.SERVER_INFO_FIELDS))

    def test_alternate_frontends_are_rejected_before_launch(self):
        from types import SimpleNamespace
        import sys
        from unittest.mock import patch
        for sources in self.sources.values():
            tree = ast.parse(policy.harden_launcher(sources["launch"]))
            run = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_server")
            namespace = {}
            exec(compile(ast.Module(body=[run], type_ignores=[]), "launcher", "exec"), namespace)
            fields = dict.fromkeys(("encoder_only", "smg_grpc_mode", "grpc_mode", "grpc_port", "use_ray"), False)
            for field in (*fields, "SGLANG_RUST_SERVER", "SGLANG_GRPC_PORT", "DUMPER_SERVER_PORT"):
                envs = SimpleNamespace(**{name: SimpleNamespace(get=lambda n=name: n == field)
                                         for name in ("SGLANG_RUST_SERVER", "SGLANG_GRPC_PORT")})
                args = SimpleNamespace(**{k: k == field for k in fields})
                environ = {"DUMPER_SERVER_PORT": "reuse"} if field == "DUMPER_SERVER_PORT" else {}
                with patch.dict(sys.modules, {"sglang.srt.environ": SimpleNamespace(envs=envs)}), \
                        patch.dict(os.environ, environ):
                    with self.assertRaisesRegex(RuntimeError, "hardened Python HTTP"):
                        namespace["run_server"](args)


if __name__ == "__main__":
    unittest.main()
