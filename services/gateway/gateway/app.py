"""HTTP routes and lifetime of inference resources."""

import asyncio
import uuid
import os
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import get_context

import aiohttp
import orjson
from aiohttp import web

from .limits import Admission, Body, Rejected
from .proxy import Output, Routing, prepare_buffer


def json_response(value, status=200, headers=None):
    return web.Response(body=orjson.dumps(value), status=status, content_type="application/json", headers=headers)


def error_response(error, admin=False):
    message = "The admin request is not authorized." if admin and error.status == 401 else "Request failed."
    value = {"code": error.code, "message": message}
    headers = {"Retry-After": str(error.retry), "Cache-Control": "no-store"} if error.retry else None
    return json_response(value if admin else {"error": value}, error.status, headers)


@web.middleware
async def errors(request, handler):
    try:
        return await handler(request)
    except Rejected as error:
        return error_response(error, request.path.startswith("/admin/"))
    except (ConnectionError, asyncio.CancelledError):
        raise
    except Exception:
        return error_response(Rejected(500, "internal_error"))


async def inference(request):
    config, keys, admission, routing = (request.app[k] for k in ("config", "keys", "admission", "routing"))
    identifier = keys.authenticate(request.headers.get("Authorization", ""))
    keys.limits.admit(identifier)
    declared = request.content_length
    if declared is not None and declared > config.maximum_body:
        raise Rejected(413, "request_too_large")
    held = await admission.memory.reserve(4 * (declared if declared is not None else config.maximum_body) + 65536, config.queue_timeout)
    request_id = str(uuid.uuid4())
    try:
        body = Body(config.maximum_body)
        async with asyncio.timeout(config.body_timeout):
            async for chunk in request.content.iter_chunked(262_144):
                if body.length + len(chunk) > config.maximum_body:
                    raise Rejected(413, "request_too_large")
                body.append(chunk)
                await asyncio.sleep(0)
            if declared is not None and body.length != declared:
                raise Rejected(400, "request_body_failed")
        concurrent = request.app["parsers"].submit(prepare_buffer, os.getpid(), body.fd, body.length, body.capacity,
            request.path, identifier, request.headers.get("X-SMG-Routing-Key"), config, routing)
        pending = asyncio.wrap_future(concurrent)
        try:
            length, model, affinity, hidden = await asyncio.shield(pending)
        except asyncio.CancelledError:
            if not concurrent.cancel():
                try:
                    await asyncio.shield(pending)
                except Exception:
                    pass
            raise
        body.length = length
        held = await admission.memory.resize(held, length)
        async with admission.inference(identifier):
            headers = {"Content-Type": "application/json", "Content-Length": str(body.length), "x-request-id": request_id}
            if affinity:
                headers["x-smg-routing-key"] = affinity
            try:
                async with asyncio.timeout(config.upstream_timeout):
                    async with request.app["http"].post(config.upstream.rstrip("/") + request.path, data=body_chunks(body), headers=headers, allow_redirects=False) as upstream:
                        if body.sent:
                            body.close()
                            body = None
                            await admission.memory.release(held)
                            held = 0
                        if upstream.status == 503:
                            raise Rejected(503, "inference_unavailable", 30)
                        if not 200 <= upstream.status < 300:
                            codes = {400: "invalid_request", 422: "invalid_request", 404: "not_found", 408: "request_timeout", 413: "request_too_large", 429: "rate_limited"}
                            code = codes.get(upstream.status, "request_rejected" if 400 <= upstream.status < 500 else "inference_error")
                            return error_response(Rejected(upstream.status, code))
                        content_type = upstream.headers.get("Content-Type", "")
                        stream = content_type.startswith("text/event-stream")
                        rewrite = stream or content_type.startswith("application/json")
                        output = Output(model, stream, hidden)
                        response_headers = {"x-request-id": request.headers.get("x-request-id", request_id), "x-ci-request-id": request_id}
                        if content_type:
                            response_headers["Content-Type"] = content_type
                        response = web.StreamResponse(status=upstream.status, headers=response_headers)
                        await response.prepare(request)
                        iterator, timeout = upstream.content.iter_any().__aiter__(), config.first_timeout
                        try:
                            while True:
                                try:
                                    async with asyncio.timeout(timeout):
                                        chunk = await anext(iterator)
                                except StopAsyncIteration:
                                    break
                                timeout = config.idle_timeout
                                value = output.push(chunk) if rewrite else chunk
                                if value:
                                    await response.write(value)
                            final = output.finish() if rewrite else b""
                            if final:
                                await response.write(final)
                            await response.write_eof()
                        except (ValueError, TimeoutError, aiohttp.ClientError, ConnectionError):
                            if request.transport:
                                request.transport.close()
                        return response
            except (aiohttp.ClientError, OSError) as error:
                raise Rejected(503, "inference_unavailable", 30) from error
    except TimeoutError as error:
        raise Rejected(408, "request_body_timeout") from error
    finally:
        if "body" in locals() and body is not None:
            body.close()
        if held:
            await admission.memory.release(held)


async def health(request):
    return json_response({"status": "ok"})


async def ready(request):
    if request.app["keys"].revision is None:
        return json_response({"status": "key_registry_not_ready"}, 503)
    return json_response({"status": "ready"})


async def models(request):
    return json_response({"object": "list", "data": [{"id": model, "object": "model", "owned_by": "confidential.ai"} for model in request.app["config"].catalog]})


async def admin(request):
    body = bytearray()
    async for chunk in request.content.iter_chunked(65536):
        if len(body) + len(chunk) > 1_048_576:
            raise Rejected(401, "invalid_body")
        body.extend(chunk)
    request.app["admin_auth"].verify(request, body)
    store = request.app["keys"]
    if request.path.endswith("/health"):
        return json_response({"status": "ready" if store.revision else "key_registry_not_ready", "cachedRevision": store.revision})
    if request.path.endswith("/source"):
        return json_response(store.status())
    try:
        snapshot = orjson.loads(body)
    except ValueError as error:
        raise Rejected(400, "invalid_request") from error
    return json_response(store.apply(snapshot))


async def body_chunks(body):
    size = body.length
    for start in range(0, size, 262_144):
        end = min(start + 262_144, size)
        chunk = body.mapping[start:end]
        if end == size:
            body.sent = True
        yield chunk
        await asyncio.sleep(0)


async def session(app):
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=10)
    connector = aiohttp.TCPConnector(limit=0, limit_per_host=0)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector, auto_decompress=False) as client:
        app["http"] = client
        with ProcessPoolExecutor(max_workers=6, mp_context=get_context("spawn")) as parsers:
            app["parsers"] = parsers
            await asyncio.gather(*(asyncio.get_running_loop().run_in_executor(parsers, os.getpid) for _ in range(6)))
            yield


def create_app(config, keys, admin_auth):
    app = web.Application(middlewares=[errors], client_max_size=64 * 1024**2)
    app.update(config=config, keys=keys, admin_auth=admin_auth, admission=Admission(config), routing=Routing())
    app.cleanup_ctx.append(session)
    app.add_routes([web.get("/health", health), web.get("/ready", ready), web.get("/v1/models", models)])
    for route in ("/v1/chat/completions", "/v1/completions", "/v1/responses"):
        app.router.add_post(route, inference)
    app.add_routes([web.get("/admin/v1/health", admin), web.get("/admin/v1/api-keys/source", admin), web.put("/admin/v1/api-keys/snapshot", admin)])
    return app
