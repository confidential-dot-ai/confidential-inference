"""HTTP routes and lifetime of inference resources."""

import asyncio
import os
import re
import time
import uuid
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from contextlib import ExitStack, asynccontextmanager
from multiprocessing import get_context
from urllib.parse import urlsplit

import aiohttp
import orjson
from aiohttp import web

from .limits import Admission, Body, Public, Rejected
from .proxy import (
    Output,
    Routing,
    clear_buffer,
    inspect_buffer,
    prepare,
    prepare_buffer,
)
from .telemetry import Audit, Metrics, StreamTiming
from .usage import AdminClient, Recorder

ADMIN_ROUTES = (
    "/admin/v1/health",
    "/admin/v1/api-keys/source",
    "/admin/v1/api-keys/snapshot",
)
INLINE_BODY_BYTES = 65536


def json_response(value, status=200, headers=None):
    return web.Response(
        body=orjson.dumps(value),
        status=status,
        content_type="application/json",
        headers=headers,
    )


def error_response(error, admin=False):
    message = (
        "The admin request is not authorized."
        if admin and error.status == 401
        else "Request failed."
    )
    value = {"code": error.code, "message": message}
    headers = (
        {"Retry-After": str(error.retry), "Cache-Control": "no-store"}
        if error.retry
        else None
    )
    return json_response(value if admin else {"error": value}, error.status, headers)


@web.middleware
async def errors(request, handler):
    admin_path = request.path in ADMIN_ROUTES
    release = None
    if not admin_path:
        request["request_id"] = str(uuid.uuid4())
        caller = request.headers.get("x-request-id", "")
        request["response_id"] = (
            caller
            if re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", caller)
            else str(uuid.uuid4())
        )
    try:
        if not admin_path:
            release = request["release_public"] = request.app["public"].enter(request)
            if (
                request.content_length is not None
                and request.content_length > 64 * 1024**2
            ):
                raise Rejected(413, "request_too_large")
            if request.method == "OPTIONS":
                return web.Response()
        return await handler(request)
    except Rejected as error:
        if not admin_path:
            request.app["metrics"].inc(
                "gateway_rejections",
                reason=error.code,
                key_id=request.get("key_id", ""),
            )
        return error_response(error, admin_path)
    except web.HTTPException as error:
        return error_response(
            Rejected(
                error.status, "not_found" if error.status == 404 else "request_rejected"
            ),
            admin_path,
        )
    except (ConnectionError, asyncio.CancelledError):
        raise
    except Exception:
        return error_response(Rejected(500, "internal_error"))
    finally:
        if release:
            release()


async def response_headers(request, response):
    if request.path in ADMIN_ROUTES:
        return
    release = request.get("release_public")
    if release:
        release()
    response.headers["x-request-id"] = request["response_id"]
    response.headers["x-ci-request-id"] = request["request_id"]
    if request.app["config"].instance:
        response.headers["x-confidential-gateway"] = request.app["config"].instance
    response.headers["Access-Control-Allow-Origin"] = "*"
    if request.method == "OPTIONS":
        response.headers["Access-Control-Allow-Methods"] = "GET,POST"
        response.headers["Access-Control-Allow-Headers"] = (
            "authorization,content-type,accept,x-smg-routing-key"
        )
    else:
        response.headers["Access-Control-Expose-Headers"] = "x-ci-request-id"
    if request.get("audit"):
        request.app["audit"].record(
            request["request_id"], request.path, response.status, request.get("key_id")
        )
        if "model" in request:
            metrics = request.app["metrics"]
            metrics.inc(
                "gateway_requests",
                model=request["model"],
                key_id=request["key_id"],
                status=response.status,
            )
            metrics.observe(
                "gateway_request_duration",
                time.monotonic() - request["started"],
                model=request["model"],
                status=response.status,
            )


async def inference(request):
    config, keys, admission, routing, metrics = (
        request.app[k] for k in ("config", "keys", "admission", "routing", "metrics")
    )
    identifier = request["key_id"] = keys.authenticate(
        request.headers.get("Authorization", "")
    )
    keys.limits.admit(identifier)
    request["started"] = time.monotonic()
    declared = request.content_length
    if declared is not None and declared > config.maximum_body:
        raise Rejected(413, "request_too_large")
    factor = 64 if declared is not None and declared <= INLINE_BODY_BYTES else 4
    held = await admission.memory.reserve(
        factor * (declared if declared is not None else config.maximum_body) + 65536,
        config.queue_timeout,
    )
    body, usage = None, None
    router = urlsplit(config.upstream).hostname or "fixed-router"
    metrics.inc("gateway_router_requests_active", router=router)
    try:
        body = Body(config.maximum_body)
        try:
            async with asyncio.timeout(config.body_timeout):
                async for chunk in request.content.iter_chunked(262_144):
                    if body.length + len(chunk) > config.maximum_body:
                        raise Rejected(413, "request_too_large")
                    body.append(chunk)
                    await asyncio.sleep(0)
                if declared is not None and body.length != declared:
                    raise Rejected(400, "request_body_failed")
        except TimeoutError as error:
            raise Rejected(408, "request_body_timeout") from error
        request["body_complete"] = time.monotonic()
        request["body_size"] = "small" if body.length <= INLINE_BODY_BYTES else "large"
        if body.length <= INLINE_BODY_BYTES:
            raw = body.mapping[: body.length]
            outgoing, model, affinity, hidden = prepare(
                raw,
                request.path,
                identifier,
                request.headers.get("X-SMG-Routing-Key"),
                config,
                routing,
            )
            if len(outgoing) > body.capacity:
                body.mapping.resize(len(outgoing))
                body.capacity = len(outgoing)
            if outgoing is not raw:
                body.mapping[: len(outgoing)] = outgoing
            length = len(outgoing)
        else:
            shared = os.getpid(), body.fd, body.length, body.capacity
            async with parsing_worker(request.app) as executor:
                held = await admission.memory.resize(held, 12 * body.length + 65536)
                cost = await parser_call(
                    executor, inspect_buffer, *shared, config.body_memory
                )
                held = await admission.memory.resize(held, cost)
                length, model, affinity, hidden = await parser_call(
                    executor,
                    prepare_buffer,
                    *shared,
                    request.path,
                    identifier,
                    request.headers.get("X-SMG-Routing-Key"),
                    config,
                    routing,
                )
            if length > body.capacity:
                body.mapping.resize(length)
                body.capacity = length
        body.length = length
        held = await admission.memory.resize(held, length)
        request["model"] = model
        if request.app["usage"] is not None:
            usage = request.app["usage"].begin(identifier, model)

        async def release_body():
            nonlocal held, body
            if body is not None and body.sent:
                body.close()
                body = None
                await admission.memory.release(held)
                held = 0

        queued = time.monotonic()
        metrics.inc("gateway_inference_queue_depth")
        try:
            async with admission.inference(identifier):
                metrics.inc("gateway_inference_queue_depth", -1)
                metrics.observe("gateway_queue_duration", time.monotonic() - queued)
                queued = None
                metrics.inc("gateway_inference_active")
                try:
                    return await forward(
                        request, body, model, affinity, hidden, usage, release_body
                    )
                finally:
                    metrics.inc("gateway_inference_active", -1)
        except Rejected:
            if usage:
                usage.finish("failed")
            raise
        finally:
            if queued is not None:
                metrics.inc("gateway_inference_queue_depth", -1)
                metrics.observe("gateway_queue_duration", time.monotonic() - queued)
    finally:
        if usage:
            usage.save()
        if body is not None:
            body.close()
        if held:
            await admission.memory.release(held)
        metrics.inc("gateway_router_requests_active", -1, router=router)


async def forward(request, body, model, affinity, hidden, usage, release_body):
    config, metrics = request.app["config"], request.app["metrics"]
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(body.length),
        "x-request-id": request["request_id"],
    }
    if affinity:
        headers["x-smg-routing-key"] = affinity
    response = None
    request["audit"] = True
    metrics.observe(
        "gateway_" + request["body_size"] + "_request_processing_seconds",
        time.monotonic() - request["body_complete"],
    )
    try:
        async with asyncio.timeout(config.upstream_timeout):
            async with request.app["http"].post(
                config.upstream.rstrip("/") + request.path,
                data=body_chunks(body),
                headers=headers,
                allow_redirects=False,
            ) as upstream:
                await release_body()
                metrics.set("gateway_upstream_reachable", upstream.status != 503)
                if upstream.status == 503:
                    raise Rejected(503, "inference_unavailable", 30)
                if not 200 <= upstream.status < 300:
                    if usage:
                        usage.finish("failed")
                    codes = {
                        400: "invalid_request",
                        422: "invalid_request",
                        404: "not_found",
                        408: "request_timeout",
                        413: "request_too_large",
                        429: "rate_limited",
                    }
                    code = codes.get(
                        upstream.status,
                        "request_rejected"
                        if 400 <= upstream.status < 500
                        else "inference_error",
                    )
                    value = {
                        "error": {
                            "code": code,
                            "type": "invalid_request_error"
                            if 400 <= upstream.status < 500
                            else "server_error",
                            "param": None,
                            "message": "The inference server did not accept the request. The gateway does not return its error text.",
                        }
                    }
                    return json_response(
                        value, upstream.status, safe_retry(upstream.headers)
                    )
                content_type = upstream.headers.get("Content-Type", "")
                stream = content_type.startswith("text/event-stream")
                rewrite = stream or content_type.startswith("application/json")
                timing = StreamTiming(
                    metrics, model, request["key_id"], request["started"]
                )
                output = Output(
                    model,
                    stream,
                    hidden,
                    expected=usage.expected if usage else None,
                    responses=request.path == "/v1/responses",
                    on_value=lambda value: (
                        timing.value(value, time.monotonic()) if stream else None
                    ),
                )
                response_headers = safe_retry(upstream.headers)
                if content_type:
                    response_headers["Content-Type"] = content_type
                response = web.StreamResponse(
                    status=upstream.status, headers=response_headers
                )
                await response.prepare(request)
                iterator, timeout = (
                    upstream.content.iter_any().__aiter__(),
                    config.first_timeout,
                )
                try:
                    while True:
                        try:
                            async with asyncio.timeout(timeout):
                                chunk = await anext(iterator)
                        except StopAsyncIteration:
                            break
                        received = time.monotonic()
                        timeout = config.idle_timeout
                        value = output.push(chunk) if rewrite else chunk
                        if usage:
                            usage.observation = output.observation
                            if output.done:
                                usage.finish("failed" if output.failed else "completed")
                        if value:
                            await response.write(value)
                            if stream:
                                metrics.observe(
                                    "gateway_stream_forward_seconds",
                                    time.monotonic() - received,
                                )
                    final = output.finish() if rewrite else b""
                    if usage:
                        usage.observation = output.observation
                        usage.finish(
                            "interrupted"
                            if stream and not output.done
                            else "failed"
                            if output.failed
                            else "completed"
                        )
                    if final:
                        await response.write(final)
                    await response.write_eof()
                except (ValueError, TimeoutError, aiohttp.ClientError, ConnectionError):
                    if usage:
                        usage.finish("interrupted")
                    if request.transport:
                        request.transport.close()
                finally:
                    if stream:
                        timing.finish(output.observation)
                    record_observation(metrics, model, request["key_id"], output)
                return response
    except (aiohttp.ClientError, OSError, TimeoutError) as error:
        if response is not None:
            if usage:
                usage.finish("interrupted")
            if request.transport:
                request.transport.close()
            return response
        if usage:
            usage.finish("failed")
        metrics.set("gateway_upstream_reachable", 0)
        raise Rejected(503, "inference_unavailable", 30) from error


def safe_retry(headers):
    value = headers.get("Retry-After", "")
    return (
        {"Retry-After": str(int(value))}
        if value.isascii() and value.isdecimal() and 1 <= int(value) <= 3600
        else {}
    )


def record_observation(metrics, model, key, output):
    labels = {"model": model, "key_id": key}
    for field, kind in (("input_tokens", "input"), ("output_tokens", "output")):
        value = output.observation.get(field)
        if value is not None:
            metrics.inc("gen_ai_client_token_usage", value, type=kind, **labels)
            metrics.observe("gateway_" + kind + "_tokens_per_request", value, **labels)
    cached = output.observation.get("cached_input_tokens")
    if cached is not None:
        metrics.inc("gen_ai_usage_cache_read_input_tokens", cached, **labels)
    if output.reason is not None:
        metrics.inc("gen_ai_response_finish_reasons", model=model, reason=output.reason)


async def health(request):
    return json_response({"status": "ok"})


async def ready(request):
    if request.app["keys"].revision is None:
        return json_response({"status": "key_registry_not_ready"}, 503)
    return json_response({"status": "ready"})


async def models(request):
    request["audit"] = True
    return json_response(
        {
            "object": "list",
            "data": [
                {"id": model, "object": "model", "owned_by": "confidential.ai"}
                for model in request.app["config"].catalog
            ],
        }
    )


async def admin(request):
    body = bytearray()
    async for chunk in request.content.iter_chunked(65536):
        if len(body) + len(chunk) > 1_048_576:
            raise Rejected(401, "invalid_body")
        body.extend(chunk)
    request.app["admin_auth"].verify(request, body)
    store = request.app["keys"]
    if request.path.endswith("/health"):
        return json_response(
            {
                "status": "ready" if store.revision else "key_registry_not_ready",
                "cachedRevision": store.revision,
            }
        )
    if request.path.endswith("/source"):
        return json_response(store.status())
    try:
        snapshot = orjson.loads(body)
    except ValueError as error:
        raise Rejected(400, "invalid_request") from error
    return json_response(store.apply(snapshot))


@asynccontextmanager
async def parsing_worker(app):
    executor = await app["parsers"].get()
    try:
        yield executor
    finally:
        try:
            await parser_call(executor, clear_buffer)
        except BrokenProcessPool:
            # A failed child must not leave a permanently unusable queue slot.
            executor.shutdown(wait=False, cancel_futures=True)
            executor = app["parser_stack"].enter_context(
                ProcessPoolExecutor(max_workers=1, mp_context=get_context("spawn"))
            )
        finally:
            app["parsers"].put_nowait(executor)


async def parser_call(executor, function, *arguments):
    concurrent = executor.submit(function, *arguments)
    pending = asyncio.wrap_future(concurrent)
    try:
        return await asyncio.shield(pending)
    except asyncio.CancelledError:
        # Keep the buffer and memory charge until a running worker releases it.
        if not concurrent.cancel():
            try:
                await asyncio.shield(pending)
            except Exception:
                pass
        raise


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
    async with aiohttp.ClientSession(
        timeout=timeout, connector=connector, auto_decompress=False
    ) as client:
        app["http"] = client
        with ExitStack() as stack:
            app["parser_stack"] = stack
            executors = [
                stack.enter_context(
                    ProcessPoolExecutor(max_workers=1, mp_context=get_context("spawn"))
                )
                for _ in range(6)
            ]
            app["parsers"] = asyncio.Queue()
            await asyncio.gather(
                *(
                    asyncio.get_running_loop().run_in_executor(executor, os.getpid)
                    for executor in executors
                )
            )
            for executor in executors:
                app["parsers"].put_nowait(executor)
            tasks = []
            admin = (
                AdminClient(app["config"], app["admin_token"], client)
                if app["admin_token"] is not None
                else None
            )
            if admin:
                tasks.append(
                    asyncio.create_task(admin.synchronize(app["keys"], app["metrics"]))
                )
                if app["usage"]:
                    tasks.append(asyncio.create_task(app["usage"].deliver(admin)))
            try:
                yield
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                if admin and app["usage"]:
                    await app["usage"].flush(admin)


def create_app(config, keys, admin_auth, token=None):
    app = web.Application(middlewares=[errors], client_max_size=64 * 1024**2)
    metrics = Metrics(config.environment)
    keys.metrics = metrics
    app.update(
        config=config,
        keys=keys,
        admin_auth=admin_auth,
        admission=Admission(config),
        public=Public(config),
        routing=Routing(),
        metrics=metrics,
        audit=Audit(keys.pepper),
        admin_token=token,
    )
    app["usage"] = Recorder(config, keys, metrics) if config.usage_enabled else None
    app.cleanup_ctx.append(session)
    app.on_response_prepare.append(response_headers)
    app.add_routes(
        [
            web.get("/health", health),
            web.get("/ready", ready),
            web.get("/v1/models", models),
        ]
    )
    app.add_routes(
        [
            web.post("/v1/chat/completions", inference),
            web.post("/v1/completions", inference),
            web.post("/v1/responses", inference),
        ]
    )
    app.add_routes(
        [
            web.get("/admin/v1/health", admin),
            web.get("/admin/v1/api-keys/source", admin),
            web.put("/admin/v1/api-keys/snapshot", admin),
        ]
    )
    return app
