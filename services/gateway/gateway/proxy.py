"""Request transformation and bounded streaming response rewriting."""

import hashlib
import hmac
import os

import orjson

from .limits import Rejected


class Routing:
    def __init__(self):
        self.secret = os.urandom(32)

    def derive(self, key_id, route, client, payload):
        if client and 1 <= len(client) <= 128 and all(33 <= ord(c) <= 126 for c in client):
            kind, material = b"client", client.encode()
        else:
            if route == "/v1/chat/completions":
                items, kind = payload.get("messages"), b"chat"
            elif route == "/v1/responses":
                items, kind = payload.get("input"), b"responses"
                if isinstance(items, str):
                    items = [{"role": "user", "content": items}]
            else:
                return None
            if not isinstance(items, list):
                return None
            opening = []
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("role"), str):
                    return None
                opening.append({"role": item["role"], "content": item.get("content")})
                if item["role"] == "user":
                    break
            else:
                return None
            if kind == b"chat":
                value = {"model": payload["model"], "messages": opening}
            else:
                value = {"model": payload["model"], "instructions": payload.get("instructions"), "input": opening}
            material = orjson.dumps(value, option=orjson.OPT_SORT_KEYS)
        mac = hmac.new(self.secret, digestmod=hashlib.sha256)
        for field in (b"confidential.ai/gateway-routing-key/v1", key_id.encode(), kind, material):
            mac.update(len(field).to_bytes(8, "big"))
            mac.update(field)
        return mac.digest()[:16].hex()


def prepare(body, route, key_id, client_key, config, routing):
    try:
        payload = orjson.loads(body)
    except (ValueError, TypeError) as error:
        raise Rejected(400, "invalid_json") from error
    model = payload.get("model") if isinstance(payload, dict) else None
    if not isinstance(model, str):
        raise Rejected(400, "model_required")
    if model not in config.models:
        raise Rejected(401, "model_not_authorized")
    responses = route == "/v1/responses"
    if responses:
        if any(payload.get(k) is not None for k in ("previous_response_id", "conversation")):
            raise Rejected(400, "stateful_responses_not_supported")
        if any(payload.get(k) is not None and payload[k] is not False for k in ("store", "background")):
            raise Rejected(400, "stateful_responses_not_supported")
        payload["store"] = False
        if payload.get("stream") is None:
            payload["stream"] = False
    routing_key = routing.derive(key_id, route, client_key, payload)
    internal_usage = not responses and config.usage_enabled and payload.get("stream") is True
    hidden = False
    if internal_usage:
        options = payload.get("stream_options")
        hidden = not isinstance(options, dict) or options.get("include_usage") is not True
        if not isinstance(options, dict):
            options = payload["stream_options"] = {}
        options["include_usage"] = True
    if internal_usage or responses:
        body = orjson.dumps(payload)
    return body, model, routing_key, hidden


class Output:
    def __init__(self, model, event_stream, hidden=False):
        self.model, self.event_stream, self.hidden = model, event_stream, hidden
        self.pending = bytearray()
        self.done = False
        self.failed = False
        self.observation = None

    def value(self, raw):
        value = orjson.loads(raw)
        if isinstance(value, dict):
            if "model" in value:
                value["model"] = self.model
            response = value.get("response")
            if isinstance(response, dict) and "model" in response:
                response["model"] = self.model
            kind = value.get("type")
            terminal = kind in ("response.completed", "response.incomplete", "response.failed")
            if terminal:
                self.done, self.failed = True, kind == "response.failed"
            observed = response if isinstance(response, dict) else value
            if isinstance(observed.get("usage"), dict):
                self.observation = observed["usage"]
            final = isinstance(value.get("usage"), dict) and value.get("choices") == []
            if final and self.hidden:
                return b""
        return orjson.dumps(value)

    def line(self, line):
        if not line.startswith(b"data:"):
            return line
        payload = line[5:]
        if payload.startswith(b" "):
            payload = payload[1:]
        payload = payload.rstrip(b"\r\n")
        if payload == b"[DONE]":
            self.done = True
            return line
        if not payload:
            return line
        value = self.value(payload)
        ending = b"\r\n" if line.endswith(b"\r\n") else b"\n" if line.endswith(b"\n") else b""
        return b"data: " + value + ending if value else b""

    def push(self, chunk):
        if not self.event_stream:
            self.pending.extend(chunk)
            if len(self.pending) > 16 * 1024**2:
                raise ValueError("response limit")
            return b""
        result = bytearray()
        start = 0
        while True:
            newline = chunk.find(b"\n", start)
            if newline < 0:
                self.pending.extend(chunk[start:])
                break
            self.pending.extend(chunk[start:newline + 1])
            if len(self.pending) > 16 * 1024**2:
                raise ValueError("response limit")
            result.extend(self.line(self.pending))
            self.pending.clear()
            start = newline + 1
        if len(self.pending) > 16 * 1024**2:
            raise ValueError("response limit")
        return result

    def finish(self):
        return self.line(self.pending) if self.event_stream else self.value(self.pending)


def prepare_buffer(parent, descriptor, length, capacity, route, key_id, client_key, config, routing):
    """Parse a volatile shared buffer; return only small control metadata."""
    import mmap
    with open(f"/proc/{parent}/fd/{descriptor}", "r+b", buffering=0) as file:
        with mmap.mmap(file.fileno(), capacity) as mapping:
            incoming = memoryview(mapping)[:length]
            try:
                outgoing, model, affinity, hidden = prepare(incoming, route, key_id, client_key, config, routing)
                if outgoing is not incoming:
                    if len(outgoing) > capacity:
                        raise Rejected(413, "request_too_large")
                    mapping[:len(outgoing)] = outgoing
                    length = len(outgoing)
                return length, model, affinity, hidden
            finally:
                incoming.release()
