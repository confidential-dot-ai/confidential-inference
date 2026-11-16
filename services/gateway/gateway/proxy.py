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


def prepare(body, route, key_id, client_key, config, routing, payload=None):
    try:
        if payload is None:
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
    def __init__(self, model, event_stream, hidden=False, expected=None, responses=False, on_value=None):
        self.model, self.event_stream, self.hidden = model, event_stream, hidden
        self.expected, self.responses, self.on_value = expected, responses, on_value
        self.pending = bytearray()
        self.done = self.failed = self.mismatch = False
        self.observation = {}
        self.reason = None

    def observe(self, value, final):
        from .telemetry import log
        observed = value.get("response") if isinstance(value.get("response"), dict) else value
        if self.responses and "model" not in observed and "usage" not in observed:
            return
        if self.expected is not None and observed.get("model") != self.expected:
            if not self.mismatch:
                log("usage model identity did not match its approved binding", "WARN")
            self.mismatch = True
        if self.mismatch:
            self.observation = {}
            return
        usage = observed.get("usage")
        if isinstance(usage, dict):
            def number(value):
                return value if type(value) is int and 0 <= value <= 9_007_199_254_740_991 else None
            def detail(parent, field):
                value = usage.get(parent)
                return number(value.get(field)) if isinstance(value, dict) else None
            if self.responses:
                input_tokens, output_tokens = number(usage.get("input_tokens")), number(usage.get("output_tokens"))
                cached, reasoning = detail("input_tokens_details", "cached_tokens"), detail("output_tokens_details", "reasoning_tokens")
            else:
                input_tokens, output_tokens = number(usage.get("prompt_tokens")), number(usage.get("completion_tokens"))
                cached = detail("prompt_tokens_details", "cached_tokens")
                if "prompt_tokens_details" in usage and usage["prompt_tokens_details"] is None:
                    cached = 0
                elif cached is None:
                    cached = number(usage.get("cache_read_input_tokens"))
                reasoning = number(usage.get("reasoning_tokens"))
                if reasoning is None:
                    reasoning = detail("completion_tokens_details", "reasoning_tokens")
            self.observation = {"input_tokens": input_tokens, "output_tokens": output_tokens,
                "cached_input_tokens": cached if input_tokens is not None and cached is not None and cached <= input_tokens else None,
                "reasoning_tokens": reasoning if output_tokens is not None and reasoning is not None and reasoning <= output_tokens else None,
                "final_usage": final}
        if self.responses:
            if observed.get("status") == "completed":
                output = observed.get("output")
                calls = isinstance(output, list) and any(isinstance(item, dict) and item.get("type") in ("function_call", "custom_tool_call") for item in output)
                self.reason = "tool_calls" if calls else "stop"
            elif observed.get("status") == "incomplete":
                details = observed.get("incomplete_details")
                reason = details.get("reason") if isinstance(details, dict) else None
                self.reason = {"max_output_tokens": "length", "content_filter": "content_filter"}.get(reason)
        else:
            choices = value.get("choices")
            if isinstance(choices, list):
                for choice in choices:
                    reason = choice.get("finish_reason") if isinstance(choice, dict) else None
                    if reason in ("stop", "length", "tool_calls", "content_filter"):
                        self.reason = reason

    def value(self, raw):
        value = orjson.loads(raw)
        if isinstance(value, dict):
            kind = value.get("type")
            terminal = kind in ("response.completed", "response.incomplete", "response.failed")
            if terminal:
                self.done, self.failed = True, kind == "response.failed"
            final = isinstance(value.get("usage"), dict) and value.get("choices") == []
            self.observe(value, not self.event_stream or terminal or final)
            if self.on_value:
                self.on_value(value)
            if "model" in value:
                value["model"] = self.model
            response = value.get("response")
            if isinstance(response, dict) and "model" in response:
                response["model"] = self.model
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


_parsed_buffer = None


def clear_buffer():
    global _parsed_buffer
    if _parsed_buffer is not None:
        _, mapping, _, _, incoming = _parsed_buffer
        incoming.release()
        mapping.close()
        _parsed_buffer = None


def prepare_buffer(parent, descriptor, length, capacity, route, key_id, client_key, config, routing):
    """Use the inspected native document on the same exclusive worker."""
    import simdjson
    if _parsed_buffer is None or _parsed_buffer[0] != (parent, descriptor, length):
        raise ValueError("missing inspected buffer")
    _, mapping, parser, document, incoming = _parsed_buffer
    if isinstance(document, simdjson.Object):
        payload = document.as_dict()
    elif isinstance(document, simdjson.Array):
        payload = document.as_list()
    else:
        payload = document
    outgoing, model, affinity, hidden = prepare(incoming, route, key_id, client_key, config, routing, payload)
    if outgoing is not incoming:
        incoming.release()
        if len(outgoing) > capacity:
            mapping.resize(len(outgoing))
        mapping[:len(outgoing)] = outgoing
        length = len(outgoing)
    return length, model, affinity, hidden


def object_items(value):
    # Object.items() recursively materializes children; key lookup stays lazy.
    for key in value.keys():
        yield key, value[key]


def inspect_buffer(parent, descriptor, length, capacity, maximum):
    """Estimate Python objects on a lazy native tree before constructing them."""
    import mmap
    import sys

    import simdjson

    global _parsed_buffer
    clear_buffer()
    with open(f"/proc/{parent}/fd/{descriptor}", "r+b", buffering=0) as file:
        mapping = mmap.mmap(file.fileno(), capacity)
    incoming = memoryview(mapping)[:length]
    try:
        parser = simdjson.Parser()
        document = parser.parse(incoming)
        # Original, native parser storage, parser scratch and rewritten bytes
        # remain charged alongside the estimated Python object tree.
        cost = 5 * length + 65536
        stack = [iter((document,))]
        while stack:
            try:
                value = next(stack[-1])
            except StopIteration:
                stack.pop()
                continue
            if isinstance(value, simdjson.Object):
                keys = tuple(value.keys())
                if len(set(keys)) != len(keys):
                    # Native lookup returns the first duplicate, while JSON
                    # object construction keeps the last. Charge a conservative
                    # whole-tree bound instead of missing a shadowed subtree.
                    cost = max(cost, 128 * length + 65536)
                    if cost > maximum:
                        raise Rejected(413, "request_too_large")
                    break
                cost += 256 + 96 * len(value)
                stack.append(object_items(value))
            elif isinstance(value, simdjson.Array):
                cost += 128 + 16 * len(value)
                stack.append(iter(value))
            elif isinstance(value, tuple):
                cost += sys.getsizeof(value[0])
                stack.append(iter((value[1],)))
            else:
                cost += sys.getsizeof(value)
            if cost > maximum:
                raise Rejected(413, "request_too_large")
        _parsed_buffer = (parent, descriptor, length), mapping, parser, document, incoming
        return cost
    except ValueError as error:
        if str(error).startswith(("NUMBER_ERROR", "BIGINT_ERROR")):
            cost = 128 * length + 65536
            if cost <= maximum:
                _parsed_buffer = (parent, descriptor, length), mapping, None, None, incoming
                return cost
            incoming.release()
            mapping.close()
            raise Rejected(413, "request_too_large") from error
        incoming.release()
        mapping.close()
        raise Rejected(400, "invalid_json") from error
    except BaseException as error:
        incoming.release()
        mapping.close()
        if isinstance(error, ValueError):
            raise Rejected(400, "invalid_json") from error
        raise
