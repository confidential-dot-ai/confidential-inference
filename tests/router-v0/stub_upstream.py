#!/usr/bin/env python3
"""Deterministic OpenAI-compatible stub upstream for the router integration test.

This file exists only for tests/router-v0/test_sglang_router.sh. It stands in
for a real inference worker so the test can exercise the pinned SGLang router
image without a GPU or a real model. It is not a service the chart deploys.
"""

from __future__ import annotations

import json
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "staging-mock"
RESPONSE_TEXT = "staging mock response"


def compact_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def error_mode(request: dict) -> bool:
    messages = request.get("messages")
    if not isinstance(messages, list):
        return False
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "system":
            continue
        content = message.get("content")
        if isinstance(content, str) and content.strip().lower() == "mock-mode:error":
            return True
    return False


class StubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: object) -> None:
        return

    def _send_json(self, status: int, body: object) -> None:
        payload = compact_json(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _log_request(self, status: int) -> None:
        path = self.path.split("?", 1)[0]
        print(compact_json({"path": path, "status": status}).decode(), flush=True)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
        elif path == "/v1/models":
            self._send_json(
                HTTPStatus.OK,
                {"object": "list", "data": [{"id": MODEL, "object": "model", "created": 0}]},
            )
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": {"message": "not found"}})
        self._log_request(HTTPStatus.OK)

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path != "/v1/chat/completions":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": {"message": "not found"}})
            self._log_request(HTTPStatus.NOT_FOUND)
            return
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        request_id = f"stub-{uuid.uuid4().hex}"

        if error_mode(request):
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "error": {
                        "message": "Deterministic mock upstream error.",
                        "type": "server_error",
                        "param": None,
                        "code": None,
                    }
                },
            )
            self._log_request(HTTPStatus.SERVICE_UNAVAILABLE)
            return

        if request.get("stream") is True:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            chunks = [
                {"role": "assistant", "content": ""},
                {"content": RESPONSE_TEXT},
                {},
            ]
            finish_reasons = [None, None, "stop"]
            for delta, finish_reason in zip(chunks, finish_reasons):
                chunk = {
                    "id": request_id,
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": MODEL,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
                }
                self.wfile.write(b"data: " + compact_json(chunk) + b"\n\n")
                self.wfile.flush()
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            self.close_connection = True
            self._log_request(HTTPStatus.OK)
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "id": request_id,
                "object": "chat.completion",
                "created": 0,
                "model": MODEL,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": RESPONSE_TEXT},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 3, "total_tokens": 4},
            },
        )
        self._log_request(HTTPStatus.OK)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 1080), StubHandler)
    print(compact_json({"event": "stub_upstream_started", "port": 1080}).decode(), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
