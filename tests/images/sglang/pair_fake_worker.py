"""Synthetic process for supervisor acceptance. Never use a real API key."""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    role = os.environ["SGLANG_PAIR_ROLE"]
    directory = Path(os.environ["SGLANG_PAIR_RUN_DIR"])
    control = Path(os.environ["PAIR_TEST_CONTROL"])
    # Exercise the raw Python and native output boundary with test canaries.
    for fd in (1, 2):
        os.write(fd, b"FAKE-KEY-DO-NOT-LOG FAKE-PROMPT-DO-NOT-LOG\n")
    signal.signal(signal.SIGQUIT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)  # HTTP remains alive after simulated stall.
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
        sender.sendto(json.dumps({"event": "rank_failed", "role": role,
                                  "message": "FAKE-KEY-DO-NOT-LOG"}).encode(), str(directory / "events.sock"))
        sender.sendto(json.dumps({"event": "cuda_error", "role": role, "rank": 0,
                                  "code": 7}).encode(), str(directory / "events.sock"))
    while True:
        command = control.read_text() if control.exists() else ""
        if command == "exit":
            return 7
        if command != "stall":
            record = {"pid": os.getpid(), "state": "idle", "updated": time.monotonic(),
                      "completed": 0, "pending_since": 0}
            path = directory / f"{role}-0.json"
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(record))
            tmp.replace(path)
        time.sleep(0.05)


if __name__ == "__main__":
    raise SystemExit(main())
