import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import unittest

from test_wait_for_model import ModelMountGateTests, REPOSITORY, REVISION, ROOT, SCRIPT


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def load_server(sequence: list[list[dict]]) -> http.server.HTTPServer:
    """Serve /v1/loads?include=core, replaying `sequence` then repeating its last entry."""
    state = {"calls": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            if self.path != "/v1/loads?include=core":
                self.send_response(404)
                self.end_headers()
                return
            index = min(state["calls"], len(sequence) - 1)
            state["calls"] += 1
            body = json.dumps(sequence[index]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    return server


class StderrReader:
    """Reads a process's stderr in the background so tests can wait on a line."""

    def __init__(self, process: subprocess.Popen[str]) -> None:
        self.process = process
        self.lines: list[str] = []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self) -> None:
        assert self.process.stderr is not None
        for line in self.process.stderr:
            with self.lock:
                self.lines.append(line)

    def text(self) -> str:
        with self.lock:
            return "".join(self.lines)

    def wait_for(self, needle: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if needle in self.text():
                return True
            time.sleep(0.02)
        return needle in self.text()


class DrainTests(ModelMountGateTests):
    """SIGTERM/SIGINT drain behavior of the wait-for-model supervisor."""

    def start_load_server(self, sequence: list[list[dict]]) -> int:
        server = load_server(sequence)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop() -> None:
            server.shutdown()
            thread.join()
            server.server_close()

        self.addCleanup(stop)
        return server.server_address[1]

    def spawn_gate(
        self, digests: dict[str, str], child_command: list[str], *, env: dict[str, str],
        timeout: int = 5,
    ) -> subprocess.Popen[str]:
        command = [
            "python3", str(SCRIPT), "--path", str(self.model),
            "--timeout-seconds", str(timeout), "--poll-seconds", "0.05",
            "--expected-repository", REPOSITORY,
            "--expected-revision", REVISION,
            "--revision-metadata", ".model-lock-local-manifest.json",
            "--mountinfo", str(self.mountinfo),
        ]
        for name in sorted(digests):
            command.extend(["--expected-file", f"{name}={digests[name]}"])
        command.append("--")
        command.extend(child_command)
        full_env = dict(os.environ)
        full_env.update(env)
        process = subprocess.Popen(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=full_env,
        )
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.stderr.close)
        return process

    def child_that_exits_on_sigterm(self, port: int, exit_code: int) -> list[str]:
        script = (
            "import signal, sys, time\n"
            f"signal.signal(signal.SIGTERM, lambda *a: sys.exit({exit_code}))\n"
            "time.sleep(30)\n"
        )
        return [sys.executable, "-c", script, f"--port={port}"]

    def wait_for_gate_ready(self, reader: StderrReader) -> None:
        # The wrapper prints "verified" to stderr right before it spawns the
        # child, then installs its signal handlers immediately after.
        self.assertTrue(reader.wait_for("model-mount: verified", 5), reader.text())
        # Give the freshly spawned child a moment to install its own SIGTERM
        # handler before the test sends a signal to the wrapper.
        time.sleep(0.2)

    def test_sigterm_waits_for_zero_before_forwarding(self) -> None:
        digests = self.create_model()
        self.set_mount()
        port = self.start_load_server([
            [{"num_running_reqs": 2, "num_waiting_reqs": 1}],
            [{"num_running_reqs": 1, "num_waiting_reqs": 0}],
            [{"num_running_reqs": 0, "num_waiting_reqs": 0}],
        ])
        process = self.spawn_gate(
            digests, self.child_that_exits_on_sigterm(port, 7),
            env={"WORKER_DRAIN_DEADLINE_SECONDS": "10"},
        )
        reader = StderrReader(process)
        self.wait_for_gate_ready(reader)
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        returncode = process.wait(timeout=5)
        reader.thread.join(timeout=2)
        elapsed = time.monotonic() - started
        stderr = reader.text()
        self.assertEqual(7, returncode, stderr)
        self.assertIn("draining up to", stderr)
        self.assertGreaterEqual(elapsed, 0.1, "the wrapper forwarded SIGTERM before draining")

    def test_sigterm_forwards_at_the_deadline_when_never_zero(self) -> None:
        digests = self.create_model()
        self.set_mount()
        port = self.start_load_server([[{"num_running_reqs": 1, "num_waiting_reqs": 0}]])
        process = self.spawn_gate(
            digests, self.child_that_exits_on_sigterm(port, 9),
            env={"WORKER_DRAIN_DEADLINE_SECONDS": "0.3"},
        )
        reader = StderrReader(process)
        self.wait_for_gate_ready(reader)
        process.send_signal(signal.SIGTERM)
        returncode = process.wait(timeout=5)
        reader.thread.join(timeout=2)
        stderr = reader.text()
        self.assertEqual(9, returncode, stderr)
        self.assertIn("drain deadline reached", stderr)

    def test_second_sigterm_escalates_before_the_deadline(self) -> None:
        # The load never reaches zero, so the drain loop is still running
        # when the second signal arrives. The wrapper must notice the
        # escalation on its own -- child.poll() cannot see the child exit
        # while called from a handler nested inside the outer child.wait(),
        # since that outer call holds subprocess.Popen's wait lock for the
        # whole time it stays interrupted.
        digests = self.create_model()
        self.set_mount()
        port = self.start_load_server([[{"num_running_reqs": 1, "num_waiting_reqs": 0}]])
        process = self.spawn_gate(
            digests, self.child_that_exits_on_sigterm(port, 11),
            env={"WORKER_DRAIN_DEADLINE_SECONDS": "10"},
        )
        reader = StderrReader(process)
        self.wait_for_gate_ready(reader)
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        time.sleep(0.3)
        process.send_signal(signal.SIGTERM)
        returncode = process.wait(timeout=5)
        elapsed = time.monotonic() - started
        reader.thread.join(timeout=2)
        stderr = reader.text()
        self.assertEqual(11, returncode, stderr)
        self.assertIn("signal received again", stderr)
        self.assertLess(elapsed, 2.0, "the second signal should escalate well before the 10s deadline")
        self.assertNotIn("drain deadline reached", stderr)

    def test_sigint_drains_the_same_way(self) -> None:
        digests = self.create_model()
        self.set_mount()
        port = self.start_load_server([[{"num_running_reqs": 0, "num_waiting_reqs": 0}]])
        process = self.spawn_gate(
            digests, self.child_that_exits_on_sigterm(port, 3),
            env={"WORKER_DRAIN_DEADLINE_SECONDS": "10"},
        )
        reader = StderrReader(process)
        self.wait_for_gate_ready(reader)
        process.send_signal(signal.SIGINT)
        returncode = process.wait(timeout=5)
        reader.thread.join(timeout=2)
        stderr = reader.text()
        self.assertEqual(3, returncode, stderr)

    def test_child_exit_code_propagates_without_a_signal(self) -> None:
        digests = self.create_model()
        self.set_mount()
        result = subprocess.run(
            [
                "python3", str(SCRIPT), "--path", str(self.model),
                "--timeout-seconds", "1", "--poll-seconds", "0.05",
                "--expected-repository", REPOSITORY,
                "--expected-revision", REVISION,
                "--revision-metadata", ".model-lock-local-manifest.json",
                "--mountinfo", str(self.mountinfo),
                *[f"--expected-file={name}={digest}" for name, digest in sorted(digests.items())],
                "--", "python3", "-c", "raise SystemExit(42)",
            ],
            text=True, capture_output=True, timeout=5,
        )
        self.assertEqual(42, result.returncode, result.stderr)

    def test_no_drain_deadline_forwards_immediately(self) -> None:
        digests = self.create_model()
        self.set_mount()
        port = self.start_load_server([[{"num_running_reqs": 5, "num_waiting_reqs": 5}]])
        process = self.spawn_gate(
            digests, self.child_that_exits_on_sigterm(port, 5), env={},
        )
        reader = StderrReader(process)
        self.wait_for_gate_ready(reader)
        process.send_signal(signal.SIGTERM)
        returncode = process.wait(timeout=5)
        reader.thread.join(timeout=2)
        stderr = reader.text()
        self.assertEqual(5, returncode, stderr)
        self.assertNotIn("draining up to", stderr)


if __name__ == "__main__":
    unittest.main()
