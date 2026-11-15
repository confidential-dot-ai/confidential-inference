import os
import signal
import subprocess
import sys
import threading
import time
import unittest

from test_wait_for_model import ModelMountGateTests, REPOSITORY, REVISION, ROOT, SCRIPT


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


class SignalTests(ModelMountGateTests):
    """wait-for-model passes SIGTERM/SIGINT straight to the server (SGLang drains itself)."""

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

    def child_that_exits_on_sigterm(self, exit_code: int) -> list[str]:
        script = (
            "import signal, sys, time\n"
            f"signal.signal(signal.SIGTERM, lambda *a: sys.exit({exit_code}))\n"
            "time.sleep(30)\n"
        )
        return [sys.executable, "-c", script]

    def wait_for_gate_ready(self, reader: StderrReader) -> None:
        # The wrapper prints "verified" to stderr right before it spawns the
        # child, then installs its signal handlers immediately after.
        self.assertTrue(reader.wait_for("model-mount: verified", 5), reader.text())
        # Give the freshly spawned child a moment to install its own SIGTERM
        # handler before the test sends a signal to the wrapper.
        time.sleep(0.2)

    def test_sigterm_is_forwarded_at_once(self) -> None:
        digests = self.create_model()
        self.set_mount()
        process = self.spawn_gate(digests, self.child_that_exits_on_sigterm(7), env={})
        reader = StderrReader(process)
        self.wait_for_gate_ready(reader)
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        returncode = process.wait(timeout=5)
        reader.thread.join(timeout=2)
        self.assertEqual(7, returncode, reader.text())
        self.assertLess(time.monotonic() - started, 2.0)

    def test_sigint_is_forwarded(self) -> None:
        digests = self.create_model()
        self.set_mount()
        process = self.spawn_gate(digests, self.child_that_exits_on_sigterm(3), env={})
        reader = StderrReader(process)
        self.wait_for_gate_ready(reader)
        process.send_signal(signal.SIGINT)
        returncode = process.wait(timeout=5)
        reader.thread.join(timeout=2)
        self.assertNotEqual(0, returncode, reader.text())

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


if __name__ == "__main__":
    unittest.main()
