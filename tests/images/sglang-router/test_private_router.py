"""Check the private router log writer with real child processes."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "images/sglang-router"))
PROGRAM = ROOT / "images/sglang-router/private_router.py"
spec = importlib.util.spec_from_file_location("private_router", PROGRAM)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
CANARY = "PRIVATE_ROUTER_TEST_VALUE_094378"


class PrivateRouterTests(unittest.TestCase):
    def fake(self, directory, source):
        package = Path(directory) / "sglang_router"
        package.mkdir()
        (package / "__init__.py").write_text("")
        (package / "launch_router.py").write_text(source)
        return {**os.environ, "PYTHONPATH": directory}

    def test_only_fixed_fields_reach_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = self.fake(directory, f"""
import json,sys
canary={CANARY!r}
print(canary,flush=True)
print(json.dumps({{'ci_event':'worker_http_error','role':'prefill','status':400,
                  'message':canary,'span':{{'request_id':canary,'uri':canary}}}}),flush=True)
print(json.dumps({{'ci_event':canary,'role':'decode','status':400}}),flush=True)
print(json.dumps({{'ci_event':'worker_http_error','role':canary,'status':400}}),flush=True)
print(json.dumps({{'ci_event':'worker_http_error','role':'decode','status':canary}}),flush=True)
print(json.dumps({{'ci_event':'worker_http_error','role':{{'private':canary}},'status':400}}),flush=True)
print(canary*1000,flush=True)
print(json.dumps({{'ci_event':'worker_request_failed','role':'decode'}}),flush=True)
sys.exit(7)
""")
            result = subprocess.run([sys.executable, str(PROGRAM)], env=environment,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(7, result.returncode)
            self.assertEqual("", result.stderr)
            self.assertNotIn(CANARY, result.stdout)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(["worker_http_error", "worker_request_failed", "router_exit"],
                             [row["event"] for row in rows])
            for row in rows:
                self.assertLessEqual(set(row), {"timestamp", "source_revision", "event", "role", "status", "code"})

    def test_trace_and_file_flags_are_rejected_including_abbreviations(self):
        for flag in ("--log-dir", "--log-d", "--enable-trace", "--enable-tra",
                     "--otlp-traces-endpoint", "--otlp-traces-e"):
            result = subprocess.run([sys.executable, str(PROGRAM), flag, CANARY],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(2, result.returncode, flag)
            self.assertNotIn(CANARY, result.stdout + result.stderr)
            self.assertEqual("router_config_rejected", json.loads(result.stdout)["event"])

    def test_sigterm_reaches_child(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = self.fake(directory, """
import json,signal,time
signal.signal(signal.SIGTERM,lambda *_:exit(0))
print(json.dumps({'ci_event':'worker_request_failed','role':'decode'}),flush=True)
while True:time.sleep(1)
""")
            process = subprocess.Popen([sys.executable, str(PROGRAM)], env=environment,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual("worker_request_failed", json.loads(process.stdout.readline())["event"])
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(0, process.returncode)
                self.assertEqual("", stderr)
                self.assertEqual("", stdout)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    unittest.main()
