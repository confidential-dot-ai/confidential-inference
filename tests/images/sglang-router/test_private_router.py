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
PROGRAM = ROOT / "images/sglang-router/private_router.py"
spec = importlib.util.spec_from_file_location("private_router", PROGRAM)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
CANARY = "PRIVATE_ROUTER_TEST_VALUE_094378"
# The node log agent enforces this contract on the router container's stdout.
CONTRACT_KEYS = {"timestamp", "source_revision", "event", "role", "status", "code"}
CONTRACT_EVENTS = module.EVENTS | {"router_config_rejected", "router_exit", "router_failed", "router_started"}
REVISION = "0123456789abcdef0123456789abcdef01234567"


def check_contract(test, rows):
    for row in rows:
        test.assertLessEqual(set(row), CONTRACT_KEYS)
        test.assertIn(row["event"], CONTRACT_EVENTS)
        test.assertIn(row["role"], {"router", "prefill", "decode"})
        test.assertRegex(row["source_revision"], r"\A(?:[0-9a-f]{40}|unknown)\Z")
        # ISO-8601 UTC, as datetime.isoformat() writes it.
        test.assertRegex(row["timestamp"], r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?\+00:00\Z")
        if "status" in row:
            test.assertIs(int, type(row["status"]))
            test.assertTrue(100 <= row["status"] <= 599)
        if "code" in row:
            test.assertIs(int, type(row["code"]))


class PrivateRouterTests(unittest.TestCase):
    def fake(self, directory, source, json_log=True):
        package = Path(directory) / "sglang_router"
        package.mkdir()
        (package / "__init__.py").write_text("")
        (package / "launch_router.py").write_text(source)
        # The launcher reads this file to decide whether to pass --json-log.
        flag = 'f"--{prefix}json-log"' if json_log else 'f"--{prefix}log-level"'
        (package / "router_args.py").write_text(f"FLAGS = [{flag}]\n")
        environment = {**os.environ, "PYTHONPATH": directory}
        environment.pop("CI_DIAGNOSTIC_SOURCE_REVISION", None)
        environment.pop("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", None)
        return environment

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
            self.assertEqual(["router_started", "worker_http_error", "worker_request_failed", "router_exit"],
                             [row["event"] for row in rows])
            check_contract(self, rows)
            self.assertEqual({"event": "router_started", "role": "router"},
                             {k: v for k, v in rows[0].items() if k not in {"timestamp", "source_revision"}})
            self.assertEqual(7, rows[-1]["code"])

    def test_canary_in_message_url_or_request_id_never_reaches_stdout(self):
        # Each line is a reviewed event with the canary in one private field.
        # Only the fixed fields may pass; no line may carry the canary.
        private = [
            {"message": CANARY},
            {"msg": f"request failed {CANARY}"},
            {"url": f"http://{CANARY}.inference-workers:30000/generate"},
            {"worker_url": f"http://10.0.0.1:30000/{CANARY}"},
            {"uri": f"/v1/chat/completions?id={CANARY}"},
            {"request_id": CANARY},
            {"x-request-id": CANARY},
            {"span": {"request_id": CANARY, "uri": CANARY}},
            {"fields": {"message": CANARY, "request_id": CANARY}},
            {"target": CANARY, "code": 9, "timestamp": CANARY, "source_revision": CANARY},
        ]
        with tempfile.TemporaryDirectory() as directory:
            environment = self.fake(directory, f"""
import json,sys
for extra in {private!r}:
    print(json.dumps({{'ci_event':'worker_http_error','role':'decode','status':502,**extra}}),flush=True)
print('ERROR request {CANARY} failed url=http://{CANARY}/', flush=True)
print('{{"ci_event":"worker_http_error","message":"' + {CANARY!r} + '"', flush=True)
sys.stderr.write({CANARY!r} + '\\n')
sys.exit(0)
""")
            environment["CI_DIAGNOSTIC_SOURCE_REVISION"] = REVISION
            result = subprocess.run([sys.executable, str(PROGRAM)], env=environment,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode)
            self.assertEqual("", result.stderr)
            self.assertNotIn(CANARY, result.stdout)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            check_contract(self, rows)
            self.assertEqual(["router_started"] + ["worker_http_error"] * len(private),
                             [row["event"] for row in rows])
            for row in rows[1:]:
                self.assertEqual({"timestamp", "source_revision", "event", "role", "status"}, set(row))
                self.assertEqual(("decode", 502), (row["role"], row["status"]))
            self.assertTrue(all(row["source_revision"] == REVISION for row in rows))

    def test_json_log_is_passed_only_when_the_router_accepts_it(self):
        for json_log in (True, False):
            with tempfile.TemporaryDirectory() as directory:
                argv = Path(directory) / "argv.json"
                environment = self.fake(directory, f"""
import json,sys
open({str(argv)!r},'w').write(json.dumps(sys.argv[1:]))
""", json_log=json_log)
                result = subprocess.run([sys.executable, str(PROGRAM), "--port=1"], env=environment,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(0, result.returncode)
                expected = ["--port=1", *(["--json-log"] if json_log else []), "--log-level", "warn"]
                self.assertEqual(expected, json.loads(argv.read_text()))
                self.assertEqual(["router_started"],
                                 [json.loads(line)["event"] for line in result.stdout.splitlines()])

    def test_launcher_sends_no_network_events(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = self.fake(directory, "print('private child output', flush=True)\n")
            audit = Path(directory) / "network-events"
            audit.write_text("")
            (Path(directory) / "sitecustomize.py").write_text(
                "import sys\n"
                f"path = {str(audit)!r}\n"
                "def audit(event, args):\n"
                "    if event in ('socket.connect', 'socket.bind', 'socket.getaddrinfo'):\n"
                "        with open(path, 'a') as log: log.write(event + '\\n')\n"
                "sys.addaudithook(audit)\n")
            environment["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = "http://127.0.0.1:4318/v1/logs"
            result = subprocess.run([sys.executable, str(PROGRAM)], env=environment,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("", result.stderr)
            self.assertEqual(["router_started"],
                             [json.loads(line)["event"] for line in result.stdout.splitlines()])
            self.assertEqual("", audit.read_text())

    def test_emit_refuses_fields_outside_the_contract(self):
        for event, fields in (("router_exit", {"role": "router", "code": "1"}),
                              ("router_exit", {"role": "router", "message": "x"}),
                              ("router_started", {"role": "decode"}),
                              ("worker_http_error", {"role": "decode", "status": 99}),
                              ("worker_http_error", {"role": "decode", "url": "x"}),
                              ("diagnostic_delivery_failed", {"role": "router", "dropped": 1})):
            with self.assertRaises(ValueError, msg=(event, fields)):
                module.emit(event, **fields)

    def test_trace_and_file_flags_are_rejected_including_abbreviations(self):
        for flag in ("--log-dir", "--log-d", "--enable-trace", "--enable-tra",
                     "--otlp-traces-endpoint", "--otlp-traces-e"):
            result = subprocess.run([sys.executable, str(PROGRAM), flag, CANARY],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(2, result.returncode, flag)
            self.assertNotIn(CANARY, result.stdout + result.stderr)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(["router_config_rejected"], [row["event"] for row in rows])
            check_contract(self, rows)

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
                self.assertEqual("router_started", json.loads(process.stdout.readline())["event"])
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
