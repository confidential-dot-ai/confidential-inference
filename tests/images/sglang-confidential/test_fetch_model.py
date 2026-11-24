from __future__ import annotations

import hashlib
import http.server
import importlib.util
import json
import re
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
FETCH = ROOT / "images/sglang-confidential/fetch_model.py"
GATE = ROOT / "images/sglang-confidential/wait_for_model.py"
REPOSITORY = "example/tiny"
REVISION = "9fb191250dd56d0ba7ec9785a025ed29c03d5998"
METADATA = ".model-lock-local-manifest.json"
FILES = {
    "config.json": b'{"model_type":"llama"}\n',
    "tokenizer_config.json": b'{"tokenizer_class":"LlamaTokenizer"}\n',
    "model.safetensors": b"weights" * 1000,
    "sub/extra.txt": b"nested\n",
}
LFS = {"model.safetensors"}


class FakeHub(http.server.BaseHTTPRequestHandler):
    files: dict[str, bytes] = {}
    requests: list[str] = []
    ranged: list[tuple[str, int, int]] = []
    ranges = True

    def do_GET(self) -> None:  # noqa: N802
        self.requests.append(self.path)
        tree = f"/api/models/{REPOSITORY}/tree/{REVISION}?recursive=true"
        prefix = f"/{REPOSITORY}/resolve/{REVISION}/"
        if self.path == tree:
            entries = [{"type": "directory", "path": "sub"}]
            for name, body in self.files.items():
                entry = {"type": "file", "path": name, "size": len(body), "oid": "0" * 40}
                if name in LFS:
                    entry["lfs"] = {"oid": hashlib.sha256(body).hexdigest(), "size": len(body)}
                entries.append(entry)
            body = json.dumps(entries).encode()
        elif self.path.startswith(prefix) and self.path[len(prefix):] in self.files:
            body = self.files[self.path[len(prefix):]]
            match = re.fullmatch(r"bytes=(\d+)-(\d+)", self.headers.get("Range", ""))
            if match and self.ranges:
                start, end = int(match.group(1)), int(match.group(2))
                self.ranged.append((self.path[len(prefix):], start, end))
                part = body[start:end + 1]
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {start}-{start + len(part) - 1}/{len(body)}")
                self.send_header("Content-Length", str(len(part)))
                self.end_headers()
                self.wfile.write(part)
                return
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


class FetchModelTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeHub.files = dict(FILES)
        FakeHub.requests = []
        FakeHub.ranged = []
        FakeHub.ranges = True
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeHub)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.endpoint = f"http://127.0.0.1:{self.server.server_address[1]}"
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.cache = self.base / "cache"
        self.cache.mkdir()
        self.manifest = self.base / "manifest.json"
        result = self.fetch_model("manifest", "--repository", REPOSITORY, "--revision", REVISION)
        self.assertEqual(0, result.returncode, result.stderr)
        self.manifest.write_bytes(result.stdout)
        self.digest = hashlib.sha256(result.stdout).hexdigest()
        FakeHub.requests = []

    def fetch_model(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(["python3", str(FETCH), "--endpoint", self.endpoint, *args],
                              capture_output=True, timeout=30)

    def fetch(self, digest: str | None = None) -> subprocess.CompletedProcess[bytes]:
        return self.fetch_model("fetch", "--path", str(self.cache), "--manifest", str(self.manifest),
                                "--manifest-sha256", digest or self.digest, "--revision-metadata", METADATA)

    def downloads(self) -> list[str]:
        return [path for path in FakeHub.requests if "/resolve/" in path]

    def test_manifest_lists_every_file_with_its_sha256(self) -> None:
        manifest = json.loads(self.manifest.read_bytes())
        self.assertEqual(f"{REPOSITORY}@{REVISION}", manifest["immutable_ref"])
        self.assertEqual(
            {name: (hashlib.sha256(body).hexdigest(), len(body)) for name, body in FILES.items()},
            {item["path"]: (item["content_sha256"], item["size"]) for item in manifest["files"]},
        )

    def test_fetch_fills_the_cache_and_the_gate_accepts_it(self) -> None:
        result = self.fetch()
        self.assertEqual(0, result.returncode, result.stderr)
        for name, body in FILES.items():
            self.assertEqual(body, (self.cache / name).read_bytes())
        self.assertEqual(self.manifest.read_bytes(), (self.cache / METADATA).read_bytes())
        for path in self.cache.rglob("*"):
            if path.is_dir():
                path.chmod(0o555)
        self.cache.chmod(0o555)
        self.addCleanup(lambda: [p.chmod(0o755) for p in [self.cache, *self.cache.rglob("*")] if p.is_dir()])
        mountinfo = self.base / "mountinfo"
        mountinfo.write_text(f"44 33 252:16 / {self.cache.resolve()} ro,nosuid,nodev,noexec - ext4 /dev/vdc ro\n")
        digests = {METADATA: self.digest, **{name: hashlib.sha256(body).hexdigest() for name, body in FILES.items()
                                             if name != "sub/extra.txt"}}
        gate = ["python3", str(GATE), "--path", str(self.cache), "--timeout-seconds", "1", "--poll-seconds", "0.05",
                "--expected-repository", REPOSITORY, "--expected-revision", REVISION,
                "--revision-metadata", METADATA, "--mountinfo", str(mountinfo),
                *[f"--expected-file={name}={digest}" for name, digest in sorted(digests.items())]]
        command = ["--", "python3", "-c", "print('server-started')"]
        refused = subprocess.run(gate + command, text=True, capture_output=True, timeout=5)
        self.assertNotEqual(0, refused.returncode)
        self.assertIn("dm-verity mapping is not attached", refused.stderr)
        accepted = subprocess.run(gate + ["--plain-cache"] + command, text=True, capture_output=True, timeout=5)
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        # Server output is private: only the fixed exit event reaches stdout.
        self.assertEqual('{"event":"worker_exit","exit_code":0,"signal":null}\n', accepted.stdout)

    def test_second_fetch_keeps_good_files_and_repairs_the_rest(self) -> None:
        self.assertEqual(0, self.fetch().returncode)
        (self.cache / "config.json").chmod(0o644)
        (self.cache / "config.json").write_bytes(b'{"model_type":"evil"}\n')
        (self.cache / "planted.py").write_bytes(b"print('x')\n")
        (self.cache / "junk").mkdir()
        FakeHub.requests = []
        result = self.fetch()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([f"/{REPOSITORY}/resolve/{REVISION}/config.json"], self.downloads())
        self.assertEqual(FILES["config.json"], (self.cache / "config.json").read_bytes())
        self.assertFalse((self.cache / "planted.py").exists())
        self.assertFalse((self.cache / "junk").exists())

    def test_unpinned_manifest_is_refused(self) -> None:
        result = self.fetch("0" * 64)
        self.assertNotEqual(0, result.returncode)
        self.assertIn(b"pinned SHA-256", result.stderr)
        self.assertEqual([], self.downloads())

    def test_plain_http_model_server_cannot_change_a_byte(self) -> None:
        # The chart allows a plain HTTP model server (inference.model.download.scheme: http):
        # the pinned byte manifest, not TLS, is what pins the model bytes. A server or a
        # network attacker that changes bytes, even at the same size, is refused, and
        # no changed file is left for the server to read.
        self.assertTrue(self.endpoint.startswith("http://"))
        body = FILES["model.safetensors"]
        FakeHub.files["model.safetensors"] = b"W" + body[1:]
        result = self.fetch()
        self.assertNotEqual(0, result.returncode)
        self.assertIn(b"model.safetensors: the download does not match the manifest", result.stderr)
        self.assertFalse((self.cache / "model.safetensors").exists())
        self.assertFalse((self.cache / "model.safetensors.partial").exists())
        self.assertFalse((self.cache / METADATA).exists())
        FakeHub.files["model.safetensors"] = body
        self.assertEqual(0, self.fetch().returncode)
        self.assertEqual(body, (self.cache / "model.safetensors").read_bytes())


    def fetch_in_process(self, *endpoints: str, chunk: int = 1000) -> int:
        # Small chunks make the test files span several byte ranges.
        spec = importlib.util.spec_from_file_location("fetch_model_under_test", FETCH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.CHUNK, module.ATTEMPTS = chunk, 2
        module.time.sleep = lambda _seconds: None
        argv = ["fetch-model", *[f"--endpoint={endpoint}" for endpoint in endpoints], "fetch",
                "--path", str(self.cache), "--manifest", str(self.manifest),
                "--manifest-sha256", self.digest, "--revision-metadata", METADATA]
        saved, sys.argv = sys.argv, argv
        try:
            return module.main()
        finally:
            sys.argv = saved

    def test_large_files_download_as_byte_ranges(self) -> None:
        self.assertEqual(0, self.fetch_in_process(self.endpoint))
        body = FILES["model.safetensors"]
        self.assertEqual(body, (self.cache / "model.safetensors").read_bytes())
        spans = sorted((start, end) for name, start, end in FakeHub.ranged if name == "model.safetensors")
        self.assertEqual([(start, min(len(body), start + 1000) - 1) for start in range(0, len(body), 1000)], spans)

    def test_a_dead_first_endpoint_falls_back_to_the_next(self) -> None:
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))
            dead = f"http://127.0.0.1:{closed.getsockname()[1]}"
        self.assertEqual(0, self.fetch_in_process(dead, self.endpoint))
        for name, body in FILES.items():
            self.assertEqual(body, (self.cache / name).read_bytes())

    def test_a_server_that_ignores_ranges_is_refused(self) -> None:
        FakeHub.ranges = False
        self.assertEqual(1, self.fetch_in_process(self.endpoint))
        self.assertFalse((self.cache / "model.safetensors").exists())
        self.assertFalse((self.cache / "model.safetensors.partial").exists())
        self.assertFalse((self.cache / METADATA).exists())


if __name__ == "__main__":
    unittest.main()
