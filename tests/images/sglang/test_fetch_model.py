from __future__ import annotations

import hashlib
import http.server
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
FETCH = ROOT / "images/sglang/fetch_model.py"
GATE = ROOT / "images/sglang/wait_for_model.py"
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
        self.assertEqual("server-started\n", accepted.stdout)

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

    def test_changed_upstream_bytes_are_refused(self) -> None:
        FakeHub.files["model.safetensors"] = b"other" * 1400
        result = self.fetch()
        self.assertNotEqual(0, result.returncode)
        self.assertIn(b"does not match the manifest", result.stderr)
        self.assertFalse((self.cache / "model.safetensors").exists())


if __name__ == "__main__":
    unittest.main()
