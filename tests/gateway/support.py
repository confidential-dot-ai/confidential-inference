"""Real-process fixtures shared by Rust/Python contract and load tests."""

import asyncio
import base64
import hashlib
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiohttp
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = ROOT / "services/gateway"
ADMIN_KEY = "test-admin-" + "a" * 32
API_KEY = "test-inference-" + "b" * 32
MODEL = "model-a"


def certificate(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gateway-test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    path = Path(directory) / "admin.crt"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path, key


def snapshot(revision=1):
    return {"schemaVersion": "confidential.ai/key-registry-snapshot/v1", "environment": "test", "revision": revision,
            "pepperFingerprint": "", "keys": [{"id": "key_test", "name": "test", "owner": "test", "prefix": "test",
            "keyHash": base64.urlsafe_b64encode(hashlib.sha256(API_KEY.encode()).digest()).decode().rstrip("="),
            "hashAlgorithm": "sha256", "pepperFingerprint": "", "createdAt": "2026-01-01T00:00:00Z", "createdBy": "test", "version": 1}]}


class Gateway:
    def __init__(self, kind, upstream, settings=None, rust=None):
        self.directory = tempfile.TemporaryDirectory(prefix="gateway-test-")
        self.kind, self.upstream, self.settings = kind, upstream, settings or {}
        self.rust = rust or os.environ.get("RUST_GATEWAY_BINARY", "/tmp/gateway-rust-baseline-target/release/confidential-gateway")
        self.process = None
        self.signer_path, self.signer = certificate(self.directory.name)

    async def start(self, apply_snapshot=True):
        directory = Path(self.directory.name)
        (directory / "pepper").write_bytes(b"test-pepper" * 4)
        (directory / "admin.json").write_text('{"token":"' + "t" * 32 + '"}')
        (directory / "admin.sha256").write_text(hashlib.sha256(ADMIN_KEY.encode()).hexdigest())
        env = {**os.environ, "PYTHONPATH": str(PYTHON_ROOT), "DEPLOYMENT_ENVIRONMENT": "test",
               "GATEWAY_INFERENCE_URL": self.upstream, "GATEWAY_ALLOW_DIRECT_INFERENCE_URL": "true",
               "GATEWAY_LISTEN": "127.0.0.1:9443", "GATEWAY_METRICS_LISTEN": "127.0.0.1:9090",
               "GATEWAY_MODEL": MODEL, "GATEWAY_API_KEY_PEPPER_FILE": str(directory / "pepper"),
               "GATEWAY_ADMIN_CONFIG_FILE": str(directory / "admin.json"),
               "GATEWAY_ADMIN_ENDPOINT": "https://127.0.0.1:1/api/usage/ingest",
               "GATEWAY_ADMIN_SIGNER_CERTIFICATE_FILE": str(self.signer_path),
               "GATEWAY_ADMIN_API_KEY_HASHES_FILE": str(directory / "admin.sha256"),
               "GATEWAY_MAXIMUM_BODY_BYTES": str(64 * 1024**2), "GATEWAY_BODY_MEMORY_BYTES": str(10 * 1024**3),
               "GATEWAY_BODY_TIMEOUT_SECONDS": "60", "GATEWAY_INFERENCE_CONCURRENCY": "128",
               "GATEWAY_PER_KEY_CONCURRENCY": "128", "GATEWAY_PER_ADDRESS_CONCURRENCY": "256",
               "GATEWAY_REQUESTS_PER_ADDRESS_PER_SECOND": "10000", "GATEWAY_INFERENCE_QUEUE": "0",
               "GATEWAY_ENDPOINT_DRAIN_SECONDS": "0", "GATEWAY_SHUTDOWN_GRACE_SECONDS": "1", **self.settings}
        command = [self.rust] if self.kind == "rust" else [sys.executable, "-m", "gateway"]
        self.log = open(directory / "output.log", "wb")
        self.process = subprocess.Popen(command, env=env, stdout=self.log, stderr=subprocess.STDOUT)
        async with aiohttp.ClientSession() as client:
            for _ in range(200):
                if self.process.poll() is not None:
                    raise RuntimeError("gateway exited: " + self.logs())
                try:
                    async with client.get("http://127.0.0.1:9443/health") as response:
                        if response.status == 200:
                            break
                except aiohttp.ClientError:
                    pass
                await asyncio.sleep(.05)
            else:
                raise RuntimeError("gateway start timeout")
            if apply_snapshot:
                async with client.put("http://127.0.0.1:9443/admin/v1/api-keys/snapshot", json=snapshot(), headers={"Authorization": "Bearer " + ADMIN_KEY}) as response:
                    value = await response.text()
                    if response.status != 200:
                        raise RuntimeError(f"snapshot refused: {response.status} {value}")
        return self

    def logs(self):
        self.log.flush()
        return (Path(self.directory.name) / "output.log").read_text(errors="replace")

    async def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            for _ in range(100):
                if self.process.poll() is not None:
                    break
                await asyncio.sleep(.05)
            else:
                self.process.kill()
            self.process.wait()
        if hasattr(self, "log"):
            self.log.close()
        self.directory.cleanup()
