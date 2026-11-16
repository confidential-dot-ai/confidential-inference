"""Real-process fixtures shared by Rust/Python contract and load tests."""

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiohttp
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = ROOT / "services/gateway"
ADMIN_KEY = "test-admin-" + "a" * 32
API_KEY = "test-inference-" + "b" * 32
MODEL = "model-a"


async def raw_request(data, port=9443):
    """Send malformed HTTP without a client library normalizing it."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(data)
        await writer.drain()
        async with asyncio.timeout(2):
            return await reader.read()
    finally:
        writer.close()
        await writer.wait_closed()


def certificate(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gateway-test")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    path = Path(directory) / "admin.crt"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path, key


def snapshot(revision=1):
    return {
        "schemaVersion": "confidential.ai/key-registry-snapshot/v1",
        "environment": "test",
        "revision": revision,
        "pepperFingerprint": "",
        "keys": [
            {
                "id": "key_test",
                "name": "test",
                "owner": "test",
                "prefix": "test",
                "keyHash": base64.urlsafe_b64encode(
                    hashlib.sha256(API_KEY.encode()).digest()
                )
                .decode()
                .rstrip("="),
                "hashAlgorithm": "sha256",
                "pepperFingerprint": "",
                "createdAt": "2026-01-01T00:00:00Z",
                "createdBy": "test",
                "version": 1,
            }
        ],
    }


class AdminPeer:
    """A real HTTPS admin with a private test CA and recorded usage batches."""

    def __init__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="gateway-admin-test-")
        self.value, self.events, self.batches = snapshot(), [], []
        self.accepted_by_id, self.duplicate_deliveries = {}, 0
        self.gets, self.fail_usage, self.unavailable = 0, 0, False
        self.reject_input_tokens = None
        self.authorizations = []

    async def start(self):
        directory = Path(self.directory.name)
        now = datetime.now(UTC)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "gateway-admin-test-ca")]
        )
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(
                x509.KeyUsage(
                    True, False, False, False, False, True, True, False, False
                ),
                True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False
            )
            .sign(ca_key, hashes.SHA256())
        )
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            )
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .sign(ca_key, hashes.SHA256())
        )
        self.ca_file = directory / "ca.pem"
        self.ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        cert_file, key_file = directory / "server.pem", directory / "server.key"
        cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        app = web.Application()
        app.router.add_get("/api/gateway/key-snapshot", self.keys)
        app.router.add_post("/api/usage/ingest", self.usage)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0, ssl_context=context)
        await site.start()
        self.endpoint = f"https://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/api/usage/ingest"
        return self

    def authorize(self, request):
        self.authorizations.append(request.headers.get("Authorization"))
        if self.authorizations[-1] != "Bearer " + "t" * 32:
            raise web.HTTPUnauthorized()
        if self.unavailable:
            raise web.HTTPServiceUnavailable()

    async def keys(self, request):
        self.gets += 1
        self.authorize(request)
        response = web.json_response(self.value)
        response.enable_compression()
        return response

    async def usage(self, request):
        self.authorize(request)
        batch = (await request.json())["events"]
        self.batches.append(batch)
        if self.reject_input_tokens is not None and any(
            event["input_tokens"] == self.reject_input_tokens for event in batch
        ):
            raise web.HTTPUnprocessableEntity()
        if self.fail_usage:
            self.fail_usage -= 1
            raise web.HTTPServiceUnavailable()
        for event in batch:
            identifier = event["request_id"]
            if identifier in self.accepted_by_id:
                if self.accepted_by_id[identifier] != event:
                    raise web.HTTPUnprocessableEntity()
                self.duplicate_deliveries += 1
            else:
                self.accepted_by_id[identifier] = event
                self.events.append(event)
        return web.json_response({"accepted": len(batch)})

    async def close(self):
        await self.runner.cleanup()
        self.directory.cleanup()


class Gateway:
    def __init__(self, kind, upstream, settings=None, rust=None):
        self.directory = tempfile.TemporaryDirectory(prefix="gateway-test-")
        self.kind, self.upstream, self.settings = kind, upstream, settings or {}
        self.rust = rust or os.environ.get(
            "RUST_GATEWAY_BINARY",
            "/tmp/gateway-rust-baseline-target/release/confidential-gateway",
        )
        self.process = None
        self.signer_path, self.signer = certificate(self.directory.name)

    async def start(
        self,
        apply_snapshot=True,
        admin_token="t" * 32,
        pepper_layout="regular",
        startup_timeout=10,
    ):
        directory = Path(self.directory.name)
        (directory / "pepper").write_bytes(b"test-pepper" * 4)
        if pepper_layout == "projected":
            (directory / "..timestamp").mkdir()
            (directory / "pepper").rename(directory / "..timestamp/pepper")
            (directory / "..data").symlink_to("..timestamp")
            (directory / "pepper").symlink_to("..data/pepper")
        elif pepper_layout == "empty":
            (directory / "pepper").write_bytes(b"")
        elif pepper_layout == "outside":
            (directory / "pepper").unlink()
            (directory / "pepper").symlink_to("/etc/os-release")
        elif pepper_layout == "fifo":
            (directory / "pepper").unlink()
            os.mkfifo(directory / "pepper", 0o644)
        elif pepper_layout != "regular":
            raise ValueError("unknown test credential layout")
        (directory / "admin.json").write_text(json.dumps({"token": admin_token}))
        (directory / "admin.sha256").write_text(
            hashlib.sha256(ADMIN_KEY.encode()).hexdigest()
        )
        env = {
            **os.environ,
            "PYTHONPATH": str(PYTHON_ROOT),
            "DEPLOYMENT_ENVIRONMENT": "test",
            "GATEWAY_INFERENCE_URL": self.upstream,
            "GATEWAY_ALLOW_DIRECT_INFERENCE_URL": "true",
            "GATEWAY_LISTEN": "127.0.0.1:9443",
            "GATEWAY_METRICS_LISTEN": "127.0.0.1:9090",
            "GATEWAY_MODEL": MODEL,
            "GATEWAY_API_KEY_PEPPER_FILE": str(directory / "pepper"),
            "GATEWAY_ADMIN_CONFIG_FILE": str(directory / "admin.json"),
            "GATEWAY_ADMIN_ENDPOINT": "https://127.0.0.1:1/api/usage/ingest",
            "GATEWAY_ADMIN_SIGNER_CERTIFICATE_FILE": str(self.signer_path),
            "GATEWAY_ADMIN_API_KEY_HASHES_FILE": str(directory / "admin.sha256"),
            "GATEWAY_MAXIMUM_BODY_BYTES": str(64 * 1024**2),
            "GATEWAY_BODY_MEMORY_BYTES": str(32 * 1024**3),
            "GATEWAY_BODY_TIMEOUT_SECONDS": "60",
            "GATEWAY_INFERENCE_CONCURRENCY": "128",
            "GATEWAY_PER_KEY_CONCURRENCY": "128",
            "GATEWAY_PER_ADDRESS_CONCURRENCY": "256",
            "GATEWAY_REQUESTS_PER_ADDRESS_PER_SECOND": "10000",
            "GATEWAY_INFERENCE_QUEUE": "0",
            "GATEWAY_ENDPOINT_DRAIN_SECONDS": "0",
            "GATEWAY_SHUTDOWN_GRACE_SECONDS": "1",
            **self.settings,
        }
        command = (
            [self.rust] if self.kind == "rust" else [sys.executable, "-m", "gateway"]
        )
        self.container = None
        image = os.environ.get("GATEWAY_TEST_IMAGE") if self.kind == "python" else None
        if image:
            # Only test settings are passed to the container, never the full
            # host environment. The credential directory contains test keys.
            directory.chmod(0o755)
            self.container = directory.name
            command = [
                "docker",
                "run",
                "--rm",
                "--name",
                self.container,
                "--network",
                "host",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "64",
                "--memory",
                "8g",
                "--cpus",
                "8",
                "--mount",
                f"type=bind,src={directory},dst=/run/test-gateway,readonly",
            ]
            ca = env.get("SSL_CERT_FILE")
            if ca:
                command.extend(
                    ["--mount", f"type=bind,src={ca},dst=/run/test-ca.pem,readonly"]
                )
            for name, value in env.items():
                if name.startswith("GATEWAY_") or name == "DEPLOYMENT_ENVIRONMENT":
                    if name.startswith("GATEWAY_TEST_"):
                        continue
                    command.extend(
                        [
                            "--env",
                            name
                            + "="
                            + value.replace(str(directory), "/run/test-gateway"),
                        ]
                    )
            if ca:
                command.extend(["--env", "SSL_CERT_FILE=/run/test-ca.pem"])
            command.append(image)
        self.log = open(directory / "output.log", "wb")
        self.process = subprocess.Popen(
            command, env=env, stdout=self.log, stderr=subprocess.STDOUT
        )
        async with aiohttp.ClientSession() as client:
            for _ in range(round(startup_timeout / 0.05)):
                if self.process.poll() is not None:
                    raise RuntimeError("gateway exited: " + self.logs())
                try:
                    async with client.get("http://127.0.0.1:9443/health") as response:
                        if response.status == 200:
                            break
                except aiohttp.ClientError:
                    pass
                await asyncio.sleep(0.05)
            else:
                raise RuntimeError("gateway start timeout")
            if apply_snapshot:
                async with client.put(
                    "http://127.0.0.1:9443/admin/v1/api-keys/snapshot",
                    json=snapshot(),
                    headers={"Authorization": "Bearer " + ADMIN_KEY},
                ) as response:
                    value = await response.text()
                    if response.status != 200:
                        raise RuntimeError(
                            f"snapshot refused: {response.status} {value}"
                        )
        return self

    def logs(self):
        self.log.flush()
        return (Path(self.directory.name) / "output.log").read_text(errors="replace")

    async def close(self, timeout=5):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            for _ in range(round(timeout / 0.05)):
                if self.process.poll() is not None:
                    break
                await asyncio.sleep(0.05)
            else:
                if self.container:
                    await asyncio.to_thread(
                        subprocess.run,
                        ["docker", "rm", "--force", self.container],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                self.process.kill()
            self.process.wait()
        if hasattr(self, "log"):
            self.log.close()
        self.directory.cleanup()
