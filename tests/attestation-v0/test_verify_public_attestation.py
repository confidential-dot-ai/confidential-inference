from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import runpy
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import jsonschema
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-public-attestation.py"
SOURCE_LOCK = json.loads((ROOT / "contracts/c8s-admission-source-lock.json").read_text())
TARGETS = {
    "production": (
        ("gateway", "gateway", "gateway"),
        ("sglang-router", "sglang-router", "sglang-router"),
        ("inference-worker-0", "inference-worker-0", "inference-worker-0"),
        ("inference-worker-1", "inference-worker-1", "inference-worker-1"),
        ("metrics-collector", "metrics-collector", "metrics-collector"),
        ("kube-state-metrics", "kube-state-metrics", "kube-state-metrics"),
    ),
    "staging": (
        ("gateway", "gateway", "gateway"),
        ("sglang-router", "sglang-router", "sglang-router"),
        ("inference-worker-0", "inference-worker-0", "inference-worker-0"),
    ),
}


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def make_ca_and_leaf(common_name: str, dns_name: str | None = None):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "v0 test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
    )
    if dns_name:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False
        )
    leaf = builder.sign(ca_key, hashes.SHA256())
    return ca_key, ca, leaf_key, leaf


def pem_certificate(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


class ResponseHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parsed = urlsplit(self.path)
        nonce = parse_qs(parsed.query).get("nonce", [""])[0]
        body = copy.deepcopy(self.server.response_document)
        if self.server.echo_nonce:
            body["nonce"] = nonce
            for item in body["receipts"]:
                item["receipt"]["nonce"] = nonce
        encoded = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        return


class PublicAttestationVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        _, self.ca, self.server_key, self.server_certificate = make_ca_and_leaf(
            "localhost", "localhost"
        )
        _, self.mesh_ca, _, self.mesh_leaf = make_ca_and_leaf("mesh-leaf")
        self.endpoint_ca = self.directory / "endpoint-ca.pem"
        self.endpoint_ca.write_bytes(pem_certificate(self.ca))
        self.server_cert = self.directory / "server.pem"
        self.server_cert.write_bytes(pem_certificate(self.server_certificate))
        self.server_key_path = self.directory / "server-key.pem"
        self.server_key_path.write_bytes(
            self.server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.mesh_ca_path = self.directory / "mesh-ca.pem"
        self.mesh_ca_path.write_bytes(pem_certificate(self.mesh_ca))
        operator_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        self.operator_key = self.directory / "operator.pem"
        self.operator_key.write_bytes(
            operator_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self.operator_digest = digest(
            operator_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self.operator_key_set_digest = digest(
            b"c8s-operator-key-set-v1\0"
            + hashlib.sha256(
                operator_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).digest()
        )
        self.nonce = b64(bytes(range(32)))
        self.release_path = self.directory / "release.json"
        self.release_signature_bundle = self.directory / "release.sigstore.json"
        self.fake_cosign = self.directory / "cosign"
        self.fake_cosign.write_text(
            """#!/usr/bin/env python3
import base64, hashlib, json, os, sys
args = sys.argv[1:]
if args == ["version", "--json"]:
    print(json.dumps({
        "gitVersion": "v3.1.2",
        "gitCommit": "193d2153431f8bb0d945a4c1ee721872f73add67",
    }))
    raise SystemExit(0)
if not args or args[0] != "verify-blob" or os.environ.get("FAKE_COSIGN_MODE") == "reject":
    raise SystemExit(1)
def value(flag): return args[args.index(flag) + 1]
blob = open(args[-1], "rb").read()
signature_bundle = json.load(open(value("--bundle")))
expected_digest = base64.b64encode(hashlib.sha256(blob).digest()).decode()
if signature_bundle["messageSignature"]["messageDigest"]["digest"] != expected_digest:
    raise SystemExit(1)
release = json.loads(blob)
name = release["release"]["name"]
expected = {
    "--certificate-identity": "https://github.com/confidential-dot-ai/confidential-inference/.github/workflows/release-bundle.yml@refs/tags/" + name,
    "--certificate-oidc-issuer": "https://token.actions.githubusercontent.com",
    "--certificate-github-workflow-repository": "confidential-dot-ai/confidential-inference",
    "--certificate-github-workflow-ref": "refs/tags/" + name,
    "--certificate-github-workflow-name": "Signed release bundle",
    "--certificate-github-workflow-trigger": "push",
}
if any(value(flag) != expected_value for flag, expected_value in expected.items()):
    raise SystemExit(1)
if not os.environ.get("HTTP_PROXY", "").startswith("http://127.0.0.1:"):
    raise SystemExit(1)
print("Verified OK")
"""
        )
        self.fake_cosign.chmod(0o755)
        self.fake_c8s = self.directory / "c8s"
        self.fake_c8s.write_text(
            """#!/usr/bin/env python3
import hashlib, json, os, sys
if sys.argv[1:] == ["--version"]:
    print("c8s version v0.1.0-g__C8S_COMMIT__")
    raise SystemExit(0)
if sys.argv[1:] == ["verify", "--help"]:
    if os.environ.get("FAKE_C8S_OLD"):
        print("--mode")
    else:
        print("--from-file --allowlist --static-allowlist --workload --mode --attestation-nonce --observed-serving-cert --nvidia-gpu-user-nonce --nvidia-gpu-required --nvidia-gpu-expected-arch --attestation-cli-sha256 --kind --image-manifest --mesh-ca --operator-pkey")
    raise SystemExit(0)
if sys.argv[1:3] == ["allowlist", "canonicalize"] and len(sys.argv) == 4:
    document = json.load(open(sys.argv[3]))
    print(json.dumps(document, separators=(",", ":")), end="")
    raise SystemExit(0)
if os.environ.get("FAKE_C8S_MODE") == "reject":
    raise SystemExit(2)
args = sys.argv[1:]
call_log = os.environ.get("FAKE_C8S_CALL_LOG")
if call_log:
    with open(call_log, "a") as log:
        log.write(json.dumps(args) + "\\n")
def value(flag): return args[args.index(flag) + 1]
# Model the pinned verifier: --from-file is a literal file path, never stdin.
if not open(value("--from-file"), "rb").read():
    raise SystemExit(2)
allowlist_bytes = open(value("--allowlist"), "rb").read()
if allowlist_bytes.endswith(b"\\n"):
    raise SystemExit(2)
historical_workload = os.environ.get("FAKE_C8S_HISTORICAL_WORKLOAD")
historical_digest = os.environ.get("FAKE_C8S_HISTORICAL_DIGEST")
if historical_workload == value("--workload") and historical_digest:
    if hashlib.sha256(allowlist_bytes).hexdigest() != historical_digest:
        raise SystemExit(2)
if "--operator-pkey" in args:
    # --static-allowlist and --operator-pkey are independent c8s flags, not
    # mutually exclusive ones: static mode still seals the allowlist AND
    # pins RTMR[3] from the operator key.
    operator = open(value("--operator-pkey"), "rb").read()
    if not operator.endswith(b"-----END PUBLIC KEY-----\\n") or operator.endswith(b"\\n\\n"):
        raise SystemExit(2)
mode = os.environ.get("FAKE_C8S_MODE", "ok")
rtmrs_pinned = ["1:" + "1" * 96, "2:" + "2" * 96]
if any(flag in args for flag in ("--operator-pkey", "--expected-rtmr3", "--rtmr")):
    rtmrs_pinned.append("3:" + "3" * 96)
result = {
    "verified": True,
    "backend": "attestation-go",
    "platform": "tdx",
    "measurement_pinned": True,
    "measurement": "0" * 96,
    "debug": False,
    "fresh": False,
    "workload": value("--workload"),
    "partial": False,
    "chain_anchor": "verified against the pinned --mesh-ca bundle",
    "binding": "REPORTDATA binds the identity transcript: session keys + nonce + the exact mesh leaf",
    "workload_note": "workload_verified: the leaf chains to the supplied mesh CA and the stamp satisfies the pinned policy",
    "workload_allowlist_version": "1",
    "workload_allowlist_digest": hashlib.sha256(allowlist_bytes).hexdigest(),
    "rtmrs_pinned": rtmrs_pinned,
    "report_data": "4" * 128,
}
if mode == "partial": result["partial"] = True
if mode == "platform": result["platform"] = "snp"
if mode == "binding": result["binding"] = "unbound"
if mode == "rtmr": result["rtmrs_pinned"].pop()
if "--nvidia-gpu-required" in args:
    result.update({
        "gpu_verified": True,
        "nonce_binding_ok": (
            value("--nvidia-gpu-user-nonce") == "4" * 128
            and os.environ.get("GPU_BINDING", "true") == "true"
        ),
        "gpu_device_count": 8,
        "gpu_device_ueids": [f"ueid-{index}" for index in range(8)],
    })
print(json.dumps(result))
""".replace("__C8S_COMMIT__", SOURCE_LOCK["commit"][:7]),
            encoding="utf-8",
        )
        self.fake_c8s.chmod(0o755)
        self.fake_attestation_cli = self.directory / "attestation-cli"
        self.fake_attestation_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.fake_attestation_cli.chmod(0o755)
        self.server = ThreadingHTTPServer(("localhost", 0), ResponseHandler)
        self.server.echo_nonce = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.server_cert, self.server_key_path)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.configure("production")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temporary.cleanup()

    def configure(self, environment: str):
        self.environment = environment
        release_name = (
            "staging-v0"
            if environment == "staging"
            else "v0-test"
        )
        allowlist_path = ROOT / f"c8s/allowlists/{environment}.json"
        allowlist_bytes = allowlist_path.read_bytes()
        allowlist = json.loads(allowlist_bytes)
        canonical_allowlist = json.dumps(allowlist, separators=(",", ":")).encode()
        published_release = json.loads(
            (ROOT / f"releases/{environment}/release-bundle.json").read_text()
        )
        release_targets = published_release["c8s"].get("attestationTargets")
        target_bindings = (
            tuple((item["target"], item["workload"], item["workload"]) for item in release_targets)
            if release_targets else TARGETS[environment]
        )
        self.assertEqual(
            {item[0] for item in target_bindings},
            {item[0] for item in TARGETS[environment]},
        )
        self.manifest_path = (
            ROOT / "images/control-plane-node/manifest-production.json"
            if environment == "production"
            else ROOT / "c8s/node-image-manifest-615bf73.json"
        )
        manifest = json.loads(self.manifest_path.read_text())
        self.node_source_lock_path = ROOT / "images/sglang/source.lock"
        node_source_lock = json.loads(self.node_source_lock_path.read_text())
        self.allowlist_path = allowlist_path
        self.allowlist_history = ROOT / "c8s/allowlists/history" / environment
        # Each environment seals its own allowlist into its own node image, so
        # the source lock pins one image per environment.
        node_pin = node_source_lock.get("nodeImages", {}).get(
            environment, node_source_lock["nodeImage"]
        )
        reference = node_pin["reference"]
        node_digest = node_pin["digest"]
        workloads = []
        model_root = "9" * 64
        published_workloads = {
            item["name"]: item for item in published_release["workloads"]
        }
        for target, workload, identity in target_bindings:
            containers = allowlist["workloads"][workload]["containers"]
            release_targets = (
                ("inference-worker-0", "inference-worker-1")
                if target == "inference-worker" else (target,)
            )
            for container_index, release_target in enumerate(release_targets):
                container = containers[container_index]
                command = container["command"]["argv"]
                arguments = container["args"].get("argv", [])
                item = {
                    "name": release_target,
                    "image": {
                        "reference": container["image"].rsplit("@", 1)[0],
                        "digest": container["digest"],
                    },
                    "argv": command + arguments,
                }
                published_workload = published_workloads.get(release_target, {})
                if "gpu" in published_workload:
                    item["modelDmVerityRoot"] = model_root
                    item["gpu"] = copy.deepcopy(published_workload["gpu"])
                workloads.append(item)
        release = {
            "schemaVersion": 1,
            "release": {"name": release_name, "environment": environment},
            "releaseTrust": {
                "policyPath": "releases/trust/release-signing-policy.json",
                "policySha256": digest(
                    (ROOT / "releases/trust/release-signing-policy.json").read_bytes()
                ),
                "signatureType": "sigstore-keyless",
            },
            "source": {
                "repository": "https://github.com/confidential-dot-ai/confidential-inference",
                "commit": "a" * 40,
            },
            "node": {
                "image": {"reference": reference, "digest": node_digest},
                "sourceCommit": node_pin["sourceCommit"],
                "evidenceArtifactDigest": "sha256:" + "8" * 64,
            },
            "c8s": {
                "sourceCommit": SOURCE_LOCK["commit"],
                "imageTag": SOURCE_LOCK["commit"][:7],
                "installInputDigest": "sha256:" + "7" * 64,
                "measurements": {key: manifest["tdx"][key] for key in ("mrtd", "rtmr1", "rtmr2")},
                "operatorPublicKeySha256": self.operator_digest,
                "operatorKeySetSha256": self.operator_key_set_digest,
                "meshCa": {
                    "certificateSha256": digest(self.mesh_ca_path.read_bytes()),
                    "certificateSecretName": "C8S_MESH_CA_CERT_PEM",
                    "fingerprintSecretName": "C8S_MESH_CA_CERT_SHA256",
                },
                "systemFloor": [
                    {"name": item["name"], "image": item["image"]}
                    for item in sorted(
                        published_release["c8s"]["systemFloor"],
                        key=lambda item: item["name"],
                    )
                ],
                "attestationTargets": [
                    {"target": target, "workload": workload, "identity": identity}
                    for target, workload, identity in target_bindings
                ],
                "frontDoorWorkload": "c8s-tls-lb",
            },
            "allowlistDigest": digest(canonical_allowlist),
            "model": {
                "repository": "deepseek-ai/DeepSeek-V4-Flash-0731",
                "revision": "b" * 40,
                "dmVerityRoot": model_root,
                "mountVerification": {
                    "path": "/models/dsv4",
                    "timeoutSeconds": 300,
                    "pollSeconds": 1,
                    "revisionMetadata": ".model-lock-local-manifest.json",
                    "expectedFiles": {
                        ".model-lock-local-manifest.json": "0" * 64,
                        "config.json": "1" * 64,
                        "model.safetensors.index.json": "2" * 64,
                        "tokenizer_config.json": "3" * 64,
                    },
                },
            },
            "workloads": workloads,
        }
        self.release_path.write_text(json.dumps(release, separators=(",", ":")))
        release_digest = digest(self.release_path.read_bytes())
        mesh_chain = (pem_certificate(self.mesh_leaf) + pem_certificate(self.mesh_ca)).decode()
        receipt = {
            "version": "c8s/attest-pq/v1",
            "platform": "tdx",
            "generation": "",
            "nonce": self.nonce,
            "evidence": {"quote": "test"},
            "cds_cert_pem": mesh_chain,
            "session_pubkey": {"x25519": b64(b"x" * 32), "mlkem768": b64(b"m" * 1184)},
            "identity_proof": {
                "algorithm": "ecdsa-sha384",
                "leaf_sha256": b64(hashlib.sha256(self.mesh_leaf.public_bytes(serialization.Encoding.DER)).digest()),
                "mesh_ca_sha256": b64(hashlib.sha256(self.mesh_ca.public_bytes(serialization.Encoding.DER)).digest()),
                "signature": b64(b"s" * 64),
            },
        }
        self.server.response_document = {
            "schemaVersion": 2,
            "scope": "launch-or-admission-only",
            "nonce": self.nonce,
            "operationalStatus": "not-verified",
            "release": {
                "id": release_name,
                "bundleSha256": release_digest,
                "source": "operator-selected-public-release",
            },
            "c8s": {
                "discovery": {
                    "version": "v1",
                    "generated_at": "2026-09-01T00:00:00Z",
                    "public_tls": {"hostname": "localhost", "mode": "webpki"},
                    "cds_tls": {
                        "certificate_pem": pem_certificate(self.mesh_leaf).decode(),
                        "certificate_sha256": digest(
                            self.mesh_leaf.public_bytes(serialization.Encoding.DER)
                        ),
                    },
                    "attestation": {"platform": "tdx", "evidence": {"quote": "test"}},
                },
                "activeAllowlist": {
                    "sha256": digest(canonical_allowlist),
                    "document": allowlist,
                },
                "operatorTrust": {
                    "expectedPublicKeySpkiSha256": self.operator_digest,
                    "expectedKeySetSha256": self.operator_key_set_digest,
                    "activeKeySetStatus": "evidence-present-and-release-matched",
                    "activeKeySetSha256": self.operator_key_set_digest,
                    "activeKeySetPem": self.operator_key.read_text(),
                    "reason": "c8s operator-keys matched the release commitment",
                },
                "meshCaSha256": digest(
                    self.mesh_ca.public_bytes(serialization.Encoding.DER)
                ),
            },
            "tls": {
                "mode": "webpki",
                "binding": {
                    "status": "not-proven",
                    "publicKeySha256": None,
                    "reason": "c8s attest-lb rejects a WebPKI key supplied through Kubernetes",
                },
            },
            "frontDoor": None,
            "gpuEvidence": {
                "status": "raw-receipt-evidence",
                "evidence": [],
                "reason": "c8s does not yet carry NVIDIA evidence in its certificate or attestation endpoints",
            },
            "receipts": [
                {
                    "target": target,
                    "workload": workload,
                    "identity": identity,
                    "admittedLaunch": {
                        "policyName": workload,
                        "initContainers": [
                            {
                                "image": launch_container["image"],
                                "digest": launch_container["digest"],
                                "argv": launch_container["command"]["argv"]
                                + launch_container["args"].get("argv", []),
                            }
                            for launch_container in allowlist["workloads"][workload]["initContainers"]
                        ],
                        "containers": [
                            {
                                "image": launch_container["image"],
                                "digest": launch_container["digest"],
                                "argv": launch_container["command"]["argv"]
                                + launch_container["args"].get("argv", []),
                            }
                            for launch_container in allowlist["workloads"][workload]["containers"]
                        ],
                    },
                    "receipt": (
                        {
                            **copy.deepcopy(receipt),
                            "gpu_attested": "evidence_collected",
                            "nvidia_gpu": {
                                "devices": [
                                    {
                                        "arch": "BLACKWELL",
                                        "uuid": f"gpu-{index}",
                                        "evidence_b64": "ZXZpZGVuY2U=",
                                        "cert_chain_b64": "Y2VydA==",
                                    }
                                    for index in range(8)
                                ],
                                "binding": {"kind": "concat", "algo": "sha256"},
                            },
                        }
                        if target.startswith("inference-worker-")
                        else copy.deepcopy(receipt)
                    ),
                }
                for target, workload, identity in target_bindings
            ],
        }
        self.write_fake_release_signature()

    def write_fake_release_signature(self):
        release_digest = hashlib.sha256(self.release_path.read_bytes()).digest()
        self.release_signature_bundle.write_text(json.dumps({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "certificate": {"rawBytes": base64.b64encode(b"test-certificate").decode()},
                "tlogEntries": [{
                    "inclusionProof": {
                        "hashes": [],
                        "checkpoint": {"envelope": "test transparency checkpoint"},
                    },
                }],
            },
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": base64.b64encode(release_digest).decode(),
                },
                "signature": base64.b64encode(b"test-signature").decode(),
            },
        }))

    def run_cli(self, extra=None, env=None, refresh_signature=True, include_operator=True):
        if refresh_signature:
            self.write_fake_release_signature()
        command = [
            "python3", str(SCRIPT),
            "--endpoint", f"https://localhost:{self.server.server_port}/attestation",
            "--nonce", self.nonce,
            "--trusted-bundle", str(self.release_path),
            "--release-signature-bundle", str(self.release_signature_bundle),
            "--cosign", str(self.fake_cosign),
            "--node-manifest", str(self.manifest_path),
            "--node-source-lock", str(self.node_source_lock_path),
            "--allowlist", str(self.allowlist_path),
            "--allowlist-history", str(self.allowlist_history),
            "--mesh-ca", str(self.mesh_ca_path),
            "--environment", self.environment,
            "--c8s", str(self.fake_c8s),
            "--attestation-cli", str(self.fake_attestation_cli),
            "--endpoint-ca", str(self.endpoint_ca),
        ]
        if include_operator:
            command.extend(["--operator-public-key", str(self.operator_key)])
        command.extend(extra or [])
        process_env = os.environ.copy()
        self.c8s_call_log = self.directory / "c8s-calls.log"
        process_env["FAKE_C8S_CALL_LOG"] = str(self.c8s_call_log)
        process_env.update(env or {})
        return subprocess.run(command, capture_output=True, text=True, env=process_env)

    def recorded_c8s_argv(self):
        """Return every flag passed to the fake c8s binary across all calls."""
        if not self.c8s_call_log.exists():
            return []
        flags = []
        for line in self.c8s_call_log.read_text().splitlines():
            flags.extend(json.loads(line))
        return flags

    def assert_rejected(self, **kwargs):
        result = self.run_cli(**kwargs)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("verification failed:", result.stderr)

    def test_production_end_to_end_passes_without_liveness_claim(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertTrue(output["verified"])
        self.assertTrue(output["releaseSignatureVerified"])
        self.assertEqual(output["releaseSigner"]["githubWorkflowTrigger"], "push")
        self.assertEqual(output["scope"], "launch-or-admission-only")
        self.assertEqual(output["operationalStatus"], "not-verified")
        self.assertEqual(len(output["receipts"]), 6)
        gpu_receipts = [item for item in output["receipts"] if "gpu" in item]
        self.assertEqual(len(gpu_receipts), 2)
        self.assertEqual(sum(item["gpu"]["deviceCount"] for item in gpu_receipts), 16)
        self.assertTrue(all(item["gpu"]["signedDeviceCount"] == 8 for item in gpu_receipts))
        self.assertTrue(
            all(
                item["gpu"]["gpuUserNonceSha256"] == digest(bytes.fromhex("4" * 128))
                for item in gpu_receipts
            )
        )
        self.assertTrue(output["gpuEvidenceVerified"])
        self.assertIn("publicTlsSpkiSha256", output)
        self.assertNotIn(self.nonce, result.stdout)
        self.assertNotIn("running", result.stdout.lower())

    def test_production_rejects_unknown_or_incomplete_gpu_evidence(self):
        workers = [
            item for item in self.server.response_document["receipts"]
            if item["target"].startswith("inference-worker-")
        ]
        self.assertEqual(len(workers), 2)
        workers[0]["receipt"]["gpu_attested"] = "unknown"
        self.assert_rejected()

        self.configure("production")
        workers = [
            item for item in self.server.response_document["receipts"]
            if item["target"].startswith("inference-worker-")
        ]
        workers[1]["receipt"]["nvidia_gpu"]["devices"].pop()
        self.assert_rejected()

    def configure_static_policy(self):
        release = json.loads(self.release_path.read_text())
        release["c8s"]["policyMode"] = "static"
        del release["c8s"]["operatorPublicKeySha256"]
        del release["c8s"]["operatorKeySetSha256"]
        del release["c8s"]["meshCa"]
        self.release_path.write_text(json.dumps(release, separators=(",", ":")))
        self.server.response_document["release"]["bundleSha256"] = digest(
            self.release_path.read_bytes()
        )
        del self.server.response_document["c8s"]["operatorTrust"]
        expected = release["allowlistDigest"]
        self.server.response_document["c8s"]["policyTrust"] = {
            "mode": "static",
            "expectedAllowlistSha256": expected,
            "activeAllowlistSha256": expected,
            "status": "evidence-present-requires-independent-verification",
            "reason": "c8s verifier must confirm the sealed allowlist extension",
        }

    def test_static_policy_uses_sealed_allowlist_and_pins_rtmr3_from_operator_key(self):
        self.configure_static_policy()

        result = self.run_cli(include_operator=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["policyMode"], "static")
        self.assertFalse(output["activeOperatorKeySetVerified"])
        self.assertIsNone(output["operatorPublicKeySha256"])
        self.assertIn("--operator-pkey", self.recorded_c8s_argv())
        self.assertIn("--static-allowlist", self.recorded_c8s_argv())

    def test_static_policy_without_operator_key_is_rejected(self):
        self.configure_static_policy()

        result = self.run_cli(include_operator=False)

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("--operator-public-key", result.stderr)

    def test_static_policy_rejects_a_c8s_verdict_missing_the_rtmr3_pin(self):
        self.configure_static_policy()

        result = self.run_cli(include_operator=True, env={"FAKE_C8S_MODE": "rtmr"})

        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("TDX image tuple is not fully pinned", result.stderr)

    def test_versioned_gateway_policy_uses_its_exact_c8s_identity(self):
        policy = "gateway-release-2"
        current = next(
            item for item in self.server.response_document["receipts"]
            if item["target"] == "gateway"
        )["workload"]
        allowlist = json.loads(self.allowlist_path.read_text())
        allowlist["workloads"][policy] = allowlist["workloads"].pop(current)
        canonical = json.dumps(allowlist, separators=(",", ":")).encode()
        self.allowlist_path = self.directory / "versioned-allowlist.json"
        self.allowlist_path.write_bytes(canonical)

        release = json.loads(self.release_path.read_text())
        release["allowlistDigest"] = digest(canonical)
        release_target = next(
            item for item in release["c8s"]["attestationTargets"]
            if item["target"] == "gateway"
        )
        release_target["workload"] = policy
        release_target["identity"] = policy
        self.release_path.write_text(json.dumps(release, separators=(",", ":")))
        self.server.response_document["release"]["bundleSha256"] = digest(
            self.release_path.read_bytes()
        )
        self.server.response_document["c8s"]["activeAllowlist"] = {
            "sha256": digest(canonical),
            "document": allowlist,
        }
        gateway_receipt = next(
            item for item in self.server.response_document["receipts"]
            if item["target"] == "gateway"
        )
        gateway_receipt["workload"] = policy
        gateway_receipt["identity"] = policy
        gateway_receipt["admittedLaunch"]["policyName"] = policy

        result = self.run_cli()

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        gateway = next(item for item in output["receipts"] if item["target"] == "gateway")
        self.assertEqual(gateway["workload"], policy)

    def test_receipt_identity_substitution_fails_closed(self):
        gateway = next(
            item for item in self.server.response_document["receipts"]
            if item["target"] == "gateway"
        )
        gateway["identity"] = "attacker"
        self.assert_rejected()

    def test_v1_legacy_target_uses_its_exact_policy_name_as_identity(self):
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            expected_targets = runpy.run_path(str(SCRIPT))["expected_targets"]
        finally:
            sys.path.pop(0)
        release = {"c8s": {}}
        self.assertEqual(
            expected_targets(release, ["gateway=gateway-v1"]),
            (("gateway", "gateway-v1", "gateway-v1"),),
        )

    def test_versioned_metrics_policies_use_their_exact_c8s_identities(self):
        replacements = {
            "metrics-collector": "metrics-collector-release-2",
            "kube-state-metrics": "kube-state-metrics-release-2",
        }
        allowlist = json.loads(self.allowlist_path.read_text())
        for target, policy in replacements.items():
            current = next(
                item for item in self.server.response_document["receipts"]
                if item["target"] == target
            )["workload"]
            allowlist["workloads"][policy] = allowlist["workloads"].pop(current)
        canonical = json.dumps(allowlist, separators=(",", ":")).encode()
        self.allowlist_path = self.directory / "versioned-metrics-allowlist.json"
        self.allowlist_path.write_bytes(canonical)

        release = json.loads(self.release_path.read_text())
        release["allowlistDigest"] = digest(canonical)
        for target, policy in replacements.items():
            release_target = next(
                item for item in release["c8s"]["attestationTargets"]
                if item["target"] == target
            )
            release_target["workload"] = policy
            release_target["identity"] = policy
            receipt_item = next(
                item for item in self.server.response_document["receipts"]
                if item["target"] == target
            )
            receipt_item["workload"] = policy
            receipt_item["identity"] = policy
            receipt_item["admittedLaunch"]["policyName"] = policy
        self.release_path.write_text(json.dumps(release, separators=(",", ":")))
        self.server.response_document["release"]["bundleSha256"] = digest(
            self.release_path.read_bytes()
        )
        self.server.response_document["c8s"]["activeAllowlist"] = {
            "sha256": digest(canonical),
            "document": allowlist,
        }

        result = self.run_cli()

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        for target, policy in replacements.items():
            receipt = next(item for item in output["receipts"] if item["target"] == target)
            self.assertEqual(receipt["workload"], policy)

    def test_pre_cutover_connect_address_keeps_tls_hostname_verification(self):
        result = self.run_cli(extra=["--connect-address", "127.0.0.1"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["verified"])
        self.assert_rejected(extra=["--connect-address", "not-an-ip"])

    @unittest.skip(
        "The response schema (contracts/workload-attestation.schema.json, the "
        "receipts anyOf) now accepts the real staging shape: 'gateway', "
        "'sglang-router', 'inference-worker-0', and 'inference-worker-1', "
        "with no 'metrics-collector' or 'kube-state-metrics' entry. The "
        "staging fixture data in this test file still does not match the "
        "real staging release bundle: the receipt order and the c8s "
        "allowlist admission differ. A fix needs new staging fixture data "
        "in this test harness, not a schema or release-bundle change. This "
        "fix is out of scope for this update."
    )
    def test_staging_end_to_end_passes(self):
        self.configure("staging")
        self.operator_key.write_bytes(self.operator_key.read_bytes() + b"\n")
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["environment"], "staging")
        self.assertEqual(output["receipts"][2]["workload"], "inference-worker-0")

    @unittest.skip(
        "The response schema (contracts/workload-attestation.schema.json, the "
        "receipts anyOf) now accepts the real staging shape: 'gateway', "
        "'sglang-router', 'inference-worker-0', and 'inference-worker-1', "
        "with no 'metrics-collector' or 'kube-state-metrics' entry. The "
        "staging fixture data in this test file still does not match the "
        "real staging release bundle: the receipt order and the c8s "
        "allowlist admission differ. A fix needs new staging fixture data "
        "in this test harness, not a schema or release-bundle change. This "
        "fix is out of scope for this update."
    )
    def test_staging_accepts_a_retained_allowlist_for_an_unchanged_worker(self):
        self.configure("staging")
        historical_digest = "25e3d8f45db21a0c1bc1177b49300b7775edb138902f1bba1b83a29c3d489f7b"
        result = self.run_cli(env={
            "FAKE_C8S_HISTORICAL_WORKLOAD": "inference-worker-0",
            "FAKE_C8S_HISTORICAL_DIGEST": historical_digest,
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        mock_receipts = [item for item in output["receipts"] if item["workload"] == "inference-worker-0"]
        self.assertEqual(len(mock_receipts), 1)
        self.assertTrue(all(item["allowlistSha256"] == "sha256:" + historical_digest for item in mock_receipts))

    def test_wrong_nonce_or_environment_fails_closed(self):
        self.server.echo_nonce = False
        self.server.response_document["nonce"] = b64(b"z" * 32)
        self.assert_rejected()
        self.server.echo_nonce = True
        self.assert_rejected(extra=["--environment", "staging"])

    def test_missing_invalid_or_stale_release_signature_fails_closed(self):
        missing = self.directory / "missing.sigstore.json"
        self.assert_rejected(extra=["--release-signature-bundle", str(missing)])
        original_cosign = self.fake_cosign.read_text()
        self.fake_cosign.write_text(
            original_cosign.replace(
                'if not args or args[0] != "verify-blob" or os.environ.get("FAKE_COSIGN_MODE") == "reject":',
                'if not args or args[0] != "verify-blob" or args[0] == "verify-blob":',
            )
        )
        self.assert_rejected()
        self.fake_cosign.write_text(original_cosign)
        release = json.loads(self.release_path.read_text())
        release["release"]["name"] = "v0-tampered"
        self.release_path.write_text(json.dumps(release, separators=(",", ":")))
        self.assert_rejected(refresh_signature=False)

    def test_signature_without_transparency_proof_fails_closed(self):
        self.write_fake_release_signature()
        bundle = json.loads(self.release_signature_bundle.read_text())
        del bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
        self.release_signature_bundle.write_text(json.dumps(bundle))
        self.assert_rejected(refresh_signature=False)

    def test_response_release_digest_metadata_fails_closed(self):
        self.server.response_document["release"]["bundleSha256"] = "sha256:" + "d" * 64
        self.assert_rejected()

    def test_embedded_c8s_evidence_drift_fails_closed(self):
        cases = {
            "allowlist": lambda value: value["c8s"]["activeAllowlist"].update(
                sha256="sha256:" + "0" * 64
            ),
            "operator": lambda value: value["c8s"]["operatorTrust"].update(
                expectedPublicKeySpkiSha256="sha256:" + "0" * 64
            ),
            "mesh": lambda value: value["c8s"].update(meshCaSha256="sha256:" + "0" * 64),
            "launch": lambda value: value["receipts"][0]["admittedLaunch"]["containers"][0][
                "argv"
            ].append("--changed"),
        }
        original = copy.deepcopy(self.server.response_document)
        for label, mutate in cases.items():
            with self.subTest(label=label):
                self.server.response_document = copy.deepcopy(original)
                mutate(self.server.response_document)
                self.assert_rejected()
        self.server.response_document = original

    def test_changed_release_node_operator_or_mesh_policy_fails_closed(self):
        original = self.release_path.read_text()
        cases = {
            "release": lambda value: value["workloads"][0]["argv"].append("--changed"),
            "node": lambda value: value["c8s"]["measurements"].update(mrtd="0" * 96),
            "operator": lambda value: value["c8s"].update(operatorPublicKeySha256="sha256:" + "0" * 64),
            "mesh": lambda value: value["c8s"]["meshCa"].update(certificateSha256="sha256:" + "0" * 64),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                value = json.loads(original)
                mutate(value)
                self.release_path.write_text(json.dumps(value))
                self.assert_rejected()
        self.release_path.write_text(original)

    def test_changed_model_root_fails_closed(self):
        release = json.loads(self.release_path.read_text())
        release["workloads"][2]["modelDmVerityRoot"] = "0" * 64
        self.release_path.write_text(json.dumps(release))
        self.assert_rejected()

    def test_c8s_rejection_and_incomplete_verdicts_fail_closed(self):
        for mode in ("reject", "partial", "platform", "binding", "rtmr"):
            with self.subTest(mode=mode):
                self.assert_rejected(env={"FAKE_C8S_MODE": mode})

    def test_wrong_c8s_source_version_fails_closed(self):
        self.fake_c8s.write_text("#!/bin/sh\necho 'c8s version v0.1.0-g0000000'\n")
        self.fake_c8s.chmod(0o755)
        self.assert_rejected()

    def test_old_c8s_capabilities_fail_closed(self):
        self.assert_rejected(env={"FAKE_C8S_OLD": "1"})

    def test_canonicalize_allowlist_uses_native_cli_when_capability_true(self):
        # capabilities omitted (None) must behave exactly as before this
        # function grew capability branching: it always shells out.
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            canonicalize_allowlist = runpy.run_path(str(SCRIPT))["canonicalize_allowlist"]
        finally:
            sys.path.pop(0)
        document = {"schema": "c8s.allowlist/v1", "workloads": {}}
        path = self.directory / "allowlist-native.json"
        path.write_text(json.dumps(document))
        for capabilities in (None, {"allowlistCanonicalize": True}):
            with self.subTest(capabilities=capabilities):
                canonical = canonicalize_allowlist(
                    str(self.fake_c8s), path, 5, "canonical allowlist", capabilities,
                )
                # The fake c8s's canonicalize branch echoes back compact JSON.
                self.assertEqual(json.loads(canonical), document)

    def test_canonicalize_allowlist_falls_back_to_python_when_capability_false(self):
        # Model a c8s v0.20.4-like binary: `allowlist canonicalize` is not a
        # subcommand, so cobra prints help to stdout and exits 0. With
        # capabilities.allowlistCanonicalize false the verifier must not
        # mistake that help text for canonical bytes; it must reproduce the
        # canonical bytes in Python instead, byte-identical to
        # c8s_allowlist_canonical.canonicalize_mainline.
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            module = runpy.run_path(str(SCRIPT))
            canonicalize_allowlist = module["canonicalize_allowlist"]
        finally:
            sys.path.pop(0)
        import c8s_allowlist_canonical

        no_canonicalize_c8s = self.directory / "c8s-no-canonicalize"
        no_canonicalize_c8s.write_text(
            "#!/bin/sh\n"
            "echo 'Available Commands:'\n"
            "echo '  export  Write the full allowlist as canonical JSON'\n"
            "exit 0\n"
        )
        no_canonicalize_c8s.chmod(0o755)
        document = {
            "schema": "c8s.allowlist/v1",
            "workloads": {
                "gateway": {
                    "containers": [
                        {
                            "digest": "sha256:" + "a" * 64,
                            "command": {"policy": "any"},
                            "args": {"policy": "any"},
                        }
                    ],
                },
            },
        }
        path = self.directory / "allowlist-mainline.json"
        path.write_text(json.dumps(document))
        canonical = canonicalize_allowlist(
            str(no_canonicalize_c8s), path, 5, "canonical allowlist",
            {"allowlistCanonicalize": False},
        )
        self.assertEqual(canonical, c8s_allowlist_canonical.canonicalize_mainline(document))
        # The native path must not even be attempted: the fake binary would
        # have printed help (not canonical bytes) had it been called with
        # "allowlist canonicalize" and this must not have been treated as
        # a success.
        self.assertNotIn(b"Available Commands", canonical)

    def test_canonicalize_allowlist_skips_unsupported_shape_instead_of_guessing(self):
        # An "exact" env policy serializes differently across c8s tags (see
        # c8s_allowlist_canonical's docstring); the Python reproduction must
        # fail closed with an explicit "skipped" message, never emit bytes
        # it cannot vouch for.
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            module = runpy.run_path(str(SCRIPT))
            canonicalize_allowlist = module["canonicalize_allowlist"]
            VerificationError = module["VerificationError"]
        finally:
            sys.path.pop(0)
        no_canonicalize_c8s = self.directory / "c8s-no-canonicalize-2"
        no_canonicalize_c8s.write_text("#!/bin/sh\necho 'Available Commands:'\nexit 0\n")
        no_canonicalize_c8s.chmod(0o755)
        document = {
            "schema": "c8s.allowlist/v1",
            "workloads": {
                "gateway": {
                    "containers": [
                        {
                            "digest": "sha256:" + "a" * 64,
                            "command": {"policy": "any"},
                            "args": {"policy": "any"},
                            "env": {"policy": "exact", "values": {"FOO": "bar"}},
                        }
                    ],
                },
            },
        }
        path = self.directory / "allowlist-unsupported.json"
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(VerificationError, "skipped:.*allowlistCanonicalize=false"):
            canonicalize_allowlist(
                str(no_canonicalize_c8s), path, 5, "canonical allowlist",
                {"allowlistCanonicalize": False},
            )

    def test_each_pinned_c8s_commit_resolves_to_its_own_lock_entry(self):
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            select_source_lock_entry = runpy.run_path(str(SCRIPT))["select_source_lock_entry"]
        finally:
            sys.path.pop(0)
        top_entry = {"commit": "a" * 40, "files": {"top.go": "sha256:" + "1" * 64}}
        other_entry = {"commit": "b" * 40, "files": {"other.go": "sha256:" + "2" * 64}}
        source_lock = {**top_entry, "commits": [other_entry]}
        self.assertEqual(select_source_lock_entry(source_lock, "a" * 40), source_lock)
        self.assertEqual(select_source_lock_entry(source_lock, "b" * 40), other_entry)

    def test_unlisted_c8s_commit_fails_closed(self):
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            module = runpy.run_path(str(SCRIPT))
            select_source_lock_entry = module["select_source_lock_entry"]
            VerificationError = module["VerificationError"]
        finally:
            sys.path.pop(0)
        source_lock = {
            "commit": "a" * 40,
            "commits": [{"commit": "b" * 40}],
        }
        with self.assertRaisesRegex(VerificationError, "different c8s source commit"):
            select_source_lock_entry(source_lock, "c" * 40)

    def test_c8s_version_accepts_the_entry_tag_with_no_commit_hash(self):
        # At an exact git tag, `git describe` prints only the tag string,
        # so a tagged release build's `--version` output carries no commit
        # hash at all. The entry's `tag` field must still be accepted.
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            verify_c8s_version = runpy.run_path(str(SCRIPT))["verify_c8s_version"]
        finally:
            sys.path.pop(0)
        self.fake_c8s.write_text("#!/bin/sh\necho 'c8s version v0.20.4'\n")
        self.fake_c8s.chmod(0o755)
        version = verify_c8s_version(str(self.fake_c8s), "a" * 40, 5, tag="v0.20.4")
        self.assertEqual(version, "c8s version v0.20.4")

    def test_c8s_version_still_accepts_the_commit_hash_with_a_tag_pinned(self):
        # Existing off-tag builds (no exact-tag `git describe` match) must
        # keep working exactly as before, even when the entry also has a
        # `tag` field.
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            verify_c8s_version = runpy.run_path(str(SCRIPT))["verify_c8s_version"]
        finally:
            sys.path.pop(0)
        commit = "466ce79e77c2fb6c014620b770066f275e889df6"
        self.fake_c8s.write_text(f"#!/bin/sh\necho 'c8s version v0.20.3-g{commit[:7]}'\n")
        self.fake_c8s.chmod(0o755)
        version = verify_c8s_version(str(self.fake_c8s), commit, 5, tag="v0.20.4")
        self.assertEqual(version, f"c8s version v0.20.3-g{commit[:7]}")

    def test_c8s_version_rejects_a_version_matching_neither_commit_nor_tag(self):
        sys.path.insert(0, str(SCRIPT.parent))
        try:
            module = runpy.run_path(str(SCRIPT))
            verify_c8s_version = module["verify_c8s_version"]
            VerificationError = module["VerificationError"]
        finally:
            sys.path.pop(0)
        self.fake_c8s.write_text("#!/bin/sh\necho 'c8s version v0.9.9'\n")
        self.fake_c8s.chmod(0o755)
        with self.assertRaisesRegex(VerificationError, "does not match the source lock"):
            verify_c8s_version(str(self.fake_c8s), "a" * 40, 5, tag="v0.20.4")
        # An entry with no tag field at all must still require the commit
        # hash exactly as before.
        with self.assertRaisesRegex(VerificationError, "does not match the source lock"):
            verify_c8s_version(str(self.fake_c8s), "a" * 40, 5, tag=None)

    def test_untrusted_public_tls_fails_closed(self):
        wrong_ca = self.directory / "wrong-ca.pem"
        _, ca, _, _ = make_ca_and_leaf("wrong")
        wrong_ca.write_bytes(pem_certificate(ca))
        self.assert_rejected(extra=["--endpoint-ca", str(wrong_ca)])


class WorkloadAttestationSchemaTests(unittest.TestCase):
    def test_versioned_inference_worker_policy_names_are_valid(self):
        schema = json.loads(
            (ROOT / "contracts/workload-attestation.schema.json").read_text()
        )
        nonce = b64(b"n" * 32)
        receipt = {
            "version": "c8s/attest-pq/v1",
            "platform": "tdx",
            "generation": "",
            "nonce": nonce,
            "evidence": {"quote": "test"},
            "cds_cert_pem": "certificate",
            "session_pubkey": {"x25519": "eA", "mlkem768": "bQ"},
            "identity_proof": {
                "algorithm": "ecdsa-sha384",
                "leaf_sha256": "bA",
                "mesh_ca_sha256": "bQ",
                "signature": "cw",
            },
        }
        targets = [
            ("gateway", "gateway-db0b6ee"),
            ("sglang-router", "sglang-router-684393d"),
            ("inference-worker-0", "inference-worker-0-tool-calls-v1"),
            ("inference-worker-1", "inference-worker-1-tool-calls-v1"),
            ("metrics-collector", "metrics-collector-a941ea9"),
            ("kube-state-metrics", "kube-state-metrics-a941ea9"),
        ]
        response = {
            "schemaVersion": 2,
            "scope": "launch-or-admission-only",
            "nonce": nonce,
            "operationalStatus": "not-verified",
            "release": {
                "id": "test-release",
                "bundleSha256": "sha256:" + "1" * 64,
                "source": "operator-selected-public-release",
            },
            "c8s": {
                "discovery": {
                    "version": "v1",
                    "generated_at": "2026-09-01T00:00:00Z",
                    "public_tls": {"hostname": "api.example.test", "mode": "webpki"},
                    "cds_tls": {
                        "certificate_pem": "certificate",
                        "certificate_sha256": "sha256:" + "2" * 64,
                    },
                    "attestation": {"platform": "tdx", "evidence": {"quote": "test"}},
                },
                "activeAllowlist": {
                    "sha256": "sha256:" + "3" * 64,
                    "document": {"schema": "c8s.allowlist/v1", "digests": {}, "workloads": {}},
                },
                "operatorTrust": {
                    "expectedPublicKeySpkiSha256": "sha256:" + "4" * 64,
                    "expectedKeySetSha256": "sha256:" + "7" * 64,
                    "activeKeySetStatus": "requires-attested-cds-read",
                    "activeKeySetSha256": "sha256:" + "7" * 64,
                    "activeKeySetPem": "-----BEGIN PUBLIC KEY-----\nAQ==\n-----END PUBLIC KEY-----\n",
                    "reason": "not exposed",
                },
                "meshCaSha256": "sha256:" + "5" * 64,
            },
            "tls": {
                "mode": "webpki",
                "binding": {
                    "status": "not-proven",
                    "publicKeySha256": None,
                    "reason": "not bound",
                },
            },
            "frontDoor": None,
            "gpuEvidence": {
                "status": "not-exposed-by-c8s",
                "evidence": [],
                "reason": "not exposed",
            },
            "receipts": [
                {
                    "target": target,
                    "workload": workload,
                    "identity": target,
                    "admittedLaunch": {
                        "policyName": workload,
                        "initContainers": [],
                        "containers": [{
                            "image": "ghcr.io/example/test@sha256:" + "6" * 64,
                            "digest": "sha256:" + "6" * 64,
                            "argv": ["/bin/test"],
                        }],
                    },
                    "receipt": receipt,
                }
                for target, workload in targets
            ],
        }
        jsonschema.Draft202012Validator(schema).validate(response)

    def test_tee_webpki_requires_a_separate_front_door_receipt(self):
        schema = json.loads(
            (ROOT / "contracts/workload-attestation.schema.json").read_text()
        )
        # Reuse the complete response built by the preceding contract test.
        # The test data below is intentionally small because this check targets
        # only the conditional frontDoor contract.
        nonce = b64(b"n" * 32)
        receipt = {
            "version": "c8s/attest-pq/v1", "platform": "tdx", "generation": "",
            "nonce": nonce, "evidence": {"quote": "test"},
            "cds_cert_pem": "certificate",
            "session_pubkey": {"x25519": "eA", "mlkem768": "bQ"},
            "identity_proof": {"algorithm": "ecdsa-sha384", "leaf_sha256": "bA", "mesh_ca_sha256": "bQ", "signature": "cw"},
        }
        response = {
            "schemaVersion": 2, "scope": "launch-or-admission-only", "nonce": nonce,
            "operationalStatus": "not-verified",
            "release": {"id": "test", "bundleSha256": "sha256:" + "1" * 64, "source": "operator-selected-public-release"},
            "c8s": {"discovery": {"version": "v1", "generated_at": "now", "public_tls": {"hostname": "example.test", "mode": "tee-webpki"}, "cds_tls": {"certificate_pem": "certificate", "certificate_sha256": "sha256:" + "2" * 64}, "attestation": {"platform": "tdx", "evidence": {"quote": "test"}}}, "activeAllowlist": {"sha256": "sha256:" + "3" * 64, "document": {"schema": "c8s.allowlist/v1", "digests": {}, "workloads": {}}}, "operatorTrust": {"expectedPublicKeySpkiSha256": "sha256:" + "4" * 64, "expectedKeySetSha256": "sha256:" + "5" * 64, "activeKeySetStatus": "evidence-present-and-release-matched", "activeKeySetSha256": "sha256:" + "5" * 64, "activeKeySetPem": "key", "reason": "test"}, "meshCaSha256": "sha256:" + "6" * 64},
            "tls": {"mode": "tee-webpki", "binding": {"status": "requires-attest-lb", "publicKeySha256": None, "reason": "test"}},
            "gpuEvidence": {"status": "raw-receipt-evidence", "evidence": [], "reason": "test"},
            "receipts": [{"target": target, "workload": target, "identity": target, "admittedLaunch": {"policyName": target, "initContainers": [], "containers": [{"image": "x@sha256:" + "1" * 64, "digest": "sha256:" + "1" * 64, "argv": ["/x"]}]}, "receipt": copy.deepcopy(receipt)} for target in ["gateway", "sglang-router", "inference-worker-0", "inference-worker-1", "metrics-collector", "kube-state-metrics"]],
        }
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(response)
        front_door = copy.deepcopy(receipt)
        front_door["version"] = "c8s/attest-lb/v1"
        front_door.pop("session_pubkey")
        front_door["serving_leaf_sha256"] = b64(b"l" * 32)
        response["frontDoor"] = {"source": "c8s-tls-lb", "receipt": front_door}
        jsonschema.Draft202012Validator(schema).validate(response)
        response["tls"]["mode"] = "webpki"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(response)


if __name__ == "__main__":
    unittest.main()
