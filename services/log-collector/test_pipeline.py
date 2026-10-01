#!/usr/bin/env python3
"""Run the actual image against local Kubernetes and Loki test servers."""
import datetime
import ctypes
import ctypes.util
import http.server
import ipaddress
import json
import pathlib
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def decode_push(body):
    library = ctypes.CDLL(ctypes.util.find_library("snappy"))
    library.snappy_uncompressed_length.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    library.snappy_uncompress.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
    size = ctypes.c_size_t()
    assert library.snappy_uncompressed_length(body, len(body), ctypes.byref(size)) == 0
    output = ctypes.create_string_buffer(size.value)
    assert library.snappy_uncompress(body, len(body), output, ctypes.byref(size)) == 0

    def fields(data):
        position = 0

        def varint():
            nonlocal position
            value, shift = 0, 0
            while True:
                byte = data[position]
                position += 1
                value |= (byte & 127) << shift
                if byte < 128:
                    return value
                shift += 7

        while position < len(data):
            tag = varint()
            wire = tag & 7
            if wire == 2:
                length = varint()
                value = data[position:position+length]
                position += length
                yield tag >> 3, value
            elif wire == 0:
                varint()
            elif wire in [1, 5]:
                position += 8 if wire == 1 else 4
            else:
                raise ValueError("Unexpected test protobuf wire type")

    streams = []
    for number, data in fields(output.raw[:size.value]):
        if number != 1:
            continue
        stream = {"stream": {}, "values": []}
        for field, value in fields(data):
            if field == 1:
                stream["stream"] = {name: json.loads(text) for name, text in
                                    re.findall(r'(\w+)=("(?:[^"\\]|\\.)*")', value.decode())}
            elif field == 2:
                line = next(text.decode() for tag, text in fields(value) if tag == 2)
                stream["values"].append(["test-timestamp", line])
        streams.append(stream)
    return {"streams": streams}


def main():
    received = []
    reads = []
    paths = []
    stop_streams = threading.Event()
    container = "log-collector-test-" + uuid.uuid4().hex[:12]
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.isoformat().replace("+00:00", "Z")
    lines = ["operational-startup-canary", "authorization=Bearer private-header-canary",
             '"prompt":"private-prompt-canary"', "token prefix Bearer private-token-canary end"]
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "gateway-test", "namespace": "confidential-inference",
                        "uid": "00000000-0000-0000-0000-000000000001",
                        "labels": {"app.kubernetes.io/part-of": "confidential-inference"}},
           "spec": {"nodeName": "node-test", "containers": [
               {"name": "gateway", "image": "test", "ports": [{"containerPort": 9443}, {"containerPort": 9090}]},
               {"name": "cds-attest", "image": "test", "ports": [{"containerPort": 9000}]}]},
           "status": {"phase": "Running", "podIP": "127.0.0.1", "containerStatuses": [
               {"name": "gateway", "containerID": "containerd://test", "ready": True,
                "restartCount": 0, "state": {"running": {"startedAt": timestamp}}}]}}

    class Kubernetes(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def stream(self, body, content_type):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.write(format(len(body), "x").encode()+b"\r\n"+body+b"\r\n")
            self.wfile.flush()
            stop_streams.wait(30)
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            paths.append(self.path)
            path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(path.query)
            if self.headers.get("Authorization") != "Bearer test-token":
                self.send_error(401)
                return
            if path.path == "/version":
                body = json.dumps({"major": "1", "minor": "36", "gitVersion": "v1.36.4"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path.path.endswith("/log"):
                reads.append(query.get("container", [""])[0])
                body = "".join(timestamp + " " + line + "\n" for line in lines).encode()
                self.stream(body, "text/plain")
            elif path.path == "/api/v1/namespaces/confidential-inference/pods":
                if query.get("watch") == ["true"]:
                    bookmark = {"type": "BOOKMARK", "object": {"apiVersion": "v1", "kind": "Pod",
                                "metadata": {"resourceVersion": "1", "annotations": {"k8s.io/initial-events-end": "true"}}}}
                    body = (json.dumps({"type": "ADDED", "object": pod}) + "\n" + json.dumps(bookmark) + "\n").encode()
                    self.stream(body, "application/json")
                    return
                else:
                    body = json.dumps({"apiVersion": "v1", "kind": "PodList", "metadata": {"resourceVersion": "1"}, "items": [pod]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path.path == "/api/v1/namespaces/confidential-inference/pods/gateway-test":
                body = json.dumps(pod).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def log_message(self, *args):
            pass

    class Loki(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(decode_push(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    with tempfile.TemporaryDirectory(prefix="log-collector-test-") as directory:
        root = pathlib.Path(directory)
        root.chmod(0o755)
        sa = root / "serviceaccount"
        client = root / "client"
        sa.mkdir(mode=0o755)
        client.mkdir(mode=0o755)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "collector-test")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
                .not_valid_after(now+datetime.timedelta(hours=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
                .sign(key, hashes.SHA256()))
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        (sa / "token").write_text("test-token")
        (sa / "namespace").write_text("confidential-inference")
        (sa / "ca.crt").write_bytes(cert_pem)
        (client / "tls.crt").write_bytes(cert_pem)
        (client / "tls.key").write_bytes(key_pem)
        for path in list(sa.iterdir())+list(client.iterdir()):
            path.chmod(0o644)
        kube = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Kubernetes)
        kube.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(client / "tls.crt", client / "tls.key")
        kube.socket = context.wrap_socket(kube.socket, server_side=True)
        loki = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Loki)
        loki.daemon_threads = True
        loki_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        loki_tls.load_cert_chain(client / "tls.crt", client / "tls.key")
        loki_tls.load_verify_locations(cafile=sa / "ca.crt")
        loki_tls.verify_mode = ssl.CERT_REQUIRED
        loki.socket = loki_tls.wrap_socket(loki.socket, server_side=True)
        for server in [kube, loki]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            command = ["docker", "run", "--detach", "--name", container, "--network", "host",
                       "--cpus", "1", "--memory", "256m", "--read-only", "--cap-drop", "ALL",
                       "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:uid=65532,gid=65532,size=64m",
                       "--volume", str(sa)+":/var/run/secrets/kubernetes.io/serviceaccount:ro",
                       "--volume", str(client)+":/mnt/c8s-data/admin-client:ro"]
            for key, value in {"KUBE_API_URL": "https://127.0.0.1:"+str(kube.server_port),
                               "LOG_NAMESPACE": "confidential-inference", "LOG_APPLICATION": "confidential-inference",
                               "DEPLOYMENT_ID": "test-deployment",
                               "SSL_CERT_FILE": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
                               "LOKI_URL": "https://127.0.0.1:"+str(loki.server_port)+"/loki/api/v1/push"}.items():
                command += ["-e", key+"="+value]
            command += ["candidate-log-collector:test"]
            subprocess.run(command, check=True, capture_output=True)
            deadline = time.monotonic()+25
            while not received and time.monotonic() < deadline:
                time.sleep(0.2)
            streams = [stream for push in received for stream in push["streams"]]
            values = [value[1].rstrip("\n") for stream in streams for value in stream["values"]]
            if not streams:
                diagnostic = subprocess.check_output(["docker", "logs", container], stderr=subprocess.STDOUT, text=True)
                raise AssertionError("No records reached the test receiver: "+json.dumps({"reads": reads, "paths": paths[-8:]})+diagnostic[-1800:])
            assert "operational-startup-canary" in values, json.dumps(streams)
            assert values.count("operational-startup-canary") == 1, "Several ports duplicated a container log"
            assert not any("private-" in value for value in values), "A sensitive canary left the pipeline"
            assert any("[REDACTED]" in value for value in values), "Bearer redaction did not run"
            assert set(reads) == {"gateway"}, "A helper container was read"
            assert any(urllib.parse.parse_qs(urllib.parse.urlparse(path).query).get("labelSelector") ==
                       ["app.kubernetes.io/part-of=confidential-inference"] for path in paths), "Application selector is missing"
            assert all(stream["stream"].get("deployment")=="test-deployment" for stream in streams)
            assert all(set(stream["stream"]) <= {"deployment", "namespace", "pod", "container"} for stream in streams)
            print(json.dumps({"passed": True, "checks": ["authenticated Kubernetes log reads",
                             "namespace selection", "helper exclusion", "deployment labels",
                             "sensitive-field rejection", "Bearer redaction", "mTLS log delivery",
                             "non-root readonly container", "one read per container with several ports"]}))
        finally:
            subprocess.run(["docker", "rm", "--force", container], capture_output=True)
            stop_streams.set()
            for server in [kube, loki]:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
