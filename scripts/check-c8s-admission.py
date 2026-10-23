#!/usr/bin/env python3
"""Check rendered pod templates against the c8s admission webhook, offline.

    helm template ... | scripts/check-c8s-admission.py -

The node's c8s webhook (C8s internal/webhook, pod_mutator.go and
pod_probes.go at the pinned c8s release) refuses a pod of an injected
namespace that

- sets hostNetwork, hostPID, hostIPC or shareProcessNamespace;
- names a container like an injected one (c8s-cert, c8s-mesh, ...);
- declares the c8s-certs volume as anything but a memory emptyDir, or mounts
  it (or anything at /etc/c8s/certs) into its own containers;
- sets a credential path annotation the injector fixes;
- has a probe the per-pod mesh cannot forward: tcpSocket or grpc, HTTP
  headers, HTTPS, a timeout over 5 s, a mesh port, a named port no port of
  the container declares, a path that is not clean, or an HTTP lifecycle hook.

c8s has no offline command for these checks yet, so this script copies
them. It also checks one deployment rule: a c8s workload (confidential.ai/cw)
whose egress a NetworkPolicy restricts must be allowed TCP 30808, the node's
CDS NodePort, to any address.

It prints one line per refusal and exits 1 when there is any.
"""

from __future__ import annotations

import posixpath
import re
import sys
from pathlib import Path

import yaml

INJECTED = {"c8s-cert", "c8s-secret", "c8s-volume", "c8s-cert-wait", "c8s-mesh"}
CERT_VOLUME = "c8s-certs"
CERT_DIR = "/etc/c8s/certs"
CREDENTIAL_ANNOTATIONS = tuple(f"confidential.ai/c8s-{name}" for name in (
    "cert-volume", "cert-dir", "cert-file", "key-file", "ca-file"))
MESH_PORTS = {15001, 15006, 15021}
MESH_PROBE_TIMEOUT = 5
PROBE_PATH = re.compile(r"^(/[A-Za-z0-9\-._~]*)+$")
CDS_PORT = 30808
POD_TEMPLATE_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}


def pods(documents: list[dict]):
    """(name, pod metadata, pod spec) of every pod or pod template."""
    for item in documents:
        kind, name = item.get("kind"), f"{item.get('kind')}/{item.get('metadata', {}).get('name')}"
        if kind == "Pod":
            yield name, item.get("metadata", {}), item.get("spec", {})
        elif kind in POD_TEMPLATE_KINDS:
            template = item["spec"]["template"]
            yield name, template.get("metadata", {}), template.get("spec", {})
        elif kind == "CronJob":
            template = item["spec"]["jobTemplate"]["spec"]["template"]
            yield name, template.get("metadata", {}), template.get("spec", {})


def forwardable_path(path: str) -> bool:
    cleaned = posixpath.normpath(path) if path != "/" else "/"
    return (cleaned == path or (cleaned != "/" and cleaned + "/" == path)) and PROBE_PATH.fullmatch(path) is not None


def probe_problem(container: dict, probe: dict) -> str | None:
    if "tcpSocket" in probe or "grpc" in probe:
        return "tcpSocket and grpc probes cannot be forwarded; use an HTTP probe"
    get = probe.get("httpGet")
    if get is None or get.get("host"):
        return None
    if get.get("httpHeaders"):
        return "forwarded probes require empty httpHeaders"
    if probe.get("timeoutSeconds", 1) > MESH_PROBE_TIMEOUT:
        return f"timeoutSeconds {probe['timeoutSeconds']} exceeds the mesh's {MESH_PROBE_TIMEOUT} s probe budget"
    if get.get("scheme", "HTTP") != "HTTP":
        return f"probe scheme {get['scheme']} cannot be forwarded; use HTTP"
    port = get.get("port")
    if isinstance(port, str) and not port.isdigit():
        declared = {p.get("name"): p["containerPort"] for p in container.get("ports", [])}
        if port not in declared:
            return f"probe port {port!r} is declared by no port of the container"
        port = declared[port]
    if int(port) in MESH_PORTS:
        return f"probe port {port} is a mesh port"
    path = get.get("path") or "/"
    if path.startswith("/probe/"):
        return f"probe path {path!r} is reserved for generated probes"
    if not forwardable_path(path):
        return f"probe path {path!r} must be a clean absolute path of unreserved characters"
    return None


def webhook_refusals(name: str, metadata: dict, spec: dict) -> list[str]:
    found = []
    for field in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"):
        if spec.get(field):
            found.append(f"{name}: sets {field}")
    for annotation in CREDENTIAL_ANNOTATIONS:
        if metadata.get("annotations", {}).get(annotation):
            found.append(f"{name}: sets {annotation}, which the injector fixes")
    for volume in spec.get("volumes", []):
        if volume["name"] == CERT_VOLUME and volume.get("emptyDir", {}).get("medium") != "Memory":
            found.append(f"{name}: volume {CERT_VOLUME} must be a memory emptyDir or omitted")
    for container in spec.get("containers", []):
        if container["name"] in INJECTED:
            found.append(f"{name}: container name {container['name']} is reserved for c8s")
    for container in spec.get("initContainers", []) + spec.get("containers", []):
        if container["name"] in INJECTED:
            continue
        where = f"{name} container {container['name']}"
        for mount in container.get("volumeMounts", []):
            path = mount.get("mountPath", "")
            if mount["name"] == CERT_VOLUME or path == CERT_DIR or path.startswith(CERT_DIR + "/"):
                found.append(f"{where}: mounts {mount['name']} at {path}; the pod's credentials are for c8s only")
        for hook in ("postStart", "preStop"):
            if "httpGet" in container.get("lifecycle", {}).get(hook, {}):
                found.append(f"{where}: HTTP lifecycle hook {hook} cannot be forwarded")
        for kind in ("startupProbe", "readinessProbe", "livenessProbe"):
            if kind in container and (problem := probe_problem(container, container[kind])):
                found.append(f"{where} {kind}: {problem}")
    return found


def selects(selector: dict, labels: dict) -> bool:
    """A Kubernetes label selector match."""
    operators = {
        "In": lambda e: labels.get(e["key"]) in e["values"],
        "NotIn": lambda e: labels.get(e["key"]) not in e["values"],
        "Exists": lambda e: e["key"] in labels,
        "DoesNotExist": lambda e: e["key"] not in labels,
    }
    return (all(labels.get(key) == value for key, value in selector.get("matchLabels", {}).items())
            and all(operators[e["operator"]](e) for e in selector.get("matchExpressions", [])))


def allows_cds(rule: dict) -> bool:
    ports = rule.get("ports")
    port_ok = not ports or any(p.get("protocol", "TCP") == "TCP" and p.get("port") in (CDS_PORT, None)
                               for p in ports)
    peers = rule.get("to")
    return port_ok and (not peers or any("ipBlock" in peer for peer in peers))


def cds_egress_refusals(documents: list[dict]) -> list[str]:
    policies = [d for d in documents if d.get("kind") == "NetworkPolicy"
                and "Egress" in d["spec"].get("policyTypes", ["Egress"] if "egress" in d["spec"] else [])]
    found = []
    for name, metadata, _ in pods(documents):
        if "confidential.ai/cw" not in metadata.get("annotations", {}):
            continue
        selecting = [p for p in policies if selects(p["spec"].get("podSelector", {}), metadata.get("labels", {}))]
        if selecting and not any(allows_cds(rule) for p in selecting for rule in p["spec"].get("egress", [])):
            found.append(f"{name}: no NetworkPolicy allows egress to the CDS NodePort TCP {CDS_PORT} "
                         f"(egress restricted by {', '.join(p['metadata']['name'] for p in selecting)})")
    return found


def refusals(documents: list[dict]) -> list[str]:
    found = [line for name, metadata, spec in pods(documents) for line in webhook_refusals(name, metadata, spec)]
    return found + cds_egress_refusals(documents)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-c8s-admission.py <rendered.yaml|->", file=sys.stderr)
        return 2
    text = sys.stdin.read() if sys.argv[1] == "-" else Path(sys.argv[1]).read_text()
    found = refusals([d for d in yaml.safe_load_all(text) if d])
    for line in found:
        print(line)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
