#!/usr/bin/env python3
"""Check rendered pod templates against C8s worker admission, offline.

    helm template ... | scripts/check-c8s-admission.py [--cds-port PORT] -

A C8s worker's webhook (internal/webhook pod_mutator.go and pod_floor.go,
internal/podmesh probes.go and floor.go, at the pinned C8s release) refuses a
pod that

- sets hostNetwork, hostPID, hostIPC or shareProcessNamespace;
- names a container like an injected one (c8s-cert, c8s-mesh, ...);
- declares the c8s-certs volume as anything but a memory emptyDir, or mounts
  it (or anything at /etc/c8s/certs) into its own containers;
- sets a credential path annotation the injector fixes;
- has a probe the per-pod mesh cannot forward: tcpSocket or grpc, HTTP
  headers, HTTPS, a timeout over 5 s, a mesh port, a named port no port of
  the container declares, a path that is not clean, an HTTP lifecycle hook,
  or (from C8s v0.99.38) an exec probe or exec lifecycle hook;
- runs a container privileged, with allowPrivilegeEscalation: true, with an
  added capability no allowlist entry may declare (ALL, NET_ADMIN, NET_RAW,
  SETUID, SETGID), or with an explicit runAsUser: 0.

The webhook's confidential-node selector check is left out: a measured worker
configures no selector.

The worker's runtime wrapper (internal/cmds/c8srunc, docs/node-exec-mode.md)
then refuses what the webhook cannot see, and this script checks the parts a
pod spec states:

- an exec probe or an exec lifecycle hook, since no exec reaches a member pod;
- a container with tty or stdin, since the wrapper refuses a terminal and a
  container stdin;
- a container whose user is not an explicit nonzero runAsUser, since root is
  refused and the image's own user is not visible here;
- a uid or gid reserved for a platform role (1337 to 1341).

c8s has no offline command for these checks yet, so this script copies
them. It also checks one deployment rule: a c8s workload (confidential.ai/cw)
whose egress a NetworkPolicy restricts must be allowed TCP to the CDS port
(8443 unless --cds-port says otherwise), with no peer or an ipBlock peer: the
CDS runs as its own VM outside the cluster.

It prints one line per refusal and exits 1 when there is any.
"""

from __future__ import annotations

import argparse
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
CDS_PORT = 8443
UNDECLARABLE_CAPABILITIES = {"ALL", "NET_ADMIN", "NET_RAW", "SETUID", "SETGID"}
RESERVED_IDS = range(1337, 1342)
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
        found += [f"{where}: sets {key}: true; a C8s worker refuses a terminal and container stdin"
                  for key in ("tty", "stdin") if container.get(key)]
        for hook in ("postStart", "preStop"):
            if "httpGet" in container.get("lifecycle", {}).get(hook, {}):
                found.append(f"{where}: HTTP lifecycle hook {hook} cannot be forwarded")
        for kind in ("startupProbe", "readinessProbe", "livenessProbe"):
            if kind in container and (problem := probe_problem(container, container[kind])):
                found.append(f"{where} {kind}: {problem}")
        found += [f"{where}: {problem}" for problem in privilege_problems(spec, container)]
    return found


def privilege_problems(spec: dict, container: dict) -> list[str]:
    """The webhook's privilege floor (podmesh.RefusePrivilegesAboveFloor, rejectRootContainers)."""
    security = container.get("securityContext") or {}
    found = []
    if security.get("privileged"):
        found.append("sets privileged: true")
    if security.get("allowPrivilegeEscalation"):
        found.append("sets allowPrivilegeEscalation: true")
    for capability in (security.get("capabilities") or {}).get("add", []):
        if capability.upper() in UNDECLARABLE_CAPABILITIES:
            found.append(f"adds capability {capability}, which no allowlist entry may declare")
    if effective(spec, container, "runAsUser") == 0:
        found.append("has runAsUser: 0; a C8s worker refuses a root container")
    return found


def effective(spec: dict, container: dict, key: str) -> int | None:
    """The container's value of a securityContext id field, which overrides the pod's."""
    value = (container.get("securityContext") or {}).get(key)
    return value if value is not None else (spec.get("securityContext") or {}).get(key)


def runtime_refusals(name: str, spec: dict) -> list[str]:
    """What the worker's runtime wrapper refuses that a pod spec states.

    The wrapper checks each container's effective uid and gid, so a pod-level
    runAsUser or runAsGroup counts only where a container does not override it.
    """
    pod_security = spec.get("securityContext") or {}
    found = [f"{name}: fsGroup {value} is reserved for a C8s platform role"
             for value in [pod_security.get("fsGroup")] if value in RESERVED_IDS]
    found += [f"{name}: supplemental group {group} is reserved for a C8s platform role"
              for group in pod_security.get("supplementalGroups", []) if group in RESERVED_IDS]
    for container in spec.get("initContainers", []) + spec.get("containers", []):
        if container["name"] in INJECTED:
            continue
        where = f"{name} container {container['name']}"
        if effective(spec, container, "runAsUser") is None:
            found.append(f"{where}: sets no runAsUser; a C8s worker refuses a root container, so set a nonzero uid")
        found += [f"{where}: {key} {value} is reserved for a C8s platform role"
                  for key in ("runAsUser", "runAsGroup") if (value := effective(spec, container, key)) in RESERVED_IDS]
        for hook in ("postStart", "preStop"):
            if "exec" in container.get("lifecycle", {}).get(hook, {}):
                found.append(f"{where}: exec lifecycle hook {hook} cannot run; a C8s worker starts no process in a running container")
        for kind in ("startupProbe", "readinessProbe", "livenessProbe"):
            if "exec" in container.get(kind, {}):
                found.append(f"{where} {kind}: exec probes cannot run; a C8s worker starts no process in a running container")
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


def allows_cds(rule: dict, cds_port: int) -> bool:
    ports = rule.get("ports")
    port_ok = not ports or any(p.get("protocol", "TCP") == "TCP" and p.get("port") in (cds_port, None)
                               for p in ports)
    peers = rule.get("to")
    return port_ok and (not peers or any("ipBlock" in peer for peer in peers))


def cds_egress_refusals(documents: list[dict], cds_port: int) -> list[str]:
    policies = [d for d in documents if d.get("kind") == "NetworkPolicy"
                and "Egress" in d["spec"].get("policyTypes", ["Egress"] if "egress" in d["spec"] else [])]
    found = []
    for name, metadata, _ in pods(documents):
        if "confidential.ai/cw" not in metadata.get("annotations", {}):
            continue
        selecting = [p for p in policies if selects(p["spec"].get("podSelector", {}), metadata.get("labels", {}))]
        if selecting and not any(allows_cds(rule, cds_port) for p in selecting for rule in p["spec"].get("egress", [])):
            found.append(f"{name}: no NetworkPolicy allows egress to the CDS on TCP {cds_port} "
                         f"(egress restricted by {', '.join(p['metadata']['name'] for p in selecting)})")
    return found


def refusals(documents: list[dict], cds_port: int = CDS_PORT) -> list[str]:
    found = []
    for name, metadata, spec in pods(documents):
        found += webhook_refusals(name, metadata, spec) + runtime_refusals(name, spec)
    return found + cds_egress_refusals(documents, cds_port)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check rendered pod templates against C8s worker admission.")
    parser.add_argument("--cds-port", type=int, default=CDS_PORT, help="the port the CDS serves on (default %(default)s)")
    parser.add_argument("rendered", help="rendered manifests, or - for standard input")
    args = parser.parse_args()
    text = sys.stdin.read() if args.rendered == "-" else Path(args.rendered).read_text()
    found = refusals([d for d in yaml.safe_load_all(text) if d], args.cds_port)
    for line in found:
        print(line)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
