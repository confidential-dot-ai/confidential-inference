#!/usr/bin/env python3
"""Start each repository image of a rendered release as its pod would, in podman.

    helm template ... > rendered.yaml
    scripts/smoke-images.py rendered.yaml [--image gateway ...]

For each container of a rendered workload that runs a repository image, the
script gives podman what the kubelet would: command and args, env, the user,
group and fsGroup, a read-only root, no capabilities, and the volumes
(ConfigMaps with their rendered data under the kubelet's ..data layout,
Secrets as placeholder files of the keys --secret-key names, emptyDirs as
tmpfs, a placeholder service account token). The pod has no network. A container passes when it is still
running after --seconds, or exited 0. CHECKS replaces the arguments of
images that cannot start without the cluster.

It catches a broken image before a deploy: a config file the image user
cannot read, a missing binary, a config the program refuses.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

REPOSITORY_IMAGES = "ghcr.io/confidential-dot-ai/confidential-inference/"
SERVICE_ACCOUNT = "/var/run/secrets/kubernetes.io/serviceaccount"
# Images that need the cluster (CDS, the c8s volume) to start: the check
# runs the binary with these arguments instead.
CHECKS = {"gateway": ["--help"]}
WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}
FIELD_VALUES = {"metadata.name": "smoke-0", "metadata.namespace": "smoke", "status.podIP": "127.0.0.1",
                "status.hostIP": "127.0.0.1", "spec.nodeName": "smoke-node", "spec.serviceAccountName": "smoke"}


def image_name(image: str) -> str:
    return image.removeprefix(REPOSITORY_IMAGES).split("@")[0].split(":")[0]


def write_volume(root: Path, files: dict[str, str], mode: int, group: int | None) -> None:
    """The kubelet's atomic writer layout: the files in ..data, one symlink per key."""
    data = root / "..data"
    data.mkdir(parents=True)
    for key, content in files.items():
        path = data / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)
        if group is not None:
            os.chown(path, 0, group)
        top = key.split("/")[0]
        if not (root / top).exists():
            (root / top).symlink_to(Path("..data") / top)


def service_account(directory: Path, group: int | None) -> Path:
    """A placeholder of the kubelet's token volume: a token, a CA certificate, the namespace."""
    root = directory / f"service-account-{group}"
    if not root.exists():
        with tempfile.TemporaryDirectory() as keys:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-nodes", "-subj", "/CN=smoke", "-days", "1", "-keyout", f"{keys}/key.pem",
                            "-out", f"{keys}/ca.crt"], capture_output=True, check=True)
            ca = Path(keys, "ca.crt").read_text()
        write_volume(root, {"token": "smoke-placeholder", "ca.crt": ca, "namespace": "smoke"}, 0o644, group)
    return root


def volume_files(volume: dict, config_maps: dict[str, dict], secret_keys: dict[str, list[str]]) -> tuple[dict[str, str], int]:
    if "configMap" in volume:
        source = volume["configMap"]
        data = config_maps.get(source["name"], {})
    elif "secret" in volume:
        source = volume["secret"]
        data = {key: "smoke-placeholder\n" for key in secret_keys.get(source["secretName"], [])}
    else:
        return {}, 0o644
    if source.get("items"):
        data = {item["path"]: data.get(item["key"], "") for item in source["items"]}
    return data, source.get("defaultMode", 0o644)


def env_value(item: dict, config_maps: dict[str, dict]) -> str:
    source = item.get("valueFrom")
    if source is None:
        return str(item.get("value", ""))
    if "fieldRef" in source:
        return FIELD_VALUES.get(source["fieldRef"]["fieldPath"], "smoke")
    if "configMapKeyRef" in source:
        ref = source["configMapKeyRef"]
        return config_maps.get(ref["name"], {}).get(ref["key"], "")
    return "smoke-placeholder"


def podman_args(pod: dict, container: dict, config_maps: dict[str, dict], secret_keys: dict[str, list[str]],
                scratch: Path) -> list[str]:
    pod_security = pod.get("securityContext", {})
    security = {**pod_security, **container.get("securityContext", {})}
    args = ["--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges"]
    if "runAsUser" in security:
        args.append(f"--user={security['runAsUser']}:{security.get('runAsGroup', security['runAsUser'])}")
    group = pod_security.get("fsGroup")
    for extra in ([group] if group is not None else []) + pod_security.get("supplementalGroups", []):
        args.append(f"--group-add={extra}")
    if security.get("readOnlyRootFilesystem"):
        args += ["--read-only", "--read-only-tmpfs=false"]
    if pod.get("hostname"):
        args.append(f"--hostname={pod['hostname']}")
    for item in container.get("env", []):
        args.append(f"--env={item['name']}={env_value(item, config_maps)}")
    if pod.get("automountServiceAccountToken", True):
        args.append(f"--volume={service_account(scratch.parent, group)}:{SERVICE_ACCOUNT}:ro")
    volumes = {volume["name"]: volume for volume in pod.get("volumes", [])}
    for mount in container.get("volumeMounts", []):
        volume = volumes.get(mount["name"], {"emptyDir": {}})
        target = mount["mountPath"]
        if "emptyDir" in volume:
            args.append(f"--mount=type=tmpfs,destination={target},tmpfs-mode=1777")
            continue
        files, mode = volume_files(volume, config_maps, secret_keys)
        source = scratch / f"{container['name']}-{mount['name']}"
        if not source.exists():
            write_volume(source, files, mode, group)
            if group is not None:
                for path in [source, source / "..data"]:
                    os.chown(path, 0, group)
                    path.chmod(0o2775)
        if mount.get("subPath"):
            source = source / mount["subPath"]
        args.append(f"--volume={source}:{target}:{'ro' if mount.get('readOnly') else 'rw'}")
    check = CHECKS.get(image_name(container["image"]))
    command = container.get("command", [])
    if command:
        args.append("--entrypoint=" + json.dumps(command[:1] if check else command))
    return [*args, container["image"], *(check or container.get("args", []))]


def run(podman: str, name: str, args: list[str], seconds: int) -> tuple[bool, str]:
    subprocess.run([podman, "rm", "-f", name], capture_output=True, check=False)
    started = subprocess.run([podman, "run", "-d", f"--name={name}", *args], capture_output=True, text=True, check=False)
    if started.returncode != 0:
        return False, started.stderr
    try:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            state = json.loads(subprocess.run([podman, "inspect", name, "--format", "{{json .State}}"],
                                              capture_output=True, text=True, check=True).stdout)
            if not state["Running"]:
                break
            time.sleep(1)
        logs = subprocess.run([podman, "logs", "--tail", "30", name], capture_output=True, text=True, check=False)
        output = logs.stdout + logs.stderr
        if state["Running"]:
            return True, f"running after {seconds} s"
        if state["ExitCode"] == 0:
            return True, "exited 0"
        return False, f"exited {state['ExitCode']}\n{output}"
    finally:
        subprocess.run([podman, "rm", "-f", name], capture_output=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("rendered", type=Path)
    parser.add_argument("--image", action="append", default=[],
                        help="only this repository image (gateway, sglang, ...); repeatable; default: all")
    parser.add_argument("--secret-key", action="append", default=[], metavar="SECRET/KEY",
                        help="a key of a Secret volume, written as a placeholder file; repeatable")
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--podman", default="podman")
    options = parser.parse_args()
    documents = [d for d in yaml.safe_load_all(options.rendered.read_text()) if d]
    config_maps = {d["metadata"]["name"]: d.get("data", {}) for d in documents if d["kind"] == "ConfigMap"}
    secret_keys: dict[str, list[str]] = {}
    for item in options.secret_key:
        secret, key = item.split("/", 1)
        secret_keys.setdefault(secret, []).append(key)
    failed = 0
    # The kubelet's volume modes, whatever the caller's umask (bin/deploy sets 077).
    os.umask(0o022)
    with tempfile.TemporaryDirectory(prefix="smoke-images-") as directory:
        os.chmod(directory, 0o755)
        for document in documents:
            if document["kind"] not in WORKLOAD_KINDS:
                continue
            pod = document["spec"]["template"]["spec"]
            for container in pod.get("initContainers", []) + pod["containers"]:
                image = container["image"]
                if not image.startswith(REPOSITORY_IMAGES) or (options.image and image_name(image) not in options.image):
                    continue
                scratch = Path(directory) / document["metadata"]["name"]
                scratch.mkdir(exist_ok=True)
                label = f"{document['kind']}/{document['metadata']['name']} {container['name']} ({image_name(image)})"
                ok, detail = run(options.podman, f"smoke-{document['metadata']['name']}-{container['name']}",
                                 podman_args(pod, container, config_maps, secret_keys, scratch), options.seconds)
                print(f"{'ok' if ok else 'FAIL'} {label}: {detail.strip()}", flush=True)
                failed += not ok
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
