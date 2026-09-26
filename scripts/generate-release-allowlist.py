#!/usr/bin/env python3
"""Generate release/allowlist.json with exact environment and mount rules.

Every application container gets `env: exact` and `mounts: exact`. The final
container environment and mount set combine five pinned sources, as the
internal release runbook describes:

1. the image: its `ENV` list, recorded in release/inputs/image-config.json;
2. the pod specification: the chart rendered with release/values.yaml;
3. Kubernetes: the `kubernetes` Service variables and `HOSTNAME`;
4. c8s: the certificate, secret, and volume mounts that its webhook adds;
5. NVIDIA CDI: the driver variables and mounts, recorded for one driver
   version in release/inputs/cdi/.

The script never learns a value from a running container. A value that no
pinned source can give (for example a node IP) is an error.

`c8s allowlist derive` from the pinned c8s release builds each entry, so c8s
itself decides which containers it injects and drops. The c8s core images are
added as unrestricted entries, as the c8s bootstrap seed names them. The
pinned Go tool in tools/c8s-allowlist-canonical writes the canonical bytes,
and `c8s allowlist lint --strict` must pass.

`--refresh-image-config` records the `ENV`, `ENTRYPOINT`, and `CMD` of every
rendered image with crane. Review that diff by hand: it is a release input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "release"
POLICY = RELEASE / "allowlist-policy.json"
CHART = ROOT / "helm/confidential-inference"
CANONICAL_TOOL = ROOT / "tools/c8s-allowlist-canonical"
OCI = re.compile(r"^([^@\s]+)@(sha256:[0-9a-f]{64})$")
C8S_MODULE = "github.com/confidential-dot-ai/c8s/cmd/c8s"
DATA_ROOT = "/mnt/c8s-data/"
DEFAULT_CERT_DIR = "/etc/c8s/certs"
DEFAULT_SECRET_DIR = "/run/c8s/secrets"
DEFAULT_VOLUME_DIR = "/run/c8s/volumes"
GPU_RESOURCE = "nvidia.com/gpu"
# Mirrors c8s internal/secrets InjectedEntrypoints at the pinned commit. CDS
# drops a running container from workload matching when its digest has an
# unrestricted entry and its argv[0] is one of these (WorkloadContainers), so
# a workload entry must not declare such a container.
INJECTED_ENTRYPOINTS = ("get-cert", "get-secret", "get-volume", "/c8s")


class GenerationError(ValueError):
    """The release allowlist cannot be generated from pinned inputs."""


def run(command: list[str], *, stdin: bytes | None = None, cwd: Path = ROOT) -> bytes:
    result = subprocess.run(command, input=stdin, cwd=cwd, capture_output=True, check=False)
    if result.returncode:
        detail = (result.stderr + result.stdout).decode("utf-8", errors="replace").strip()
        raise GenerationError(f"command failed: {' '.join(command)}: {detail}")
    return result.stdout


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GenerationError(f"cannot read {path.relative_to(ROOT) if ROOT in path.parents else path}: {error}") from error


def split_image(image: Any) -> tuple[str, str]:
    match = OCI.fullmatch(image) if isinstance(image, str) else None
    if match is None:
        raise GenerationError(f"a rendered image is not digest-pinned: {image!r}")
    return match.group(1), match.group(2)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


def render_chart(policy: dict[str, Any], values: Path) -> list[dict[str, Any]]:
    chart = policy["chart"]
    output = run([
        "helm", "template", chart["release"], str(CHART),
        "--namespace", chart["namespace"], "--kube-version", chart["kubeVersion"],
        "--values", str(values),
    ]).decode()
    return [item for item in yaml.safe_load_all(output) if isinstance(item, dict)]


def controllers(documents: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        f"{item['kind']}/{item['metadata']['name']}": item
        for item in documents
        if item.get("kind") in {"Deployment", "StatefulSet", "DaemonSet"}
    }


def image_env_list(values: list[str]) -> dict[str, str]:
    """Return the image environment. The runtime keeps the last value of a name."""
    env: dict[str, str] = {}
    for item in values:
        name, separator, value = item.partition("=")
        if not separator or not name:
            raise GenerationError(f"an image ENV entry is malformed: {item!r}")
        env[name] = value
    return env


def kubernetes_env(service_host: str) -> dict[str, str]:
    """The variables of the `kubernetes` Service, added with service links off."""
    address = f"tcp://{service_host}:443"
    return {
        "KUBERNETES_SERVICE_HOST": service_host,
        "KUBERNETES_SERVICE_PORT": "443",
        "KUBERNETES_SERVICE_PORT_HTTPS": "443",
        "KUBERNETES_PORT": address,
        "KUBERNETES_PORT_443_TCP": address,
        "KUBERNETES_PORT_443_TCP_PROTO": "tcp",
        "KUBERNETES_PORT_443_TCP_PORT": "443",
        "KUBERNETES_PORT_443_TCP_ADDR": service_host,
    }


NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def expand(value: str, known: dict[str, str]) -> str:
    """Mirror the kubelet $(VAR) expansion for names defined earlier.

    `$$` is an escaped `$`. `$(NAME)` becomes the value of an earlier name, and
    stays as written when the name is unknown.
    """
    output: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "$" and index + 1 < len(value):
            following = value[index + 1]
            if following == "$":
                output.append("$")
                index += 2
                continue
            if following == "(":
                end = value.find(")", index + 2)
                name = value[index + 2:end] if end != -1 else ""
                if end != -1 and NAME.fullmatch(name):
                    output.append(known.get(name, value[index:end + 1]))
                    index = end + 1
                    continue
        output.append(char)
        index += 1
    return "".join(output)


def pod_name(controller: dict[str, Any]) -> str:
    kind = controller["kind"]
    name = controller["metadata"]["name"]
    pod = controller["spec"]["template"]["spec"]
    if pod.get("hostname"):
        return pod["hostname"]
    if kind == "StatefulSet" and int(controller["spec"].get("replicas", 1)) == 1:
        return f"{name}-0"
    raise GenerationError(
        f"{kind}/{name} has a random pod name, so HOSTNAME is not exact; set spec.template.spec.hostname"
    )


def container_env(
    controller: dict[str, Any],
    container: dict[str, Any],
    image_env: dict[str, list[str]],
    policy: dict[str, Any],
    cdi: dict[str, Any] | None,
) -> dict[str, str]:
    label = f"{controller['kind']}/{controller['metadata']['name']} container {container['name']}"
    pod = controller["spec"]["template"]["spec"]
    if pod.get("enableServiceLinks", True) is not False:
        raise GenerationError(f"{label}: enableServiceLinks must be false")
    image = container["image"]
    if image not in image_env:
        raise GenerationError(f"{label}: release/inputs/image-config.json has no record for {image}")
    env = image_env_list(image_env[image]["env"])
    env["HOSTNAME"] = pod_name(controller)
    env.update(kubernetes_env(policy["kubernetes"]["serviceHost"]))
    if container.get("envFrom"):
        raise GenerationError(f"{label}: envFrom values are not pinned by the release")
    defined: dict[str, str] = {}
    for item in container.get("env", []):
        name = item["name"]
        if "value" in item:
            value = expand(str(item["value"]), defined)
        elif "valueFrom" in item and "fieldRef" in item["valueFrom"]:
            field = item["valueFrom"]["fieldRef"]["fieldPath"]
            if field == "metadata.name":
                value = pod_name(controller)
            elif field == "metadata.namespace":
                value = policy["chart"]["namespace"]
            else:
                raise GenerationError(f"{label}: env {name} reads {field}, which differs per node or pod")
        else:
            raise GenerationError(f"{label}: env {name} has a value the release does not pin")
        defined[name] = value
        env[name] = value
    if requests_gpu(container):
        if cdi is None:
            raise GenerationError(f"{label}: requests GPUs, and the NVIDIA CDI record is absent")
        env.update(cdi["env"])
    return dict(sorted(env.items()))


def effective_process(container: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Merge the pod command and args with the image defaults, as the runtime does.

    A pod `command` replaces ENTRYPOINT and drops CMD; pod `args` replace CMD.
    """
    merged = dict(container)
    if container.get("command"):
        merged["command"] = container["command"]
        merged["args"] = container.get("args") or []
    else:
        entrypoint = config.get("entrypoint") or []
        if not entrypoint:
            raise GenerationError(f"container {container['name']}: the image has no ENTRYPOINT and the pod sets no command")
        merged["command"] = entrypoint
        merged["args"] = container["args"] if container.get("args") else (config.get("cmd") or [])
    if not merged["args"]:
        merged.pop("args", None)
    return merged


def requests_gpu(container: dict[str, Any]) -> bool:
    resources = container.get("resources", {})
    return any(GPU_RESOURCE in resources.get(field, {}) for field in ("limits", "requests"))


def data_rule(destination: str, label: str) -> dict[str, str]:
    if not destination.startswith(DATA_ROOT):
        raise GenerationError(
            f"{label}: a data mount at {destination} must be below {DATA_ROOT} for an exact rule"
        )
    return {"destination": destination, "kind": "data"}


def container_mounts(
    controller: dict[str, Any], container: dict[str, Any], cdi: dict[str, Any] | None
) -> list[dict[str, Any]]:
    label = f"{controller['kind']}/{controller['metadata']['name']} container {container['name']}"
    template = controller["spec"]["template"]
    pod = template["spec"]
    annotations = template.get("metadata", {}).get("annotations", {})
    volumes = {volume["name"]: volume for volume in pod.get("volumes", [])}
    rules: list[dict[str, Any]] = []
    for mount in container.get("volumeMounts", []):
        volume = volumes.get(mount["name"])
        destination = mount["mountPath"]
        if volume is None:
            raise GenerationError(f"{label}: mount {mount['name']} names no pod volume")
        if mount.get("subPath") or mount.get("subPathExpr"):
            rules.append(data_rule(destination, label))
        elif "emptyDir" in volume:
            rules.append({"destination": destination, "kind": "emptyDir"})
        elif "hostPath" in volume:
            rule = {"destination": destination, "kind": "host", "source": volume["hostPath"]["path"]}
            if mount.get("readOnly"):
                rule["readOnly"] = True
            rules.append(rule)
        elif any(key in volume for key in ("configMap", "secret", "projected", "downwardAPI", "persistentVolumeClaim", "csi")):
            rules.append(data_rule(destination, label))
        else:
            raise GenerationError(f"{label}: mount {mount['name']} has a volume type the release cannot classify")
    # c8s adds these to every container of an opted-in pod.
    if "confidential.ai/cw" in annotations:
        rules.append({"destination": annotations.get("confidential.ai/c8s-cert-dir", DEFAULT_CERT_DIR), "kind": "emptyDir"})
        if annotations.get("confidential.ai/c8s-secrets"):
            rules.append({"destination": annotations.get("confidential.ai/c8s-secret-dir", DEFAULT_SECRET_DIR), "kind": "emptyDir"})
        if annotations.get("confidential.ai/c8s-volumes"):
            directory = annotations.get("confidential.ai/c8s-volume-dir", DEFAULT_VOLUME_DIR).rstrip("/")
            for entry in annotations["confidential.ai/c8s-volumes"].split(","):
                name = entry.partition("=")[0]
                rules.append(data_rule(f"{directory}/{name}", label))
    if requests_gpu(container):
        if cdi is None:
            raise GenerationError(f"{label}: requests GPUs, and the NVIDIA CDI record is absent")
        rules.extend(cdi["mounts"])
    destinations = [rule["destination"] for rule in rules]
    if len(set(destinations)) != len(destinations):
        raise GenerationError(f"{label}: two mounts share one destination")
    return sorted(rules, key=lambda rule: rule["destination"])


def read_cdi(policy: dict[str, Any]) -> dict[str, Any] | None:
    record = policy.get("cdi")
    if record is None:
        return None
    path = ROOT / record["input"]
    if not path.is_file():
        return None
    value = read_json(path)
    if value.get("driverVersion") != record["driverVersion"]:
        raise GenerationError(f"{record['input']} records a different driver version")
    for rule in value["mounts"]:
        if rule.get("kind") != "host" or not rule.get("source") or not rule.get("destination"):
            raise GenerationError(f"{record['input']} has a mount that is not an exact host rule")
    return value


# ---------------------------------------------------------------------------
# c8s
# ---------------------------------------------------------------------------


def verify_c8s_binary(executable: Path, commit: str) -> None:
    info = run(["go", "version", "-m", str(executable)]).decode()
    if f"\tpath\t{C8S_MODULE}\n" not in info:
        raise GenerationError("--c8s is not the c8s command binary")
    if f"vcs.revision={commit}" not in info and f"Version={commit}" not in info and "\tmod\tgithub.com/confidential-dot-ai/c8s\tv" not in info:
        raise GenerationError("--c8s was not built from the pinned c8s source commit")


def argv0(container: dict[str, Any]) -> str | None:
    command = container.get("command", {})
    if command.get("policy") == "exact" and command.get("argv"):
        return command["argv"][0]
    return None


def is_carved_out(container: dict[str, Any], core_digests: set[str]) -> bool:
    """Report whether CDS drops this rendered container from workload matching."""
    _reference, digest = split_image(container.get("image"))
    command = container.get("command") or []
    return digest in core_digests and bool(command) and command[0] in INJECTED_ENTRYPOINTS


def derive(
    executable: Path,
    name: str,
    controller: dict[str, Any],
    env_policies: dict[str, Any],
    mount_policies: dict[str, Any],
    secret_reads: list[str],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="release-allowlist-") as directory:
        base = Path(directory)
        (base / "object.json").write_text(json.dumps(controller))
        (base / "env.json").write_text(json.dumps(env_policies))
        (base / "mounts.json").write_text(json.dumps(mount_policies))
        command = [
            str(executable), "allowlist", "derive", name, str(base / "object.json"),
            "--env-file", str(base / "env.json"), "--mounts-file", str(base / "mounts.json"),
            "-o", "json",
        ]
        for path in secret_reads:
            command += ["--secret-read", path]
        entry = json.loads(run(command))
    return entry[name] if name in entry else entry


def floor_entry(image: str) -> tuple[str, dict[str, Any]]:
    """Mirror the c8s seed: one unrestricted entry for each core image."""
    _reference, digest = split_image(image)
    base = image.split("@")[0].rsplit("/", 1)[-1].split(":")[0][:50]
    name = base + "-" + digest.removeprefix("sha256:")[:12]
    return name, {
        "label": image,
        "initContainers": [],
        "containers": [{
            "digest": digest, "image": image,
            "command": {"policy": "any"}, "args": {"policy": "any"},
            "env": {"policy": "any"}, "mounts": {"policy": "any"},
        }],
    }


def canonicalize(document: dict[str, Any], tool: Path | None) -> bytes:
    data = json.dumps(document).encode()
    if tool is not None:
        return run([str(tool), "-"], stdin=data)
    return run(["go", "run", ".", "-"], stdin=data, cwd=CANONICAL_TOOL)


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def generate(policy_path: Path, executable: Path, tool: Path | None) -> bytes:
    policy = read_json(policy_path)
    if policy.get("schema") != "confidential.ai/release-allowlist-policy/v1":
        raise GenerationError("release/allowlist-policy.json has the wrong schema")
    verify_c8s_binary(executable, policy["c8s"]["sourceCommit"])
    rendered = controllers(render_chart(policy, RELEASE / "values.yaml"))
    expected = {item["controller"] for item in policy["workloads"]}
    if set(rendered) != expected:
        raise GenerationError(
            f"the chart workloads differ from the policy: missing={sorted(expected - set(rendered))} "
            f"extra={sorted(set(rendered) - expected)}"
        )
    image_env = read_json(RELEASE / "inputs/image-config.json")
    cdi = read_cdi(policy)
    core_digests = {split_image(image)[1] for image in policy["c8s"]["coreImages"]}
    workloads: dict[str, Any] = {}
    errors: list[str] = []
    for item in sorted(policy["workloads"], key=lambda value: value["name"]):
        controller = rendered[item["controller"]]
        pod = controller["spec"]["template"]["spec"]
        containers = {c["name"]: c for c in pod.get("initContainers", []) + pod.get("containers", [])}
        env_policies: dict[str, Any] = {}
        mount_policies: dict[str, Any] = {}
        for container_name, container in containers.items():
            if is_carved_out(container, core_digests):
                env_policies[container_name] = {"policy": "any"}
                mount_policies[container_name] = {"policy": "any"}
                continue
            try:
                env_policies[container_name] = {
                    "policy": "exact",
                    "values": container_env(controller, container, image_env, policy, cdi),
                }
                rules = container_mounts(controller, container, cdi)
                mount_policies[container_name] = {"policy": "exact", "rules": rules} if rules else {"policy": "deny"}
            except GenerationError as error:
                errors.append(str(error))
        if errors:
            continue
        reads = sorted(set(item.get("secretReads", [])) | set(volume_reads(controller)))
        explicit = json.loads(json.dumps(controller))
        explicit_pod = explicit["spec"]["template"]["spec"]
        for field in ("initContainers", "containers"):
            explicit_pod[field] = [
                effective_process(c, image_env.get(c["image"], {})) for c in explicit_pod.get(field, [])
            ] if field in explicit_pod else []
        entry = derive(executable, item["name"], explicit, env_policies, mount_policies, reads)
        for field in ("initContainers", "containers"):
            entry[field] = [
                c for c in entry.get(field, [])
                if not (c["digest"] in core_digests and argv0(c) in INJECTED_ENTRYPOINTS)
            ]
        workloads[item["name"]] = entry
    if errors:
        raise GenerationError("the release allowlist has unpinned inputs:\n  - " + "\n  - ".join(errors))
    for image in policy["c8s"]["coreImages"]:
        name, entry = floor_entry(image)
        if name in workloads:
            raise GenerationError(f"the core entry {name} collides with a workload")
        workloads[name] = entry
    canonical = canonicalize({"schema": "c8s.allowlist/v1", "workloads": workloads}, tool)
    with tempfile.TemporaryDirectory(prefix="release-allowlist-lint-") as directory:
        candidate = Path(directory) / "allowlist.json"
        candidate.write_bytes(canonical)
        run([str(executable), "allowlist", "lint", "--strict", str(candidate)])
    return canonical


def volume_reads(controller: dict[str, Any]) -> list[str]:
    annotations = controller["spec"]["template"].get("metadata", {}).get("annotations", {})
    encoded = annotations.get("confidential.ai/c8s-volumes", "")
    return sorted({entry.partition("=")[2] for entry in encoded.split(",") if entry})


def refresh_image_config(policy_path: Path) -> dict[str, dict[str, list[str]]]:
    policy = read_json(policy_path)
    images: set[str] = set()
    for controller in controllers(render_chart(policy, RELEASE / "values.yaml")).values():
        pod = controller["spec"]["template"]["spec"]
        for container in pod.get("initContainers", []) + pod.get("containers", []):
            split_image(container["image"])
            images.add(container["image"])
    record = {}
    for image in sorted(images):
        config = json.loads(run(["crane", "config", image])).get("config", {})
        record[image] = {
            "env": config.get("Env") or [],
            "entrypoint": config.get("Entrypoint") or [],
            "cmd": config.get("Cmd") or [],
        }
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=POLICY)
    parser.add_argument("--c8s", type=Path, help="the c8s CLI built from the pinned source commit")
    parser.add_argument("--canonical-tool", type=Path, help="a built tools/c8s-allowlist-canonical binary")
    parser.add_argument("--check", action="store_true", help="fail when release/allowlist.json differs")
    parser.add_argument("--refresh-image-config", action="store_true")
    args = parser.parse_args()
    try:
        if args.refresh_image_config:
            path = RELEASE / "inputs/image-config.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(refresh_image_config(args.policy), indent=2, sort_keys=True) + "\n")
            print(json.dumps({"imageConfig": str(path)}))
            return 0
        if args.c8s is None:
            raise GenerationError("--c8s is required")
        canonical = generate(args.policy, args.c8s.resolve(), args.canonical_tool)
        output = RELEASE / "allowlist.json"
        if args.check:
            if not output.is_file() or output.read_bytes() not in (canonical, canonical + b"\n"):
                raise GenerationError("release/allowlist.json differs from a new generation")
        else:
            output.write_bytes(canonical + b"\n")
    except (GenerationError, OSError, KeyError) as error:
        print(f"generate-release-allowlist: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"allowlist": "release/allowlist.json", "sha256": "sha256:" + hashlib.sha256(canonical).hexdigest()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
