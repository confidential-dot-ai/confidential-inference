#!/usr/bin/env python3
"""Generate the allowlist of a release profile with exact environment and mount rules.

The release build (scripts/build-release-manifest.py) calls `generate` with
the image digests of the release, and publishes the result as the release
asset allowlist.json. The allowlist is not in the repository: it names image
digests and is a build output, like the release manifest.

Every application container gets `env: exact` and `mounts: exact`. The final
container environment and mount set combine five pinned sources, as the
internal release runbook describes:

1. the image: its `ENV` list. release/inputs/image-config.json records it for
   every image that this repository does not build. The release build reads
   it for a repository image from the registry by digest;
2. the pod specification: the chart rendered with the profile values files
   (release/profiles.json) and the image digests of the release;
3. Kubernetes: the `kubernetes` Service variables and `HOSTNAME`;
4. c8s: the certificate, secret, and volume mounts that its webhook adds;
5. NVIDIA CDI: the driver variables and mounts, recorded for one driver
   version in release/inputs/cdi/.

The script never learns a value from a running container. A value that no
pinned source can give (for example a node IP) is an error.

`c8s allowlist derive` from the pinned c8s release builds each entry, so c8s
itself decides which containers it injects and drops. The c8s core entries mirror the bootstrap seed: from c8s v0.47.0 as
the chart renders it, one pinned entry per component shape and the router pod;
before it, one floor entry per core image pinned to its complete image
ENTRYPOINT beside the seed. The
pinned Go tool in tools/c8s-allowlist-canonical writes the canonical bytes,
and `c8s allowlist lint --strict` must pass.

`--refresh-image-config` records the `ENV`, `ENTRYPOINT`, and `CMD` of every
image that any profile renders and this repository does not build, with
crane. All profiles share this record. Review that diff by hand: it is a
release input.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_profiles

ROOT = Path(__file__).resolve().parents[1]
POLICY_SCHEMA = "confidential.ai/release-allowlist-policy/v2"
SEARCH_PATH_FINDING = re.compile(
    r'^error: workload "(?P<entry>[^"]+)" container sha256:[0-9a-f]{64} pins (?P<variable>[A-Z_]+) '
    r'to a search path overlapping (?P<kind>[a-zA-Z]+) mount "(?P<path>[^"]+)"; '
    r'operator-supplied content could be loaded as code$'
)
LINT_SUMMARY = re.compile(r"^(?P<count>[0-9]+) lint (error|warning)\(s\)( with --strict)?$")
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
INJECTED_NAMES = {"c8s-cert", "c8s-cert-wait", "c8s-secret", "c8s-volume"}
INJECTED_MODES = {"get-cert", "probe-file", "get-secret", "get-volume"}
# The pinned node integration uses these NRI socket settings. The mount is
# added to the final OCI spec, so Helm's pod specification does not show it.
CLAIMS_SOCKET_CONSUMERS = {"c8s-cert", "c8s-secret", "c8s-volume", "cds-attest"}
# The first c8s release whose node policy observes the socket directory it
# bind-mounts itself as a platform mount (c8s #915). Earlier releases report it
# as a read-only host mount, which an exact policy must list; from this one a
# host rule for it refuses the secrets grant, and no rule names it.
CLAIMS_SOCKET_PLATFORM_SINCE = (0, 50, 0)
# The first c8s release whose chart seed names one entry per component shape
# (`<image>-<digest>-<shape>`), pins its args and mounts, and seeds the router
# pod's composition (c8s #876, #878). From it the release mirrors the seed as
# it is: a floor entry or a native router entry beside it would leave args,
# mounts or env `any`, which `c8s allowlist lint --strict` refuses.
SEED_PINS_COMPONENTS_SINCE = (0, 47, 0)
CLAIMS_SOCKET_SOURCE = "/var/run/nri-image-policy"
CLAIMS_SOCKET_DESTINATION = "/run/c8s/workload-claims"


def c8s_at_least(release: str | None, version: tuple[int, int, int]) -> bool:
    if release is None:
        return False
    match = re.fullmatch(r"v([0-9]+)\.([0-9]+)\.([0-9]+)(?:-beta\.[1-9][0-9]*)?", release)
    if match is None:
        raise GenerationError(f"unsupported c8s release: {release}")
    return tuple(int(part) for part in match.groups()) >= version


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


def render_chart(
    policy: dict[str, Any], profile: release_profiles.Profile, overlay: Path,
) -> list[dict[str, Any]]:
    """Render the chart with the profile values files in layer order, then the overlay."""
    chart = policy["chart"]
    output = run([
        "helm", "template", chart["release"], str(CHART),
        "--namespace", chart["namespace"], "--kube-version", chart["kubeVersion"],
        *release_profiles.helm_values_args(profile, overlay),
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
        raise GenerationError(f"{label}: the image configuration has no record for {image}")
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
    controller: dict[str, Any], container: dict[str, Any], cdi: dict[str, Any] | None,
    *, c8s_release: str | None = None,
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
        if (c8s_at_least(c8s_release, (0, 44, 6)) and not c8s_at_least(c8s_release, CLAIMS_SOCKET_PLATFORM_SINCE)
                and container["name"] in CLAIMS_SOCKET_CONSUMERS):
            rules.append({"destination": CLAIMS_SOCKET_DESTINATION, "kind": "host",
                          "source": CLAIMS_SOCKET_SOURCE, "readOnly": True})
    if requests_gpu(container):
        if cdi is None:
            raise GenerationError(f"{label}: requests GPUs, and the NVIDIA CDI record is absent")
        rules.extend(cdi["mounts"])
    destinations = [rule["destination"] for rule in rules]
    if len(set(destinations)) != len(destinations):
        raise GenerationError(f"{label}: two mounts share one destination")
    return sorted(rules, key=lambda rule: rule["destination"])


def read_cdi(policy: dict[str, Any], node_image: str) -> dict[str, Any] | None:
    """Read the CDI record. It must list the pinned node image when one is given.

    A record lists every node image that it holds for. scripts/bump-c8s.py adds
    a node image only when the pinned NVIDIA driver inputs did not change.
    """
    record = policy.get("cdi")
    if record is None:
        return None
    path = ROOT / record["input"]
    if not path.is_file():
        return None
    value = read_json(path)
    if value.get("driverVersion") != record["driverVersion"]:
        raise GenerationError(f"{record['input']} records a different driver version")
    if node_image not in value.get("nodeImages", []):
        raise GenerationError(f"{record['input']} does not hold for the node image {node_image}")
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


def is_carved_out(container: dict[str, Any], core_digests: set[str], release: str | None = None) -> bool:
    """Omit injected containers from authored input; retain application sidecars."""
    _reference, digest = split_image(container.get("image"))
    command = container.get("command") or []
    if c8s_at_least(release, (0, 41, 0)):
        argv = command + (container.get("args") or [])
        return (digest in core_digests and container.get("name") in INJECTED_NAMES
                and len(argv) >= 2 and argv[0] == "/c8s" and argv[1] in INJECTED_MODES)
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


def component_entrypoint(image: str, config: dict[str, Any]) -> list[str]:
    """Match component command pins; platform installer rules stay in C8s."""
    repository, _digest = split_image(image)
    entrypoint = list(config.get("entrypoint", []))
    if repository == "nginxinc/nginx-unprivileged":
        cmd = config.get("cmd", [])
        if not cmd or cmd[0] != "nginx":
            raise GenerationError("the nginx core image CMD must start with nginx")
        entrypoint.append(cmd[0])
    return entrypoint


def floor_entry(image: str, entrypoint: list[str] | None = None) -> tuple[str, dict[str, Any]]:
    """Mirror the selected c8s seed, including its component command pins."""
    if entrypoint is not None and (not entrypoint or not all(isinstance(arg, str) and arg for arg in entrypoint)):
        raise GenerationError(f"core image {image} has no valid ENTRYPOINT")
    _reference, digest = split_image(image)
    base = image.split("@")[0].rsplit("/", 1)[-1].split(":")[0][:50]
    name = base + "-" + digest.removeprefix("sha256:")[:12]
    return name, {
        "label": image,
        "initContainers": [],
        "containers": [{
            "digest": digest, "image": image,
            "command": {"policy": "any"} if entrypoint is None else {"policy": "exact", "argv": entrypoint},
            "args": {"policy": "any"},
            "env": {"policy": "any"}, "mounts": {"policy": "any"},
        }],
    }


def core_seed(c8s: dict[str, Any]) -> dict[str, Any]:
    if not c8s_at_least(c8s["release"], (0, 44, 0)):
        return {}
    path = ROOT / "release/inputs/c8s-seeds" / (c8s["sourceCommit"] + ".json")
    record = read_json(path)
    if record.get("sourceCommit") != c8s["sourceCommit"] or record.get("coreImages") != c8s["coreImages"]:
        raise GenerationError("the C8s node seed inputs differ from the profile pins")
    seed = record.get("allowlist", {})
    if seed.get("schema") != "c8s.allowlist/v1" or not isinstance(seed.get("workloads"), dict):
        raise GenerationError("the C8s node seed record has no valid allowlist")
    return seed["workloads"]


def core_entries(images: list[str], configs: dict[str, Any], release: str | None,
                 seed: dict[str, Any]) -> dict[str, Any]:
    if c8s_at_least(release, SEED_PINS_COMPONENTS_SINCE):
        return seeded_core_entries(images, configs, seed)
    entries = {}
    for image in images:
        entrypoint = component_entrypoint(image, configs.get(image, {})) if c8s_at_least(release, (0, 44, 0)) else None
        name, entry = floor_entry(image, entrypoint)
        if name in seed:
            entry = seed[name]
            digest = split_image(image)[1]
            if not entry.get("containers") or any(c.get("digest") != digest for c in entry["containers"]):
                raise GenerationError(f"seed entry {name} does not bind its core image")
            if entrypoint is not None and any(
                c.get("command", {}).get("policy") != "exact"
                or c["command"].get("argv") != entrypoint for c in entry["containers"]
            ):
                raise GenerationError(f"seed entry {name} does not preserve its component command pin")
        entries[name] = entry
    return entries


def seeded_core_entries(images: list[str], configs: dict[str, Any], seed: dict[str, Any]) -> dict[str, Any]:
    """Mirror the chart's seed: every entry as rendered, each core image bound.

    The seed pins each component shape's command at the image entrypoint, so a
    seed container of a core image must still carry that pin.
    """
    bound = set()
    for name, entry in seed.items():
        for container in entry.get("initContainers", []) + entry.get("containers", []):
            image = container.get("image", "")
            if image not in images:
                continue
            bound.add(image)
            entrypoint = component_entrypoint(image, configs.get(image, {}))
            if container.get("command", {}).get("policy") != "exact" or container["command"].get("argv") != entrypoint:
                raise GenerationError(f"seed entry {name} does not preserve its component command pin")
    missing = [image for image in images if image not in bound]
    if missing:
        raise GenerationError(f"the C8s node seed binds no entry to the core images {missing}")
    return copy.deepcopy(seed)


def native_core_entries(c8s: dict[str, Any], configs: dict[str, Any]) -> dict[str, Any]:
    if not c8s_at_least(c8s["release"], (0, 44, 6)) or c8s_at_least(c8s["release"], SEED_PINS_COMPONENTS_SINCE):
        return {}
    record = read_json(ROOT / "release/inputs/c8s-seeds" / (c8s["sourceCommit"] + ".json"))
    helper = runpy.run_path(str(ROOT / "scripts/native_c8s_allowlist.py"))
    try:
        return helper["native_entries"](c8s, configs, record)
    except helper["NativeRuleError"] as error:
        raise GenerationError(str(error)) from error


def canonicalize(document: dict[str, Any], tool: Path | None) -> bytes:
    data = json.dumps(document).encode()
    if tool is not None:
        return run([str(tool), "-"], stdin=data)
    return run(["go", "run", ".", "-"], stdin=data, cwd=CANONICAL_TOOL)


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def generate(
    profile: release_profiles.Profile,
    executable: Path,
    tool: Path | None,
    *,
    overlay: Path,
    image_env: dict[str, Any],
) -> bytes:
    """Return the canonical allowlist bytes of the profile.

    `overlay` is the values file with the image digests of the release, and
    `image_env` holds the configuration of every rendered image.
    """
    policy = release_profiles.policy_for_release(
        read_json(profile.policy), yaml.safe_load(overlay.read_text())["attestationReceipts"]["releaseId"])
    if policy.get("schema") != POLICY_SCHEMA:
        raise GenerationError(f"{profile.relative(profile.policy)} has the wrong schema")
    # The specification is the one place that pins c8s.
    c8s = release_profiles.read_spec(profile)["c8s"]
    verify_c8s_binary(executable, c8s["sourceCommit"])
    node_image = f"{c8s['nodeImage']['reference']}@{c8s['nodeImage']['digest']}"
    rendered = controllers(render_chart(policy, profile, overlay))
    expected = {item["controller"] for item in policy["workloads"]}
    if set(rendered) != expected:
        raise GenerationError(
            f"the chart workloads differ from the policy: missing={sorted(expected - set(rendered))} "
            f"extra={sorted(set(rendered) - expected)}"
        )
    cdi = read_cdi(policy, node_image)
    core_digests = {split_image(image)[1] for image in c8s["coreImages"]}
    workloads: dict[str, Any] = {}
    errors: list[str] = []
    for item in sorted(policy["workloads"], key=lambda value: value["name"]):
        controller = rendered[item["controller"]]
        pod = controller["spec"]["template"]["spec"]
        containers = {c["name"]: c for c in pod.get("initContainers", []) + pod.get("containers", [])}
        env_policies: dict[str, Any] = {}
        mount_policies: dict[str, Any] = {}
        for container_name, container in containers.items():
            if is_carved_out(effective_process(container, image_env.get(container["image"], {})),
                             core_digests, c8s["release"]):
                env_policies[container_name] = {"policy": "any"}
                mount_policies[container_name] = {"policy": "any"}
                continue
            try:
                env_policies[container_name] = {
                    "policy": "exact",
                    "values": container_env(controller, container, image_env, policy, cdi),
                }
                rules = container_mounts(controller, container, cdi, c8s_release=c8s["release"])
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
        # New c8s derive already omits injected names. Authored cds-attest
        # and allowlist-proxy must remain in the exact workload definition.
        if not c8s_at_least(c8s["release"], (0, 41, 0)):
            for field in ("initContainers", "containers"):
                entry[field] = [
                    c for c in entry.get(field, [])
                    if not (c["digest"] in core_digests and argv0(c) in INJECTED_ENTRYPOINTS)
                ]
        workloads[item["name"]] = entry
    if errors:
        raise GenerationError("the release allowlist has unpinned inputs:\n  - " + "\n  - ".join(errors))
    for name, entry in core_entries(c8s["coreImages"], image_env, c8s["release"], core_seed(c8s)).items():
        if name in workloads:
            raise GenerationError(f"the core entry {name} collides with a workload")
        workloads[name] = entry
    for name, entry in native_core_entries(c8s, image_env).items():
        if name in workloads:
            raise GenerationError(f"the native entry {name} collides with a workload")
        workloads[name] = entry
    canonical = canonicalize({"schema": "c8s.allowlist/v1", "workloads": workloads}, tool)
    with tempfile.TemporaryDirectory(prefix="release-allowlist-lint-") as directory:
        candidate = Path(directory) / "allowlist.json"
        candidate.write_bytes(canonical)
        lint(executable, candidate, {finding for finding in read_accepted_findings(profile.accepted_findings)
                                    if finding[0] in workloads})
    return canonical


def read_accepted_findings(path: Path) -> set[tuple[str, str, str, str, str]]:
    """Read the reviewed lint findings that the release accepts."""
    if not path.is_file():
        return set()
    value = read_json(path)
    if value.get("schema") != "confidential.ai/release-accepted-lint-findings/v1":
        raise GenerationError(f"{path.name} has the wrong schema")
    for field in ("reason", "issue", "reviewedBy"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise GenerationError(f"{path.name} needs a {field}")
    accepted = set()
    for item in value.get("findings", []):
        key = (item.get("entry"), item.get("rule"), item.get("variable"), item.get("mountKind"), item.get("mountPath"))
        if item.get("rule") != "search-path-overlaps-mount" or not all(isinstance(part, str) and part for part in key):
            raise GenerationError(f"{path.name} has an incomplete finding: {item}")
        if key in accepted:
            raise GenerationError(f"{path.name} lists a finding twice: {item}")
        accepted.add(key)
    return accepted


def lint(executable: Path, candidate: Path, accepted: set[tuple[str, str, str, str, str]]) -> None:
    """Run `c8s allowlist lint --strict`, allowing only the accepted findings.

    Every finding must be one that release/accepted-lint-findings.json lists,
    and every listed finding must still appear. A line the parser does not
    know is a failure.
    """
    result = subprocess.run(
        [str(executable), "allowlist", "lint", "--strict", str(candidate)],
        capture_output=True, check=False,
    )
    lines = [line.strip() for line in (result.stdout + result.stderr).decode("utf-8", "replace").splitlines() if line.strip()]
    if result.returncode == 0 and not accepted:
        return
    seen: set[tuple[str, str, str, str, str]] = set()
    unknown: list[str] = []
    summary = None
    for line in lines:
        match = SEARCH_PATH_FINDING.fullmatch(line)
        if match:
            seen.add((match["entry"], "search-path-overlaps-mount", match["variable"], match["kind"], match["path"]))
            continue
        count = LINT_SUMMARY.fullmatch(line)
        if count and summary is None:
            summary = int(count["count"])
            continue
        unknown.append(line)
    problems = [f"a lint line is not an accepted finding: {line}" for line in unknown]
    problems += [f"a lint finding is not accepted: {key}" for key in sorted(seen - accepted)]
    problems += [f"an accepted finding no longer appears; remove it: {key}" for key in sorted(accepted - seen)]
    if result.returncode != 0 and summary != len(seen):
        problems.append(f"lint reported {summary} findings, and {len(seen)} were parsed")
    if result.returncode == 0 and seen:
        problems.append("lint passed but printed findings")
    if problems:
        raise GenerationError("c8s allowlist lint --strict failed:\n  - " + "\n  - ".join(problems))


def volume_reads(controller: dict[str, Any]) -> list[str]:
    annotations = controller["spec"]["template"].get("metadata", {}).get("annotations", {})
    encoded = annotations.get("confidential.ai/c8s-volumes", "")
    return sorted({entry.partition("=")[2] for entry in encoded.split(",") if entry})


def image_config(image: str) -> dict[str, list[str]]:
    """Read the `ENV`, `ENTRYPOINT`, and `CMD` of one digest-pinned image with crane."""
    split_image(image)
    config = json.loads(run(["crane", "config", image])).get("config", {})
    return {
        "env": config.get("Env") or [],
        "entrypoint": config.get("Entrypoint") or [],
        "cmd": config.get("Cmd") or [],
    }


def refresh_image_config(profiles: tuple[release_profiles.Profile, ...]) -> dict[str, dict[str, list[str]]]:
    """Record the configuration of every rendered image that this repository does not build.

    The chart needs a digest for each repository image, so this renders it
    with a placeholder digest and skips those images.
    """
    images: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="release-image-config-") as directory:
        for profile in profiles:
            images.update(release_profiles.read_spec(profile)["c8s"]["coreImages"])
            placeholder = {
                key: f"{value}@sha256:{'0' * 64}"
                for key, value in release_profiles.read_values(profile).get("images", {}).items()
                if isinstance(value, str) and value.startswith(release_profiles.REPOSITORY_IMAGES)
            }
            overlay = Path(directory) / f"{profile.name}.yaml"
            overlay.write_text(json.dumps({"images": placeholder}))
            policy = read_json(profile.policy)
            for controller in controllers(render_chart(policy, profile, overlay)).values():
                pod = controller["spec"]["template"]["spec"]
                for container in pod.get("initContainers", []) + pod.get("containers", []):
                    split_image(container["image"])
                    if not container["image"].startswith(release_profiles.REPOSITORY_IMAGES):
                        images.add(container["image"])
    return {image: image_config(image) for image in sorted(images)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-image-config", action="store_true", required=True,
                        help="record the image configuration of every profile")
    parser.parse_args()
    try:
        path = release_profiles.IMAGE_CONFIG
        path.parent.mkdir(parents=True, exist_ok=True)
        record = refresh_image_config(release_profiles.load())
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    except (GenerationError, release_profiles.ProfileError, OSError, KeyError) as error:
        print(f"generate-release-allowlist: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"imageConfig": str(path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
