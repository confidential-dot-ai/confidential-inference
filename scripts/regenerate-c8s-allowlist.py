#!/usr/bin/env python3
"""Reproduce the public production c8s static allowlist from committed inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "c8s/production-policy.json"
STAGING_POLICY = ROOT / "c8s/staging-policy.json"
CONF_INFERENCE_PROD_POLICY = ROOT / "c8s/conf-inference-prod-policy.json"
ALLOWED_POLICIES = (POLICY, STAGING_POLICY, CONF_INFERENCE_PROD_POLICY)
SCHEMA = ROOT / "c8s/production-policy.schema.json"
OCI = re.compile(r"^([^@\s]+)@(sha256:[0-9a-f]{64})$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
C8S_MODULE = "github.com/confidential-dot-ai/c8s/cmd/c8s"


class RegenerationError(ValueError):
    """The public production policy cannot be reproduced safely."""


def run_text(command: list[str], cwd: Path = ROOT) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RegenerationError(f"command failed: {' '.join(command)}: {detail}")
    return result.stdout


def run_bytes(command: list[str], cwd: Path = ROOT) -> bytes:
    result = subprocess.run(command, cwd=cwd, capture_output=True, check=False)
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RegenerationError(f"command failed: {' '.join(command)}: {detail}")
    if not result.stdout:
        raise RegenerationError(f"command produced no output: {' '.join(command)}")
    return result.stdout


def public_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise RegenerationError(f"{label} must be a relative public repository path")
    path = (ROOT / value).resolve()
    if path != ROOT and ROOT not in path.parents:
        raise RegenerationError(f"{label} escapes the public repository")
    return path


def load_policy(path: Path) -> dict[str, Any]:
    allowed = {candidate.resolve() for candidate in ALLOWED_POLICIES}
    if path.resolve() not in allowed:
        names = ", ".join(str(candidate.relative_to(ROOT)) for candidate in ALLOWED_POLICIES)
        raise RegenerationError(f"--config must be one of: {names}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(value), key=lambda e: list(e.path))
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as error:
        raise RegenerationError(f"cannot read the public production policy: {error}") from error
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.path) or "policy"
        raise RegenerationError(f"{location}: {error.message}")
    return value


def split_image(value: Any) -> tuple[str, str]:
    if not isinstance(value, str):
        raise RegenerationError("a rendered container has no image")
    match = OCI.fullmatch(value)
    if match is None:
        raise RegenerationError(f"rendered image is not an exact OCI pin: {value}")
    return match.group(1), match.group(2)


def validate_binding(policy: dict[str, Any], output: Path) -> None:
    if output.resolve() != public_path(policy["output"], "policy.output"):
        raise RegenerationError("--output does not match policy.output")
    chart = policy["chart"]
    chart_path = public_path(chart["path"], "chart.path")
    values_path = public_path(chart["values"], "chart.values")
    if not chart_path.joinpath("Chart.yaml").is_file() or not values_path.is_file():
        raise RegenerationError("the public production chart or values file is absent")
    for image, label in policy["systemImages"].items():
        if OCI.fullmatch(image) is None or not isinstance(label, str) or not label:
            raise RegenerationError("systemImages must map exact OCI pins to labels")
    names = [item["name"] for item in policy["workloads"]]
    controllers = [item["controller"] for item in policy["workloads"]]
    if len(set(names)) != len(names) or len(set(controllers)) != len(controllers):
        raise RegenerationError("workload names and controllers must be unique")
    for image, records in policy["imageConfigs"].items():
        if OCI.fullmatch(image) is None:
            raise RegenerationError(f"imageConfigs contains a non-OCI image: {image}")
        for record in records:
            if not record["command"]:
                raise RegenerationError(f"the command for {image} is empty")
            if "args" not in record:
                raise RegenerationError(f"the command for {image} must include exact args")
    if COMMIT.fullmatch(policy["c8s"]["sourceCommit"]) is None:
        raise RegenerationError("c8s.sourceCommit is not a full Git commit")


def verify_c8s_binary(policy: dict[str, Any], executable: Path) -> None:
    executable = executable.resolve()
    if not executable.is_file():
        raise RegenerationError(f"--c8s is not a file: {executable}")
    info = run_text(["go", "version", "-m", str(executable)], executable.parent)
    if f"\tpath\t{C8S_MODULE}\n" not in info:
        raise RegenerationError("--c8s is not the c8s command binary")
    commit = policy["c8s"]["sourceCommit"]
    exact_module_version = f"Version={commit}" in info
    exact_clean_vcs_revision = (
        f"vcs.revision={commit}" in info and "vcs.modified=false" in info
    )
    if not (exact_module_version or exact_clean_vcs_revision):
        raise RegenerationError("--c8s does not contain the pinned source commit")


def selected_controller(documents: list[dict[str, Any]], name: str) -> dict[str, Any]:
    kind, separator, resource = name.partition("/")
    if not separator:
        raise RegenerationError(f"invalid controller name: {name}")
    matches = [item for item in documents if item.get("kind") == kind and item.get("metadata", {}).get("name") == resource]
    if len(matches) != 1:
        raise RegenerationError(f"the public chart did not render exactly one {name}")
    return matches[0]


def effective_argv(container: dict[str, Any], image: str) -> tuple[list[str], list[str]]:
    command = container.get("command") or []
    args = container.get("args") or []
    if not isinstance(command, list) or not isinstance(args, list) or any(not isinstance(x, str) for x in command + args):
        raise RegenerationError(f"the {image} command or args is invalid")
    return command, args


def command_record(container: dict[str, Any], configs: dict[str, Any]) -> dict[str, Any]:
    image = container.get("image")
    _reference, digest = split_image(image)
    command, args = effective_argv(container, image)
    records = configs.get(image)
    if not isinstance(records, list) or not records:
        raise RegenerationError(f"the public policy has no exact command for {image}")
    matched = False
    selected_command = command
    selected_args = args
    for record in records:
        if command and command != record["command"]:
            continue
        expected_args = record.get("args", [])
        if args != expected_args:
            continue
        if not command:
            selected_command = record["command"]
        if not args and "args" in record:
            selected_args = expected_args
        if "args" in record and args == expected_args:
            matched = True
    if not matched:
        raise RegenerationError(f"the rendered command is not a public exact command for {image}")
    return {"digest": digest, "image": image,
            "command": {"policy": "exact", "argv": selected_command},
            "args": {"policy": "exact", "argv": selected_args} if selected_args else {"policy": "deny"},
            "mounts": {"policy": "any"}, "env": {"policy": "any"}}


def volume_reads(document: dict[str, Any]) -> list[str]:
    annotations = document.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {})
    encoded = annotations.get("confidential.ai/c8s-volumes")
    if encoded is None:
        return []
    if not isinstance(encoded, str) or not encoded:
        raise RegenerationError("the chart c8s volume annotation is invalid")
    reads = []
    for entry in encoded.split(","):
        _name, separator, source = entry.partition("=")
        if not separator or not source.startswith("/") or source in reads:
            raise RegenerationError("the chart c8s volume annotation is invalid")
        reads.append(source)
    return sorted(reads)


def application_allowlist(policy: dict[str, Any], documents: list[dict[str, Any]]) -> dict[str, Any]:
    expected = {item["controller"] for item in policy["workloads"]}
    rendered = {f"{x.get('kind')}/{x.get('metadata', {}).get('name')}": x for x in documents if x.get("kind") in {"Deployment", "StatefulSet", "DaemonSet"}}
    if expected != set(rendered):
        raise RegenerationError(f"the public workload map differs from the rendered chart: missing={sorted(expected-set(rendered))}, extra={sorted(set(rendered)-expected)}")
    workloads = {}
    for mapping in sorted(policy["workloads"], key=lambda item: item["name"]):
        document = selected_controller(documents, mapping["controller"])
        pod = document.get("spec", {}).get("template", {}).get("spec", {})
        if not isinstance(pod, dict):
            raise RegenerationError(f"{mapping['controller']} has no pod spec")
        init_containers, containers = [], []
        for field, target in (("initContainers", init_containers), ("containers", containers)):
            for container in pod.get(field, []):
                target.append(command_record(container, policy["imageConfigs"]))
        if not init_containers and not containers:
            raise RegenerationError(f"{mapping['controller']} has no application container")
        reads = sorted(set(mapping.get("secretReads", [])) | set(volume_reads(document)))
        entry = {"label": (containers or init_containers)[0]["image"], "initContainers": init_containers, "containers": containers}
        if reads:
            entry["secrets"] = {"policy": "allow", "read": reads}
        workloads[mapping["name"]] = entry
    for name, item in sorted(policy.get("systemWorkloads", {}).items()):
        rendered = {"label": item["label"], "initContainers": [], "containers": []}
        for field in ("initContainers", "containers"):
            for container in item[field]:
                _reference, digest = split_image(container["image"])
                command = container["command"]
                args = container["args"]
                rendered[field].append({
                    "digest": digest,
                    "image": container["image"],
                    "command": {"policy": "exact", "argv": command},
                    "args": ({"policy": "exact", "argv": args}
                             if args else {"policy": "deny"}),
                    "mounts": {"policy": "any"},
                    "env": {"policy": "any"},
                })
        if not rendered["containers"]:
            raise RegenerationError(f"system workload {name} has no main container")
        workloads[name] = rendered
    return {"schema": "c8s.allowlist/v1", "digests": {}, "workloads": workloads}


def render_application(policy: dict[str, Any]) -> list[dict[str, Any]]:
    chart = policy["chart"]
    command = ["helm", "template", chart["release"], str(public_path(chart["path"], "chart.path")),
               "--namespace", chart["namespace"], "--kube-version", chart["kubeVersion"],
               "--values", str(public_path(chart["values"], "chart.values"))]
    output = run_text(command)
    try:
        return [item for item in yaml.safe_load_all(output) if isinstance(item, dict)]
    except yaml.YAMLError as error:
        raise RegenerationError(f"the public Helm chart output is invalid: {error}") from error


def canonicalize(executable: Path, document: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="c8s-allowlist-") as directory:
        candidate = Path(directory) / "allowlist.json"
        candidate.write_bytes(document)
        return run_bytes([str(executable.resolve()), "allowlist", "canonicalize", str(candidate)])


# --------------------------------------------------------------------------
# Main-line c8s (post-079aeb4): the folded allowlist model
#
# c8s 75af991a ("feat(allowlist)!: fold floor digests into workload entries")
# removed Allowlist.Digests, `c8s render-allowlist`, and `c8s allowlist
# canonicalize`. The floor is now a set of any-argv workload entries named
# <image basename>-<first 12 digest hex> (pkg/allowlist.DigestEntryName, and
# the chart's c8s.digestWorkloadName), and the canonical bytes are Go's
# json.Marshal of the normalized pkg/allowlist.Allowlist struct. The
# functions below reproduce both in Python so this generator keeps working
# with a main-line c8s binary; `c8s allowlist lint` (which main line keeps)
# validates the result.
# --------------------------------------------------------------------------


def binary_has_render_allowlist(executable: Path) -> bool:
    """Report whether the pinned c8s binary still ships render-allowlist."""
    result = subprocess.run(
        [str(executable.resolve()), "render-allowlist", "--help"],
        capture_output=True, check=False,
    )
    return result.returncode == 0


def digest_entry_name(digest: str, image: str) -> str:
    """Mirror pkg/allowlist.DigestEntryName for one floor image."""
    base = image.split("@")[0].rsplit("/", 1)[-1].split(":")[0][:50]
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", base) is None:
        base = "image"
    return base + "-" + digest.removeprefix("sha256:")[:12]


def digest_entry(digest: str, image: str) -> dict[str, Any]:
    """Mirror pkg/allowlist.DigestEntry: one any-argv floor workload."""
    return {
        "label": image,
        "initContainers": [],
        "containers": [{
            "digest": digest,
            "image": image,
            "command": {"policy": "any"},
            "args": {"policy": "any"},
        }],
    }


def _normalize_container(container: dict[str, Any]) -> dict[str, Any]:
    """Mirror normalizeContainers: default absent argv/mount/env policies."""
    normalized: dict[str, Any] = {"digest": container["digest"]}
    if container.get("image"):
        normalized["image"] = container["image"]
    for key in ("command", "args"):
        policy = (container.get(key) or {}).get("policy", "")
        argv = (container.get(key) or {}).get("argv")
        if policy in ("", "any"):
            normalized[key] = {"policy": "any"}
        elif policy == "deny":
            normalized[key] = {"policy": "deny"}
        elif policy == "exact":
            if not argv:
                raise RegenerationError("an exact argv policy needs its argv")
            normalized[key] = {"policy": "exact", "argv": list(argv)}
        else:
            raise RegenerationError(f"unknown argv policy: {policy}")
    mounts = container.get("mounts") or {}
    if mounts.get("policy", "") in ("", "any"):
        normalized["mounts"] = {"policy": "any"}
    elif mounts.get("policy") == "exact":
        destinations = mounts.get("destinations") or []
        if not destinations:
            raise RegenerationError("an exact mounts policy needs destinations")
        normalized["mounts"] = {"policy": "exact", "destinations": sorted(set(destinations))}
    else:
        raise RegenerationError(f"unknown mounts policy: {mounts.get('policy')}")
    env = container.get("env") or {}
    if env.get("policy", "") in ("", "any"):
        normalized["env"] = {"policy": "any"}
    elif env.get("policy") == "exact":
        names = env.get("names") or []
        if not names:
            raise RegenerationError("an exact env policy needs names")
        normalized["env"] = {"policy": "exact", "names": sorted(set(names))}
    else:
        raise RegenerationError(f"unknown env policy: {env.get('policy')}")
    return normalized


def _policy_key(container: dict[str, Any]) -> str:
    return json.dumps([container["command"], container["args"]], separators=(",", ":"))


def canonicalize_mainline(document: dict[str, Any]) -> bytes:
    """Mirror Allowlist.Canonical() on main-line c8s (Go json.Marshal output).

    Field order follows the Go struct declarations; the workloads map is
    key-sorted by encoding/json; container lists sort by (digest, policyKey),
    exactly like sortContainers. Verified byte-identical against
    pkg/allowlist.Canonical() for this document shape.
    """
    if document.get("schema") != "c8s.allowlist/v1":
        raise RegenerationError("the composed allowlist has the wrong schema")
    workloads = document.get("workloads")
    if not isinstance(workloads, dict) or not workloads:
        raise RegenerationError("the composed allowlist has no workloads")
    out: dict[str, Any] = {}
    for name in sorted(workloads):
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is None or len(name) > 63:
            raise RegenerationError(f"the workload name is invalid: {name}")
        entry = workloads[name]
        normalized_entry: dict[str, Any] = {}
        if entry.get("label"):
            normalized_entry["label"] = entry["label"]
        for field in ("initContainers", "containers"):
            containers = [_normalize_container(c) for c in (entry.get(field) or [])]
            containers.sort(key=lambda c: (c["digest"], _policy_key(c)))
            normalized_entry[field] = containers
        secrets = entry.get("secrets")
        if secrets and secrets.get("policy") == "allow":
            grant: dict[str, Any] = {"policy": "allow"}
            if secrets.get("read"):
                grant["read"] = sorted(set(secrets["read"]))
            if secrets.get("write"):
                grant["write"] = sorted(set(secrets["write"]))
            normalized_entry["secrets"] = grant
        out[name] = normalized_entry
    return json.dumps(
        {"schema": "c8s.allowlist/v1", "workloads": out},
        separators=(",", ":"), ensure_ascii=False,
    ).encode()


def compose_mainline(policy: dict[str, Any], bootstrap: dict[str, Any]) -> bytes:
    """Compose the folded-model allowlist: floor entries plus app workloads."""
    workloads: dict[str, Any] = {}
    for image, label in policy["systemImages"].items():
        if label != image:
            raise RegenerationError("main-line systemImages labels must equal the image")
        _reference, digest = split_image(image)
        name = digest_entry_name(digest, image)
        if name in workloads:
            raise RegenerationError(f"duplicate floor entry: {name}")
        workloads[name] = digest_entry(digest, image)
    for name, entry in bootstrap["workloads"].items():
        if name in workloads:
            raise RegenerationError(f"the {name} workload collides with a floor entry")
        workloads[name] = entry
    canonical = canonicalize_mainline({"schema": "c8s.allowlist/v1", "workloads": workloads})
    return canonical


def compose(policy: dict[str, Any], executable: Path, bootstrap: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="c8s-render-allowlist-") as directory:
        candidate = Path(directory) / "bootstrap.json"
        candidate.write_bytes(bootstrap)
        c8s = policy["c8s"]
        command = [str(executable.resolve()), "render-allowlist", "--cvm-mode", c8s["cvmMode"],
                   "--hardware-platform", c8s["hardwarePlatform"], "--image-tag", c8s["imageTag"],
                   "--kube-version", policy["chart"]["kubeVersion"],
                   "--bootstrap-allowlist", str(candidate), "--distro", c8s["distro"]]
        if c8s["volumes"]:
            command.append("--volumes")
        if c8s["attest"]:
            command.append("--attest")
        return canonicalize(executable, run_bytes(command))


def validate_composed(policy: dict[str, Any], bootstrap: dict[str, Any], composed: bytes) -> bytes:
    try:
        value = json.loads(composed)
    except json.JSONDecodeError as error:
        raise RegenerationError(f"c8s produced invalid JSON: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != "c8s.allowlist/v1":
        raise RegenerationError("c8s produced an invalid allowlist schema")
    def walk(item: Any) -> None:
        if isinstance(item, dict):
            if "identity" in item:
                raise RegenerationError("c8s output contains unsupported identity field")
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)
    walk(value)
    if value.get("workloads") != bootstrap.get("workloads"):
        raise RegenerationError("c8s changed the public workload policy")
    expected_floor = {split_image(image)[1]: label for image, label in policy["systemImages"].items()}
    if value.get("digests") != dict(sorted(expected_floor.items())):
        raise RegenerationError("c8s system floor does not match the public OCI pins")
    return composed


def generate(config_path: Path, output: Path | None, executable: Path, _source: Path | None = None) -> tuple[bytes, str, Path]:
    policy = load_policy(config_path)
    if output is None:
        output = public_path(policy["output"], "policy.output")
    validate_binding(policy, output.resolve())
    verify_c8s_binary(policy, executable)
    bootstrap = application_allowlist(policy, render_application(policy))
    if binary_has_render_allowlist(executable):
        bootstrap_bytes = json.dumps(bootstrap, separators=(",", ":"), ensure_ascii=False).encode()
        bootstrap_bytes = canonicalize(executable, bootstrap_bytes)
        bootstrap = json.loads(bootstrap_bytes)
        canonical = validate_composed(policy, bootstrap, compose(policy, executable, bootstrap_bytes))
    else:
        # Main-line c8s: compose and canonicalize in Python (see above), then
        # let the pinned binary's own linter check the result.
        canonical = compose_mainline(policy, bootstrap)
        with tempfile.TemporaryDirectory(prefix="c8s-allowlist-lint-") as directory:
            candidate = Path(directory) / "allowlist.json"
            candidate.write_bytes(canonical)
            run_text([str(executable.resolve()), "allowlist", "lint", str(candidate)])
    return canonical, "sha256:" + hashlib.sha256(canonical).hexdigest(), output.resolve()


def update_output(output: Path, canonical: bytes, apply: bool) -> bool:
    try:
        current = output.read_bytes()
    except FileNotFoundError:
        # A new environment's allowlist does not exist yet; --apply creates it.
        current = None
    changed = current not in (canonical, canonical + b"\n")
    if changed and not apply:
        raise RegenerationError("the public production allowlist has policy drift; rerun with --apply")
    if changed:
        output.write_bytes(canonical + b"\n")
    return changed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=POLICY)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--c8s", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        canonical, digest, output = generate(args.config, args.output, args.c8s)
        changed = update_output(output, canonical, args.apply)
    except (OSError, RegenerationError) as error:
        print(f"c8s-allowlist-generate: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"allowlist": str(output), "changed": changed, "digest": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
