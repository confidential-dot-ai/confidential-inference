#!/usr/bin/env python3
"""Render a historical v0 release bundle for old receipt verification.

Do not use this tool to create a current release. Current releases use
scripts/build-release-manifest.py and the release-bundle workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_GENERATOR = ROOT / "scripts/regenerate-c8s-allowlist.py"


def load_allowlist_generator() -> Any:
    """Load regenerate-c8s-allowlist.py for its main-line canonical helpers."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "regenerate_c8s_allowlist", ALLOWLIST_GENERATOR
    )
    if spec is None or spec.loader is None:
        raise BundleError("cannot load the c8s allowlist generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
DIGEST_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
WORKLOAD_KINDS = {"Deployment", "DaemonSet", "StatefulSet"}
FIXTURE_DIGEST = "sha256:" + "8" * 64
OWNED_IMAGE_PREFIX = "ghcr.io/confidential-dot-ai/confidential-inference/"
LEGACY_C8S_SOURCE_COMMITS = {"615bf738bb44a48f3f249aefd2fe823868e035a7"}


class BundleError(ValueError):
    """A deterministic release input is absent or invalid."""


def require_attestation_transport(value: dict[str, Any]) -> None:
    """Require one attestation transport and reject mixed transport inputs."""
    cluster = value.get("cluster", {})
    c8s = value.get("c8s", {})
    if c8s.get("sourceCommit") in LEGACY_C8S_SOURCE_COMMITS:
        return
    if cluster.get("cvmMode") != "node":
        raise BundleError("the attestation service requires node-CVM mode")
    capabilities = c8s.get("capabilities", [])
    if "node-attestation-http" in capabilities:
        if "baked-node-socket" in capabilities:
            raise BundleError("the c8s install selects two attestation transports")
        if "workloadClaimsHostDir" in c8s or "workloadClaimsSocket" in c8s:
            raise BundleError("node HTTP attestation must not declare a workload-claims socket")
        return
    if c8s.get("workloadClaimsHostDir") != "/var/run/nri-image-policy":
        raise BundleError("the c8s install must pin the workload-claims host directory")
    if c8s.get("workloadClaimsSocket") != "attestation-api.sock":
        raise BundleError("the c8s install must pin the workload-claims attestation socket")
    if "baked-node-socket" not in c8s.get("capabilities", []):
        raise BundleError("the c8s install lacks the baked-node-socket capability")


def _policy_has_proxy(policy: dict[str, Any]) -> bool:
    """Report whether one allowlist policy runs a workload-proxy container."""
    containers = policy.get("containers", [])
    if not isinstance(containers, list):
        return False
    for item in containers:
        if not isinstance(item, dict) or not isinstance(item.get("command"), dict):
            continue
        argv = item["command"].get("argv")
        args_value = item.get("args", {})
        args = args_value.get("argv", []) if isinstance(args_value, dict) else []
        if argv == ["/workload-proxy"]:
            return True
        if argv == ["/c8s"] and isinstance(args, list) and args[:1] == ["workload-proxy"]:
            return True
    return False


def _argv_is_proxy(item: Any) -> bool:
    """Report whether one rendered workload record is a workload proxy."""
    if not isinstance(item, dict) or not isinstance(item.get("argv"), list):
        return False
    argv = item["argv"]
    return argv[:1] == ["/workload-proxy"] or argv[:2] == ["/c8s", "workload-proxy"]


def proxy_peer_workload(policy: dict[str, Any], workload: str) -> str:
    """Return the one exact peer allowlist entry from a proxy policy."""
    containers = policy.get("containers", [])
    if not isinstance(containers, list):
        raise BundleError(f"the {workload} policy has an invalid container list")
    # The proxy runs as /c8s workload-proxy (the published c8s-operator image
    # ships only the /c8s multicall binary); the legacy alias form
    # ["/workload-proxy"] is accepted for older pins.
    def _is_proxy(item: dict[str, Any]) -> bool:
        if not isinstance(item, dict) or not isinstance(item.get("command"), dict):
            return False
        argv = item["command"].get("argv")
        if argv == ["/workload-proxy"]:
            return True
        args_value = item.get("args", {})
        args = args_value.get("argv", []) if isinstance(args_value, dict) else []
        return argv == ["/c8s"] and isinstance(args, list) and args[:1] == ["workload-proxy"]

    proxies = [item for item in policy.get("containers", []) if _is_proxy(item)]
    if len(proxies) != 1:
        raise BundleError(f"the {workload} policy must contain one workload proxy")
    args_value = proxies[0].get("args", {})
    args = args_value.get("argv", []) if isinstance(args_value, dict) else []
    if not isinstance(args, list):
        args = []
    peers = [item.removeprefix("--peer-workload=") for item in args
             if item.startswith("--peer-workload=")]
    if len(peers) != 1 or not peers[0]:
        raise BundleError(f"the {workload} proxy must pin one peer workload")
    return peers[0]


def rendered_proxy_peer_workload(
    workloads: list[dict[str, Any]], source: str
) -> str:
    """Return the peer allowlist entry from one rendered Helm proxy."""
    mode = "--mode=client" if source == "gateway" else "--mode=server"
    proxies = [
        item for item in workloads
        if isinstance(item, dict)
        and isinstance(item.get("argv"), list)
        and (item["argv"][0:1] == ["/workload-proxy"]
             or item["argv"][0:2] == ["/c8s", "workload-proxy"])
        and mode in item["argv"]
    ]
    if len(proxies) != 1:
        raise BundleError(f"the rendered {source} proxy is absent or ambiguous")
    peers = [
        item.removeprefix("--peer-workload=")
        for item in proxies[0]["argv"]
        if item.startswith("--peer-workload=")
    ]
    if len(peers) != 1 or not peers[0]:
        raise BundleError(f"the rendered {source} proxy must pin one peer workload")
    return peers[0]


def validate_proxy_identity_bindings(
    policies: dict[str, Any],
    targets: list[dict[str, str]],
    rendered_targets: dict[str, str] | None = None,
    rendered_workloads: list[dict[str, Any]] | None = None,
) -> None:
    """Bind proxies and Helm receipt targets to active target identities."""
    by_target: dict[str, dict[str, str]] = {}
    for item in targets:
        if not isinstance(item, dict):
            raise BundleError("the attestation target entries are invalid")
        target = item.get("target")
        if (
            not isinstance(target, str)
            or not isinstance(item.get("workload"), str)
            or not isinstance(item.get("identity"), str)
            or target in by_target
        ):
            raise BundleError("the attestation target names are absent or duplicated")
        by_target[target] = item
    required = {"gateway", "sglang-router"}
    if not required.issubset(by_target):
        proxy_workloads = []
        for name, policy in policies.items():
            containers = policy.get("containers", []) if isinstance(policy, dict) else []
            if isinstance(containers, list) and any(
                isinstance(container, dict)
                and isinstance(container.get("command"), dict)
                and container["command"].get("argv") == ["/workload-proxy"]
                for container in containers
            ):
                proxy_workloads.append(name)
        if required.intersection(by_target) or proxy_workloads:
            missing = sorted(required - set(by_target))
            raise BundleError(
                "the gateway and router targets are required for workload proxies; "
                f"missing={missing}"
            )
        return
    if rendered_targets is not None and set(rendered_targets) != set(by_target):
        missing = sorted(set(by_target) - set(rendered_targets))
        extra = sorted(set(rendered_targets) - set(by_target))
        raise BundleError(
            "the rendered attestation targets differ from the active targets; "
            f"missing={missing}, extra={extra}"
        )
    for source, peer in (("gateway", "sglang-router"), ("sglang-router", "gateway")):
        source_target = by_target[source]
        peer_target = by_target[peer]
        source_workload = source_target.get("workload")
        if not isinstance(source_workload, str):
            raise BundleError(f"the {source} attestation target has no workload")
        source_policy = policies.get(source_workload)
        if not isinstance(source_policy, dict):
            raise BundleError(
                f"the {source} attestation target references a missing allowlist policy"
            )
        if source_target["identity"] != source_target["workload"]:
            raise BundleError(
                f"the {source} receipt identity is not its exact c8s workload name"
            )
        if rendered_targets is not None:
            rendered_identity = rendered_targets.get(source)
            if rendered_identity != source_target["identity"]:
                raise BundleError(
                    f"the {source} attestation target identity does not match the active allowlist"
                )
        # The peer binding applies only when the topology actually runs the
        # workload proxy: with namedWorkloadProxy off (e.g. conf-inference-prod,
        # whose main-line c8s images ship no workload-proxy binary) there is no
        # proxy to bind, and the per-workload attestation above is the check.
        if _policy_has_proxy(source_policy):
            peer_workload = proxy_peer_workload(source_policy, source_target["workload"])
            if peer_workload != peer_target["workload"]:
                raise BundleError(
                    f"the {source} proxy peer workload does not match {peer}"
                )
        if rendered_workloads is not None and any(
            _argv_is_proxy(item) for item in rendered_workloads
        ):
            rendered_peer = rendered_proxy_peer_workload(rendered_workloads, source)
            if rendered_peer != peer_target["workload"]:
                raise BundleError(
                    f"the rendered {source} proxy peer workload does not match {peer}"
                )


def allowlist_container_record(
    container: dict[str, Any], configs: dict[str, Any], strict: bool
) -> dict[str, Any]:
    """Create the exact image, command, and argument record used by c8s."""
    image = container.get("image")
    if not isinstance(image, str):
        raise BundleError("a rendered container has no image")
    pin = image_pin(image, strict)
    command = container.get("command") or []
    args = container.get("args")
    if not isinstance(command, list) or any(
        not isinstance(item, str) or not item for item in command
    ):
        raise BundleError(f"the {image} command is invalid")
    if args is not None and (
        not isinstance(args, list)
        or any(not isinstance(item, str) or not item for item in args)
    ):
        raise BundleError(f"the {image} arguments are invalid")
    image_config = configs.get(image)
    if not isinstance(image_config, dict):
        if not command:
            raise BundleError(f"the image configuration is missing for {image}")
        image_config = {"entrypoint": [], "cmd": []}
    entrypoint = image_config.get("entrypoint", [])
    image_command = image_config.get("cmd", [])
    if not isinstance(entrypoint, list) or not isinstance(image_command, list):
        raise BundleError(f"the image configuration is invalid for {image}")
    effective_command = command or entrypoint
    effective_args = args if args is not None else image_command
    if (
        not effective_command
        or any(not isinstance(item, str) or not item for item in effective_command)
        or any(not isinstance(item, str) or not item for item in effective_args)
    ):
        raise BundleError(f"the effective command is invalid for {image}")
    result = {
        "digest": pin["digest"],
        "image": f"{pin['reference']}@{pin['digest']}",
        "command": {"policy": "exact", "argv": effective_command},
        "args": {"policy": "exact" if effective_args else "deny"},
    }
    if effective_args:
        result["args"]["argv"] = effective_args
    return result


def allowlist_shape(record: dict[str, Any]) -> tuple[Any, ...]:
    """Return policy fields that are derived from a rendered container."""
    return (
        record.get("digest"),
        record.get("image"),
        json.dumps(record.get("command"), sort_keys=True, separators=(",", ":")),
        json.dumps(record.get("args"), sort_keys=True, separators=(",", ":")),
    )


def rendered_mapping_records(
    rendered: str,
    mappings: list[dict[str, Any]],
    configs: dict[str, Any],
    floor_digests: set[str],
    strict: bool,
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Collect non-floor rendered records for each c8s workload mapping."""
    documents: dict[str, dict[str, Any]] = {}
    for document in workload_documents(rendered):
        metadata = document.get("metadata", {})
        if not isinstance(metadata, dict) or not isinstance(metadata.get("name"), str):
            raise BundleError("a rendered workload has no name")
        key = f"{document.get('kind')}/{metadata['name']}"
        if key in documents:
            raise BundleError(f"the rendered release duplicates {key}")
        documents[key] = document
    result: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for mapping in mappings:
        name = mapping.get("allowlistName")
        controllers = mapping.get("controllers")
        if not isinstance(name, str) or not isinstance(controllers, list) or not controllers:
            raise BundleError("the c8s workload mapping is invalid")
        if name in result:
            raise BundleError(f"the c8s workload mapping duplicates {name}")
        controller_records: list[dict[str, list[dict[str, Any]]]] = []
        for controller in controllers:
            document = documents.get(controller)
            if document is None:
                raise BundleError(f"the rendered release omits {controller}")
            pod = document.get("spec", {}).get("template", {})
            pod_spec = pod.get("spec", {}) if isinstance(pod, dict) else {}
            records: dict[str, list[dict[str, Any]]] = {
                "initContainers": [], "containers": []
            }
            for field in ("initContainers", "containers"):
                values = pod_spec.get(field, [])
                if not isinstance(values, list):
                    raise BundleError(f"the rendered {controller} has invalid {field}")
                for container in values:
                    record = allowlist_container_record(container, configs, strict)
                    # Named proxies are application policy even when the
                    # candidate image is also present in the c8s floor.
                    is_proxy = record["command"].get("argv") == ["/workload-proxy"]
                    # cds-attest is not: it runs on the c8s-operator image
                    # under InjectedEntrypoints ("/c8s"). When that image's
                    # digest is a floor entry (admitted under any argv), c8s's
                    # own WorkloadContainers drops it before workload matching
                    # runs, so it must not be declared as a main container
                    # here either -- declaring it made every one of these
                    # entries permanently unmatchable in staging. See
                    # "Allowlist: do not emit the cds-attest sidecar as a main
                    # container" (confidential-inference PR #6) and the
                    # 2026-09-17 staging mesh diagnosis / staging-v2 release
                    # deployment receipts.
                    if record["digest"] not in floor_digests or is_proxy:
                        records[field].append(record)
            controller_records.append(records)
        first = controller_records[0]
        if any(
            sorted(allowlist_shape(record) for record in item[field])
            != sorted(allowlist_shape(record) for record in first[field])
            for item in controller_records[1:]
            for field in ("initContainers", "containers")
        ):
            raise BundleError(f"the controllers for {name} do not share one image and argv shape")
        result[name] = first
    return result


def validate_rendered_allowlist(
    rendered: str,
    install_input: dict[str, Any],
    active_allowlist: dict[str, Any],
    configs: dict[str, Any],
    strict: bool,
) -> None:
    """Require rendered workload records to equal the active generated policy."""
    policies = active_allowlist.get("workloads")
    # Main-line c8s (post-079aeb4) folds the digests floor into any-argv
    # workload entries, so the document has no "digests" map at all; a floor
    # entry is one whose every container leaves command and args unconstrained
    # (pkg/allowlist: an entry with command and args both "any" is what a floor
    # digest used to be). Older releases keep the separate "digests" map, and
    # those documents are still required to carry it.
    folded_floor = "digests" not in active_allowlist
    digests = active_allowlist.get("digests", {})
    mappings = install_input.get("workloadMappings")
    external_mappings = install_input.get("externalWorkloadMappings", [])
    if not isinstance(policies, dict) or not isinstance(digests, dict):
        raise BundleError("the active public allowlist is not a generated policy")
    if folded_floor:
        def is_floor_policy(policy: Any) -> bool:
            if not isinstance(policy, dict):
                return False
            containers = [
                container
                for field in ("initContainers", "containers")
                for container in (policy.get(field) or [])
            ]
            return bool(containers) and all(
                (container.get("command") or {}).get("policy") == "any"
                and (container.get("args") or {}).get("policy") == "any"
                for container in containers
            )

        # A folded-floor document has no top-level "digests" map (see above),
        # but every-argv-admitted floor entries are still present, one per
        # digest, among the workloads themselves (pkg/allowlist.DigestEntry).
        # floor_digests must come from THOSE, not from the empty `digests`
        # dict, or a floor digest is never recognized here and an injected
        # sidecar sharing that digest (cds-attest, on c8s-operator) never
        # gets excluded from the rendered comparison below -- see the
        # 2026-09-17 staging mesh diagnosis and staging-v2 release
        # deployment receipts.
        digests = {
            container["digest"]: container.get("image", "")
            for policy in policies.values()
            if is_floor_policy(policy)
            for field in ("initContainers", "containers")
            for container in (policy.get(field) or [])
        }
        policies = {
            name: policy for name, policy in policies.items() if not is_floor_policy(policy)
        }
    if not isinstance(mappings, list) or not isinstance(external_mappings, list):
        raise BundleError("the c8s workload mappings are invalid")
    # Legacy unit fixtures contain only identity and proxy snippets. They do
    # not claim to be generated policies because they have no image records.
    generated_records = [
        record
        for policy in policies.values()
        if isinstance(policy, dict)
        for field in ("initContainers", "containers")
        if isinstance(policy.get(field), list)
        for record in policy[field]
        if isinstance(record, dict) and "image" in record
    ]
    if not generated_records:
        return
    floor_digests = set(digests)
    rendered_by_mapping = rendered_mapping_records(
        rendered, mappings, configs, floor_digests, strict
    )
    mapping_names = [mapping.get("allowlistName") for mapping in mappings]
    if any(not isinstance(name, str) for name in mapping_names):
        raise BundleError("the c8s workload mappings have invalid allowlist names")
    external_names = [mapping.get("allowlistName") for mapping in external_mappings]
    if any(not isinstance(name, str) for name in external_names):
        raise BundleError("the external c8s workload mappings are invalid")
    expected_names = set(mapping_names)
    declared_names = expected_names | set(external_names)
    missing = sorted(declared_names - set(policies))
    extra = sorted(set(policies) - declared_names)
    if missing or extra:
        raise BundleError(
            "the active allowlist workload names differ from c8s mappings; "
            f"missing={missing}, extra={extra}"
        )
    for name in sorted(expected_names):
        policy = policies[name]
        if not isinstance(policy, dict):
            raise BundleError(f"the active allowlist policy for {name} is invalid")
        actual = rendered_by_mapping[name]
        for field in ("initContainers", "containers"):
            expected = policy.get(field)
            if not isinstance(expected, list):
                raise BundleError(f"the active allowlist policy for {name} lacks {field}")
            if not all(isinstance(record, dict) for record in expected):
                raise BundleError(f"the active allowlist policy for {name} has invalid {field}")
            expected_shapes = sorted(allowlist_shape(record) for record in expected)
            actual_shapes = sorted(allowlist_shape(record) for record in actual[field])
            if expected_shapes != actual_shapes:
                raise BundleError(
                    f"the rendered {name} {field} differ from the active public allowlist"
                )
        expected_label = policy.get("label")
        if not isinstance(expected_label, str):
            raise BundleError(f"the active allowlist policy for {name} has no image label")
        rendered_records = actual["containers"] or actual["initContainers"]
        if not any(record["image"] == expected_label for record in rendered_records):
            raise BundleError(f"the rendered {name} image label differs from the active public allowlist")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise BundleError(f"cannot read JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise BundleError(f"{path} must contain one JSON object")
    return value


def canonical_digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def install_input_digest(value: dict[str, Any]) -> str:
    """Hash runtime policy, but not the source locator for that policy."""
    normalized = dict(value)
    allowlist = dict(value.get("allowlist", {}))
    allowlist.pop("file", None)
    allowlist.pop("publicRelease", None)
    normalized["allowlist"] = allowlist
    return canonical_digest(normalized)


def c8s_allowlist_digest(path: Path, executable: str) -> str:
    generator = load_allowlist_generator()
    if not generator.binary_has_render_allowlist(Path(executable)):
        # Main-line c8s dropped `c8s allowlist canonicalize`; canonicalize in
        # Python (regenerate-c8s-allowlist.py's verified mirror) instead.
        canonical = generator.canonicalize_mainline(read_json(path))
        raw = path.read_bytes()
        if raw not in (canonical, canonical + b"\n"):
            raise BundleError("the release allowlist differs from c8s canonical bytes")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()
    try:
        result = subprocess.run(
            [executable, "allowlist", "canonicalize", str(path)],
            cwd=ROOT,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BundleError("the pinned c8s allowlist canonicalizer did not run") from error
    if result.returncode or not result.stdout:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise BundleError(
            "the pinned c8s allowlist canonicalizer rejected the release policy"
            + (f": {detail}" if detail else "")
        )
    raw = path.read_bytes()
    if raw not in (result.stdout, result.stdout + b"\n"):
        raise BundleError("the release allowlist differs from c8s canonical bytes")
    return "sha256:" + hashlib.sha256(result.stdout).hexdigest()


def config_path(value: str, base: Path) -> Path:
    if value.startswith("repo://"):
        return (ROOT / value.removeprefix("repo://")).resolve()
    path = Path(value)
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def install_allowlist_path(value: dict[str, Any], install_path: Path) -> Path:
    """Resolve the allowlist from its local file or public release locator."""
    allowlist = value.get("allowlist", {})
    file_value = allowlist.get("file")
    if isinstance(file_value, str):
        if file_value.startswith("repo://") or Path(file_value).is_absolute():
            return config_path(file_value, install_path.parent)
        return (ROOT / file_value).resolve()
    public_release = allowlist.get("publicRelease")
    if isinstance(public_release, dict) and isinstance(public_release.get("path"), str):
        return (ROOT / public_release["path"]).resolve()
    raise BundleError("the install input has no allowlist source")


def c8s_release_input(
    path: Path,
    allowlist_path: Path,
    allowlist_digest: str,
    mesh_ca_sha256: str | None,
    strict: bool,
    environment: str,
) -> dict[str, Any]:
    value = read_json(path)
    schema = read_json(ROOT / "c8s/install-input.schema.json")
    try:
        jsonschema.Draft202012Validator(schema).validate(value)
    except jsonschema.ValidationError as error:
        location = ".".join(str(item) for item in error.absolute_path) or "input"
        raise BundleError(f"the c8s install input fails at {location}: {error.message}") from error
    require_attestation_transport(value)
    if value["environment"] != environment:
        raise BundleError("the c8s install input environment differs from the release")
    if value["allowlist"]["digest"] != allowlist_digest:
        raise BundleError("the release allowlist digest differs from the c8s install input")
    manifest = read_json(config_path(value["nodeImage"]["manifest"], path.parent))
    mode = value["c8s"].get("policyMode", "operator")
    if mode == "static":
        configured_allowlist = install_allowlist_path(value, path)
        if allowlist_path.resolve() != configured_allowlist.resolve():
            raise BundleError(
                "static c8s policy mode requires the canonical allowlist from the install input"
            )
        try:
            raw_allowlist = allowlist_path.read_bytes()
            parsed_allowlist = json.loads(raw_allowlist)
            canonical_allowlist = json.dumps(
                parsed_allowlist, separators=(",", ":"), ensure_ascii=False
            ).encode()
        except (OSError, json.JSONDecodeError) as error:
            raise BundleError("the static c8s policy allowlist is not valid JSON") from error
        if raw_allowlist not in (canonical_allowlist, canonical_allowlist + b"\n"):
            raise BundleError("the static c8s policy allowlist is not canonical")
        if "sha256:" + hashlib.sha256(canonical_allowlist).hexdigest() != allowlist_digest:
            raise BundleError("the static c8s policy allowlist digest is not canonical")
        operator_key_set_sha256 = None
    else:
        if mesh_ca_sha256 is None:
            raise BundleError("operator policy mode needs the mesh CA certificate digest")
        validate_sha256(mesh_ca_sha256, "mesh CA certificate digest", strict)
        operator_key_set_sha256 = value["operatorPublicKey"].get("keySetSha256")
        if operator_key_set_sha256 is None:
            raise BundleError("operatorPublicKey.keySetSha256 is required")
        validate_sha256(operator_key_set_sha256, "operator key set digest", strict)
    system_floor = value.get("systemFloor")
    if not isinstance(system_floor, list) or not system_floor:
        raise BundleError("the c8s install input has no system-floor image pins")
    floor: list[dict[str, str]] = []
    for item in system_floor:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("image"), str):
            raise BundleError("the c8s system-floor entry is invalid")
        pin = image_pin(item["image"], strict)
        floor.append({"name": item["name"], "image": f"{pin['reference']}@{pin['digest']}"})
    allowlist = read_json(allowlist_path)
    policies = allowlist.get("workloads")
    if not isinstance(policies, dict):
        raise BundleError("the active public allowlist has no workloads object")
    attestation_targets = []
    target_names: set[str] = set()
    for item in value["workloadMappings"]:
        target = item.get("confidentialWorkloadId")
        if not target:
            continue
        if target in target_names:
            raise BundleError(f"the c8s input duplicates attestation target {target}")
        target_names.add(target)
        workload = item["allowlistName"]
        policy = policies.get(workload)
        if not isinstance(policy, dict):
            raise BundleError(f"the active public allowlist omits {workload}")
        # c8s authenticates the exact allowlist workload name. Do not invent a
        # second, stable alias that is absent from the signed c8s policy.
        identity = workload
        if not isinstance(identity, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,62}", identity
        ):
            raise BundleError(f"the {workload} allowlist identity is invalid")
        attestation_targets.append({
            "target": target,
            "workload": workload,
            "identity": identity,
        })
    attestation_targets.sort(key=lambda item: item["target"])
    if not attestation_targets:
        raise BundleError("the c8s input has no attested application targets")
    validate_proxy_identity_bindings(policies, attestation_targets)
    result = {
        "sourceCommit": value["c8s"]["sourceCommit"],
        "imageTag": value["c8s"]["imageTag"],
        "policyMode": mode,
        "installInputDigest": install_input_digest(value),
        "measurements": {
            name: manifest["tdx"][name] for name in ("mrtd", "rtmr1", "rtmr2")
        },
        "systemFloor": sorted(floor, key=lambda item: item["name"]),
        "attestationTargets": attestation_targets,
    }
    for field in ("release", "confosSourceCommit", "components"):
        if field in value["c8s"]:
            result[field] = value["c8s"][field]
    if mode == "operator":
        result["operatorPublicKeySha256"] = value["operatorPublicKey"]["fingerprint"]
        result["operatorKeySetSha256"] = operator_key_set_sha256
        result["meshCa"] = {
            "certificateSha256": mesh_ca_sha256,
            "certificateSecretName": value["meshCa"]["certificateSecretName"],
            "fingerprintSecretName": value["meshCa"]["fingerprintSecretName"],
        }
    # c8s creates one workload for the front-door evidence endpoint,
    # separate from the application gateway receipt. Its allowlist name
    # follows the c8s chart's own component name -- "c8s-tls-lb" on the
    # older tlsLb chart key, "c8s-router" since c8s PR #606 renamed it to
    # "router" -- so read it from the install input's own
    # externalWorkloadMappings instead of hard-coding either string. The
    # front-door entry is the one the c8s chart itself renders
    # (source.type == "c8s-chart"); every other externalWorkloadMappings
    # entry (for example a node-agent sidecar) comes from a plain manifest.
    front_door_entries = [
        item for item in value.get("externalWorkloadMappings", [])
        if isinstance(item, dict) and item.get("source", {}).get("type") == "c8s-chart"
    ]
    if len(front_door_entries) > 1:
        raise BundleError(
            "the c8s install input must name at most one c8s-chart front-door "
            f"workload in externalWorkloadMappings, found {len(front_door_entries)}"
        )
    if front_door_entries:
        front_door_name = front_door_entries[0].get("allowlistName")
        if not isinstance(front_door_name, str) or not front_door_name:
            raise BundleError("the front-door externalWorkloadMappings entry has no allowlistName")
    else:
        # No install input declares its front door this way yet. Fall back to
        # the legacy default so older/fixture inputs keep building; every
        # install input this repository ships should declare one instead.
        front_door_name = "c8s-tls-lb"
    result["frontDoorWorkload"] = front_door_name
    return result


def run(command: list[str], cwd: Path = ROOT) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise BundleError(f"command failed: {' '.join(command)}: {detail}")
    return result.stdout


def image_pin(value: str, strict: bool) -> dict[str, str]:
    if "@" not in value:
        raise BundleError(f"the image uses a tag or lacks a digest: {value}")
    reference, separator, digest = value.rpartition("@")
    match = DIGEST_RE.fullmatch(digest)
    if not separator or not reference or match is None:
        raise BundleError(f"the image pin is invalid: {value}")
    if ":" in reference.rsplit("/", 1)[-1]:
        raise BundleError(f"the image includes a tag: {value}")
    if strict and len(set(match.group(1))) == 1:
        raise BundleError(f"the image uses a placeholder digest: {value}")
    return {"reference": reference, "digest": digest}


def image_config_argv(
    image: str, container: dict[str, Any], configs: dict[str, Any]
) -> list[str]:
    command = container.get("command") or []
    args = container.get("args") or []
    if not isinstance(command, list) or not isinstance(args, list):
        raise BundleError("a workload command and its arguments must be string lists")
    if command:
        argv = command + args
    else:
        config = configs.get(image)
        if not isinstance(config, dict):
            raise BundleError(f"the image configuration is missing for {image}")
        entrypoint = config.get("entrypoint") or []
        image_command = config.get("cmd") or []
        if not isinstance(entrypoint, list) or not isinstance(image_command, list):
            raise BundleError(f"the image configuration is invalid for {image}")
        argv = entrypoint + (args if args else image_command)
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise BundleError(f"the effective argv is invalid for {image}")
    return argv


def image_build(image: str, configs: dict[str, Any], strict: bool) -> dict[str, str] | None:
    config = configs.get(image)
    build = config.get("build") if isinstance(config, dict) else None
    owned = image.partition("@")[0].startswith(OWNED_IMAGE_PREFIX)
    if build is None:
        if strict and owned:
            raise BundleError(f"the repository-owned image lacks build provenance: {image}")
        return None
    expected = {"repository", "commit", "context", "dockerfile", "platform"}
    if not isinstance(build, dict) or set(build) != expected:
        raise BundleError(f"the image build provenance is invalid for {image}")
    if any(not isinstance(build[name], str) or not build[name] for name in expected):
        raise BundleError(f"the image build provenance is invalid for {image}")
    return {name: build[name] for name in sorted(expected)}


def workload_documents(rendered: str) -> list[dict[str, Any]]:
    documents = []
    for document in yaml.safe_load_all(rendered):
        if isinstance(document, dict) and document.get("kind") in WORKLOAD_KINDS:
            documents.append(document)
    return documents


def collect_workloads(
    rendered: str,
    configs: dict[str, Any],
    model_root: str,
    strict: bool,
) -> list[dict[str, Any]]:
    workloads: list[dict[str, Any]] = []
    for document in workload_documents(rendered):
        controller_name = document["metadata"]["name"]
        pod = document["spec"]["template"]
        containers = pod["spec"].get("containers", [])
        if not containers:
            raise BundleError(f"the {controller_name} workload has no container")
        annotation = pod.get("metadata", {}).get("annotations", {}).get(
            "confidential.ai/cw", ""
        )
        for index, container in enumerate(containers):
            name = controller_name
            if index > 0:
                name = f"{controller_name}-{container['name']}"
            if annotation == "inference-worker" and container.get("name") in {
                "sglang-0",
                "sglang-1",
            }:
                name = f"inference-worker-{container['name'].removeprefix('sglang-')}"
            image = container.get("image")
            if not isinstance(image, str):
                raise BundleError(f"the {name} workload has no image")
            workload = {
                "name": name,
                "image": image_pin(image, strict),
                "argv": image_config_argv(image, container, configs),
            }
            build = image_build(image, configs, strict)
            if build is not None:
                workload["build"] = build
            if annotation == "inference-worker" or str(annotation).startswith("inference-worker-"):
                workload["modelDmVerityRoot"] = model_root
                gpu_count = None
                resources = container.get("resources")
                if isinstance(resources, dict):
                    for section in ("limits", "requests"):
                        values = resources.get(section)
                        if not isinstance(values, dict) or "nvidia.com/gpu" not in values:
                            continue
                        try:
                            candidate = int(values["nvidia.com/gpu"])
                        except (TypeError, ValueError):
                            raise BundleError(f"the {name} GPU count is invalid") from None
                        if candidate < 1 or candidate > 16:
                            raise BundleError(f"the {name} GPU count is outside the safe range")
                        if gpu_count is not None and gpu_count != candidate:
                            raise BundleError(f"the {name} GPU request and limit differ")
                        gpu_count = candidate
                if gpu_count is not None:
                    pod_annotations = pod.get("metadata", {}).get("annotations", {})
                    architectures_text = pod_annotations.get(
                        "confidential.ai/gpu-architectures", ""
                    )
                    architectures = [item.strip().upper() for item in str(architectures_text).split(",") if item.strip()]
                    if not architectures:
                        raise BundleError(f"the {name} GPU policy has no explicit architecture")
                    if any(item not in {"HOPPER", "BLACKWELL", "LS10"} for item in architectures):
                        raise BundleError(f"the {name} GPU architecture policy is invalid")
                    # The device-plugin allocation (nvidia.com/gpu) is not the
                    # attested device set: driver-level evidence enumerates
                    # every device visible in the CVM. The chart records that
                    # expected evidence count in the attested-gpu-count
                    # annotation; it defaults to the allocation.
                    device_count = gpu_count
                    attested_text = str(pod_annotations.get("confidential.ai/attested-gpu-count", "")).strip()
                    if attested_text:
                        try:
                            attested_count = int(attested_text)
                        except ValueError:
                            raise BundleError(f"the {name} attested GPU count is invalid") from None
                        if attested_count < 1 or attested_count > 16:
                            raise BundleError(f"the {name} attested GPU count is outside the safe range")
                        if attested_count < gpu_count:
                            raise BundleError(f"the {name} attested GPU count is below the allocated GPU count")
                        device_count = attested_count
                    workload["gpu"] = {
                        "required": True,
                        "deviceCount": device_count,
                        "architectures": sorted(set(architectures)),
                    }
            workloads.append(workload)
    workloads.sort(key=lambda item: item["name"])
    names = [item["name"] for item in workloads]
    if len(names) != len(set(names)):
        raise BundleError("the rendered release contains duplicate workload names")
    return workloads


def collect_external_workloads(
    specifications: list[str], configs: dict[str, Any], strict: bool
) -> list[dict[str, Any]]:
    workloads = []
    for specification in specifications:
        name, separator, image = specification.partition("=")
        if not separator or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name):
            raise BundleError(f"the external workload is invalid: {specification}")
        workload = {
                "name": name,
                "image": image_pin(image, strict),
                "argv": image_config_argv(image, {}, configs),
            }
        build = image_build(image, configs, strict)
        if build is not None:
            workload["build"] = build
        workloads.append(workload)
    return workloads


def validate_source_lock(
    workloads: list[dict[str, Any]], source_lock: dict[str, Any], environment: str
) -> None:
    by_name = {workload["name"]: workload for workload in workloads}
    expected_image = source_lock.get("deploymentImage")
    roles = source_lock.get("roles")
    simulator_roles = source_lock.get("simulatorRoles", {})
    # Reviewed alternate argv shapes (e.g. the unproxied router conf-inference-prod
    # runs while its pinned c8s image lacks /workload-proxy). Each entry names one
    # additional allowed argv for that role; it never replaces the primary pin.
    alternate_roles = source_lock.get("alternateArgvRoles", {})
    environment_roles = source_lock.get("environmentRoles", {})
    if (
        not isinstance(expected_image, dict)
        or not isinstance(expected_image.get("reference"), str)
        or set(expected_image) != {"reference"}
        or not isinstance(roles, dict)
        or not isinstance(simulator_roles, dict)
        or not isinstance(alternate_roles, dict)
        or not isinstance(environment_roles, dict)
    ):
        raise BundleError("the SGLang source lock is incomplete")
    for name, role in roles.items():
        workload = by_name.get(name)
        if workload is None:
            # A role the chart did not render at all is a reviewed topology
            # decision (e.g. conf-inference-prod runs one inference worker, so
            # no inference-worker-1 container exists anywhere in its render),
            # not a release omission. Refuse only a partial render, where some
            # container of the role made it into the release but the primary
            # one did not.
            if any(candidate.startswith(name + "-") for candidate in by_name):
                raise BundleError(f"the rendered release omits the {name} workload")
            continue
        if set(role) != {"argv"}:
            raise BundleError(f"the {name} source-lock role has unexpected fields")
        if workload["image"]["reference"] != expected_image["reference"]:
            raise BundleError(f"the {name} image repository does not match the SGLang source lock")
        simulator_role = simulator_roles.get(name)
        valid_argv = [role.get("argv")]
        if simulator_role is not None:
            if set(simulator_role) != {"argv"}:
                raise BundleError(
                    f"the {name} simulator source-lock role has unexpected fields"
                )
            valid_argv.append(simulator_role.get("argv"))
        alternate_role = alternate_roles.get(name)
        if alternate_role is not None:
            if set(alternate_role) != {"argv"}:
                raise BundleError(
                    f"the {name} alternate source-lock role has unexpected fields"
                )
            valid_argv.append(alternate_role.get("argv"))
        environment_role = environment_roles.get(environment, {}).get(name)
        if environment_role is not None:
            if set(environment_role) != {"argv"}:
                raise BundleError(
                    f"the {name} {environment} source-lock role has unexpected fields"
                )
            valid_argv.append(environment_role.get("argv"))
        if workload["argv"] not in valid_argv:
            raise BundleError(f"the {name} argv does not match the SGLang source lock")


def git_value(arguments: list[str]) -> str:
    return run(["git", *arguments]).strip()


def source_repository(override: str | None) -> str:
    value = override or git_value(["remote", "get-url", "origin"])
    if value.startswith("git@github.com:"):
        value = "https://github.com/" + value.removeprefix("git@github.com:")
    if value.endswith(".git"):
        value = value[:-4]
    return value


def validate_sha256(value: str, label: str, strict: bool) -> None:
    match = DIGEST_RE.fullmatch(value)
    if match is None:
        raise BundleError(f"the {label} must be one SHA-256 digest")
    if strict and len(set(match.group(1))) == 1:
        raise BundleError(f"the {label} uses a placeholder digest")


def render(args: argparse.Namespace) -> str:
    command = [
        "helm", "template", args.helm_release, str(args.chart),
        "--namespace", args.namespace, "-f", str(args.values),
    ]
    for value in args.helm_set:
        flag = "--set" if value.endswith("=true") or value.endswith("=false") else "--set-string"
        command.extend([flag, value])
    return run(command)


def rendered_attestation_target_identities(rendered: str) -> dict[str, str]:
    """Read stable target identities from the rendered gateway contract."""
    documents = [item for item in yaml.safe_load_all(rendered) if isinstance(item, dict)]
    gateway = next(
        (
            item for item in documents
            if item.get("kind") == "Deployment"
            and item.get("metadata", {}).get("name") == "gateway"
        ),
        None,
    )
    if gateway is None:
        return {}
    containers = gateway.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
    application = next((item for item in containers if item.get("name") == "gateway"), None)
    if application is None:
        raise BundleError("the rendered gateway has no gateway container")
    values = {
        item.get("name"): item.get("value")
        for item in application.get("env", [])
        if isinstance(item, dict)
    }
    encoded = values.get("GATEWAY_C8S_RECEIPT_TARGETS")
    if not isinstance(encoded, str) or not encoded:
        raise BundleError("the rendered gateway has no c8s receipt target identities")
    result: dict[str, str] = {}
    for entry in encoded.split(","):
        left, separator, _url = entry.partition("=")
        fields = left.split("|")
        if not separator or len(fields) != 3 or any(not field for field in fields):
            raise BundleError("the rendered c8s receipt target identity format is invalid")
        target, _workload, identity = fields
        if target in result:
            raise BundleError(f"the rendered c8s receipt target {target} is duplicated")
        result[target] = identity
    return result


def source_lock_node_image(
    source_lock: dict[str, Any], environment: str
) -> dict[str, Any]:
    """Return the node image the source lock pins for one environment.

    Each environment seals its own allowlist into its own measured node image,
    so the source lock carries one entry per environment under `nodeImages`.
    `nodeImage` stays as the production entry, so an older reader keeps
    working.
    """
    per_environment = source_lock.get("nodeImages")
    if isinstance(per_environment, dict):
        selected = per_environment.get(environment)
        if isinstance(selected, dict):
            return selected
        if per_environment:
            raise BundleError(
                f"the source lock pins no node image for {environment}"
            )
    node_image = source_lock.get("nodeImage")
    if not isinstance(node_image, dict):
        raise BundleError("the source lock pins no node image")
    return node_image


def source_lock_node_evidence_artifact(
    source_lock: dict[str, Any], environment: str
) -> dict[str, Any]:
    """Return the node evidence artifact pinned for one environment."""
    per_environment = source_lock.get("nodeEvidenceArtifacts")
    if isinstance(per_environment, dict):
        selected = per_environment.get(environment)
        if isinstance(selected, dict):
            return selected
        if per_environment:
            raise BundleError(
                f"the source lock pins no node evidence artifact for {environment}"
            )
    artifact = source_lock.get("nodeEvidenceArtifact")
    if not isinstance(artifact, dict):
        raise BundleError("the source lock pins no node evidence artifact")
    return artifact


def build(args: argparse.Namespace) -> dict[str, Any]:
    source_lock = read_json(args.source_lock)
    install_input = read_json(args.c8s_install_input)
    configs_document = (
        read_json(args.image_configs)
        if args.image_configs is not None
        else {"fixtureOnly": False, "images": install_input.get("imageConfigs", {})}
    )
    configs = configs_document.get("images")
    if not isinstance(configs, dict):
        raise BundleError("the image configuration file needs an images object")
    if args.strict:
        if args.allowlist_digest is None:
            raise BundleError("strict mode needs --allowlist-digest")
        if args.allowlist is None:
            raise BundleError("strict mode needs --allowlist")
        if args.model_dm_verity_root is None:
            raise BundleError("strict mode needs --model-dm-verity-root")
        if (
            install_input.get("c8s", {}).get("policyMode", "operator") == "operator"
            and args.mesh_ca_sha256 is None
        ):
            raise BundleError("strict mode needs --mesh-ca-sha256")
        if git_value(["status", "--porcelain"]) and not args.allow_dirty_source:
            raise BundleError("the source worktree is not clean")
        if configs_document.get("fixtureOnly") is not False:
            raise BundleError("strict mode needs verified image configuration")

    allowlist_digest = args.allowlist_digest or read_json(args.c8s_install_input)["allowlist"]["digest"]
    configured_path = install_allowlist_path(install_input, args.c8s_install_input.resolve())
    allowlist_path = args.allowlist or configured_path
    if not allowlist_path.is_file():
        raise BundleError("the active public allowlist file is unavailable")
    if args.strict:
        actual_allowlist_digest = c8s_allowlist_digest(args.allowlist, args.c8s)
        if actual_allowlist_digest != allowlist_digest:
            raise BundleError(
                "the c8s canonical allowlist digest differs from --allowlist-digest"
            )
    mesh_ca_sha256 = args.mesh_ca_sha256 or ("sha256:" + "6" * 64)
    model_root = args.model_dm_verity_root or FIXTURE_DIGEST.removeprefix("sha256:")
    validate_sha256(allowlist_digest, "allowlist digest", args.strict)
    validate_sha256("sha256:" + model_root, "model dm-verity root", args.strict)

    rendered = render(args)
    source_commit = args.source_commit or git_value(["rev-parse", "HEAD"])
    if args.strict and source_commit != git_value(["rev-parse", "HEAD"]):
        raise BundleError("the source commit does not match the checked-out commit")
    node_image = source_lock_node_image(source_lock, args.environment)
    node_evidence_artifact = source_lock_node_evidence_artifact(
        source_lock, args.environment
    )
    node_pin = image_pin(
        f"{node_image['reference']}@{node_image['digest']}", args.strict
    )
    workloads = collect_workloads(rendered, configs, model_root, args.strict)
    workloads.extend(collect_external_workloads(args.external_workload, configs, args.strict))
    workloads.sort(key=lambda item: item["name"])
    names = [item["name"] for item in workloads]
    if len(names) != len(set(names)):
        raise BundleError("the release contains duplicate workload names")
    validate_source_lock(workloads, source_lock, args.environment)
    active_allowlist = read_json(allowlist_path)
    if not isinstance(active_allowlist.get("workloads"), dict):
        raise BundleError("the active public allowlist has no workloads object")
    release_trust_bytes = args.release_trust_policy.read_bytes()
    release_trust = json.loads(release_trust_bytes)
    if release_trust.get("schema") != "confidential-inference.release-trust/v1":
        raise BundleError("the release trust policy has the wrong schema")
    try:
        release_trust_path = args.release_trust_policy.relative_to(ROOT).as_posix()
    except ValueError as error:
        raise BundleError("the release trust policy must be inside this repository") from error
    bundle = {
        "schemaVersion": 2,
        "release": {
            "name": args.release_name,
            "environment": args.release_environment or args.environment,
        },
        "releaseTrust": {
            "policyPath": release_trust_path,
            "policySha256": "sha256:" + hashlib.sha256(release_trust_bytes).hexdigest(),
            "signatureType": release_trust["signatureType"],
        },
        "source": {
            "repository": source_repository(args.source_repository),
            "commit": source_commit,
        },
        "node": {
            "image": node_pin,
            "sourceCommit": node_image["sourceCommit"],
            "evidenceArtifactDigest": node_evidence_artifact["digest"],
        },
        "c8s": c8s_release_input(
            args.c8s_install_input,
            allowlist_path,
            allowlist_digest,
            mesh_ca_sha256,
            args.strict,
            args.environment,
        ),
        "allowlistDigest": allowlist_digest,
        "model": {
            "repository": source_lock["model"]["repository"],
            "revision": source_lock["model"]["revision"],
            "dmVerityRoot": model_root,
            "mountVerification": source_lock["model"]["mountVerification"],
        },
        "workloads": workloads,
    }
    validate_proxy_identity_bindings(
        active_allowlist["workloads"],
        bundle["c8s"]["attestationTargets"],
        rendered_attestation_target_identities(rendered),
        workloads,
    )
    validate_rendered_allowlist(
        rendered, install_input, active_allowlist, configs, args.strict
    )
    schema = read_json(args.schema)
    try:
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(bundle)
    except jsonschema.ValidationError as error:
        location = ".".join(str(item) for item in error.absolute_path) or "bundle"
        raise BundleError(f"the release bundle fails its schema at {location}: {error.message}") from error
    return bundle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--chart", type=Path, default=ROOT / "helm/confidential-inference")
    parser.add_argument("--values", type=Path)
    parser.add_argument("--source-lock", type=Path, default=ROOT / "images/sglang/source.lock")
    parser.add_argument("--schema", type=Path, default=ROOT / "contracts/release-bundle.schema.json")
    parser.add_argument(
        "--release-trust-policy",
        type=Path,
        default=ROOT / "releases/trust/release-signing-policy.json",
    )
    parser.add_argument("--image-configs", type=Path)
    parser.add_argument("--source-repository")
    parser.add_argument("--source-commit")
    parser.add_argument("--allowlist-digest")
    parser.add_argument("--allowlist", type=Path)
    parser.add_argument("--c8s", default="c8s")
    parser.add_argument("--mesh-ca-sha256")
    parser.add_argument("--c8s-install-input", type=Path)
    parser.add_argument("--environment", required=True)
    parser.add_argument(
        "--release-environment",
        help=(
            "release channel recorded in the bundle; defaults to --environment. "
            "Use this when a production release is rendered for a candidate target."
        ),
    )
    parser.add_argument(
        "--allow-dirty-source",
        action="store_true",
        help="allow reviewed workspace changes; the source commit is still pinned",
    )
    parser.add_argument("--model-dm-verity-root")
    parser.add_argument("--helm-release", default="confidential-inference")
    parser.add_argument("--namespace", default="confidential-inference")
    parser.add_argument("--helm-set", action="append", default=[])
    parser.add_argument("--external-workload", action="append", default=[])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--strict", action="store_true")
    mode.add_argument("--fixture", dest="strict", action="store_false")
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        if args.values is None:
            raise BundleError("--values must name an explicit environment overlay")
        if args.c8s_install_input is None:
            raise BundleError("--c8s-install-input must name an explicit environment input")
        if args.image_configs is None and args.strict:
            raise BundleError("strict mode needs --image-configs from inspected manifests")
        bundle = build(args)
        encoded = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    except BundleError as error:
        print(f"release-bundle: {error}", file=sys.stderr)
        return 1
    print(f"release-bundle: wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
