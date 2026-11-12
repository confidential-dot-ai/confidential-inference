#!/usr/bin/env python3
"""Render the allowlist of one deployment from a verified framework release.

The framework release (scripts/build-release-manifest.py) names the software.
A deployment adds its own settings: Helm values files and an allowlist
policy (the workloads that it runs, its chart release name and namespace).
This tool joins them. Run it from a checkout of this repository at the
framework release's source commit:

    python3 scripts/render-allowlist.py \\
      --release release-bundle.json --signature release-bundle.sigstore.json \\
      --values values.yaml --policy allowlist-policy.json \\
      --c8s ./c8s --canonical-tool ./c8s-allowlist-canonical --output-dir out

It refuses to render when:

- the framework release signature or schema is not valid;
- the checkout is not the release's source commit, or its chart, spec, or
  source lock differ from the release;
- a values file sets `images` or `attestationReceipts.releaseId`: the
  framework release supplies them;
- the chart renders an image that the framework release does not name;
- `c8s allowlist lint --strict` finds a problem that the deployment did not
  accept (--accepted-findings).

These checks are a convenience for the operator. The client does not trust
this tool: it reads the live allowlist, checks each digest against the
signed framework release, and reviews the rest.

It writes to --output-dir:

- allowlist.json: the canonical C8s allowlist of the deployment;
- release-values.yaml: the framework image digests and the release ID as a
  Helm values file. Apply it after the deployment values files;
- render.json: what it rendered from, by SHA-256.
"""

from __future__ import annotations

import argparse
import json
import runpy
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_signature
import release_spec

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "helm/confidential-inference"
MAN = runpy.run_path(str(ROOT / "scripts/build-release-manifest.py"))
ALLOWLIST_GENERATOR = runpy.run_path(str(ROOT / "scripts/generate-release-allowlist.py"))
ManifestError = MAN["ManifestError"]
require = MAN["require"]
sha256 = MAN["sha256"]
OCI = MAN["OCI"]
# The values that the framework release supplies. A deployment cannot set them.
FRAMEWORK_VALUES = ("images", ("attestationReceipts", "releaseId"))


def verify_release(release: Path, signature: Path, cosign: Path) -> tuple[dict[str, Any], bytes]:
    """Return the framework release manifest and its bytes after checking its signature and format.

    The bytes are read once before the check and must be unchanged after it,
    so the manifest that the tool uses is the one that the signature covers.
    """
    data = release.read_bytes()
    try:
        release_signature.verify_release_signature(release, signature, cosign, 60)
    except (OSError, release_signature.ReleaseSignatureError) as error:
        raise ManifestError(f"framework release signature: {error}") from error
    require(release.read_bytes() == data, "the framework release changed during its signature check")
    try:
        manifest = json.loads(data)
    except json.JSONDecodeError as error:
        raise ManifestError(f"the framework release is not JSON: {error}") from error
    require(isinstance(manifest, dict) and manifest.get("schema") == MAN["SCHEMA"],
            f"the framework release is not {MAN['SCHEMA']}")
    MAN["validate_schema"](manifest)
    return manifest, data


def require_checkout(manifest: dict[str, Any], chart: Path = CHART, repo: Path = ROOT) -> dict[str, Any]:
    """Require this checkout to be the release's source, and return its spec."""
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True)
    require(head.returncode == 0 and head.stdout.strip() == manifest["source"]["commit"],
            f"check out source commit {manifest['source']['commit']} of the framework release first")
    # Untracked files count too: the generator reads files under release/inputs/.
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all",
                            "--", "release", "scripts", "helm", "tools"], cwd=repo, capture_output=True, text=True)
    require(dirty.returncode == 0 and not dirty.stdout.strip(), "the checkout has changes or extra files")
    require(MAN["chart_identity"](chart)["treeSha256"] == manifest["chart"]["sha256"],
            "the chart differs from the framework release")
    require(sha256((repo / manifest["sourceLock"]["path"]).read_bytes()) == manifest["sourceLock"]["sha256"],
            "the source lock differs from the framework release")
    spec = MAN["read_spec"]()
    require({key: spec["c8s"][key] for key in ("release", "sourceCommit")}
            == {key: manifest["c8s"][key] for key in ("release", "sourceCommit")}
            and sorted(spec["c8s"]["coreImages"]) == manifest["c8s"]["coreImages"],
            "release/spec.yaml pins another c8s than the framework release")
    return spec


def require_deployment_values(deployment: release_spec.Deployment) -> None:
    """Refuse a deployment values file that sets a framework value."""
    for path in deployment.values_files:
        values = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        require(isinstance(values, dict), f"{path} is not a mapping")
        for key in FRAMEWORK_VALUES:
            keys = (key,) if isinstance(key, str) else key
            current: Any = values
            for part in keys:
                current = current.get(part) if isinstance(current, dict) else None
            require(current is None, f"{path} sets {'.'.join(keys)}; the framework release supplies it")


def release_overlay(manifest: dict[str, Any]) -> bytes:
    """The Helm values that the framework release supplies."""
    overlay = {"images": manifest["images"], "attestationReceipts": {"releaseId": manifest["release"]["name"]}}
    return yaml.safe_dump(overlay, sort_keys=True).encode()


def render_chart(chart: Path, deployment: release_spec.Deployment, settings: dict[str, str],
                 overlay: Path) -> list[dict[str, Any]]:
    """Render the chart with the deployment values files in order, then the overlay."""
    result = subprocess.run(
        ["helm", "template", settings["release"], str(chart),
         "--namespace", settings["namespace"], "--kube-version", settings["kubeVersion"],
         *deployment.helm_values_args(overlay)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise ManifestError(f"helm template failed: {result.stderr.strip()}")
    return [item for item in yaml.safe_load_all(result.stdout) if isinstance(item, dict)]


def read_allowlist_policy(path: Path) -> dict[str, Any]:
    policy = MAN["read_json"](path)
    require(isinstance(policy, dict) and policy.get("schema") == ALLOWLIST_GENERATOR["POLICY_SCHEMA"],
            f"{path.name} has the wrong schema")
    chart = policy.get("chart")
    require(isinstance(chart, dict) and set(chart) == {"release", "namespace", "kubeVersion"},
            "allowlist policy chart settings are incomplete")
    for name in ("release", "namespace", "kubeVersion"):
        require(isinstance(chart[name], str) and bool(chart[name]),
                f"allowlist policy chart.{name} is invalid")
    require("c8s" not in policy, "the allowlist policy must not pin c8s; the framework release does")
    workloads = policy.get("workloads")
    require(isinstance(workloads, list) and workloads,
            "allowlist policy has no workloads")
    require(all(isinstance(item, dict) and isinstance(item.get("name"), str)
                and isinstance(item.get("controller"), str) for item in workloads),
            "allowlist policy has an invalid workload")
    require(len({item["name"] for item in workloads}) == len(workloads)
            and len({item["controller"] for item in workloads}) == len(workloads),
            "allowlist policy repeats a workload name or controller")
    return policy


def rendered_images(documents: list[dict[str, Any]]) -> list[str]:
    images: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"containers", "initContainers", "ephemeralContainers"} and isinstance(child, list):
                    for container in child:
                        image = container.get("image") if isinstance(container, dict) else None
                        require(isinstance(image, str) and OCI.fullmatch(image) is not None,
                                f"a rendered container image is not digest-pinned: {image!r}")
                        images.add(image)
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(documents)
    require(bool(images), "the chart rendered no container")
    return sorted(images)


def image_configs(images: list[str]) -> dict[str, Any]:
    """Return the image configuration of every rendered image.

    release/inputs/image-config.json records each image that this repository
    does not build. A repository image is read from the registry by digest.
    """
    record = MAN["read_json"](release_spec.IMAGE_CONFIG)
    require(isinstance(record, dict), "release image configuration is not a mapping")
    require(not any(image.startswith(release_spec.REPOSITORY_IMAGES) for image in record),
            "release/inputs/image-config.json must not record a repository image")
    for image in images:
        if image not in record:
            require(image.startswith(release_spec.REPOSITORY_IMAGES),
                    f"release/inputs/image-config.json has no record for {image}")
            try:
                record[image] = ALLOWLIST_GENERATOR["image_config"](image)
            except ALLOWLIST_GENERATOR["GenerationError"] as error:
                raise ManifestError(str(error)) from error
    return record


def require_allowlist_contract(
    allowlist: dict[str, Any],
    policy: dict[str, Any],
    core_images: list[str],
    documents: list[dict[str, Any]],
    image_configs: dict[str, Any],
    c8s_release: str | None = None,
    core_seed: dict[str, Any] | None = None,
) -> None:
    rendered = ALLOWLIST_GENERATOR["controllers"](documents)
    policy_controllers = {item["controller"] for item in policy["workloads"]}
    require(set(rendered) == policy_controllers,
            f"rendered controllers differ from allowlist policy: rendered={sorted(rendered)} policy={sorted(policy_controllers)}")
    expected_names = {item["name"] for item in policy["workloads"]} | set(core_seed or {})
    workloads = allowlist.get("workloads")
    require(isinstance(workloads, dict) and set(workloads) == expected_names,
            "the allowlist entries differ from the allowlist policy")
    core_digests = {OCI.fullmatch(image).group(2) for image in core_images}
    effective_process = ALLOWLIST_GENERATOR["effective_process"]
    for name, expected in ALLOWLIST_GENERATOR["core_entries"](core_images, core_seed or {}).items():
        require(workloads[name] == expected, f"core entry {name} differs from the baked seed")
    for item in policy["workloads"]:
        pod = rendered[item["controller"]]["spec"]["template"]["spec"]
        expected_processes = []
        for container in pod.get("initContainers", []) + pod.get("containers", []):
            image = container.get("image")
            match = OCI.fullmatch(image) if isinstance(image, str) else None
            require(match is not None, f"{item['controller']} has an unpinned container image")
            try:
                process = effective_process(container, image_configs.get(image, {}))
            except ALLOWLIST_GENERATOR["GenerationError"] as error:
                raise ManifestError(f"{item['controller']}: {error}") from error
            command, args = process["command"], process.get("args", [])
            if ALLOWLIST_GENERATOR["is_carved_out"](process, core_digests, c8s_release):
                continue
            expected_processes.append((match.group(2), command, args))
        actual_processes = []
        entry = workloads[item["name"]]
        for container in entry.get("initContainers", []) + entry.get("containers", []):
            command_policy = container.get("command", {})
            args_policy = container.get("args", {})
            require(command_policy.get("policy") == "exact",
                    f"allowlist workload {item['name']} has a non-exact command")
            require(args_policy.get("policy") in {"exact", "deny"},
                    f"allowlist workload {item['name']} has a non-exact argument policy")
            actual_processes.append((
                container.get("digest"),
                command_policy.get("argv"),
                args_policy.get("argv", []) if args_policy.get("policy") == "exact" else [],
            ))
        # C8s canonicalization sorts rules by digest. Compare all exact
        # processes with duplicate counts, independent of chart order.
        process_key = lambda process: json.dumps(process, sort_keys=True)
        require(sorted(actual_processes, key=process_key) == sorted(expected_processes, key=process_key),
                f"allowlist workload {item['name']} process differs from the rendered chart")


def render(
    manifest: dict[str, Any],
    spec: dict[str, Any],
    deployment: release_spec.Deployment,
    c8s: Path,
    canonical_tool: Path | None,
    bundle_sha256: str,
    chart: Path = CHART,
) -> dict[str, bytes]:
    """Return the deployment files by name: allowlist.json, release-values.yaml, and render.json."""
    require_deployment_values(deployment)
    policy = read_allowlist_policy(deployment.policy)
    overlay_bytes = release_overlay(manifest)
    framework_images = set(manifest["images"].values()) | set(manifest["c8s"]["coreImages"])
    feature = ALLOWLIST_GENERATOR["feature_release"](spec["c8s"])
    with tempfile.TemporaryDirectory(prefix="render-allowlist-") as directory:
        overlay_path = Path(directory) / "release-values.yaml"
        overlay_path.write_bytes(overlay_bytes)
        documents = render_chart(chart, deployment, policy["chart"], overlay_path)
        images = rendered_images(documents)
        foreign = [image for image in images if image not in framework_images]
        require(not foreign, f"the chart renders images that the framework release does not name: {foreign}")
        config_images = set(images)
        if ALLOWLIST_GENERATOR["c8s_at_least"](feature, (0, 44, 0)):
            config_images.update(spec["c8s"]["coreImages"])
        configs = image_configs(sorted(config_images))
        try:
            allowlist_bytes = ALLOWLIST_GENERATOR["generate"](
                deployment, c8s, canonical_tool, overlay=overlay_path, image_env=configs, c8s=spec["c8s"],
            )
        except ALLOWLIST_GENERATOR["GenerationError"] as error:
            raise ManifestError(str(error)) from error
    allowlist = json.loads(allowlist_bytes)
    require(allowlist.get("schema") == "c8s.allowlist/v1", "the allowlist has the wrong schema")
    require_allowlist_contract(allowlist, policy, spec["c8s"]["coreImages"], documents, configs,
                               feature, ALLOWLIST_GENERATOR["core_seed"](spec["c8s"]))
    allowlisted = {
        container["digest"]
        for entry in allowlist["workloads"].values()
        for container in entry.get("initContainers", []) + entry.get("containers", [])
    }
    missing = [image for image in images if OCI.fullmatch(image).group(2) not in allowlisted]
    require(not missing, f"rendered images absent from the allowlist: {missing}")
    # The client check: every digest of the allowlist is named by the release.
    named = {image.rsplit("@", 1)[1] for image in
             [*manifest["images"].values(), *manifest["c8s"]["coreImages"], *manifest["c8s"]["seedImages"]]}
    unnamed = sorted(allowlisted - named)
    require(not unnamed, f"the allowlist names digests that the framework release does not name: {unnamed}")
    record = {
        "schema": "confidential.ai/deployment-render/v1",
        "frameworkRelease": {"name": manifest["release"]["name"], "sourceCommit": manifest["source"]["commit"],
                             "bundleSha256": bundle_sha256},
        "values": [{"path": deployment.relative(path), "sha256": sha256(path.read_bytes())}
                   for path in deployment.values_files],
        "policy": {"path": deployment.relative(deployment.policy), "sha256": sha256(deployment.policy.read_bytes())},
        "acceptedFindings": None if deployment.accepted_findings is None else {
            "path": deployment.relative(deployment.accepted_findings),
            "sha256": sha256(deployment.accepted_findings.read_bytes())},
        "allowlistSha256": sha256(allowlist_bytes),
        "releaseValuesSha256": sha256(overlay_bytes),
    }
    return {
        "allowlist.json": allowlist_bytes,
        "release-values.yaml": overlay_bytes,
        "render.json": (json.dumps(record, indent=2, sort_keys=True) + "\n").encode(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--release", type=Path, required=True, help="the framework release-bundle.json")
    parser.add_argument("--signature", type=Path, required=True, help="its release-bundle.sigstore.json")
    parser.add_argument("--values", type=Path, action="append", required=True,
                        help="a deployment Helm values file; repeat it, in order")
    parser.add_argument("--policy", type=Path, required=True, help="the deployment allowlist policy")
    parser.add_argument("--accepted-findings", type=Path, help="the lint findings that the deployment accepts")
    parser.add_argument("--c8s", type=Path, required=True,
                        help="the c8s CLI built from the c8s source commit of the framework release")
    parser.add_argument("--canonical-tool", type=Path, help="a built tools/c8s-allowlist-canonical binary")
    parser.add_argument("--cosign", type=Path, help="the Cosign verifier (default: cosign on PATH)")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        cosign = args.cosign or (Path(found) if (found := shutil.which("cosign")) else None)
        require(cosign is not None, "verifying the framework release needs cosign")
        manifest, bundle = verify_release(args.release, args.signature, cosign.resolve())
        spec = require_checkout(manifest)
        deployment = release_spec.Deployment(
            tuple(path.resolve() for path in args.values), args.policy.resolve(),
            args.accepted_findings.resolve() if args.accepted_findings else None)
        files = render(manifest, spec, deployment, args.c8s.resolve(),
                       args.canonical_tool.resolve() if args.canonical_tool else None,
                       sha256(bundle))
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            (args.output_dir / name).write_bytes(data)
    except (ManifestError, OSError, KeyError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"render-allowlist: {error}", file=sys.stderr)
        return 1
    print(json.dumps({name: sha256(data) for name, data in files.items()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
