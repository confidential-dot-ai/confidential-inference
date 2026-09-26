#!/usr/bin/env python3
"""Build the release manifest, the file that the release signs.

The manifest states what the release is. The client verifies it. It lists:

- the release version and the public hostnames;
- every container image digest that the chart renders with release/values.yaml;
- the Helm chart identity;
- the c8s release, its source commit, its core image digests, and the source
  lock entry for that commit;
- the node image digest and its TDX measurements;
- the model identity;
- the SHA-256 of release/allowlist.json.

It holds no deployment value: no mesh CA, no operator key, no node name. It
names the source commit of the release tag, so it is not committed to the
repository. The release workflow builds it at the tag, signs it, and attaches
it to the GitHub release. Anyone can rebuild it from the tagged tree with
`--source-commit <tag commit>` and compare the bytes.

The output must match contracts/release-manifest.schema.json.
`--check` fails when an existing file differs from a new build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import runpy
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "release"
CHART = ROOT / "helm/confidential-inference"
SOURCE_LOCK = ROOT / "contracts/c8s-admission-source-lock.json"
SCHEMA = "confidential.ai/release-manifest/v1"
MANIFEST_SCHEMA = ROOT / "contracts/release-manifest.schema.json"
PUBLICATION_SCHEMA = ROOT / "contracts/image-publication-manifest.schema.json"
TRUST_POLICY = ROOT / "releases/trust/release-signing-policy.json"
REPOSITORY = "https://github.com/confidential-dot-ai/confidential-inference"
IMAGE_SELECTOR = runpy.run_path(str(ROOT / "scripts/affected-release-images.py"))
VERSION = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-staging)?$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
OCI = re.compile(r"^([^@\s]+)@(sha256:[0-9a-f]{64})$")
MEASUREMENT = re.compile(r"^[0-9a-f]{96}$")
HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class ManifestError(ValueError):
    """The release inputs are incomplete or inconsistent."""


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def read_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ManifestError(f"cannot read {path}: {error}") from error


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError(f"cannot read {path}: {error}") from error


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def read_spec(path: Path) -> dict[str, Any]:
    spec = read_yaml(path)
    require(isinstance(spec, dict), "release/spec.yaml is not a mapping")
    require(
        set(spec) == {"version", "imageSourceCommit", "c8s", "model", "publicHostnames"},
        "release/spec.yaml must hold exactly version, imageSourceCommit, c8s, model, and publicHostnames",
    )
    require(isinstance(spec["version"], str) and VERSION.fullmatch(spec["version"]) is not None,
            "version must be vX.Y.Z or vX.Y.Z-staging")
    require(COMMIT.fullmatch(str(spec["imageSourceCommit"])) is not None,
            "imageSourceCommit must be a full Git commit")
    c8s = spec["c8s"]
    require(isinstance(c8s, dict), "c8s must be a mapping")
    require(isinstance(c8s.get("release"), str) and VERSION.fullmatch(c8s["release"]) is not None,
            "c8s.release must be vX.Y.Z")
    require(isinstance(c8s.get("sourceCommit"), str) and COMMIT.fullmatch(c8s["sourceCommit"]) is not None,
            "c8s.sourceCommit must be a full Git commit")
    node = c8s.get("nodeImage", {})
    require(isinstance(node.get("reference"), str) and DIGEST.fullmatch(str(node.get("digest"))) is not None,
            "c8s.nodeImage needs a reference and a digest")
    require(DIGEST.fullmatch(str(c8s.get("nodeManifestArtifact", {}).get("digest"))) is not None,
            "c8s.nodeManifestArtifact.digest must be a SHA-256 digest")
    model = spec["model"]
    require(isinstance(model, dict) and set(model) == {"repository", "revision", "byteManifestSha256"},
            "model must hold exactly repository, revision, and byteManifestSha256")
    require(COMMIT.fullmatch(str(model["revision"])) is not None, "model.revision must be a full commit")
    require(re.fullmatch(r"[0-9a-f]{64}", str(model["byteManifestSha256"])) is not None,
            "model.byteManifestSha256 must be 64 hex characters")
    hosts = spec["publicHostnames"]
    require(isinstance(hosts, list) and hosts and len(set(hosts)) == len(hosts)
            and all(isinstance(h, str) and HOSTNAME.fullmatch(h) for h in hosts),
            "publicHostnames must be unique lowercase DNS names")
    return spec


def render_chart(
    chart: Path,
    values: Path,
    *,
    release_name: str,
    namespace: str,
    kube_version: str,
) -> list[dict[str, Any]]:
    result = subprocess.run(
        ["helm", "template", release_name, str(chart),
         "--namespace", namespace, "--kube-version", kube_version,
         "--values", str(values)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise ManifestError(f"helm template failed: {result.stderr.strip()}")
    return [item for item in yaml.safe_load_all(result.stdout) if isinstance(item, dict)]


def read_allowlist_policy(path: Path, spec: dict[str, Any]) -> dict[str, Any]:
    policy = read_json(path)
    require(isinstance(policy, dict) and policy.get("schema") == "confidential.ai/release-allowlist-policy/v1",
            "release/allowlist-policy.json has the wrong schema")
    chart = policy.get("chart")
    require(isinstance(chart, dict) and set(chart) == {"release", "namespace", "kubeVersion"},
            "allowlist policy chart settings are incomplete")
    for name in ("release", "namespace", "kubeVersion"):
        require(isinstance(chart[name], str) and bool(chart[name]),
                f"allowlist policy chart.{name} is invalid")
    c8s = policy.get("c8s")
    require(isinstance(c8s, dict), "allowlist policy c8s settings are absent")
    require(c8s.get("release") == spec["c8s"]["release"],
            "allowlist policy c8s release differs from the release specification")
    require(c8s.get("sourceCommit") == spec["c8s"]["sourceCommit"],
            "allowlist policy c8s source commit differs from the release specification")
    core_images = c8s.get("coreImages")
    require(isinstance(core_images, list) and core_images
            and len(set(core_images)) == len(core_images)
            and all(isinstance(image, str) and OCI.fullmatch(image) is not None for image in core_images),
            "allowlist policy core images are invalid")
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


def require_model_agreement(spec: dict[str, Any], values: dict[str, Any]) -> None:
    model = values.get("inference", {}).get("model", {})
    release_model = spec["model"]
    require(model.get("name") == release_model["repository"],
            "values model name differs from spec model repository")
    require(model.get("revision") == release_model["revision"],
            "values model revision differs from spec model revision")
    verification = model.get("mountVerification", {})
    metadata = verification.get("revisionMetadata")
    expected = verification.get("expectedFiles", {})
    require(isinstance(metadata, str) and metadata,
            "values model mount verification has no revision metadata file")
    require(isinstance(expected, dict) and expected.get(metadata) == release_model["byteManifestSha256"],
            "values model byte manifest differs from spec model byte manifest")


def allowlist_core_name(image: str) -> str:
    match = OCI.fullmatch(image)
    require(match is not None, f"an allowlist core image is not digest-pinned: {image!r}")
    base = image.split("@")[0].rsplit("/", 1)[-1].split(":")[0][:50]
    return base + "-" + match.group(2).removeprefix("sha256:")[:12]


def require_allowlist_contract(
    allowlist: dict[str, Any],
    policy: dict[str, Any],
    documents: list[dict[str, Any]],
    image_configs: dict[str, Any],
) -> None:
    rendered = {
        f"{item['kind']}/{item['metadata']['name']}": item
        for item in documents
        if item.get("kind") in {"Deployment", "StatefulSet", "DaemonSet"}
    }
    policy_controllers = {item["controller"] for item in policy["workloads"]}
    require(set(rendered) == policy_controllers,
            f"rendered controllers differ from allowlist policy: rendered={sorted(rendered)} policy={sorted(policy_controllers)}")
    expected_names = {item["name"] for item in policy["workloads"]}
    expected_names |= {allowlist_core_name(image) for image in policy["c8s"].get("coreImages", [])}
    workloads = allowlist.get("workloads")
    require(isinstance(workloads, dict) and set(workloads) == expected_names,
            "release/allowlist.json entries differ from the profile allowlist policy")
    core_digests = {OCI.fullmatch(image).group(2) for image in policy["c8s"].get("coreImages", [])}
    injected = {"get-cert", "get-secret", "get-volume", "/c8s"}
    for item in policy["workloads"]:
        pod = rendered[item["controller"]]["spec"]["template"]["spec"]
        expected_processes = []
        for container in pod.get("initContainers", []) + pod.get("containers", []):
            image = container.get("image")
            match = OCI.fullmatch(image) if isinstance(image, str) else None
            require(match is not None, f"{item['controller']} has an unpinned container image")
            config = image_configs.get(image, {})
            command = container.get("command") or config.get("entrypoint") or []
            args = container.get("args") if container.get("args") else (
                [] if container.get("command") else config.get("cmd") or []
            )
            if match.group(2) in core_digests and command and command[0] in injected:
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
        require(actual_processes == expected_processes,
                f"allowlist workload {item['name']} process differs from the rendered profile")


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


def chart_identity(chart: Path) -> dict[str, str]:
    meta = read_yaml(chart / "Chart.yaml")
    files = sorted(p for p in chart.rglob("*") if p.is_file())
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(chart).as_posix()
        data = path.read_bytes()
        digest.update(relative.encode() + b"\0" + str(len(data)).encode() + b"\0" + data)
    return {"name": meta["name"], "version": str(meta["version"]), "treeSha256": "sha256:" + digest.hexdigest()}


def source_lock_entry(lock: dict[str, Any], commit: str) -> dict[str, Any]:
    entries = [lock, *lock.get("commits", [])]
    matches = [entry for entry in entries if entry.get("commit") == commit]
    require(len(matches) == 1, f"the source lock does not pin c8s commit {commit} exactly once")
    entry = {key: value for key, value in matches[0].items() if key != "commits" and key != "schema"}
    return entry


def node_measurements(path: Path, spec: dict[str, Any]) -> dict[str, Any]:
    data = path.read_bytes()
    document = json.loads(data)
    tdx = document.get("tdx", {})
    values = {name: tdx.get(name) for name in ("mrtd", "rtmr1", "rtmr2")}
    for name, value in values.items():
        require(isinstance(value, str) and MEASUREMENT.fullmatch(value) is not None,
                f"release/node-manifest.json tdx.{name} is invalid")
    node = spec["c8s"]["nodeImage"]
    return {
        "image": f"{node['reference']}@{node['digest']}",
        "tag": node.get("tag"),
        "manifestArtifact": spec["c8s"]["nodeManifestArtifact"]["digest"],
        "manifestJsonSha256": sha256(data),
        "tdx": values,
    }


def image_names(values: dict[str, Any], images: list[str]) -> dict[str, str]:
    """Name each rendered image by its key in the values `images` map."""
    named = {key: value for key, value in values.get("images", {}).items() if value in images}
    unnamed = sorted(set(images) - set(named.values()))
    require(not unnamed, f"rendered images with no name in values.images: {unnamed}")
    return dict(sorted(named.items()))


def image_publication(
    path: Path,
    *,
    release_version: str,
    source_commit: str,
    release_images: dict[str, str],
) -> dict[str, Any]:
    """Validate publication evidence and bind it into the signed manifest."""
    data = path.read_bytes()
    publication = json.loads(data)
    schema = read_json(PUBLICATION_SCHEMA)
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(publication),
        key=lambda error: list(error.path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "manifest"
        raise ManifestError(f"image publication {location}: {errors[0].message}")
    require(publication["releaseVersion"] == release_version,
            "image publication release version differs from the release specification")
    require(publication["source"]["repository"] == REPOSITORY,
            "image publication repository differs from the release repository")
    require(publication["source"]["commit"] == source_commit,
            "image publication source commit differs from imageSourceCommit")
    deployed_by_repository = {
        image.rsplit("@", 1)[0]: image
        for image in release_images.values()
    }
    names: list[str] = []
    bound: dict[str, str] = {}
    registered = {
        f"ghcr.io/confidential-dot-ai/confidential-inference/{image.image}"
        for image in IMAGE_SELECTOR["IMAGES"]
    }
    for entry in publication["images"]:
        name = entry["name"]
        pushed = entry["pushedDigest"]
        reproducible = entry["reproducibilityDigest"]
        require(pushed == reproducible,
                f"published digest differs from reproducibility digest for {name}")
        require(name in registered, f"published image is outside the release image registry: {name}")
        deployed = deployed_by_repository.get(name)
        if deployed is not None:
            require(deployed == f"{name}@{pushed}",
                    f"published image digest differs from the rendered release: {name}@{pushed}")
        names.append(name)
        bound[name] = pushed
    require(names == sorted(names) and len(names) == len(set(names)),
            "image publication entries must have unique sorted names")
    require(bool(bound), "image publication has no image")
    return {
        "artifact": "image-publication-manifest.json",
        "manifestSha256": sha256(data),
        "releaseVersion": publication["releaseVersion"],
        "sourceCommit": publication["source"]["commit"],
        "baseRef": publication["source"]["baseRef"],
        "baseRefCommit": publication["source"]["baseRefCommit"],
        "images": dict(sorted(bound.items())),
    }


def verify_image_source_boundary(
    image_source_commit: str,
    release_source_commit: str,
    repo: Path = ROOT,
) -> None:
    """Require a later pin-only release commit for the published images."""
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", image_source_commit, release_source_commit],
        cwd=repo, capture_output=True, text=True,
    )
    require(ancestor.returncode == 0,
            "imageSourceCommit must be an ancestor of the release source commit")
    changed = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRTD",
         image_source_commit, release_source_commit],
        cwd=repo, capture_output=True, text=True,
    )
    require(changed.returncode == 0, "cannot compare image and release source commits")
    selector_path = "scripts/affected-release-images.py"
    selector_changed = subprocess.run(
        ["git", "diff", "--quiet", image_source_commit, release_source_commit, "--", selector_path],
        cwd=repo,
    )
    require(selector_changed.returncode == 0,
            "the image selector changed after imageSourceCommit")
    affected = IMAGE_SELECTOR["affected_images"](changed.stdout.splitlines())
    require(not affected,
            "image build inputs changed after imageSourceCommit: "
            + ", ".join(image.image for image in affected))


def build(
    release: Path,
    chart: Path,
    lock_path: Path,
    source_commit: str,
    publication_path: Path,
) -> dict[str, Any]:
    release = release.resolve()
    chart = chart.resolve()
    require(COMMIT.fullmatch(source_commit) is not None, "--source-commit must be a full Git commit")
    spec = read_spec(release / "spec.yaml")
    verify_image_source_boundary(spec["imageSourceCommit"], source_commit)
    policy = read_allowlist_policy(release / "allowlist-policy.json", spec)
    allowlist_path = release / "allowlist.json"
    require(allowlist_path.is_file(), "release/allowlist.json is absent; generate it first")
    allowlist_bytes = allowlist_path.read_bytes()
    allowlist = json.loads(allowlist_bytes)
    require(allowlist.get("schema") == "c8s.allowlist/v1", "release/allowlist.json has the wrong schema")
    values = read_yaml(release / "values.yaml")
    require(isinstance(values, dict), "release/values.yaml is not a mapping")
    require_model_agreement(spec, values)
    image_configs = read_json(release / "inputs/image-config.json")
    require(isinstance(image_configs, dict), "release image configuration is not a mapping")
    chart_settings = policy["chart"]
    documents = render_chart(
        chart,
        release / "values.yaml",
        release_name=chart_settings["release"],
        namespace=chart_settings["namespace"],
        kube_version=chart_settings["kubeVersion"],
    )
    require_allowlist_contract(allowlist, policy, documents, image_configs)
    images = rendered_images(documents)
    allowlisted = {
        container["digest"]
        for entry in allowlist["workloads"].values()
        for container in entry.get("initContainers", []) + entry.get("containers", [])
    }
    missing = [image for image in images if OCI.fullmatch(image).group(2) not in allowlisted]
    require(not missing, f"rendered images absent from release/allowlist.json: {missing}")
    lock = source_lock_entry(read_json(lock_path), spec["c8s"]["sourceCommit"])
    require(lock.get("tag") == spec["c8s"]["release"], "the source lock tag differs from c8s.release")
    node_reference = f"{spec['c8s']['nodeImage']['reference']}@{spec['c8s']['nodeImage']['digest']}"
    require(lock["nodeImage"] == node_reference, "the source lock node image differs from c8s.nodeImage")
    node = node_measurements(release / "node-manifest.json", spec)
    named_images = image_names(values, images)
    publication = image_publication(
        publication_path,
        release_version=spec["version"],
        source_commit=spec["imageSourceCommit"],
        release_images=named_images,
    )
    manifest = {
        "schema": SCHEMA,
        "release": {
            "name": spec["version"],
            "environment": "staging" if spec["version"].endswith("-staging") else "production",
        },
        "releaseTrust": {
            "policyPath": TRUST_POLICY.relative_to(ROOT).as_posix(),
            "policySha256": sha256(TRUST_POLICY.read_bytes()),
            "signatureType": "sigstore-keyless",
        },
        "source": {"repository": REPOSITORY, "commit": source_commit},
        "imagePublication": publication,
        "images": named_images,
        "chart": {
            "name": chart_identity(chart)["name"],
            "version": chart_identity(chart)["version"],
            "sha256": chart_identity(chart)["treeSha256"],
        },
        "c8s": {"release": spec["c8s"]["release"], "sourceCommit": spec["c8s"]["sourceCommit"]},
        # The SHA-256 of release/node-manifest.json, the c8s manifest.json that
        # records the measurements. Its bytes equal the manifest.json layer of
        # the pinned c8s measurement artifact.
        "nodeImage": {"reference": node_reference, "manifestSha256": node["manifestJsonSha256"]},
        # TEErminator reads the TDX measurements from these top-level fields.
        "mrtd": node["tdx"]["mrtd"],
        "rtmr1": node["tdx"]["rtmr1"],
        "rtmr2": node["tdx"]["rtmr2"],
        "sourceLock": {
            "path": lock_path.relative_to(ROOT).as_posix() if ROOT in lock_path.resolve().parents else str(lock_path),
            "sha256": sha256(lock_path.read_bytes()),
        },
        "model": spec["model"],
        "allowlist": {
            "path": allowlist_path.relative_to(ROOT).as_posix(),
            "sha256": sha256(allowlist_bytes),
        },
        "publicHostnames": spec["publicHostnames"],
    }
    validate_schema(manifest)
    return manifest


def validate_schema(manifest: dict[str, Any]) -> None:
    schema = read_json(MANIFEST_SCHEMA)
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(manifest), key=lambda e: list(e.path))
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "manifest"
        raise ManifestError(f"the manifest does not match {MANIFEST_SCHEMA.name}: {location}: {errors[0].message}")


def encode(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, default=RELEASE)
    parser.add_argument("--chart", type=Path, default=CHART)
    parser.add_argument("--source-lock", type=Path, default=SOURCE_LOCK)
    parser.add_argument("--source-commit", required=True,
                        help="the commit of this repository that the release tag names")
    parser.add_argument("--image-publication", type=Path, required=True,
                        help="verified image publication manifest from the release-images workflow")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        data = encode(build(
            args.release,
            args.chart,
            args.source_lock.resolve(),
            args.source_commit,
            args.image_publication.resolve(),
        ))
        output = args.output
        if args.check:
            require(output.is_file() and output.read_bytes() == data,
                    f"{output} differs from a new build")
        else:
            output.write_bytes(data)
    except (ManifestError, OSError, KeyError, json.JSONDecodeError) as error:
        print(f"build-release-manifest: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"manifest": str(args.output), "sha256": sha256(data)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
