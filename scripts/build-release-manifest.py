#!/usr/bin/env python3
"""Build a release: the release manifest, which the release signs, and the files it binds.

The manifest states what the release is. The client verifies it. It lists:

- the release version and the public hostnames;
- every container image digest that the chart renders with the profile values;
- the Helm chart identity;
- the c8s release, its source commit, its core image digests, and the source
  lock entry for that commit;
- the node image digest and its TDX measurements;
- the model identity;
- the SHA-256 of the generated allowlist and of the generated values file.

It holds no deployment value: no mesh CA, no operator key, no node name.

The release tag is the version. The tag selects the profile
(release/profiles.json), and the build sets the release name and the chart
value attestationReceipts.releaseId to it. A release needs no commit that
changes a version.

The repository holds no digest of an image that it builds. The build takes
each one from signed evidence:

- an image that changed after the base release of the image publication: the
  publication evidence of the release-images run, which pushed the audited
  digest;
- any other image: the signed manifest of that base release. The build
  verifies its signature and that no build input of the image changed since.

The publication evidence names its base (source.baseRef). When the base is a
release tag, the build downloads release-bundle.json and
release-bundle.sigstore.json of that GitHub release itself. The repository
is public, so it needs no token; the build sends GH_TOKEN when it is set.
When the base is a commit, there is no base release. The caller does not
choose. --download-dir keeps the downloaded files; the build uses the files
already there, after the same checks.

The build writes three files to --output-dir:

- release-bundle.json: the manifest. It must match
  contracts/release-manifest.schema.json;
- allowlist.json: the c8s allowlist, generated with the pinned c8s CLI from
  the chart rendered with these digests. The manifest binds its SHA-256;
- release-values.yaml: the Helm values file with the repository image
  digests and the release ID. Apply it after the profile values files. The
  manifest binds its SHA-256 (releaseValues).

The release workflow builds them at the tag, signs the manifest, and attaches
all three to the GitHub release. Anyone can build them again from the tagged
tree with the same inputs and compare the bytes. `--check` fails when an
existing file differs from a new build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

import jsonschema
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_profiles
import release_signature

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "helm/confidential-inference"
SOURCE_LOCK = ROOT / "contracts/c8s-admission-source-lock.json"
SCHEMA = "confidential.ai/release-manifest/v1"
MANIFEST_SCHEMA = ROOT / "contracts/release-manifest.schema.json"
TRUST_POLICY = ROOT / "releases/trust/release-signing-policy.json"
REPOSITORY = "https://github.com/confidential-dot-ai/confidential-inference"
IMAGE_SELECTOR = runpy.run_path(str(ROOT / "scripts/affected-release-images.py"))
ALLOWLIST_GENERATOR = runpy.run_path(str(ROOT / "scripts/generate-release-allowlist.py"))
PUBLICATION = runpy.run_path(str(ROOT / "scripts/image-publication-manifest.py"))
C8S_VERSION = re.compile(f"^{release_profiles.VERSION}(?:-beta\.([1-9][0-9]*))?$")
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


def read_spec(profile: release_profiles.Profile) -> dict[str, Any]:
    """Read the profile specification, which its spec.yaml layers make."""
    try:
        spec = release_profiles.read_spec(profile)
    except release_profiles.ProfileError as error:
        raise ManifestError(str(error)) from error
    return validate_spec(spec)


def validate_spec(spec: Any) -> dict[str, Any]:
    require(isinstance(spec, dict), "the release specification is not a mapping")
    require(
        set(spec) == {"c8s", "model", "publicHostnames"},
        "the release specification must hold exactly c8s, model, and publicHostnames; the tag is the version",
    )
    c8s = spec["c8s"]
    require(isinstance(c8s, dict), "c8s must be a mapping")
    require(isinstance(c8s.get("release"), str) and C8S_VERSION.fullmatch(c8s["release"]) is not None,
            "c8s.release must be vX.Y.Z or vX.Y.Z-beta.N")
    require(isinstance(c8s.get("sourceCommit"), str) and COMMIT.fullmatch(c8s["sourceCommit"]) is not None,
            "c8s.sourceCommit must be a full Git commit")
    node = c8s.get("nodeImage", {})
    require(isinstance(node.get("reference"), str) and DIGEST.fullmatch(str(node.get("digest"))) is not None,
            "c8s.nodeImage needs a reference and a digest")
    require(DIGEST.fullmatch(str(c8s.get("nodeManifestArtifact", {}).get("digest"))) is not None,
            "c8s.nodeManifestArtifact.digest must be a SHA-256 digest")
    require(DIGEST.fullmatch(str(c8s["nodeManifestArtifact"].get("manifestJson"))) is not None,
            "c8s.nodeManifestArtifact.manifestJson must be a SHA-256 digest")
    core_images = c8s.get("coreImages")
    require(isinstance(core_images, list) and core_images
            and len(set(core_images)) == len(core_images)
            and all(isinstance(image, str) and OCI.fullmatch(image) is not None for image in core_images),
            "c8s.coreImages must be unique digest-pinned images")
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
    chart: Path, profile: release_profiles.Profile, settings: dict[str, str], overlay: Path,
) -> list[dict[str, Any]]:
    """Render the chart with the profile values files in layer order, then the overlay."""
    result = subprocess.run(
        ["helm", "template", settings["release"], str(chart),
         "--namespace", settings["namespace"], "--kube-version", settings["kubeVersion"],
         *release_profiles.helm_values_args(profile, overlay)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise ManifestError(f"helm template failed: {result.stderr.strip()}")
    return [item for item in yaml.safe_load_all(result.stdout) if isinstance(item, dict)]


def read_allowlist_policy(path: Path) -> dict[str, Any]:
    policy = read_json(path)
    require(isinstance(policy, dict) and policy.get("schema") == ALLOWLIST_GENERATOR["POLICY_SCHEMA"],
            f"{path.name} has the wrong schema")
    chart = policy.get("chart")
    require(isinstance(chart, dict) and set(chart) == {"release", "namespace", "kubeVersion"},
            "allowlist policy chart settings are incomplete")
    for name in ("release", "namespace", "kubeVersion"):
        require(isinstance(chart[name], str) and bool(chart[name]),
                f"allowlist policy chart.{name} is invalid")
    require("c8s" not in policy, "the allowlist policy must not pin c8s; spec.yaml does")
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


def require_model_files(spec: dict[str, Any], documents: list[dict[str, Any]]) -> None:
    """Require each rendered worker to check the byte manifest of the spec.

    The chart decides which files a worker checks, so this reads the rendered
    arguments, not the values.
    """
    workers = [item for item in documents if item.get("kind") == "StatefulSet"
               and item.get("metadata", {}).get("name", "").startswith("inference-worker-")]
    require(bool(workers), "the chart renders no inference worker")
    for worker in workers:
        container = next(item for item in worker["spec"]["template"]["spec"]["containers"]
                         if item["name"] == "sglang")
        args = container.get("args", [])
        metadata = [arg.removeprefix("--revision-metadata=") for arg in args
                    if arg.startswith("--revision-metadata=")]
        require(len(metadata) == 1, "a worker has no single revision metadata file")
        digests = [arg.removeprefix(f"--expected-file={metadata[0]}=") for arg in args
                   if arg.startswith(f"--expected-file={metadata[0]}=")]
        require(digests == [spec["model"]["byteManifestSha256"]],
                "the rendered model byte manifest differs from spec model byte manifest")


def require_c8s_agreement(spec: dict[str, Any], values: dict[str, Any]) -> None:
    operator = values.get("images", {}).get("c8sOperator")
    require(operator in spec["c8s"]["coreImages"],
            "values c8s operator image is not one of the spec c8s core images")


def require_allowlist_contract(
    allowlist: dict[str, Any],
    policy: dict[str, Any],
    core_images: list[str],
    documents: list[dict[str, Any]],
    image_configs: dict[str, Any],
) -> None:
    rendered = ALLOWLIST_GENERATOR["controllers"](documents)
    policy_controllers = {item["controller"] for item in policy["workloads"]}
    require(set(rendered) == policy_controllers,
            f"rendered controllers differ from allowlist policy: rendered={sorted(rendered)} policy={sorted(policy_controllers)}")
    expected_names = {item["name"] for item in policy["workloads"]}
    expected_names |= {ALLOWLIST_GENERATOR["floor_entry"](image)[0] for image in core_images}
    workloads = allowlist.get("workloads")
    require(isinstance(workloads, dict) and set(workloads) == expected_names,
            "the allowlist entries differ from the profile allowlist policy")
    core_digests = {OCI.fullmatch(image).group(2) for image in core_images}
    injected = ALLOWLIST_GENERATOR["INJECTED_ENTRYPOINTS"]
    effective_process = ALLOWLIST_GENERATOR["effective_process"]
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


CHART_REPOSITORY = "ghcr.io/confidential-dot-ai/confidential-inference/charts"
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def chart_version(tag: str, profile: release_profiles.Profile) -> str:
    """The package version: the tag without `v` and without the profile suffix.

    One package per source commit: vX.Y.Z-staging and vX.Y.Z share version
    X.Y.Z, and the production release binds the package the staging release
    built (staging_chart_binding).
    """
    suffix = profile.tag_suffix
    require(tag.startswith("v") and (not suffix or tag.endswith(suffix)),
            f"tag {tag} does not fit profile {profile.name}")
    version = tag[1:len(tag) - len(suffix)] if suffix else tag[1:]
    require(VERSION.fullmatch(version) is not None, f"tag {tag} is not vX.Y.Z{suffix}")
    return version


def chart_reference(name: str, version: str) -> str:
    """The OCI reference of the chart package, by version. The archive digest identifies its bytes."""
    return f"{CHART_REPOSITORY}/{name}:{version}"


def package_chart(chart: Path, version: str, directory: Path) -> Path:
    """Package `chart` as `version` into `directory` with the helm on PATH."""
    result = subprocess.run(
        ["helm", "package", str(chart), "--version", version, "--destination", str(directory)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise ManifestError(f"helm package failed: {result.stderr.strip()}")
    archive = directory / f"{chart_identity(chart)['name']}-{version}.tgz"
    require(archive.is_file(), f"helm package wrote no {archive.name}")
    return archive


def verify_archive_content(archive: Path, chart: Path, version: str) -> None:
    """Require that the archive holds the chart tree, with only the version of Chart.yaml changed.

    helm package rewrites Chart.yaml and the archive bytes carry mtimes, so the
    archive is evidence like an image digest: this compares its content with
    the tagged tree instead of its bytes.
    """
    name = chart_identity(chart)["name"]
    expected = {p.relative_to(chart).as_posix(): p.read_bytes() for p in chart.rglob("*") if p.is_file()}
    try:
        with tarfile.open(archive, "r:gz") as tar:
            members = {m.name: m for m in tar.getmembers() if m.isfile()}
            require(all(m.startswith(f"{name}/") for m in members), "the archive holds files outside the chart")
            actual = {m[len(name) + 1:]: tar.extractfile(members[m]).read() for m in members}
    except (tarfile.TarError, OSError) as error:
        raise ManifestError(f"cannot read the chart archive: {error}") from error
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    require(not missing and not extra, f"archive files differ from the chart: missing {missing}, extra {extra}")
    for path in sorted(expected):
        if path == "Chart.yaml":
            want = {**yaml.safe_load(expected[path]), "version": version}
            require(yaml.safe_load(actual[path]) == want,
                    f"Chart.yaml in the archive differs from the chart at version {version}")
        else:
            require(actual[path] == expected[path], f"{path} in the archive differs from the chart")


def source_lock_entry(lock: dict[str, Any], commit: str) -> dict[str, Any]:
    entries = [lock, *lock.get("commits", [])]
    matches = [entry for entry in entries if entry.get("commit") == commit]
    require(len(matches) == 1, f"the source lock does not pin c8s commit {commit} exactly once")
    entry = {key: value for key, value in matches[0].items() if key != "commits" and key != "schema"}
    return entry


def node_measurements(path: Path, spec: dict[str, Any]) -> dict[str, Any]:
    data = path.read_bytes()
    require(sha256(data) == spec["c8s"]["nodeManifestArtifact"]["manifestJson"],
            f"{path.name} differs from c8s.nodeManifestArtifact.manifestJson")
    document = json.loads(data)
    tdx = document.get("tdx", {})
    values = {name: tdx.get(name) for name in ("mrtd", "rtmr1", "rtmr2")}
    for name, value in values.items():
        require(isinstance(value, str) and MEASUREMENT.fullmatch(value) is not None,
                f"the node manifest tdx.{name} is invalid")
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


def read_publication(path: Path) -> tuple[bytes, dict[str, Any]]:
    data = path.read_bytes()
    try:
        publication = PUBLICATION["validate"](json.loads(data))
    except (PUBLICATION["PublicationError"], json.JSONDecodeError) as error:
        raise ManifestError(f"image publication: {error}") from error
    registered = {f"{release_profiles.REPOSITORY_IMAGES}{image.image}" for image in IMAGE_SELECTOR["IMAGES"]}
    for entry in publication["images"]:
        require(entry["name"] in registered,
                f"published image is outside the release image registry: {entry['name']}")
    return data, publication


def changed_paths(base: str, head: str, repo: Path = ROOT) -> list[str]:
    """Return the paths that changed from base to head. Base must be an ancestor."""
    ancestor = subprocess.run(["git", "merge-base", "--is-ancestor", base, head],
                              cwd=repo, capture_output=True, text=True)
    require(ancestor.returncode == 0, f"{base} is not an ancestor of {head}")
    changed = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "--diff-filter=ACMRTD", base, head],
        cwd=repo, capture_output=True, text=True,
    )
    require(changed.returncode == 0, f"cannot compare {base} and {head}")
    return changed.stdout.splitlines()


BASE_RELEASE_FILES = ("release-bundle.json", "release-bundle.sigstore.json")
MAX_BASE_RELEASE_FILE_BYTES = 16 * 1024 * 1024


def fetch(url: str) -> bytes:
    """Return the bytes at `url`. GH_TOKEN, when set, authenticates to GitHub only."""
    request = urllib.request.Request(url)
    if os.environ.get("GH_TOKEN"):
        # An unredirected header is not sent to the asset host that GitHub redirects to.
        request.add_unredirected_header("Authorization", f"Bearer {os.environ['GH_TOKEN']}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(MAX_BASE_RELEASE_FILE_BYTES + 1)
    except OSError as error:
        raise ManifestError(f"cannot download {url}: {error}") from error
    require(len(data) <= MAX_BASE_RELEASE_FILE_BYTES, f"{url} is too large")
    return data


def download_base_release(tag: str, directory: Path) -> tuple[Path, Path]:
    """Return the signed manifest and Sigstore bundle of release `tag` in `directory`.

    The build downloads them from the GitHub release of this repository. The
    repository is public, so it needs no token; it sends GH_TOKEN when it is
    set. When both files are already in `directory`, it uses them. The
    caller trusts neither file until it verifies the signature.
    """
    paths = tuple(directory / name for name in BASE_RELEASE_FILES)
    if not all(path.is_file() for path in paths):
        directory.mkdir(parents=True, exist_ok=True)
        for path in paths:
            path.write_bytes(fetch(f"{REPOSITORY}/releases/download/{tag}/{path.name}"))
    return paths


def base_release_images(
    publication: dict[str, Any],
    download_dir: Path,
    repo: Path = ROOT,
) -> dict[str, str]:
    """Return the repository image digests of the base release of the publication.

    The image run publishes only the images that changed after its base. When
    the base is a release tag (release_profiles.tag_pattern), every other
    image keeps the digest that the signed manifest of that release names.
    The build downloads that manifest and its Sigstore bundle into
    `download_dir`. The manifest must carry a valid release signature, name
    the base tag and commit of the publication, and no build input of an
    image outside the publication may have changed since. When the base is a
    commit, there is no base release.
    """
    source = publication["source"]
    if release_profiles.tag_pattern().fullmatch(source["baseRef"]) is None:
        return {}
    base_path, signature_path = download_base_release(source["baseRef"], download_dir)
    cosign = shutil.which("cosign")
    require(cosign is not None, "verifying the base release needs cosign")
    try:
        release_signature.verify_release_signature(base_path, signature_path, Path(cosign).resolve(), 60)
    except (OSError, release_signature.ReleaseSignatureError) as error:
        raise ManifestError(f"the base release signature: {error}") from error
    base = read_json(base_path)
    validate_schema(base)
    require(base["release"]["name"] == source["baseRef"],
            "the base release manifest names a different release than the image publication base")
    require(base["source"]["commit"] == source["baseRefCommit"],
            "the base release source commit differs from the image publication base commit")
    changed = changed_paths(source["baseRefCommit"], source["commit"], repo)
    published = {entry["name"] for entry in publication["images"]}
    unpublished = [image.image for image in IMAGE_SELECTOR["affected_images"](changed)
                   if f"{release_profiles.REPOSITORY_IMAGES}{image.image}" not in published]
    require(not unpublished,
            "image build inputs changed after the base release, and the publication has no new digest: "
            + ", ".join(unpublished))
    images: dict[str, str] = {}
    for image in base["images"].values():
        name, digest = image.rsplit("@", 1)
        if name.startswith(release_profiles.REPOSITORY_IMAGES):
            images[name] = digest
    return images


def release_images(
    values: dict[str, Any], publication: dict[str, Any], base: dict[str, str],
) -> dict[str, str]:
    """Give each repository image of the values its digest: published, else from the base release."""
    published = {entry["name"]: entry["digest"] for entry in publication["images"]}
    resolved: dict[str, str] = {}
    for key, value in values.get("images", {}).items():
        if not isinstance(value, str) or not value.startswith(release_profiles.REPOSITORY_IMAGES):
            continue
        require("@" not in value,
                f"values.images.{key} pins a digest; the release takes it from the image publication")
        digest = published.get(value) or base.get(value)
        require(digest is not None, f"neither the image publication nor the base release names {value}")
        resolved[key] = f"{value}@{digest}"
    return dict(sorted(resolved.items()))


def image_configs(images: list[str]) -> dict[str, Any]:
    """Return the image configuration of every rendered image.

    release/inputs/image-config.json records each image that this repository
    does not build. A repository image is read from the registry by digest.
    """
    record = read_json(release_profiles.IMAGE_CONFIG)
    require(isinstance(record, dict), "release image configuration is not a mapping")
    require(not any(image.startswith(release_profiles.REPOSITORY_IMAGES) for image in record),
            "release/inputs/image-config.json must not record a repository image")
    for image in images:
        if image not in record:
            require(image.startswith(release_profiles.REPOSITORY_IMAGES),
                    f"release/inputs/image-config.json has no record for {image}")
            try:
                record[image] = ALLOWLIST_GENERATOR["image_config"](image)
            except ALLOWLIST_GENERATOR["GenerationError"] as error:
                raise ManifestError(str(error)) from error
    return record


def publication_binding(
    data: bytes, publication: dict[str, Any], release_images: dict[str, str],
) -> dict[str, Any]:
    """Bind the publication evidence into the signed manifest."""
    for entry in publication["images"]:
        deployed = [image for image in release_images.values() if image.rsplit("@", 1)[0] == entry["name"]]
        require(all(image == f"{entry['name']}@{entry['digest']}" for image in deployed),
                f"published image digest differs from the rendered release: {entry['name']}@{entry['digest']}")
    return {
        "artifact": "image-publication-manifest.json",
        "manifestSha256": sha256(data),
        "sourceCommit": publication["source"]["commit"],
        "baseRef": publication["source"]["baseRef"],
        "baseRefCommit": publication["source"]["baseRefCommit"],
        "images": {entry["name"]: entry["digest"] for entry in publication["images"]},
    }


def verify_image_source_boundary(
    image_source_commit: str,
    release_source_commit: str,
    repo: Path = ROOT,
) -> None:
    """Require that no image build input changed from the image source to the release commit.

    The release commit is the image source commit, or a later commit that
    changes no image. The selector of the release commit decides what an
    image input is, here and for the base-to-source check of the build, so
    a change of the selector itself needs no new images: the whole diff from
    the base release to the release commit is re-read with the new selector.
    """
    try:
        paths = changed_paths(image_source_commit, release_source_commit, repo)
    except ManifestError as error:
        raise ManifestError(f"the image source commit must be an ancestor of the release commit: {error}") from error
    affected = IMAGE_SELECTOR["affected_images"](paths)
    require(not affected,
            "image build inputs changed after the image source commit: "
            + ", ".join(image.image for image in affected))


def build(
    tag: str,
    chart: Path,
    lock_path: Path,
    source_commit: str,
    publication_path: Path,
    download_dir: Path | None,
    c8s: Path,
    canonical_tool: Path | None,
) -> dict[str, bytes]:
    """Return the release files by name: the manifest, the allowlist, and the values overlay."""
    try:
        profile = release_profiles.for_tag(tag)
    except release_profiles.ProfileError as error:
        raise ManifestError(str(error)) from error
    chart = chart.resolve()
    require(COMMIT.fullmatch(source_commit) is not None, "--source-commit must be a full Git commit")
    spec = read_spec(profile)
    publication_bytes, publication = read_publication(publication_path)
    verify_image_source_boundary(publication["source"]["commit"], source_commit)
    with tempfile.TemporaryDirectory(prefix="base-release-") as directory:
        base = base_release_images(publication, download_dir or Path(directory))
    policy = read_allowlist_policy(profile.policy)
    values = release_profiles.read_values(profile)
    require(isinstance(values, dict) and bool(values), "the profile values are not a mapping")
    overlay = {
        "images": release_images(values, publication, base),
        "attestationReceipts": {"releaseId": tag},
    }
    overlay_bytes = yaml.safe_dump(overlay, sort_keys=True).encode()
    values = release_profiles.merge_values(values, overlay)
    require_model_agreement(spec, values)
    require_c8s_agreement(spec, values)
    with tempfile.TemporaryDirectory(prefix="release-build-") as directory:
        overlay_path = Path(directory) / "release-values.yaml"
        overlay_path.write_bytes(overlay_bytes)
        documents = render_chart(chart, profile, policy["chart"], overlay_path)
        images = rendered_images(documents)
        unresolved = [image for image in images if image.startswith(release_profiles.REPOSITORY_IMAGES)
                      and image not in overlay["images"].values()]
        require(not unresolved, f"rendered repository images without a published digest: {unresolved}")
        configs = image_configs(images)
        try:
            allowlist_bytes = ALLOWLIST_GENERATOR["generate"](
                profile, c8s, canonical_tool, overlay=overlay_path, image_env=configs,
            ) + b"\n"
        except ALLOWLIST_GENERATOR["GenerationError"] as error:
            raise ManifestError(str(error)) from error
    allowlist_path = profile.allowlist
    allowlist = json.loads(allowlist_bytes)
    require(allowlist.get("schema") == "c8s.allowlist/v1", "the allowlist has the wrong schema")
    require_model_files(spec, documents)
    require_allowlist_contract(allowlist, policy, spec["c8s"]["coreImages"], documents, configs)
    allowlisted = {
        container["digest"]
        for entry in allowlist["workloads"].values()
        for container in entry.get("initContainers", []) + entry.get("containers", [])
    }
    missing = [image for image in images if OCI.fullmatch(image).group(2) not in allowlisted]
    require(not missing, f"rendered images absent from the allowlist: {missing}")
    lock = source_lock_entry(read_json(lock_path), spec["c8s"]["sourceCommit"])
    require(lock.get("tag") == spec["c8s"]["release"], "the source lock tag differs from c8s.release")
    node_reference = f"{spec['c8s']['nodeImage']['reference']}@{spec['c8s']['nodeImage']['digest']}"
    require(lock["nodeImage"] == node_reference, "the source lock node image differs from c8s.nodeImage")
    node = node_measurements(release_profiles.node_manifest(profile), spec)
    named_images = image_names(values, images)
    publication = publication_binding(publication_bytes, publication, named_images)
    manifest = {
        "schema": SCHEMA,
        "release": {
            "name": tag,
            "environment": profile.environment,
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
        "releaseValues": {
            "path": profile.release_values.relative_to(ROOT).as_posix(),
            "sha256": sha256(overlay_bytes),
        },
        "publicHostnames": spec["publicHostnames"],
    }
    validate_schema(manifest)
    return {
        "release-bundle.json": encode(manifest),
        "allowlist.json": allowlist_bytes,
        "release-values.yaml": overlay_bytes,
    }


def validate_schema(manifest: dict[str, Any]) -> None:
    schema = read_json(MANIFEST_SCHEMA)
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(manifest), key=lambda e: list(e.path))
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "manifest"
        raise ManifestError(f"the manifest does not match {MANIFEST_SCHEMA.name}: {location}: {errors[0].message}")


def encode(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag", required=True,
                        help="the release tag, vX.Y.Z or vX.Y.Z-staging; it selects the profile")
    parser.add_argument("--chart", type=Path, default=CHART)
    parser.add_argument("--source-lock", type=Path, default=SOURCE_LOCK)
    parser.add_argument("--source-commit", required=True,
                        help="the commit of this repository that the release tag names")
    parser.add_argument("--image-publication", type=Path, required=True,
                        help="verified image publication manifest from the release-images workflow")
    parser.add_argument("--download-dir", type=Path,
                        help="where the build keeps the signed base release that it downloads "
                             "(default: a temporary directory); it uses the files already there")
    parser.add_argument("--c8s", type=Path, required=True,
                        help="the c8s CLI built from the pinned c8s source commit")
    parser.add_argument("--canonical-tool", type=Path,
                        help="a built tools/c8s-allowlist-canonical binary")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        files = build(
            args.tag,
            args.chart,
            args.source_lock.resolve(),
            args.source_commit,
            args.image_publication.resolve(),
            args.download_dir.resolve() if args.download_dir else None,
            args.c8s.resolve(),
            args.canonical_tool.resolve() if args.canonical_tool else None,
        )
        for name, data in files.items():
            output = args.output_dir / name
            if args.check:
                require(output.is_file() and output.read_bytes() == data,
                        f"{output} differs from a new build")
            else:
                args.output_dir.mkdir(parents=True, exist_ok=True)
                output.write_bytes(data)
    except (ManifestError, OSError, KeyError, json.JSONDecodeError) as error:
        print(f"build-release-manifest: {error}", file=sys.stderr)
        return 1
    print(json.dumps({name: sha256(data) for name, data in files.items()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
