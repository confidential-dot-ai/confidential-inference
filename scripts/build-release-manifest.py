#!/usr/bin/env python3
"""Build a framework release: the release manifest, which the release signs, and the chart package.

The framework release is the product. Its manifest states what the release
is, and a client verifies it. It lists:

- the release version and the source commit;
- the digest of every image that the chart can run (release/spec.yaml);
- the Helm chart identity and the chart package;
- the c8s release, its source commit, its core image digests, the images of
  its node seed, and the source lock entry for that commit;
- the node image digest and its TDX measurements;
- the CDS guest image digest and the SHA-256 of its manifest.json.

It holds no deployment value: no allowlist, no Helm values, no model, no
hostname, no address. Each deployment renders its own allowlist from a
verified framework release with scripts/render-allowlist.py.

The release tag `vX.Y.Z` is the version. The chart package has version
X.Y.Z. A release needs no commit that changes a version.

The repository holds no digest of an image that it builds. The build takes
each one from signed evidence:

- an image that changed after the base release of the image publication: the
  publication evidence of the release-images run, which pushed the audited
  digest;
- any other image: the signed manifest of that base release (or, for a
  release of the earlier format, its hash-bound values asset). The build
  verifies its signature and that no build input of the image changed since.

The publication evidence names its base (source.baseRef). When the base is a
release tag, the build downloads release-bundle.json and
release-bundle.sigstore.json of that GitHub release itself. The repository
is public, so it needs no token; the build sends GH_TOKEN when it is set.
When the base is a commit, there is no base release. --download-dir keeps
the downloaded files; the build uses the files already there, after the same
checks.

The build writes three files to --output-dir:

- release-bundle.json: the manifest. It must match
  api/release-manifest-v2.schema.json;
- <chart>-<X.Y.Z>.tgz: the chart package. The manifest binds its SHA-256
  (chart.archiveSha256) and the OCI reference the publish job pushes it to
  (chart.reference). The build writes the archive itself with fixed metadata
  (not helm package, whose output carries file times), so a rebuild gives
  the same bytes;
- cds-manifest.json: the CDS guest image manifest.json (release/cds-manifest.json).
  The manifest binds its SHA-256 (cdsImage.manifestSha256). A client needs
  its measurements to check the CDS pin of a deployment.

The release workflow builds them at the tag, signs the manifest, and attaches
both to the GitHub release. Anyone can build them again from the tagged tree
with the same inputs and compare the bytes. `--check` fails when an existing
file differs from a new build.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
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
import release_signature
import release_spec

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "helm/confidential-inference"
SOURCE_LOCK = ROOT / "release/inputs/c8s-source-lock.json"
SCHEMA = "confidential.ai/release-manifest/v2"
# The schema of each manifest format. A base release can be of the earlier format.
MANIFEST_SCHEMAS = {
    "confidential.ai/release-manifest/v1": ROOT / "api/release-manifest.schema.json",
    SCHEMA: ROOT / "api/release-manifest-v2.schema.json",
}
TRUST_POLICY = release_signature.POLICY_PATH
REPOSITORY = "https://github.com/confidential-dot-ai/confidential-inference"
IMAGE_SELECTOR = runpy.run_path(str(ROOT / "scripts/affected-release-images.py"))
PUBLICATION = runpy.run_path(str(ROOT / "scripts/image-publication-manifest.py"))
ALLOWLIST_GENERATOR = runpy.run_path(str(ROOT / "scripts/generate-release-allowlist.py"))
C8S_VERSION = re.compile(rf"^{release_spec.VERSION}(?:-beta\.[1-9][0-9]*)?$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
OCI = re.compile(r"^([^@\s]+)@(sha256:[0-9a-f]{64})$")
MEASUREMENT = re.compile(r"^[0-9a-f]{96}$")
IMAGE_KEY = re.compile(r"^[a-z][A-Za-z0-9]*$")
CHART_REPOSITORY = "ghcr.io/confidential-dot-ai/confidential-inference/charts"


class ManifestError(ValueError):
    """The release inputs are incomplete or inconsistent."""


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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


def read_spec(path: Path = release_spec.SPEC) -> dict[str, Any]:
    """Read and check release/spec.yaml: the c8s pin and the image map."""
    try:
        spec = release_spec.read_spec(path)
    except release_spec.SpecError as error:
        raise ManifestError(str(error)) from error
    return validate_spec(spec)


def validate_spec(spec: Any) -> dict[str, Any]:
    require(isinstance(spec, dict) and set(spec) == {"c8s", "images"},
            "the release specification holds exactly c8s and images; the tag is the version")
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
    cds = c8s.get("cdsImage")
    require(isinstance(cds, dict) and isinstance(cds.get("reference"), str)
            and DIGEST.fullmatch(str(cds.get("digest"))) is not None,
            "c8s.cdsImage needs a reference and a digest")
    artifact = c8s.get("cdsManifestArtifact")
    require(isinstance(artifact, dict) and DIGEST.fullmatch(str(artifact.get("digest"))) is not None
            and DIGEST.fullmatch(str(artifact.get("manifestJson"))) is not None,
            "c8s.cdsManifestArtifact needs a digest and a manifestJson SHA-256 digest")
    core_images = c8s.get("coreImages")
    require(isinstance(core_images, list) and core_images
            and len(set(core_images)) == len(core_images)
            and all(isinstance(image, str) and OCI.fullmatch(image) is not None for image in core_images),
            "c8s.coreImages must be unique digest-pinned images")
    images = spec["images"]
    require(isinstance(images, dict) and images, "images must be a mapping")
    for key, image in images.items():
        require(isinstance(key, str) and IMAGE_KEY.fullmatch(key) is not None, f"images.{key} is not a chart image key")
        require(isinstance(image, str) and image, f"images.{key} is not an image")
        if image.startswith(release_spec.REPOSITORY_IMAGES):
            require("@" not in image, f"images.{key} pins a digest; the release takes it from the image publication")
        else:
            require(OCI.fullmatch(image) is not None, f"images.{key} is not digest-pinned")
    require(images.get("c8sOperator") in core_images, "images.c8sOperator is not one of the c8s core images")
    return spec


def chart_identity(chart: Path) -> dict[str, str]:
    meta = read_yaml(chart / "Chart.yaml")
    files = sorted(p for p in chart.rglob("*") if p.is_file())
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(chart).as_posix()
        data = path.read_bytes()
        digest.update(relative.encode() + b"\0" + str(len(data)).encode() + b"\0" + data)
    return {"name": meta["name"], "version": str(meta["version"]), "treeSha256": "sha256:" + digest.hexdigest()}



def chart_version(tag: str) -> str:
    """The package version: the tag without `v`."""
    require(release_spec.TAG.fullmatch(tag) is not None, f"the release tag {tag!r} is not vX.Y.Z")
    return tag[1:]


def chart_reference(name: str, version: str) -> str:
    """The OCI reference of the chart package, by version. The archive digest identifies its bytes."""
    return f"{CHART_REPOSITORY}/{name}:{version}"


def chart_metadata(chart_yaml: bytes, version: str) -> bytes:
    """Chart.yaml of the package: the chart's file with its version line set to `version`.

    A text substitution, not a YAML dump, so the bytes depend on the tagged file alone.
    """
    text = chart_yaml.decode()
    lines = [line for line in text.splitlines(keepends=True) if re.match(r"^version:", line)]
    require(len(lines) == 1, "Chart.yaml must set version once at the top level")
    return text.replace(lines[0], f"version: {version}\n", 1).encode()


def package_chart(chart: Path, name: str, version: str) -> bytes:
    """The chart package `<name>-<version>.tgz` of the tree at `chart`.

    The package is a function of the tagged tree and the version alone: entries
    in sorted path order with TarInfo's fixed metadata (mode 0644, uid and gid
    0, mtime 0, no names), gzip without a name or time. helm package rewrites
    Chart.yaml and records file times, so its archive is not reproducible; this
    one is, so the local build and the signed release have the same bytes, as
    every other release file does. Helm reads it like any chart archive.
    """
    files = {p.relative_to(chart).as_posix(): p.read_bytes() for p in chart.rglob("*") if p.is_file()}
    require("Chart.yaml" in files, "the chart has no Chart.yaml")
    files["Chart.yaml"] = chart_metadata(files["Chart.yaml"], version)
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(files):
            info = tarfile.TarInfo(f"{name}/{path}")
            info.size = len(files[path])
            tar.addfile(info, io.BytesIO(files[path]))
    return out.getvalue()


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


def cds_image(path: Path, spec: dict[str, Any]) -> dict[str, str]:
    """The pinned CDS guest image and the SHA-256 of its manifest.json, which the CDS pin of a deployment binds."""
    data = path.read_bytes()
    require(sha256(data) == spec["c8s"]["cdsManifestArtifact"]["manifestJson"],
            f"{path.name} differs from c8s.cdsManifestArtifact.manifestJson")
    image = spec["c8s"]["cdsImage"]
    return {"reference": f"{image['reference']}@{image['digest']}", "manifestSha256": sha256(data)}


def read_publication(path: Path) -> tuple[bytes, dict[str, Any]]:
    data = path.read_bytes()
    try:
        publication = PUBLICATION["validate"](json.loads(data))
    except (PUBLICATION["PublicationError"], json.JSONDecodeError) as error:
        raise ManifestError(f"image publication: {error}") from error
    registered = {f"{release_spec.REPOSITORY_IMAGES}{image.image}" for image in IMAGE_SELECTOR["IMAGES"]}
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


def validate_schema(manifest: dict[str, Any]) -> None:
    path = MANIFEST_SCHEMAS.get(manifest.get("schema") if isinstance(manifest, dict) else None)
    require(path is not None, "the manifest names no known schema")
    schema = read_json(path)
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(manifest), key=lambda e: list(e.path))
    if errors:
        location = ".".join(str(part) for part in errors[0].path) or "manifest"
        raise ManifestError(f"the manifest does not match {path.name}: {location}: {errors[0].message}")


def signed_release(tag: str, directory: Path, what: str) -> dict[str, Any]:
    """Return the manifest of release `tag` after verifying its signature.

    The build downloads the manifest and its Sigstore bundle into `directory`
    (download_base_release), requires a valid release signature, and requires
    the manifest to match its schema and to name `tag`. `what` names the
    release in errors.
    """
    manifest_path, signature_path = download_base_release(tag, directory)
    cosign = shutil.which("cosign")
    require(cosign is not None, f"verifying {what} needs cosign")
    try:
        release_signature.verify_release_signature(manifest_path, signature_path, Path(cosign).resolve(), 60)
    except (OSError, release_signature.ReleaseSignatureError) as error:
        raise ManifestError(f"{what} signature: {error}") from error
    manifest = read_json(manifest_path)
    validate_schema(manifest)
    require(manifest["release"]["name"] == tag, f"the manifest of {what} {tag} names a different release")
    return manifest


def base_release_images(
    publication: dict[str, Any],
    download_dir: Path,
    repo: Path = ROOT,
    required_images: set[str] | None = None,
) -> dict[str, str]:
    """Return the repository image digests of the base release of the publication.

    The image run publishes only the images that changed after its base. When
    the base is a release tag, every other image keeps the digest that the
    signed manifest of that release names. The build downloads that manifest
    and its Sigstore bundle into `download_dir`. The manifest must carry a
    valid release signature, name the base tag and commit of the publication,
    and no build input of an image outside the publication may have changed
    since. When the base is a commit, there is no base release.
    """
    source = publication["source"]
    if release_spec.HISTORICAL_TAG.fullmatch(source["baseRef"]) is None:
        return {}
    base = signed_release(source["baseRef"], download_dir, "the base release")
    require(base["source"]["commit"] == source["baseRefCommit"],
            "the base release source commit differs from the image publication base commit")
    changed = changed_paths(source["baseRefCommit"], source["commit"], repo)
    published = {entry["name"] for entry in publication["images"]}
    unpublished = [image.image for image in IMAGE_SELECTOR["affected_images"](changed)
                   if f"{release_spec.REPOSITORY_IMAGES}{image.image}" not in published]
    require(not unpublished,
            "image build inputs changed after the base release, and the publication has no new digest: "
            + ", ".join(unpublished))
    images: dict[str, str] = dict(base.get("imagePublication", {}).get("images", {}))
    for key, image in base["images"].items():
        if "transition" in base and re.fullmatch(r"transitionInput[0-9]+", key):
            continue
        name, digest = image.rsplit("@", 1)
        if name.startswith(release_spec.REPOSITORY_IMAGES):
            require(name not in images or images[name] == digest,
                    "the base release has ambiguous component image digests")
            images[name] = digest
    # A release of the earlier format names only the images its profile
    # rendered. Its values asset pins the others. Trust it only after
    # checking the asset hash bound by the verified base signature.
    missing = (required_images or set()) - images.keys() - published
    if missing and "releaseValues" in base:
        path = download_dir / "release-values.yaml"
        if not path.is_file():
            path.write_bytes(fetch(f"{REPOSITORY}/releases/download/{source['baseRef']}/release-values.yaml"))
        require(sha256(path.read_bytes()) == base["releaseValues"]["sha256"],
                "the base release values differ from its signed manifest")
        values = read_yaml(path)
        require(isinstance(values, dict) and isinstance(values.get("images"), dict),
                "the base release values have no image mapping")
        for reference in values["images"].values():
            match = OCI.fullmatch(reference) if isinstance(reference, str) else None
            if match and match.group(1) in missing:
                name, digest = match.groups()
                require(name not in images or images[name] == digest,
                        "the base release values have ambiguous component image digests")
                images[name] = digest
    return images


def release_images(
    spec_images: dict[str, str], publication: dict[str, Any], base: dict[str, str],
) -> dict[str, str]:
    """Give each image of the spec its digest: a repository image from the publication, else the base release."""
    published = {entry["name"]: entry["digest"] for entry in publication["images"]}
    resolved: dict[str, str] = {}
    for key, value in spec_images.items():
        if not value.startswith(release_spec.REPOSITORY_IMAGES):
            resolved[key] = value
            continue
        digest = published.get(value) or base.get(value)
        require(digest is not None, f"neither the image publication nor the base release names {value}")
        resolved[key] = f"{value}@{digest}"
    return dict(sorted(resolved.items()))


def publication_binding(
    data: bytes, publication: dict[str, Any], release_images: dict[str, str],
) -> dict[str, Any]:
    """Bind the publication evidence into the signed manifest."""
    for entry in publication["images"]:
        deployed = [image for image in release_images.values() if image.rsplit("@", 1)[0] == entry["name"]]
        require(all(image == f"{entry['name']}@{entry['digest']}" for image in deployed),
                f"published image digest differs from the release: {entry['name']}@{entry['digest']}")
    return {
        "artifact": "image-publication-manifest.json",
        "manifestSha256": sha256(data),
        "sourceCommit": publication["source"]["commit"],
        "baseRef": publication["source"]["baseRef"],
        "baseRefCommit": publication["source"]["baseRefCommit"],
        "images": {entry["name"]: entry["digest"] for entry in publication["images"]},
    }


def seed_images(c8s: dict[str, Any]) -> list[str]:
    """The images of the C8s node seed: the core entries that every allowlist mirrors.

    The seed is the record of the pinned commit in release/inputs/c8s-seeds/,
    which scripts/bump-c8s.py renders with the c8s CLI of that commit, and
    scripts/render-allowlist.py renders again. It can name images that are
    not C8s core images, for example kube-state-metrics.
    """
    try:
        seed = ALLOWLIST_GENERATOR["core_seed"](c8s)
    except ALLOWLIST_GENERATOR["GenerationError"] as error:
        raise ManifestError(f"C8s seed: {error}") from error
    images = set()
    for name, entry in seed.items():
        for container in entry.get("initContainers", []) + entry.get("containers", []):
            image = container.get("image")
            match = OCI.fullmatch(image) if isinstance(image, str) else None
            require(match is not None and match.group(2) == container.get("digest"),
                    f"the C8s seed entry {name} has no digest-pinned image")
            images.add(image)
    return sorted(images)


def build(
    tag: str,
    chart: Path,
    lock_path: Path,
    source_commit: str,
    publication_path: Path,
    download_dir: Path | None,
    spec_path: Path = release_spec.SPEC,
    node_manifest: Path = release_spec.NODE_MANIFEST,
    cds_manifest: Path = release_spec.CDS_MANIFEST,
) -> dict[str, bytes]:
    """Return the release files by name: the manifest, the chart package and the CDS image manifest."""
    version = chart_version(tag)
    chart = chart.resolve()
    identity = chart_identity(chart)
    require(COMMIT.fullmatch(source_commit) is not None, "--source-commit must be a full Git commit")
    spec = read_spec(spec_path)
    publication_bytes, publication = read_publication(publication_path)
    verify_image_source_boundary(publication["source"]["commit"], source_commit)
    required_images = {value for value in spec["images"].values() if value.startswith(release_spec.REPOSITORY_IMAGES)}
    with tempfile.TemporaryDirectory(prefix="base-release-") as directory:
        base = base_release_images(publication, download_dir or Path(directory), required_images=required_images)
    images = release_images(spec["images"], publication, base)
    node = node_measurements(node_manifest, spec)
    cds = cds_image(cds_manifest, spec)
    lock = source_lock_entry(read_json(lock_path), spec["c8s"]["sourceCommit"])
    require(lock.get("tag") == spec["c8s"]["release"], "the source lock tag differs from c8s.release")
    node_reference = f"{spec['c8s']['nodeImage']['reference']}@{spec['c8s']['nodeImage']['digest']}"
    require(lock["nodeImage"] == node_reference, "the source lock node image differs from c8s.nodeImage")
    archive = package_chart(chart, identity["name"], version)
    archive_name = f"{identity['name']}-{version}.tgz"
    manifest = {
        "schema": SCHEMA,
        "release": {"name": tag},
        "releaseTrust": {
            "policyPath": TRUST_POLICY.relative_to(ROOT).as_posix(),
            "policySha256": sha256(TRUST_POLICY.read_bytes()),
            "signatureType": "sigstore-keyless",
        },
        "source": {"repository": REPOSITORY, "commit": source_commit},
        "imagePublication": publication_binding(publication_bytes, publication, images),
        "images": images,
        "chart": {
            "name": identity["name"],
            "version": version,
            "sha256": identity["treeSha256"],
            "archiveSha256": sha256(archive),
            "reference": chart_reference(identity["name"], version),
        },
        "c8s": {
            "release": spec["c8s"]["release"],
            "sourceCommit": spec["c8s"]["sourceCommit"],
            "coreImages": sorted(spec["c8s"]["coreImages"]),
            # Every deployment allowlist mirrors the seed entries, so a client
            # needs these digests too.
            "seedImages": seed_images(spec["c8s"]),
        },
        # The SHA-256 of release/node-manifest.json, the c8s manifest.json that
        # records the measurements. Its bytes equal the manifest.json layer of
        # the pinned c8s measurement artifact.
        "nodeImage": {"reference": node_reference, "manifestSha256": node["manifestJsonSha256"]},
        # TEErminator reads the TDX measurements from these top-level fields.
        "mrtd": node["tdx"]["mrtd"],
        "rtmr1": node["tdx"]["rtmr1"],
        "rtmr2": node["tdx"]["rtmr2"],
        # The SHA-256 of release/cds-manifest.json, the manifest.json of the
        # pinned CDS guest image, which the release publishes beside the manifest.
        "cdsImage": cds,
        "sourceLock": {
            "path": lock_path.relative_to(ROOT).as_posix() if ROOT in lock_path.resolve().parents else str(lock_path),
            "sha256": sha256(lock_path.read_bytes()),
        },
    }
    validate_schema(manifest)
    return {"release-bundle.json": encode(manifest), archive_name: archive,
            "cds-manifest.json": cds_manifest.read_bytes()}


def encode(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag", required=True, help="the release tag, vX.Y.Z")
    parser.add_argument("--chart", type=Path, default=CHART)
    parser.add_argument("--source-lock", type=Path, default=SOURCE_LOCK)
    parser.add_argument("--source-commit", required=True,
                        help="the commit of this repository that the release tag names")
    parser.add_argument("--image-publication", type=Path, required=True,
                        help="verified image publication manifest from the release-images workflow")
    parser.add_argument("--download-dir", type=Path,
                        help="where the build keeps the signed base release that it downloads "
                             "(default: a temporary directory); it uses the files already there")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--check", action="store_true",
                        help="fail when a file in --output-dir differs from a new build")
    args = parser.parse_args()
    try:
        files = build(
            args.tag,
            args.chart,
            args.source_lock.resolve(),
            args.source_commit,
            args.image_publication.resolve(),
            args.download_dir.resolve() if args.download_dir else None,
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
