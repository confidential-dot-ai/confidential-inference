#!/usr/bin/env python3
"""Move release profiles to one c8s release tag.

Usage:

    scripts/bump-c8s.py --tag v0.33.8 --c8s-repo ../c8s [--profile staging]
        [--confos-repo ../confidential-os-builder]

--c8s-repo is a clean c8s checkout at the tag. Without --profile, the script
moves every profile. With --profile, it moves only the named profiles: a
profile that takes c8s from a shared layer gets its own c8s pins, so staging
can move ahead of production. The script:

1. reads the published digests of the tag from the registry with crane;
2. writes the new `c8s` mapping into the spec.yaml layer that holds it, and
   the c8s operator image into the values.yaml layer that holds it. It edits
   only those values, then parses each file again and requires that nothing
   else changed;
3. adds the source lock entry, and shares the attestation protocol manifest
   when the protocol source files did not change;
4. adds the new node image to the NVIDIA CDI record when the pinned driver
   inputs did not change. The inputs are bin/confos-fetch-gpu at the
   confidential-os-builder ref that c8s pins in .github/build-pins.json. When
   the ref changed, --confos-repo must be a confidential-os-builder checkout;
5. fetches each node manifest and refreshes the image config;
6. runs the release checks.

The release build generates the allowlist with a c8s CLI built from the
pinned commit, so the bump does not write one.

It stops when a step needs a person: changed protocol source files, changed
NVIDIA driver inputs, a pin it cannot edit in place, or a failed check. Review
the full diff before you commit. The image config diff is a release input.
"""

from __future__ import annotations

import argparse
import copy
import functools
import hashlib
import json
import os
import re
import runpy
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_profiles

ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOCK = ROOT / "contracts/c8s-admission-source-lock.json"
PROTOCOLS = ROOT / "contracts/c8s-attestation-protocols"
CDI_DIR = ROOT / "release/inputs/cdi"
CANONICAL_TOOL = ROOT / "tools/c8s-allowlist-canonical"
NODE = runpy.run_path(str(ROOT / "scripts/fetch-node-manifest.py"))
REGISTRY = "ghcr.io/confidential-dot-ai/"
C8S_MODULE = "github.com/confidential-dot-ai/c8s"
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
# The c8s file that pins the confidential-os-builder ref of the node image, and
# the confidential-os-builder script that pins the NVIDIA driver and toolkit.
BUILD_PINS = ".github/build-pins.json"
GPU_FETCH = "bin/confos-fetch-gpu"
# The protocol manifest also depends on the whole pkg/types tree.
PROTOCOL_TREES = ("pkg/types",)


class BumpError(RuntimeError):
    """A step needs a person."""


def run(command: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        raise BumpError(f"command failed: {' '.join(command)}\n{result.stderr.strip()}")
    return result.stdout


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def git(repo: Path, *args: str) -> str:
    return run(["git", "-C", str(repo), *args]).strip()


def git_show(repo: Path, commit: str, name: str) -> bytes:
    result = subprocess.run(["git", "-C", str(repo), "show", f"{commit}:{name}"], capture_output=True, check=False)
    if result.returncode:
        raise BumpError(f"cannot read {name} at {commit} in {repo}")
    return result.stdout


def go_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("GOPRIVATE", "github.com/confidential-dot-ai/*")
    env["GOWORK"] = "off"
    return env


@functools.cache
def digest(reference: str) -> str:
    value = run(["crane", "digest", reference]).strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise BumpError(f"crane returned no digest for {reference}")
    return value


def write_json(path: Path, value: object) -> None:
    """Write JSON in the two-space form that the repository uses."""
    text = path.read_text(encoding="utf-8")
    if json.dumps(json.loads(text), indent=2, ensure_ascii=False) + "\n" != text:
        raise BumpError(f"{path.relative_to(ROOT)} is not in the expected JSON form")
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Pins
# ---------------------------------------------------------------------------


def operator_image(c8s: dict[str, Any]) -> str:
    return next(image for image in c8s["coreImages"] if image.partition("@")[0] == f"{REGISTRY}c8s-operator")


def new_c8s(tag: str, commit: str, old: dict[str, Any]) -> dict[str, Any]:
    """Return the c8s mapping of the tag in the shape of the old one."""
    old_tag = old["release"]
    node, artifact = old["nodeImage"], old["nodeManifestArtifact"]
    if node["tag"] != f"rke2-tdx-cdi-{old_tag}" or artifact["tag"] != f"rke2-tdx-{old_tag}":
        raise BumpError("the node image tags do not follow the c8s release tag; edit them by hand")
    reference = node["reference"]
    artifact_digest = digest(f"{reference}:rke2-tdx-{tag}")
    core = []
    for image in old["coreImages"]:
        name = image.partition("@")[0]
        core.append(f"{name}@{digest(f'{name}:{tag}')}" if name.startswith(REGISTRY) else image)
    value = copy.deepcopy(old)
    value.update({
        "release": tag,
        "sourceCommit": commit,
        "coreImages": core,
    })
    value["nodeImage"].update({"tag": f"rke2-tdx-cdi-{tag}", "digest": digest(f"{reference}:rke2-tdx-cdi-{tag}")})
    value["nodeManifestArtifact"].update({
        "tag": f"rke2-tdx-{tag}",
        "digest": artifact_digest,
        "manifestJson": NODE["manifest_json_digest"](reference, artifact_digest),
    })
    return value


def leaves(value: Any, path: tuple[Any, ...] = ()) -> dict[tuple[Any, ...], Any]:
    if isinstance(value, dict):
        return {k: v for key, child in value.items() for k, v in leaves(child, (*path, key)).items()}
    if isinstance(value, list):
        return {k: v for index, child in enumerate(value) for k, v in leaves(child, (*path, index)).items()}
    return {path: value}


def set_key(document: dict[str, Any], path: tuple[str, ...], value: Any) -> dict[str, Any]:
    result = copy.deepcopy(document)
    target = result
    for key in path[:-1]:
        target = target.setdefault(key, {})
    target[path[-1]] = value
    return result


def edit_yaml(path: Path, key_path: tuple[str, ...], value: Any) -> None:
    """Set one key of a commented YAML file and keep every other byte.

    Each changed scalar is replaced where it is the whole value of a line. The
    file is then parsed again and must equal the old document with only that
    key changed. A key that the file does not set is appended.
    """
    text = path.read_text(encoding="utf-8")
    document = yaml.safe_load(text) or {}
    expected = set_key(document, key_path, value)
    current: Any = document
    for key in key_path:
        current = current.get(key) if isinstance(current, dict) else None
    if current is None:
        if len(key_path) > 1 and key_path[0] in document:
            raise BumpError(f"{path.relative_to(ROOT)} sets {key_path[0]} but not {'.'.join(key_path)}; edit it by hand")
        appended = {key_path[0]: expected[key_path[0]]}
        text = text.rstrip("\n") + "\n\n" + yaml.safe_dump(appended, sort_keys=False)
    else:
        old_leaves, new_leaves = leaves(current), leaves(value)
        if old_leaves.keys() != new_leaves.keys():
            raise BumpError(f"{path.relative_to(ROOT)} {'.'.join(key_path)} changes shape; edit it by hand")
        for leaf, old in old_leaves.items():
            new = new_leaves[leaf]
            if old == new:
                continue
            pattern = re.compile(rf"(?m)^(\s*(?:[A-Za-z0-9_]+:|-)\s+)(['\"]?){re.escape(str(old))}\2[ \t]*$")
            text, count = pattern.subn(lambda match: f"{match.group(1)}{match.group(2)}{new}{match.group(2)}", text)
            if count == 0:
                raise BumpError(f"{path.relative_to(ROOT)} has no line for {old}; edit it by hand")
    if yaml.safe_load(text) != expected:
        raise BumpError(f"{path.relative_to(ROOT)} changed more than {'.'.join(key_path)}; edit it by hand")
    path.write_text(text, encoding="utf-8")


def target_file(layer_file: Path, owner: release_profiles.Profile, moved: list[release_profiles.Profile],
                users: list[release_profiles.Profile]) -> Path:
    """Edit a shared layer only when every profile that uses it moves."""
    if all(profile in moved for profile in users):
        return layer_file
    return owner.directory / layer_file.name


def pin_profiles(moved: list[release_profiles.Profile], everyone: tuple[release_profiles.Profile, ...],
                 c8s: dict[str, Any]) -> None:
    # The file that holds each pin, for every profile, read once.
    pins = {
        ("c8s",): ({p: release_profiles.owning_file(p.spec_files, ("c8s",)) for p in everyone}, c8s),
        ("images", "c8sOperator"): (
            {p: release_profiles.owning_file(p.values_files, ("images", "c8sOperator")) for p in everyone},
            operator_image(c8s),
        ),
    }
    for key_path, (owners, value) in pins.items():
        targets = set()
        for profile in moved:
            users = [other for other in everyone if owners[other] == owners[profile]]
            targets.add(target_file(owners[profile], profile, moved, users))
        for path in sorted(targets):
            edit_yaml(path, key_path, value)


# ---------------------------------------------------------------------------
# Shared c8s records
# ---------------------------------------------------------------------------


def bump_module(old_tag: str, tag: str) -> None:
    path = CANONICAL_TOOL / "go.mod"
    text = path.read_text(encoding="utf-8")
    old_line, new_line = f"require {C8S_MODULE} {old_tag}\n", f"require {C8S_MODULE} {tag}\n"
    if old_line in text:
        path.write_text(text.replace(old_line, new_line), encoding="utf-8")
    elif new_line not in text:
        raise BumpError(f"{path.relative_to(ROOT)} does not require {C8S_MODULE} {old_tag}")
    run(["go", "mod", "tidy"], cwd=CANONICAL_TOOL, env=go_env())


def add_source_lock(c8s_repo: Path, old: dict[str, Any], new: dict[str, Any]) -> None:
    lock = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
    if any(entry["commit"] == new["sourceCommit"] for entry in lock["commits"]):
        return
    previous = [entry for entry in lock["commits"] if entry["commit"] == old["sourceCommit"]]
    if not previous:
        raise BumpError(f"the source lock has no entry for the old commit {old['sourceCommit']}")
    entry = copy.deepcopy(previous[0])
    entry.update({
        "commit": new["sourceCommit"],
        "tag": new["release"],
        "nodeImage": f"{new['nodeImage']['reference']}@{new['nodeImage']['digest']}",
        "c8sOperatorImage": operator_image(new),
    })
    for name in entry["files"]:
        entry["files"][name] = sha256_bytes(git_show(c8s_repo, new["sourceCommit"], name))
    lock["commits"].append(entry)
    write_json(SOURCE_LOCK, lock)


def share_protocol_manifest(c8s_repo: Path, old_commit: str, new_commit: str, tag: str) -> None:
    for path in sorted(PROTOCOLS.glob("*.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        shared = manifest.get("sharedWithCommits", [])
        if new_commit == manifest["commit"] or new_commit in shared:
            return
        if old_commit != manifest["commit"] and old_commit not in shared:
            continue
        sources = list(manifest["capturedFrom"].values()) + list(PROTOCOL_TREES)
        changed = git(c8s_repo, "diff", "--name-only", old_commit, new_commit, "--", *sources)
        if changed:
            raise BumpError("the attestation protocol source files changed: " + ", ".join(changed.splitlines())
                            + ". Capture a new protocol manifest by hand.")
        manifest["sharedWithCommits"] = shared + [new_commit]
        manifest["capturedFromNote"] += (
            f" c8s {tag} commit {new_commit} is byte-identical to commit {old_commit} in "
            + ", ".join(sources) + ", and therefore shares this manifest."
        )
        write_json(path, manifest)
        return
    raise BumpError(f"no attestation protocol manifest covers the old commit {old_commit}")


def confos_ref(c8s_repo: Path, commit: str) -> str:
    pins = json.loads(git_show(c8s_repo, commit, BUILD_PINS))
    return pins["builds"]["node-image"]["confos_ref"]


def driver_inputs(c8s_repo: Path, commit: str, confos_repo: Path | None) -> str:
    """Return the SHA-256 of the confidential-os-builder script that pins the driver."""
    if confos_repo is None:
        raise BumpError("the node image confidential-os-builder ref changed; pass --confos-repo")
    return sha256_bytes(git_show(confos_repo, confos_ref(c8s_repo, commit), GPU_FETCH))


def extend_cdi_record(c8s_repo: Path, confos_repo: Path | None, old: dict[str, Any], new: dict[str, Any]) -> None:
    """Let each CDI record hold for the new node image when its driver inputs did not change."""
    old_image = f"{old['nodeImage']['reference']}@{old['nodeImage']['digest']}"
    new_image = f"{new['nodeImage']['reference']}@{new['nodeImage']['digest']}"
    same_ref = confos_ref(c8s_repo, old["sourceCommit"]) == confos_ref(c8s_repo, new["sourceCommit"])
    for path in sorted(CDI_DIR.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if old_image not in record.get("nodeImages", []) or new_image in record["nodeImages"]:
            continue
        if not same_ref:
            pinned = record.get("driverInputs", {}).get("confosFetchGpuSha256")
            if driver_inputs(c8s_repo, new["sourceCommit"], confos_repo) != pinned:
                raise BumpError(f"the pinned NVIDIA driver inputs changed. Derive {path.name} again.")
        record["nodeImages"].append(new_image)
        write_json(path, record)


# ---------------------------------------------------------------------------
# Generation and checks
# ---------------------------------------------------------------------------


def regenerate(moved: list[release_profiles.Profile]) -> None:
    # Profiles can share a node manifest, so each file is fetched once.
    fetched: set[Path] = set()
    for profile in moved:
        manifest = release_profiles.node_manifest(profile)
        if manifest not in fetched:
            fetched.add(manifest)
            run([sys.executable, "scripts/fetch-node-manifest.py", "--release", profile.relative(profile.directory)],
                cwd=ROOT)
    run([sys.executable, "scripts/generate-release-allowlist.py", "--refresh-image-config"], cwd=ROOT)


def check(c8s_repo: Path, commit: str) -> None:
    run([sys.executable, "scripts/verify-c8s-admission-source.py", "--repository", str(c8s_repo),
         "--commit", commit], cwd=ROOT)
    run([sys.executable, "scripts/check-c8s-protocol-lockstep.py"], cwd=ROOT)
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests/release-v1", "-p", "test_*.py"], cwd=ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag", required=True, help="the c8s release tag, for example v0.33.8")
    parser.add_argument("--c8s-repo", required=True, type=Path, help="a clean c8s checkout at the tag")
    parser.add_argument("--profile", action="append", help="a profile to move (default: every profile)")
    parser.add_argument("--confos-repo", type=Path, help="a confidential-os-builder checkout")
    args = parser.parse_args()
    try:
        if not TAG.fullmatch(args.tag):
            raise BumpError("--tag must be vX.Y.Z")
        c8s_repo = args.c8s_repo.resolve()
        commit = git(c8s_repo, "rev-parse", f"{args.tag}^{{commit}}")
        if git(c8s_repo, "rev-parse", "HEAD") != commit or git(c8s_repo, "status", "--porcelain"):
            raise BumpError(f"--c8s-repo must be a clean checkout at {args.tag}")
        if git(ROOT, "status", "--porcelain"):
            raise BumpError("the repository must be clean")
        everyone = release_profiles.load()
        names = args.profile or [profile.name for profile in everyone]
        unknown = sorted(set(names) - {profile.name for profile in everyone})
        if unknown:
            raise BumpError(f"unknown profiles: {unknown}")
        moved = [profile for profile in everyone
                 if profile.name in names and release_profiles.read_spec(profile)["c8s"]["release"] != args.tag]
        if not moved:
            raise BumpError(f"the profiles already pin {args.tag}")
        olds = [release_profiles.read_spec(profile)["c8s"] for profile in moved]
        if any(value != olds[0] for value in olds):
            raise BumpError("the moved profiles pin different c8s releases; move them one at a time")
        old = olds[0]
        new = new_c8s(args.tag, commit, old)

        pin_profiles(moved, everyone, new)
        bump_module(old["release"], args.tag)
        add_source_lock(c8s_repo, old, new)
        share_protocol_manifest(c8s_repo, old["sourceCommit"], commit, args.tag)
        extend_cdi_record(c8s_repo, args.confos_repo.resolve() if args.confos_repo else None, old, new)

        regenerate(moved)
        check(c8s_repo, commit)
    except (BumpError, release_profiles.ProfileError, NODE["FetchError"]) as error:
        print(f"bump-c8s: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"tag": args.tag, "profiles": [profile.name for profile in moved], "c8s": new}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
