#!/usr/bin/env python3
"""Move every release profile to one c8s release tag.

Usage:

    scripts/bump-c8s.py --tag v0.33.8 --c8s-repo ../c8s

--c8s-repo is a clean c8s checkout at the tag. The script:

1. reads the published digests of the tag from the registry with crane;
2. replaces the old c8s pins in each profile (spec, values, allowlist policy,
   accepted lint findings);
3. adds the source lock entry, and shares the attestation protocol manifest
   when the protocol source files did not change;
4. renames the NVIDIA CDI record when the node image driver inputs did not
   change;
5. fetches each node manifest, refreshes the image config, and regenerates
   each allowlist with a c8s CLI built from the tag;
6. runs the release checks.

It stops when a step needs a person: changed protocol source files, changed
NVIDIA driver inputs, or a failed check. Review the full diff before you
commit. The image config diff is a release input.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOCK = ROOT / "contracts/c8s-admission-source-lock.json"
PROTOCOLS = ROOT / "contracts/c8s-attestation-protocols"
CDI_DIR = ROOT / "release/inputs/cdi"
CANONICAL_TOOL = ROOT / "tools/c8s-allowlist-canonical"
RELEASE_TESTS = ROOT / "tests/release-v1/test_release_tools.py"
REGISTRY = "ghcr.io/confidential-dot-ai/"
NODE_IMAGE = REGISTRY + "node-guest-base"
C8S_MODULE = "github.com/confidential-dot-ai/c8s"
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
# Node image changes in these words can change the NVIDIA CDI record.
DRIVER_WORDS = re.compile(r"nvidia|driver|toolkit|cuda", re.IGNORECASE)
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


def go_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("GOPRIVATE", "github.com/confidential-dot-ai/*")
    env["GOWORK"] = "off"
    return env


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


def replace_all(path: Path, pairs: list[tuple[str, str]]) -> None:
    text = path.read_text(encoding="utf-8")
    for old, new in pairs:
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")


def profiles() -> list[Path]:
    return sorted(path.parent for path in (ROOT / "release").glob("**/spec.yaml"))


def old_pins(profile: Path) -> dict[str, str]:
    spec = yaml.safe_load((profile / "spec.yaml").read_text(encoding="utf-8"))
    c8s = spec["c8s"]
    policy = json.loads((profile / "allowlist-policy.json").read_text(encoding="utf-8"))
    pins = {
        "release": c8s["release"],
        "commit": c8s["sourceCommit"],
        "nodeImage": c8s["nodeImage"]["digest"],
        "nodeManifestArtifact": c8s["nodeManifestArtifact"]["digest"],
    }
    for image in policy["c8s"]["coreImages"]:
        name, _, value = image.partition("@")
        if name.startswith(REGISTRY):
            pins["core:" + name.removeprefix(REGISTRY)] = value
    return pins


def new_pins(tag: str, commit: str, old: dict[str, str]) -> dict[str, str]:
    pins = {
        "release": tag,
        "commit": commit,
        "nodeImage": digest(f"{NODE_IMAGE}:rke2-tdx-cdi-{tag}"),
        "nodeManifestArtifact": digest(f"{NODE_IMAGE}:rke2-tdx-{tag}"),
    }
    for key in old:
        if key.startswith("core:"):
            pins[key] = digest(f"{REGISTRY}{key.removeprefix('core:')}:{tag}")
    return pins


def pairs_for(old: dict[str, str], new: dict[str, str]) -> list[tuple[str, str]]:
    # Full values first, then the short commit, then the version text.
    pairs = [(old[key], new[key]) for key in old if key not in ("release", "commit")]
    pairs.append((old["commit"], new["commit"]))
    pairs.append((old["commit"][:8], new["commit"][:8]))
    pairs.append((old["release"], new["release"]))
    return pairs


NODE_IMAGE_TEXT = re.compile(r"c8s v[0-9]+\.[0-9]+\.[0-9]+ node image")


def bump_profile(profile: Path, pairs: list[tuple[str, str]], new: dict[str, str]) -> None:
    for name in ("spec.yaml", "values.yaml", "allowlist-policy.json", "accepted-lint-findings.json"):
        path = profile / name
        if path.exists():
            replace_all(path, pairs)
    # The policy records the source commit that the generator checks against
    # the c8s CLI. An older profile can hold a stale value.
    policy_path = profile / "allowlist-policy.json"
    text, count = re.subn(r'"sourceCommit": "[0-9a-f]{40}"', f'"sourceCommit": "{new["commit"]}"',
                          policy_path.read_text(encoding="utf-8"))
    if count != 1:
        raise BumpError(f"{policy_path.relative_to(ROOT)} must have one sourceCommit")
    policy_path.write_text(text, encoding="utf-8")
    # A lint reason can name an older node image than the old pin.
    lint = profile / "accepted-lint-findings.json"
    if lint.exists():
        lint.write_text(NODE_IMAGE_TEXT.sub(f"c8s {new['release']} node image", lint.read_text(encoding="utf-8")),
                        encoding="utf-8")


def bump_module(old_tag: str, tag: str) -> None:
    replace_all(CANONICAL_TOOL / "go.mod", [(f"require {C8S_MODULE} {old_tag}", f"require {C8S_MODULE} {tag}")])
    run(["go", "mod", "tidy"], cwd=CANONICAL_TOOL, env=go_env())


def add_source_lock(c8s_repo: Path, old: dict[str, str], new: dict[str, str]) -> None:
    lock = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
    if any(entry["commit"] == new["commit"] for entry in lock["commits"]):
        return
    previous = [entry for entry in lock["commits"] if entry["commit"] == old["commit"]]
    if not previous:
        raise BumpError(f"the source lock has no entry for the old commit {old['commit']}")
    entry = copy.deepcopy(previous[0])
    entry.update({
        "commit": new["commit"],
        "tag": new["release"],
        "nodeImage": f"{NODE_IMAGE}@{new['nodeImage']}",
        "c8sOperatorImage": f"{REGISTRY}c8s-operator@{new['core:c8s-operator']}",
    })
    for name in entry["files"]:
        data = subprocess.run(["git", "-C", str(c8s_repo), "show", f"{new['commit']}:{name}"],
                              capture_output=True, check=True).stdout
        entry["files"][name] = sha256_bytes(data)
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
        changed = [name for name in sources
                   if git(c8s_repo, "rev-parse", f"{old_commit}:{name}") != git(c8s_repo, "rev-parse", f"{new_commit}:{name}")]
        if changed:
            raise BumpError("the attestation protocol source files changed: " + ", ".join(changed)
                            + ". Capture a new protocol manifest by hand.")
        manifest["sharedWithCommits"] = shared + [new_commit]
        manifest["capturedFromNote"] += (
            f" c8s {tag} commit {new_commit} is byte-identical to commit {old_commit} in "
            + ", ".join(sources) + ", and therefore shares this manifest."
        )
        write_json(path, manifest)
        return
    raise BumpError(f"no attestation protocol manifest covers the old commit {old_commit}")


def rename_cdi_record(c8s_repo: Path, old: dict[str, str], new: dict[str, str]) -> None:
    diff = git(c8s_repo, "diff", old["commit"], new["commit"], "--", "node-guest-image")
    changed = [line for line in diff.splitlines()
               if line[:1] in "+-" and not line.startswith(("+++", "---")) and DRIVER_WORDS.search(line)]
    if changed:
        raise BumpError("the node image NVIDIA inputs changed. Derive the CDI record again:\n" + "\n".join(changed[:10]))
    for path in sorted(CDI_DIR.glob("*")):
        text = NODE_IMAGE_TEXT.sub(f"c8s {new['release']} node image", path.read_text(encoding="utf-8"))
        path.write_text(text, encoding="utf-8")
        if path.suffix == ".json":
            record = json.loads(text)
            if "nodeImage" in record:
                record["nodeImage"] = f"{NODE_IMAGE}@{new['nodeImage']}"
                reuse = (f"Reused for the c8s {new['release']} node image because its NVIDIA inputs "
                         "did not change.")
                source = re.sub(r"^Reused for the c8s v[0-9.]+ node image because [^.]*\. ", "", record["source"])
                record["source"] = f"{reuse} {source}"
                write_json(path, record)


def build(c8s_repo: Path, out: Path) -> tuple[Path, Path]:
    c8s = out / "c8s"
    run(["go", "build", "-o", str(c8s), "./cmd/c8s"], cwd=c8s_repo,
        env={**go_env(), "GOWORK": os.environ.get("GOWORK", "")})
    canonical = out / "c8s-allowlist-canonical"
    run(["go", "build", "-o", str(canonical), "."], cwd=CANONICAL_TOOL, env=go_env())
    return c8s, canonical


def release_args(profile: Path) -> list[str]:
    # The generator reads the normal profile when no --release is given.
    return [] if profile == ROOT / "release" else ["--release", str(profile.relative_to(ROOT))]


def regenerate(profile: Path, c8s: Path, canonical: Path) -> None:
    relative = str(profile.relative_to(ROOT))
    run([sys.executable, "scripts/fetch-node-manifest.py", "--spec", f"{relative}/spec.yaml",
         "--output", f"{relative}/node-manifest.json"], cwd=ROOT)
    tools = release_args(profile) + ["--c8s", str(c8s), "--canonical-tool", str(canonical)]
    run([sys.executable, "scripts/generate-release-allowlist.py", *tools, "--refresh-image-config"], cwd=ROOT)
    run([sys.executable, "scripts/generate-release-allowlist.py", *tools], cwd=ROOT)


def check(c8s_repo: Path, commit: str, c8s: Path, canonical: Path) -> None:
    run([sys.executable, "scripts/verify-c8s-admission-source.py", "--repository", str(c8s_repo),
         "--commit", commit], cwd=ROOT)
    run([sys.executable, "scripts/check-c8s-protocol-lockstep.py"], cwd=ROOT)
    for profile in profiles():
        run([sys.executable, "scripts/generate-release-allowlist.py", *release_args(profile),
             "--c8s", str(c8s), "--canonical-tool", str(canonical), "--check"], cwd=ROOT)
    run([sys.executable, "-m", "unittest", "discover", "-s", "tests/release-v1", "-p", "test_*.py"], cwd=ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag", required=True, help="the c8s release tag, for example v0.33.8")
    parser.add_argument("--c8s-repo", required=True, type=Path, help="a clean c8s checkout at the tag")
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

        normal = ROOT / "release"
        old = old_pins(normal)
        if old["release"] == args.tag:
            raise BumpError(f"the normal profile already pins {args.tag}")
        new = new_pins(args.tag, commit, old)
        old_manifest = sha256_bytes((normal / "node-manifest.json").read_bytes())

        for profile in profiles():
            profile_old = old_pins(profile)
            if profile_old["release"] != args.tag:
                profile_new = new_pins(args.tag, commit, profile_old)
                bump_profile(profile, pairs_for(profile_old, profile_new), profile_new)
        bump_module(old["release"], args.tag)
        add_source_lock(c8s_repo, old, new)
        share_protocol_manifest(c8s_repo, old["commit"], commit, args.tag)
        rename_cdi_record(c8s_repo, old, new)

        with tempfile.TemporaryDirectory() as directory:
            c8s, canonical = build(c8s_repo, Path(directory))
            for profile in profiles():
                regenerate(profile, c8s, canonical)
            new_manifest = sha256_bytes((normal / "node-manifest.json").read_bytes())
            replace_all(RELEASE_TESTS, [(old_manifest, new_manifest)])
            check(c8s_repo, commit, c8s, canonical)
    except BumpError as error:
        print(f"bump-c8s: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"tag": args.tag, "commit": commit, **{k: v for k, v in new.items() if k not in ("release", "commit")}},
                     indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
