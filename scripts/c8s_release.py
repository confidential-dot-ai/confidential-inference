"""Exact C8s release channels. Beta use requires explicit approval."""
import re

TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-beta\.([1-9][0-9]*))?$")


def version(tag):
    match = TAG.fullmatch(tag)
    if match is None:
        raise ValueError(f"invalid C8s release tag: {tag}")
    return (*map(int, match.group(1, 2, 3)), 0 if match[4] else 1, int(match[4] or 0))


def channel(tag, allow_beta=False):
    version(tag)
    if "-beta." in tag:
        if not allow_beta:
            raise ValueError("C8s beta requires explicit opt-in")
        return "beta"
    return "main"


def signer(tag, allow_beta=False):
    branch = channel(tag, allow_beta)
    return f"https://github.com/confidential-dot-ai/C8s/.github/workflows/semver-tag.yml@refs/heads/{branch}"

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from collections.abc import Callable

C8S_REPOSITORY = "confidential-dot-ai/c8s"
C8S_SIGNED_REPOSITORY = "confidential-dot-ai/C8s"
C8S_STATEMENT = "release-statement.json"
C8S_BUNDLE = "release-statement.sigstore.json"
C8S_SIGNER_ISSUER = "https://token.actions.githubusercontent.com"


class ReleaseError(RuntimeError):
    """A release does not meet the channel trust requirements."""


def verify_c8s_tag(tag: str, run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
                   cosign: str | None = None, allow_beta: bool = False) -> dict[str, Any]:
    """Check a c8s release tag and, when it has one, its release signature.

    The tag commit must have a GitHub-verified signature and be on its channel branch.
    Beta commits must not be on main. Beta releases require signed assets.
    Since c8s#760, the c8s semver-tag workflow also signs a statement
    {repository, tag, commit} keyless with Sigstore and attaches it and its
    bundle to the GitHub release of the tag. When both assets exist, cosign
    must verify the bundle against the exact workflow identity and issuer, and
    the statement must name this repository, this tag and its commit. Then
    releaseSignature is "verified" and the pipeline merges the public bump.

    A tag without the assets (all tags up to v0.35.0) gives releaseSignature
    "absent": a person merges the bump. A signature that is present but
    does not verify, or only one of the two assets, stops the bump.
    """
    try:
        branch = channel(tag, allow_beta)
    except ValueError as error:
        raise ReleaseError(str(error)) from error

    def gh(*args: str) -> subprocess.CompletedProcess[str]:
        return run(["gh", *args], text=True, capture_output=True, check=False)

    def api(path: str) -> Any:
        result = gh("api", f"repos/{C8S_REPOSITORY}/{path}")
        if result.returncode:
            raise ReleaseError(f"gh api {path} failed: {result.stderr.strip()}")
        return json.loads(result.stdout)

    reference = api(f"git/ref/tags/{tag}")["object"]
    tag_object = api(f"git/tags/{reference['sha']}") if reference["type"] == "tag" else None
    commit = tag_object["object"]["sha"] if tag_object else reference["sha"]
    verification = api(f"commits/{commit}")["commit"]["verification"]
    if not verification.get("verified"):
        raise ReleaseError(f"c8s {tag} commit {commit} has no verified signature: {verification.get('reason')}")
    comparison = api(f"compare/{commit}...{branch}")
    if comparison.get("status") not in {"ahead", "identical"}:
        raise ReleaseError(f"c8s {tag} commit {commit} is not on c8s {branch}")
    if branch == "beta" and api(f"compare/{commit}...main").get("status") in {"ahead", "identical"}:
        raise ReleaseError("a beta tag must name a commit on beta and not on main")
    result = {"tag": tag, "commit": commit, "commitSignature": "verified", "onMain": branch == "main", "branch": branch,
              "tagSignature": (tag_object or {}).get("verification", {}).get("reason", "lightweight")}

    release = gh("api", f"repos/{C8S_REPOSITORY}/releases/tags/{tag}")
    if release.returncode and "HTTP 404" in release.stderr:
        if branch == "beta":
            raise ReleaseError("a beta requires a signed prerelease with both statement assets")
        return {**result, "releaseSignature": "absent"}
    if release.returncode:
        raise ReleaseError(f"cannot read the c8s {tag} release: {release.stderr.strip()}")
    release_data = json.loads(release.stdout)
    if branch == "beta" and release_data.get("prerelease") is not True:
        raise ReleaseError("a beta release must be marked prerelease")
    names = {asset["name"] for asset in release_data.get("assets", [])}
    present = names & {C8S_STATEMENT, C8S_BUNDLE}
    if not present:
        if branch == "beta":
            raise ReleaseError("a beta requires a signed prerelease with both statement assets")
        return {**result, "releaseSignature": "absent"}
    if present != {C8S_STATEMENT, C8S_BUNDLE}:
        raise ReleaseError(f"the c8s {tag} release has {sorted(present)} but needs both "
                             f"{C8S_STATEMENT} and {C8S_BUNDLE}")
    with tempfile.TemporaryDirectory() as directory:
        signed = signed_statement(tag, Path(directory), run, cosign, allow_beta)
    if signed["commit"] != commit:
        raise ReleaseError(f"the signed c8s {tag} statement does not name commit {commit}")
    return {**result, "releaseSignature": "verified"}


def signed_statement(tag: str, directory: Path, run: Callable[..., subprocess.CompletedProcess[str]],
                     cosign: str | None, allow_beta: bool, *assets: str) -> dict[str, Any]:
    """Download the release statement, its bundle and `assets` of the c8s tag
    into `directory`; return the statement after cosign verifies it against
    the exact release workflow identity and it names this repository and tag."""
    cosign = cosign or shutil.which("cosign")
    if not cosign:
        raise ReleaseError(f"the c8s {tag} release is signed, but cosign is not installed")
    patterns = [arg for name in (C8S_STATEMENT, C8S_BUNDLE, *assets) for arg in ("--pattern", name)]
    download = run(["gh", "release", "download", tag, "--repo", C8S_REPOSITORY, "--dir", str(directory), *patterns],
                   text=True, capture_output=True, check=False)
    if download.returncode:
        raise ReleaseError(f"cannot download the c8s {tag} release statement: {download.stderr.strip()}")
    statement = directory / C8S_STATEMENT
    checked = run([cosign, "verify-blob", "--bundle", str(directory / C8S_BUNDLE),
                   "--certificate-identity", signer(tag, allow_beta),
                   "--certificate-oidc-issuer", C8S_SIGNER_ISSUER, str(statement)],
                  text=True, capture_output=True, check=False)
    if checked.returncode:
        raise ReleaseError(f"the c8s {tag} release signature does not verify: {checked.stderr.strip()}")
    try:
        signed = json.loads(statement.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ReleaseError(f"the c8s {tag} release statement is not JSON: {error}") from error
    # Since C8s #1070 the statement also lists the allowlist seed assets.
    if (not isinstance(signed, dict) or set(signed) - {"repository", "tag", "commit", "allowlistSeeds"}
            or signed.get("repository") != C8S_SIGNED_REPOSITORY or signed.get("tag") != tag
            or not isinstance(signed.get("commit"), str)):
        raise ReleaseError(f"the signed c8s {tag} statement {signed} does not name {C8S_SIGNED_REPOSITORY} {tag}")
    return signed


def allowlist_seed(tag: str, commit: str, platform: str,
                   run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
                   cosign: str | None = None) -> dict[str, Any]:
    """The allowlist seed that the node images of a c8s release bake for
    `platform` (tdx or snp): the release asset allowlist-seed-<platform>.json,
    whose sha256 the signed release statement of `commit` lists (C8s #975)."""
    asset = f"allowlist-seed-{platform}.json"
    with tempfile.TemporaryDirectory() as directory:
        signed = signed_statement(tag, Path(directory), run, cosign, "-beta." in tag, asset)
        data = (Path(directory) / asset).read_bytes()
    if signed["commit"] != commit:
        raise ReleaseError(f"the signed c8s {tag} statement does not name commit {commit}")
    listed = signed.get("allowlistSeeds", {}).get(platform)
    if listed != {"asset": asset, "sha256": hashlib.sha256(data).hexdigest()}:
        raise ReleaseError(f"the c8s {tag} {asset} is not the seed the signed release statement lists: {listed}")
    return json.loads(data)
