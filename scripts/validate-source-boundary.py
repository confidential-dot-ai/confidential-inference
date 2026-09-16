#!/usr/bin/env python3
"""Reject private code, credentials, and unpinned artifacts in public files."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


POLICY_IMPLEMENTATION = "scripts/validate-source-boundary.py"
POLICY_ALLOWLIST = "security/source-boundary-allowlist.json"
GENERATED_DIRECTORY_NAMES = {"__pycache__", "dist", "node_modules", "target"}

PRIVATE_PATH_RE = re.compile(
    r"(?:^|[-_.])(?:private|proprietary)(?:$|[-_.])|"
    r"(?:private[-_.]?optim|optim(?:ization)?[-_.]?private|candidate[-_.]?private)",
    re.IGNORECASE,
)
IMAGE_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}(?:\s|$|[\"'])", re.IGNORECASE)
ACTION_PIN_RE = re.compile(r"\buses:\s*[^\s@]+@([0-9a-f]{40})(?:\s|$)", re.IGNORECASE)
YAML_IMAGE_RE = re.compile(r"^\s*(?:image|nodeBootCdiImage)\s*:\s*(?![{$])([^\s#]+)", re.IGNORECASE)
JSON_IMAGE_RE = re.compile(r'"(?:image|nodeBootCdiImage)"\s*:\s*"([^"\s]+)"', re.IGNORECASE)
DOCKER_IMAGE_RE = re.compile(r"^\s*FROM\s+(?![${])([^\s#]+)", re.IGNORECASE)
REMOTE_FETCH_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n]*https?://|\bgit\s+clone\b|"
    r"^\s*(?:ADD|COPY)\s+https?://",
    re.IGNORECASE,
)
KEY_VAULT_RE = re.compile(
    r"\.vault\.azure\.net|\baz\s+keyvault\b|\bazure[._/-]keyvault\b|"
    r"@azure/keyvault|\bSecretClient\s*\(|\bAZURE_KEY_VAULT\b",
    re.IGNORECASE,
)
# --- Infrastructure identifiers --------------------------------------------
#
# A public tree must describe how the system works. It must not say where the
# system runs. The three rules below reject the identifiers that say where:
# private addresses, maintainer home directories, and known host names.
#
# Each rule keeps its patterns as data. Add a pattern to the data below; do
# not write a new branch in scan_file for it.

# RFC 1918 and RFC 6598. The RFC 6598 range is the Tailscale address range.
PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(item)
    for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
)
# RFC 5737. These three ranges exist for documentation and examples. A public
# file may name them freely, so this rule never reports them.
DOCUMENTATION_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(item)
    for item in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
IPV4_RE = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])")

# An absolute path into a user home directory names a maintainer machine.
HOME_PATH_RE = re.compile(r"(?:/home|/Users)/[A-Za-z0-9._-]+")

# Known host name shapes. Each entry is one fragment of a regular expression.
# The scanner joins them and requires a whole token, so a longer name that
# merely contains one of these fragments does not match.
HOST_NAME_FRAGMENTS = (
    r"conf-inference-[a-z0-9]+-(?:control-plane|gateway|inference|inference-\d+|worker-\d+)",
    r"confidential-inference-(?:production|staging)-(?:control-plane|gateway|inference)[a-z0-9-]*",
    r"tdx-(?:node|host|vm|runner|builder)[a-z0-9-]*",
    r"b300-node[a-z0-9-]*",
    r"b200-[a-z0-9]+[a-z0-9-]*",
    r"[a-z0-9]+[a-z0-9-]*-gh-runner",
    r"kettle-build[a-z0-9-]*",
    r"lunal-host[a-z0-9-]*",
)
HOST_NAME_RE = re.compile(
    r"(?<![-\w])(?:" + "|".join(HOST_NAME_FRAGMENTS) + r")(?![-\w])",
    re.IGNORECASE,
)

TAILNET_RE = re.compile(r"(?:^|[^a-z])(?:tailscale|tailnet)(?:[^a-z]|$)|\.ts\.net\b", re.IGNORECASE)
SYSTEMD_RE = re.compile(r"\b(?:systemctl|systemd-run|journalctl)\b", re.IGNORECASE)
PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
KNOWN_SECRET_RE = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{30,}\b|"
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b|"
    r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
NAMED_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)\b"
    r"\s*(?:=|:)\s*[\"']?([^\s\"',}\]]+)"
)
KUBECONFIG_MARKERS = ("clusters:", "contexts:", "current-context:", "users:")
SYSTEMD_SUFFIXES = (".service", ".socket", ".timer", ".target", ".mount")
REVIEWED_SYSTEMD_FILES = {
    "images/control-plane-node/profile/control-plane-state/mkosi.extra/etc/systemd/system/control-plane-state-disk.service",
    "images/control-plane-node/profile/control-plane-state/mkosi.extra/etc/systemd/system/rke2-server.service.d/zz-control-plane-state.conf",
    # Writes the profile's remaining measured units (cred-release identities,
    # the bootstrap-window scheduler) as literal, reviewed heredocs, and
    # loads them with systemctl at boot. See
    # images/control-plane-node/README.md, "Profile packaging".
    "images/control-plane-node/profile/control-plane-state/mkosi.extra/usr/local/libexec/confidential-inference/control-plane-state-disk.sh",
    # Layer 1 (test_boot_units.py) and layer 2 (boot-sim/) test fixtures:
    # verbatim c8s units hash-checked against the pinned commit
    # (fixtures/c8s-base/), hand-written stubs for units genuinely outside
    # the c8s tree (fixtures/external-stubs/), and the boot-sim container's
    # fake base image units (boot-sim/fixtures/base/). See
    # images/control-plane-node/README.md, "Testing the profile".
    "tests/images/control-plane-node/fixtures/c8s-base/etc/systemd/system/cred-release.service",
    "tests/images/control-plane-node/fixtures/c8s-base/etc/systemd/system/gpu-cc-enforce.service",
    "tests/images/control-plane-node/fixtures/c8s-base/etc/systemd/system/rke2-role.service",
    "tests/images/control-plane-node/fixtures/c8s-base/etc/systemd/system/scratch-enforce.service",
    "tests/images/control-plane-node/fixtures/c8s-base/etc/systemd/system/rke2-agent.service.d/20-role.conf",
    "tests/images/control-plane-node/fixtures/c8s-base/etc/systemd/system/rke2-agent.service.d/no-modprobe.conf",
    "tests/images/control-plane-node/fixtures/c8s-base/etc/systemd/system/rke2-server.service.d/20-role.conf",
    "tests/images/control-plane-node/fixtures/c8s-base/etc/systemd/system/rke2-server.service.d/no-modprobe.conf",
    "tests/images/control-plane-node/fixtures/external-stubs/etc/systemd/system/attestation-api.service",
    "tests/images/control-plane-node/fixtures/external-stubs/etc/systemd/system/rke2-agent.service",
    "tests/images/control-plane-node/fixtures/external-stubs/etc/systemd/system/rke2-server.service",
    "tests/images/control-plane-node/boot-sim/fixtures/base/etc/systemd/system/attestation-api.service",
    "tests/images/control-plane-node/boot-sim/fixtures/base/etc/systemd/system/boot-sim-prep.service",
    "tests/images/control-plane-node/boot-sim/fixtures/base/etc/systemd/system/cred-release.service",
    "tests/images/control-plane-node/boot-sim/fixtures/base/etc/systemd/system/cred-release.service.d/10-platform.conf",
    "tests/images/control-plane-node/boot-sim/fixtures/base/etc/systemd/system/rke2-agent.service",
    "tests/images/control-plane-node/boot-sim/fixtures/base/etc/systemd/system/rke2-role.service",
    "tests/images/control-plane-node/boot-sim/fixtures/base/etc/systemd/system/rke2-server.service",
}
SECRET_ARTIFACT_NAMES = {
    ".env",
    "agent-token",
    "credentials",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
    "server-token",
    "service-account.json",
}
SECRET_ARTIFACT_SUFFIXES = (".key", ".p12", ".pfx", ".jks")
PLACEHOLDER_FRAGMENTS = (
    "example", "invalid", "placeholder", "replace", "changeme", "redacted",
    "<", "${", "{{", "secretkeyref", "schema", "pattern", "type",
)


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line_number: int
    line: str
    message: str


@dataclass(frozen=True)
class AllowEntry:
    rule: str
    path: str
    line_sha256: str


def tracked_files(root: Path) -> list[Path]:
    """Return files from the active Git index without reading another worktree."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    return [root / item.decode("utf-8", errors="surrogateescape") for item in result.stdout.split(b"\0") if item]


def is_secret_artifact(path: PurePosixPath) -> bool:
    name = path.name.lower()
    return (
        name in SECRET_ARTIFACT_NAMES
        or name.startswith(".env.")
        or name.endswith(SECRET_ARTIFACT_SUFFIXES)
        or name.endswith(".private.pem")
    )


def is_sensitive_root_path(relative: PurePosixPath) -> bool:
    return (
        relative.as_posix() == ".infisical.json"
        or ".kube" in relative.parts
        or is_secret_artifact(relative)
    )


def public_files(root: Path) -> list[Path]:
    tracked = tracked_files(root)
    if tracked:
        return sorted(path for path in tracked if path.is_file() or path.is_symlink())
    return sorted(
        path
        for path in root.rglob("*")
        if ".git" not in path.relative_to(root).parts
        and not GENERATED_DIRECTORY_NAMES.intersection(path.relative_to(root).parts)
        and (path.is_file() or path.is_symlink())
    )


def load_allowlist(path: Path | None) -> set[AllowEntry]:
    if path is None:
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("entries"), list):
        raise ValueError("the allowlist must contain version 1 and an entries list")
    entries: set[AllowEntry] = set()
    for item in data["entries"]:
        if not item.get("reason"):
            raise ValueError("each allowlist entry must contain a reason")
        entries.add(AllowEntry(item["rule"], item["path"], item["line_sha256"]))
    return entries


def line_digest(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def is_allowed(finding: Finding, allowlist: set[AllowEntry]) -> bool:
    return AllowEntry(finding.rule, finding.path, line_digest(finding.line)) in allowlist


def add(findings: list[Finding], rule: str, path: str, number: int, line: str, message: str) -> None:
    findings.append(Finding(rule, path, number, line, message))


def looks_like_plaintext_secret(line: str) -> bool:
    match = NAMED_SECRET_RE.search(line)
    if not match:
        return False
    value = match.group(1).strip()
    lowered = line.lower()
    if any(fragment in lowered for fragment in PLACEHOLDER_FRAGMENTS):
        return False
    if value.lower() in {"none", "null", "false", "true", "required", "string"}:
        return False
    if "(" in value or ")" in value:
        return False
    return len(value) >= 12


def contains_tailnet_address(line: str) -> bool:
    if TAILNET_RE.search(line):
        return True
    for candidate in re.findall(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])", line):
        try:
            if ipaddress.ip_address(candidate) in ipaddress.ip_network("100.64.0.0/10"):
                return True
        except ValueError:
            continue
    return False


def is_tailnet_network_policy_exclusion(path: str, lines: list[str], index: int) -> bool:
    """Allow the Tailnet CIDR only when a NetworkPolicy explicitly denies it."""
    if not path.endswith("network-policy.yaml") and not path.endswith("network-policies.yaml"):
        return False
    if lines[index].strip() != "- 100.64.0.0/10":
        return False
    return any(line.strip() == "except:" for line in lines[max(0, index - 12):index])


def private_ipv4_addresses(line: str, path: str, lines: list[str], index: int) -> list[str]:
    """Return the private IPv4 addresses on one line that this rule reports.

    The rule skips an RFC 5737 documentation address, a reviewed NetworkPolicy
    exclusion, and a Tailscale address the tailnet rule already reports. The
    second skip and the third one keep one line to one finding.
    """
    if is_tailnet_network_policy_exclusion(path, lines, index):
        return []
    reported: list[str] = []
    tailnet_reported = contains_tailnet_address(line)
    for candidate in IPV4_RE.findall(line):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if any(address in network for network in DOCUMENTATION_IPV4_NETWORKS):
            continue
        if not any(address in network for network in PRIVATE_IPV4_NETWORKS):
            continue
        if tailnet_reported and address in ipaddress.ip_network("100.64.0.0/10"):
            continue
        reported.append(candidate)
    return reported


def is_public_attestation_record(path: str) -> bool:
    """Allow exact image labels in published c8s allowlist records."""
    return (
        path.startswith("c8s/allowlists/")
        or path.startswith("releases/")
    ) and path.endswith(".json")


def is_reviewed_systemd(path: str) -> bool:
    """Allow only system services that are part of a public base image."""
    return path in REVIEWED_SYSTEMD_FILES


def contains_unpinned_remote_fetch(line: str) -> bool:
    if not REMOTE_FETCH_RE.search(line):
        return False
    without_loopback = re.sub(
        r"https?://(?:127\.0\.0\.1|localhost|\[::1\])(?=[:/]|$)",
        "loopback",
        line,
        flags=re.IGNORECASE,
    )
    return bool(REMOTE_FETCH_RE.search(without_loopback))


def scan_file(root: Path, path: Path) -> list[Finding]:
    relative = path.relative_to(root).as_posix()
    findings: list[Finding] = []
    pure = PurePosixPath(relative)

    if any(PRIVATE_PATH_RE.search(part) for part in pure.parts):
        add(findings, "private-optimization-path", relative, 0, relative, "the path name identifies private source")
    if pure.name == ".infisical.json":
        add(findings, "infisical-local-config", relative, 0, relative, "the public tree contains an Infisical local configuration")
    if pure.name.lower() in {"kubeconfig", "config.kubeconfig"} or ".kube" in pure.parts:
        add(findings, "kubeconfig", relative, 0, relative, "the public tree contains a kubeconfig path")
    if pure.suffix.lower() in SYSTEMD_SUFFIXES and not is_reviewed_systemd(relative):
        add(findings, "systemd-unit", relative, 0, relative, "the public tree contains a systemd unit")
    if is_secret_artifact(pure):
        add(findings, "secret-artifact", relative, 0, relative, "the public tree contains a secret artifact")
    if path.is_symlink():
        add(findings, "symbolic-link", relative, 0, relative, "the public tree contains a symbolic link")
        return findings

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return findings
    if relative == POLICY_ALLOWLIST:
        return findings

    marker_count = sum(marker in text.lower() for marker in KUBECONFIG_MARKERS)
    if marker_count >= 3 and relative != POLICY_IMPLEMENTATION:
        add(findings, "kubeconfig", relative, 1, text.splitlines()[0] if text else "", "the file contains kubeconfig data")
    if (
        re.search(r"(?mi)^\s*\[Unit\]\s*$", text)
        and re.search(r"(?mi)^\s*\[Service\]\s*$", text)
        and not is_reviewed_systemd(relative)
    ):
        add(findings, "systemd-unit", relative, 1, text.splitlines()[0] if text else "", "the file contains a systemd unit")

    lines = text.splitlines()
    for number, line in enumerate(lines, start=1):
        if PEM_RE.search(line):
            add(findings, "pem-private-key", relative, number, line, "the file contains a PEM private key")
        if KNOWN_SECRET_RE.search(line) or looks_like_plaintext_secret(line):
            add(findings, "plaintext-api-key", relative, number, line, "the file contains plaintext secret material")
        if (
            KEY_VAULT_RE.search(line)
            and relative != POLICY_IMPLEMENTATION
        ):
            add(findings, "azure-key-vault-runtime", relative, number, line, "the file depends on Azure Key Vault at runtime")
        if (
            contains_tailnet_address(line)
            and relative != POLICY_IMPLEMENTATION
            and not is_public_attestation_record(relative)
            and not is_tailnet_network_policy_exclusion(relative, lines, number - 1)
        ):
            add(findings, "tailnet-service-traffic", relative, number, line, "the file sends service traffic through a Tailnet")
        if (
            SYSTEMD_RE.search(line)
            and relative != POLICY_IMPLEMENTATION
            and not is_reviewed_systemd(relative)
        ):
            add(findings, "systemd-unit", relative, number, line, "the file contains a systemd runtime dependency")
        if relative != POLICY_IMPLEMENTATION:
            if private_ipv4_addresses(line, relative, lines, number - 1):
                add(findings, "private-ip-address", relative, number, line,
                    "the file names a private network address")
            if HOME_PATH_RE.search(line):
                add(findings, "home-directory-path", relative, number, line,
                    "the file names an absolute path in a user home directory")
            if HOST_NAME_RE.search(line):
                add(findings, "infrastructure-host-name", relative, number, line,
                    "the file names a real infrastructure host")

        if pure.name.lower().startswith("dockerfile"):
            image_match = DOCKER_IMAGE_RE.search(line)
        elif pure.suffix.lower() == ".json":
            image_match = JSON_IMAGE_RE.search(line)
        elif pure.suffix.lower() in {".yaml", ".yml"}:
            image_match = YAML_IMAGE_RE.search(line)
        else:
            image_match = None
        if image_match and not IMAGE_DIGEST_RE.search(image_match.group(1)):
            add(findings, "image-tag", relative, number, line, "the image reference does not use a SHA-256 digest")
        if pure.parts[:2] == (".github", "workflows") and "uses:" in line:
            action_match = ACTION_PIN_RE.search(line)
            if not action_match:
                add(findings, "unpinned-remote-artifact", relative, number, line, "the workflow action does not use a full commit SHA")
        if contains_unpinned_remote_fetch(line):
            add(findings, "unpinned-remote-artifact", relative, number, line, "the remote fetch has no verifiable content pin")
    return findings


def validate(root: Path, allowlist: set[AllowEntry]) -> list[Finding]:
    findings = [finding for path in public_files(root) for finding in scan_file(root, path)]
    return [finding for finding in findings if not is_allowed(finding, allowlist)]


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--allowlist", type=Path, help="an explicit exact-line allowlist for deliberate test fixtures")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    allowlist_path = args.allowlist
    if allowlist_path is None:
        candidate = root / POLICY_ALLOWLIST
        if candidate.is_file():
            allowlist_path = candidate
    try:
        allowlist = load_allowlist(allowlist_path)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"source-boundary: invalid allowlist: {error}", file=sys.stderr)
        return 2
    findings = validate(root, allowlist)
    for finding in findings:
        location = f"{finding.path}:{finding.line_number}" if finding.line_number else finding.path
        print(f"{location}: [{finding.rule}] {finding.message}")
    if findings:
        print(f"source-boundary: failed with {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print(f"source-boundary: passed ({len(public_files(root))} public files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
