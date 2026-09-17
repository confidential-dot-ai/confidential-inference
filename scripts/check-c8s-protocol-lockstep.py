#!/usr/bin/env python3
"""Check that the gateway's declared c8s attestation protocol, and its test
fixtures' receipt field set, match the pinned c8s commit's real protocol.

`version` is identical text (`c8s/attest-pq/v1`) on both c8s protocols (see
`contracts/README.md`), so nothing on the wire tells a stale gateway it is
speaking to the wrong one; it must know the protocol in advance. This script
is the deploy-time guard: it reads the c8s route table and receipt field set
this repo already captured, read-only, into
`contracts/c8s-attestation-protocols/<commit>.json` for each protocol c8s has
ever spoken, and compares them against `contracts/c8s-admission-source-lock.json`
(which pins one protocol per environment) and the gateway's own Rust test
fixtures (which is the only place the gateway commits to a wire shape).

This makes no network call and reads only files already committed to this
repository.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOCK = ROOT / "contracts/c8s-admission-source-lock.json"
PROTOCOLS_DIR = ROOT / "contracts/c8s-attestation-protocols"
GATEWAY_TESTS = ROOT / "services/gateway/tests"

OLD_PROTOCOL = "c8s/attest-pq/v1"
XWING_PROTOCOL = "c8s/attest-pq/v1+xwing"

# The one field that exists on the wire only for a given protocol's attest-pq
# receipt. Their presence (or absence) in the gateway's own committed test
# fixtures is the only true statement this repo can make about which shape
# the gateway builds and validates, short of running it.
PROTOCOL_MARKER_FIELDS = {
    OLD_PROTOCOL: ("session_pubkey",),
    XWING_PROTOCOL: ("xwing_ek", "xwing_ct", "session_id"),
}


class LockstepError(ValueError):
    """The gateway and the pinned c8s commit disagree about the protocol."""


def read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LockstepError(f"cannot read valid JSON from {label} ({path})") from error


def lock_entries(source_lock: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Split the source lock into its frozen top-level entry and active commits.

    The top-level entry pins whatever c8s commit the already-shipped,
    frozen production gateway image was built and verified against (see
    `docs/plans/gateway-attestation-c8s-v0.20.4.md` section 4: "Only
    production runs the old protocol, and production is frozen on its
    current gateway image. No environment needs both."). This repository's
    current gateway source speaks exactly one protocol at a time
    (lockstep, not dual), so it can never satisfy a frozen historical
    entry's fixture requirements again — that entry was validated once,
    when its own image shipped. Only `commits` entries name c8s versions
    the *current* gateway build is meant to interoperate with, so only
    those get checked against today's gateway test fixtures.
    """
    extra = source_lock.get("commits", [])
    active = [entry for entry in extra if isinstance(entry, dict)] if isinstance(extra, list) else []
    return source_lock, active


def load_manifests() -> dict[str, dict[str, Any]]:
    """Return every protocol manifest, indexed by every commit it covers.

    A manifest keyed by its own commit also covers every commit named in its
    optional `sharedWithCommits` list: a c8s commit that serves the identical
    route table and bundle field set as an already-captured commit does not
    need its own byte-for-byte capture, only a recorded claim of identity
    (`contracts/c8s-attestation-protocols/README` documents this).
    """
    if not PROTOCOLS_DIR.is_dir():
        raise LockstepError(f"{PROTOCOLS_DIR} does not exist")
    by_commit: dict[str, dict[str, Any]] = {}
    for path in sorted(PROTOCOLS_DIR.glob("*.json")):
        manifest = read_json(path, f"protocol manifest {path.name}")
        commit = manifest.get("commit")
        if not isinstance(commit, str):
            raise LockstepError(f"{path} has no commit field")
        if path.stem != commit:
            raise LockstepError(f"{path} is not named after its own commit field")
        by_commit[commit] = manifest
        for shared in manifest.get("sharedWithCommits", []):
            if shared in by_commit and by_commit[shared] is not manifest:
                raise LockstepError(f"commit {shared} is claimed by two protocol manifests")
            by_commit[shared] = manifest
    return by_commit


def field_is_constructed(field: str, text: str) -> bool:
    """True only where `field` appears as a JSON object key being built.

    A fixture that asserts a field's *absence* (for example
    `response["receipt"]["session_pubkey"].is_null()`, proving the gateway
    does NOT build the old shape) contains the field name as a bracket
    index, not as a `"field": value` key. Only the latter is evidence the
    gateway actually constructs that field, so the marker search must
    require the colon, or a regression test asserting absence of the other
    protocol's field reads as if the gateway still built it.
    """
    return re.search(rf'"{re.escape(field)}"\s*:', text) is not None


def gateway_fixture_text() -> str:
    if not GATEWAY_TESTS.is_dir():
        raise LockstepError(f"{GATEWAY_TESTS} does not exist")
    chunks = []
    for path in sorted(GATEWAY_TESTS.rglob("*.rs")):
        chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def check_entry(
    entry: dict[str, Any],
    manifests: dict[str, dict[str, Any]],
    fixture_text: str,
    *,
    require_fixture_match: bool,
) -> str:
    commit = entry.get("commit")
    if not isinstance(commit, str):
        raise LockstepError("a source lock entry has no commit field")
    protocol = entry.get("attestationProtocol", OLD_PROTOCOL)
    if protocol not in PROTOCOL_MARKER_FIELDS:
        raise LockstepError(f"commit {commit} pins an unknown attestation protocol {protocol!r}")
    manifest = manifests.get(commit)
    if manifest is None:
        raise LockstepError(
            f"commit {commit} has no protocol manifest under {PROTOCOLS_DIR.relative_to(ROOT)}"
        )
    if manifest["attestationProtocol"] != protocol:
        raise LockstepError(
            f"commit {commit}: the source lock says {protocol!r}, "
            f"but its protocol manifest says {manifest['attestationProtocol']!r}"
        )
    markers = PROTOCOL_MARKER_FIELDS[protocol]
    missing_from_manifest = [f for f in markers if f not in manifest["attestationBundleFields"]]
    if missing_from_manifest:
        raise LockstepError(
            f"commit {commit}: the {protocol!r} manifest omits its own marker field(s) "
            f"{missing_from_manifest}"
        )
    if not require_fixture_match:
        return f"commit {commit}: protocol {protocol!r} matches its manifest (frozen entry, not checked against gateway fixtures)"
    missing_from_gateway = [f for f in markers if not field_is_constructed(f, fixture_text)]
    if missing_from_gateway:
        raise LockstepError(
            f"commit {commit} pins protocol {protocol!r}, which the gateway's own test "
            f"fixtures (services/gateway/tests) do not build: missing field(s) "
            f"{missing_from_gateway}"
        )
    # A gateway that still emits the OTHER protocol's marker fields as well
    # has not actually cut over; `version` cannot tell the two apart on the
    # wire, so ambiguity here is a real defect, not noise.
    for other_protocol, other_markers in PROTOCOL_MARKER_FIELDS.items():
        if other_protocol == protocol:
            continue
        if all(field_is_constructed(f, fixture_text) for f in other_markers):
            raise LockstepError(
                f"the gateway test fixtures build both {protocol!r} and "
                f"{other_protocol!r} receipt shapes; c8s's identical `version` "
                "string on both protocols means a gateway must speak exactly one"
            )
    return f"commit {commit}: protocol {protocol!r} matches the gateway test fixtures"


def main() -> int:
    try:
        source_lock = read_json(SOURCE_LOCK, "c8s admission source lock")
        manifests = load_manifests()
        fixture_text = gateway_fixture_text()
        frozen_entry, active_entries = lock_entries(source_lock)
        verdicts = [check_entry(frozen_entry, manifests, fixture_text, require_fixture_match=False)]
        verdicts.extend(
            check_entry(entry, manifests, fixture_text, require_fixture_match=True)
            for entry in active_entries
        )
    except LockstepError as error:
        print(f"c8s protocol lockstep check failed: {error}", file=sys.stderr)
        return 1
    for verdict in verdicts:
        print(verdict)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
