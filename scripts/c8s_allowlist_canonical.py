#!/usr/bin/env python3
"""Reproduce c8s's canonical allowlist JSON bytes in Python.

c8s commit 75af991a ("feat(allowlist)!: fold floor digests into workload
entries") removed `pkg/allowlist.Allowlist.Digests`, `c8s render-allowlist`,
and the offline `c8s allowlist canonicalize <file>` command. Every c8s tag
after that commit (v0.15.5, v0.20.4, ...) can no longer turn an allowlist
file into canonical bytes without a live CDS connection (`c8s allowlist
export` fetches the *served* allowlist over the network; it does not take a
file).

canonicalize_mainline() below reproduces pkg/allowlist.Allowlist.Canonical()
(Go's encoding/json.Marshal of the normalized, folded-floor allowlist
struct) for the c8s.allowlist/v1 schema those tags use. It is verified
byte-identical against a build of pkg/allowlist at c8s commit 466ce79
(v0.20.4) for every allowlist file this repository pins
(c8s/allowlists/*.json) — see the PR that added this module for the
verification method (a standalone Go program built against
pkg/allowlist@466ce79, compared byte-for-byte against this function's
output).

Known gap: c8s v0.20.4 changed `EnvPolicy` from constraining variable NAMES
(`{"policy":"exact","names":[...]}`, still what this function emits — the
079aeb48/v0.15.5 shape) to constraining the complete VALUES map
(`{"policy":"exact","values":{...}}`). This function cannot reproduce the
v0.20.4 "exact" env shape. Every allowlist this repository pins uses
`"env":{"policy":"any"}`, so the gap is latent; UnsupportedAllowlistShape
fails closed instead of emitting the wrong bytes if it is ever hit.
"""

from __future__ import annotations

import json
import re
from typing import Any


class UnsupportedAllowlistShape(Exception):
    """The document uses a shape this canonicalizer cannot reproduce safely."""


def _normalize_container(container: dict[str, Any]) -> dict[str, Any]:
    """Mirror normalizeContainers: default absent argv/mount/env policies."""
    normalized: dict[str, Any] = {"digest": container["digest"]}
    if container.get("image"):
        normalized["image"] = container["image"]
    for key in ("command", "args"):
        policy = (container.get(key) or {}).get("policy", "")
        argv = (container.get(key) or {}).get("argv")
        if policy in ("", "any"):
            normalized[key] = {"policy": "any"}
        elif policy == "deny":
            normalized[key] = {"policy": "deny"}
        elif policy == "exact":
            if not argv:
                raise UnsupportedAllowlistShape("an exact argv policy needs its argv")
            normalized[key] = {"policy": "exact", "argv": list(argv)}
        else:
            raise UnsupportedAllowlistShape(f"unknown argv policy: {policy}")
    mounts = container.get("mounts") or {}
    if mounts.get("policy", "") in ("", "any"):
        normalized["mounts"] = {"policy": "any"}
    elif mounts.get("policy") == "exact":
        destinations = mounts.get("destinations") or []
        if not destinations:
            raise UnsupportedAllowlistShape("an exact mounts policy needs destinations")
        normalized["mounts"] = {"policy": "exact", "destinations": sorted(set(destinations))}
    else:
        raise UnsupportedAllowlistShape(f"unknown mounts policy: {mounts.get('policy')}")
    env = container.get("env") or {}
    if env.get("policy", "") in ("", "any"):
        normalized["env"] = {"policy": "any"}
    elif env.get("policy") == "exact":
        # See the module docstring: c8s v0.20.4 serializes this policy as
        # {"policy":"exact","values":{...}}, not {"names":[...]}. Fail closed
        # rather than guess which shape the pinned binary expects.
        raise UnsupportedAllowlistShape(
            "an exact env policy cannot be canonicalized without the pinned "
            "c8s binary: its wire shape changed between c8s tags "
            "(names -> values) and this reproduction only covers the "
            "always-\"any\" case this repository's allowlists use"
        )
    else:
        raise UnsupportedAllowlistShape(f"unknown env policy: {env.get('policy')}")
    return normalized


def _policy_key(container: dict[str, Any]) -> str:
    return json.dumps([container["command"], container["args"]], separators=(",", ":"))


def canonicalize_mainline(document: dict[str, Any]) -> bytes:
    """Mirror Allowlist.Canonical() on main-line (post-75af991a) c8s.

    Field order follows the Go struct declarations; the workloads map is
    key-sorted by encoding/json; container lists sort by (digest, policyKey),
    exactly like sortContainers. Raises UnsupportedAllowlistShape rather than
    guessing when the document uses a shape not covered above (see the
    module docstring for the one known gap).
    """
    if document.get("schema") != "c8s.allowlist/v1":
        raise UnsupportedAllowlistShape("the allowlist has the wrong schema")
    workloads = document.get("workloads")
    if not isinstance(workloads, dict) or not workloads:
        raise UnsupportedAllowlistShape("the allowlist has no workloads")
    out: dict[str, Any] = {}
    for name in sorted(workloads):
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is None or len(name) > 63:
            raise UnsupportedAllowlistShape(f"the workload name is invalid: {name}")
        entry = workloads[name]
        normalized_entry: dict[str, Any] = {}
        if entry.get("label"):
            normalized_entry["label"] = entry["label"]
        for field in ("initContainers", "containers"):
            containers = [_normalize_container(c) for c in (entry.get(field) or [])]
            containers.sort(key=lambda c: (c["digest"], _policy_key(c)))
            normalized_entry[field] = containers
        secrets = entry.get("secrets")
        if secrets and secrets.get("policy") == "allow":
            grant: dict[str, Any] = {"policy": "allow"}
            if secrets.get("read"):
                grant["read"] = sorted(set(secrets["read"]))
            if secrets.get("write"):
                grant["write"] = sorted(set(secrets["write"]))
            normalized_entry["secrets"] = grant
        out[name] = normalized_entry
    return json.dumps(
        {"schema": "c8s.allowlist/v1", "workloads": out},
        separators=(",", ":"), ensure_ascii=False,
    ).encode()
