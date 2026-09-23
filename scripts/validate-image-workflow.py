#!/usr/bin/env python3
"""Validate the publication safety rules for the v0 image workflow."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "v0-images.yml"
FULL_SHA_ACTION = re.compile(r"^\s*uses:\s*[^\s@]+@([0-9a-f]{40})(?:\s+#.*)?$", re.MULTILINE)
ANY_ACTION = re.compile(r"^\s*uses:\s*[^\s@]+@([^\s]+)", re.MULTILINE)


def validate(text: str) -> list[str]:
    errors: list[str] = []
    policy_text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())

    action_refs = ANY_ACTION.findall(text)
    pinned_refs = FULL_SHA_ACTION.findall(text)
    if not action_refs or len(action_refs) != len(pinned_refs):
        errors.append("each action must use a full 40-character commit SHA")

    required = (
        "pull_request:",
        "workflow_dispatch:",
        "publish:",
        "rebuild_audit:",
        "publish_target:",
        "type: boolean",
        "default: false",
        "github.event_name == 'workflow_dispatch' &&",
        "inputs.publish &&",
        "(github.ref == 'refs/heads/main' || github.ref == 'refs/heads/staging')",
        "environment: ghcr-production",
        "packages: write",
        "push: false",
        "push=true",
        "image: gateway",
        "image: sglang",
        "image: maintenance-gateway",
        "image: metrics-collector",
        "image: kube-state-metrics",
        "images/sglang",
        "services/maintenance-gateway",
        "images/maintenance-gateway",
        "images/metrics-collector",
        "images/kube-state-metrics",
        "ghcr.io/confidential-dot-ai/confidential-inference/${{ matrix.image }}:sha-${{ github.sha }}",
        "org.opencontainers.image.source=",
        "org.opencontainers.image.revision=",
        "org.opencontainers.image.version=sha-${{ github.sha }}",
        "provenance: mode=max",
        "sbom: ${{ matrix.image != 'sglang' }}",
        "steps.build.outputs.digest",
        "SOURCE_DATE_EPOCH=${{ steps.source.outputs.epoch }}",
        "no-cache: true",
        "v0-first-${{ github.run_id }}-${{ matrix.image }}",
        "v0-second-${{ github.run_id }}-${{ matrix.image }}",
        "builder: ${{ steps.first-builder.outputs.name }}",
        "builder: ${{ steps.second-builder.outputs.name }}",
        "rewrite-timestamp=true",
        "BUILDX_VERSION: v0.36.1",
        "BUILDKIT_IMAGE: moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8",
        "version: ${{ env.BUILDX_VERSION }}",
        "driver-opts: image=${{ env.BUILDKIT_IMAGE }}",
        "inputs.publish_target == 'all' || inputs.publish_target == matrix.image",
        "verify-reproducible-oci.py",
        "inputs.rebuild_audit",
        "needs: validate",
        "github.event_name != 'workflow_dispatch' || inputs.publish_target == 'all' || inputs.publish_target == matrix.image",
        "reproducibility-sglang-build:",
        "reproducibility-sglang-compare:",
        "needs: reproducibility-sglang-build",
        "(inputs.publish_target == 'all' || inputs.publish_target == 'sglang')",
        "pass: [1, 2]",
        "TMPDIR: /mnt/tmp",
        "DOCKER_TMPDIR: /mnt/tmp",
        "--compare-records",
        "--record /tmp/sglang-",
        "v0-sglang-record-",
        "v0-platform-digest-sglang",
    )
    for item in required:
        if item not in policy_text:
            errors.append(f"the workflow lacks the required value: {item}")

    if re.search(r"(?i)(?:^|[/:_-])latest(?:[,\s]|$)", text):
        errors.append("the workflow must not use a latest tag")

    publish = text.split("\n  publish-images:", 1)[-1].split("\n  publish-release-bundle:", 1)[0]
    reproducibility = text.split("\n  reproducibility:", 1)[-1].split("\n  publish-images:", 1)[0]
    selection_condition = (
        "github.event_name != 'workflow_dispatch' || inputs.publish_target == 'all' || "
        "inputs.publish_target == matrix.image"
    )
    if reproducibility.count(selection_condition) < 9:
        errors.append("manual reproducibility must run only for the selected image")
    if "- image: gateway" not in publish:
        errors.append("the image publication matrix must include the gateway")
    if "needs: validate" not in publish:
        errors.append("image publication must require validation")
    if "reproducibility" in re.search(r"^\s+needs:\s*(.+)$", publish, re.MULTILINE).group(1):
        errors.append("image publication must not depend on the rebuild audit")
    if "inputs.rebuild_audit" not in reproducibility:
        errors.append("the rebuild audit must require explicit manual selection")

    sglang_matrix_entry = text.split("\n  reproducibility:", 1)[-1].split(
        "\n  reproducibility-sglang-build:", 1
    )[0]
    if "image: sglang" in sglang_matrix_entry:
        errors.append(
            "the sglang image must not build twice on one runner in the shared "
            "reproducibility matrix; it needs its own split build jobs"
        )

    sglang_build = text.split("\n  reproducibility-sglang-build:", 1)[-1].split(
        "\n  reproducibility-sglang-compare:", 1
    )[0]
    sglang_compare = text.split("\n  reproducibility-sglang-compare:", 1)[-1].split(
        "\n  publish-images:", 1
    )[0]
    if "needs: validate" not in sglang_build:
        errors.append("the sglang build jobs must require validation")
    if "inputs.rebuild_audit" not in sglang_build:
        errors.append("the sglang build jobs must require explicit manual selection")
    if "needs: reproducibility-sglang-build" not in sglang_compare:
        errors.append("the sglang compare job must wait for both sglang build jobs")
    if "inputs.rebuild_audit" not in sglang_compare:
        errors.append("the sglang compare job must require explicit manual selection")
    for name, block in (
        ("build", sglang_build),
        ("compare", sglang_compare),
    ):
        if "(inputs.publish_target == 'all' || inputs.publish_target == 'sglang')" not in block:
            errors.append(f"the sglang {name} job must run only when sglang is selected")

    if "github.event_name == 'push' &&" in text:
        errors.append("a push event must never enable publication")

    expected_condition = (
        "github.event_name == 'workflow_dispatch' && inputs.publish && "
        "(github.ref == 'refs/heads/main' || github.ref == 'refs/heads/staging')"
    )
    for name, block in (("image", publish),):
        condition = re.search(r"^\s+if:\s*>-\s*\n((?:\s{6}.*\n?)+)", block)
        normalized = " ".join(condition.group(1).split()) if condition else ""
        if normalized != expected_condition:
            errors.append(f"the {name} publication condition is not exact")
        if "environment: ghcr-production" not in block or "packages: write" not in block:
            errors.append(f"the {name} publication lacks its protected write policy")

    if "provenance: mode=max" not in publish or (
        "sbom: ${{ matrix.image != 'sglang' }}" not in publish
    ):
        errors.append(
            "image publication must create maximum provenance and an SBOM "
            "for every image except sglang, whose SBOM exceeds BuildKit's "
            "attestation size cap"
        )

    for label in (
        "org.opencontainers.image.title=",
        "org.opencontainers.image.source=",
        "org.opencontainers.image.revision=",
        "org.opencontainers.image.version=",
    ):
        if policy_text.count(label) < 3:
            errors.append(f"clean and published builds must use the same OCI label: {label}")
    pull_request_block = text.split("pull_request:", 1)[1].split("workflow_dispatch:", 1)[0]
    if "publish" in pull_request_block:
        errors.append("the pull request trigger must not enable publication")

    return errors




def validate_repositories() -> list[str]:
    expected = {
        "gateway": "ghcr.io/confidential-dot-ai/confidential-inference/gateway@sha256:",
        "sglang": "ghcr.io/confidential-dot-ai/confidential-inference/sglang@sha256:",
        "metricsCollector": "ghcr.io/confidential-dot-ai/confidential-inference/metrics-collector@sha256:",
        "kubeStateMetrics": "ghcr.io/confidential-dot-ai/confidential-inference/kube-state-metrics@sha256:",
    }
    values = (ROOT / "helm" / "confidential-inference" / "values.yaml").read_text()
    errors = []
    for key, prefix in expected.items():
        if not re.search(rf"^\s*{re.escape(key)}:\s+{re.escape(prefix)}", values, re.MULTILINE):
            errors.append(f"the Helm {key} image does not use {prefix.removesuffix('@sha256:')}")
    maintenance = (ROOT / "helm" / "maintenance-gateway" / "values.yaml").read_text()
    maintenance_prefix = (
        "ghcr.io/confidential-dot-ai/confidential-inference/maintenance-gateway@sha256:"
    )
    if not re.search(rf"^image:\s+{re.escape(maintenance_prefix)}", maintenance, re.MULTILINE):
        errors.append("the maintenance gateway image does not use its monorepo GHCR name")
    return errors


def main() -> int:
    errors = (
        validate(WORKFLOW.read_text(encoding="utf-8"))
        + validate_repositories()
    )
    for error in errors:
        print(f"image-workflow: {error}")
    if errors:
        return 1
    print("image-workflow: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
