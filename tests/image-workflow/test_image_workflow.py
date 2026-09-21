#!/usr/bin/env python3
"""Tests for the v0 image workflow policy validator."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "validate-image-workflow.py"
SPEC = importlib.util.spec_from_file_location("validate_image_workflow", VALIDATOR)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("the image workflow validator cannot load")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ImageWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.valid = (ROOT / ".github" / "workflows" / "v0-images.yml").read_text(encoding="utf-8")
        self.assertEqual([], MODULE.validate(self.valid))

    def test_rejects_an_unpinned_action(self) -> None:
        invalid = self.valid.replace(
            "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
            "actions/checkout@v4",
            1,
        )
        self.assertIn("each action must use a full 40-character commit SHA", MODULE.validate(invalid))

    def test_rejects_a_latest_tag(self) -> None:
        invalid = self.valid.replace(":sha-${{ github.sha }}", ":latest", 1)
        self.assertIn("the workflow must not use a latest tag", MODULE.validate(invalid))

    def test_requires_the_pinned_oci_builder(self) -> None:
        invalid = self.valid.replace(
            "moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8",
            "moby/buildkit:v0.32.2",
        )
        self.assertIn(
            "the workflow lacks the required value: BUILDKIT_IMAGE: "
            "moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8",
            MODULE.validate(invalid),
        )

    def test_publication_does_not_depend_on_reproducibility(self) -> None:
        invalid = self.valid.replace(
            "needs: [validate, select-publish-images]",
            "needs: [validate, select-publish-images, reproducibility]",
            1,
        )
        self.assertIn(
            "image publication must not depend on the rebuild audit",
            MODULE.validate(invalid),
        )

    def test_rebuild_audit_requires_manual_selection(self) -> None:
        # Every occurrence: the audit now spans three jobs (the shared
        # reproducibility job, and the split sglang build and compare jobs),
        # each gated on this input.
        invalid = self.valid.replace("inputs.rebuild_audit", "true")
        self.assertIn(
            "the workflow lacks the required value: inputs.rebuild_audit",
            MODULE.validate(invalid),
        )

    def test_requires_matching_clean_and_published_labels(self) -> None:
        # Every occurrence of the templated title: the sglang build job
        # bakes a literal title instead (it has no `matrix.title`), so a
        # single replacement would leave the count at the required minimum.
        invalid = self.valid.replace(
            "org.opencontainers.image.title=${{ matrix.title }}",
            "org.opencontainers.image.name=${{ matrix.title }}",
        )
        self.assertIn(
            "clean and published builds must use the same OCI label: "
            "org.opencontainers.image.title=",
            MODULE.validate(invalid),
        )

    def test_manual_reproducibility_uses_selected_image(self) -> None:
        invalid = self.valid.replace(
            "github.event_name != 'workflow_dispatch' || inputs.publish_target == 'all' || "
            "inputs.publish_target == matrix.image",
            "true",
            1,
        )
        self.assertIn(
            "manual reproducibility must run only for the selected image",
            MODULE.validate(invalid),
        )

    def test_requires_maximum_provenance(self) -> None:
        invalid = self.valid.replace("provenance: mode=max", "provenance: false")
        self.assertIn(
            "the workflow lacks the required value: provenance: mode=max",
            MODULE.validate(invalid),
        )

    def test_requires_sbom_generation(self) -> None:
        invalid = self.valid.replace(
            "sbom: ${{ matrix.image != 'sglang' }}", "sbom: false"
        )
        self.assertIn(
            "the workflow lacks the required value: "
            "sbom: ${{ matrix.image != 'sglang' }}",
            MODULE.validate(invalid),
        )

    def test_requires_explicit_manual_publication(self) -> None:
        invalid = self.valid.replace("inputs.publish &&", "true &&")
        self.assertIn(
            "the workflow lacks the required value: "
            "inputs.publish &&",
            MODULE.validate(invalid),
        )

    def test_rejects_automatic_push_publication(self) -> None:
        invalid = self.valid.replace(
            "github.event_name == 'workflow_dispatch' &&",
            "github.event_name == 'push' &&",
            1,
        )
        self.assertIn("a push event must never enable publication", MODULE.validate(invalid))

    def test_rejects_a_broadened_publication_condition(self) -> None:
        invalid = self.valid.replace(
            "inputs.publish &&\n      (github.ref == 'refs/heads/main' || "
            "github.ref == 'refs/heads/staging')",
            "inputs.publish &&\n      (github.ref == 'refs/heads/main' || "
            "github.ref == 'refs/heads/staging' || github.event_name == 'push')",
        )
        self.assertIn("the image publication condition is not exact", MODULE.validate(invalid))

    def test_accepts_publication_from_staging(self) -> None:
        # The valid fixture's publication condition must name the staging
        # branch, not only main, so a workflow_dispatch from staging can
        # publish images.
        self.assertIn(
            "github.ref == 'refs/heads/main' || github.ref == 'refs/heads/staging'",
            self.valid,
        )
        self.assertEqual([], MODULE.validate(self.valid))

    def test_comments_cannot_satisfy_the_sbom_policy(self) -> None:
        invalid = (
            self.valid.replace("sbom: ${{ matrix.image != 'sglang' }}", "sbom: false")
            + "\n# sbom: ${{ matrix.image != 'sglang' }}\n"
        )
        self.assertIn(
            "the workflow lacks the required value: "
            "sbom: ${{ matrix.image != 'sglang' }}",
            MODULE.validate(invalid),
        )

    def test_repo_built_images_bind_the_same_stable_source_inputs(self) -> None:
        for relative in ("images/maintenance-gateway/Dockerfile",):
            recipe = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("ARG SOURCE_REVISION", recipe)
            self.assertIn("ARG SOURCE_DATE_EPOCH", recipe)
            self.assertIn('org.opencontainers.image.revision="${SOURCE_REVISION}"', recipe)
            self.assertIn('org.opencontainers.image.version="sha-${SOURCE_REVISION}"', recipe)
            self.assertIn(
                'ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"',
                recipe,
            )

    def test_helm_uses_only_the_monorepo_image_names(self) -> None:
        self.assertEqual([], MODULE.validate_repositories())


if __name__ == "__main__":
    unittest.main()
