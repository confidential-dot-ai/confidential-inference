"""Prove the path-filter categories in v0-validation.yml match the right jobs.

This test does not run GitHub Actions. It reads the `filters:` block the
"changes" job passes to dorny/paths-filter, re-implements enough of that
action's glob matching to judge our patterns (globstar directories, a
single-level "*", and a leading "!" exclusion, which is all our patterns
use), and checks a small table of sample change sets against the category
each one must, and must not, turn on. See "Continuous integration" in
README.md for the category table this test enforces.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "v0-validation.yml"


def pattern_to_regex(pattern: str) -> re.Pattern[str]:
    specials = ".^$+()[]{}|\\"
    out: list[str] = ["^"]
    i = 0
    while i < len(pattern):
        if pattern[i : i + 3] == "**/":
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern[i : i + 2] == "**":
            out.append(".*")
            i += 2
            continue
        char = pattern[i]
        if char == "*":
            out.append("[^/]*")
        elif char in specials:
            out.append("\\" + char)
        else:
            out.append(char)
        i += 1
    out.append("$")
    return re.compile("".join(out))


def matches_category(changed_paths: list[str], patterns: list[str]) -> bool:
    positive = [pattern_to_regex(p) for p in patterns if not p.startswith("!")]
    negative = [pattern_to_regex(p[1:]) for p in patterns if p.startswith("!")]
    for path in changed_paths:
        if any(p.match(path) for p in positive) and not any(p.match(path) for p in negative):
            return True
    return False


def load_filters() -> dict[str, list[str]]:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    step = workflow["jobs"]["changes"]["steps"][-1]
    assert step["uses"].startswith("dorny/paths-filter@"), step
    return yaml.safe_load(step["with"]["filters"])


class PathFilterMappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.filters = load_filters()
        self.categories = ("rust", "helm-and-contracts", "node-image-profile", "release-bundle", "docs-only")
        self.assertEqual(set(self.categories), set(self.filters))

    def assert_categories(self, changed_paths: list[str], expected_on: set[str]) -> None:
        actual_on = {
            category
            for category in self.categories
            if matches_category(changed_paths, self.filters[category])
        }
        self.assertEqual(expected_on, actual_on, f"for changed paths {changed_paths}")

    def test_bundle_only_change(self) -> None:
        # This is the exact change described in the September 4, 2026
        # incident report: a bundle-only release PR waited on the Rust
        # test and lint job, which cannot fail on this change.
        self.assert_categories(
            [
                "releases/staging/release-bundle.json",
                "c8s/staging-values.yaml",
                "images/sglang/source.lock",
            ],
            {"release-bundle"},
        )

    def test_rust_only_change(self) -> None:
        self.assert_categories(
            ["services/gateway/src/main.rs"],
            {"rust"},
        )

    def test_node_image_profile_only_change(self) -> None:
        self.assert_categories(
            ["images/control-plane-node/profile/control-plane-state"],
            {"node-image-profile"},
        )

    def test_docs_only_change(self) -> None:
        self.assert_categories(
            ["docs/threat-model.md"],
            {"docs-only"},
        )

    def test_mixed_change(self) -> None:
        self.assert_categories(
            [
                "services/gateway/src/main.rs",
                "helm/confidential-inference/Chart.yaml",
                "README.md",
            ],
            {"rust", "helm-and-contracts", "docs-only"},
        )

    def test_control_plane_node_tests_do_not_double_run_the_python_suite(self) -> None:
        # tests/images/control-plane-node/** sits under tests/**, which
        # helm-and-contracts would otherwise also match. The exclusion
        # keeps that suite scoped to the node-image-profile job alone.
        self.assert_categories(
            ["tests/images/control-plane-node/test_boot_units.py"],
            {"node-image-profile"},
        )

    def test_workflow_file_change_runs_every_category(self) -> None:
        self.assert_categories(
            [".github/workflows/v0-validation.yml"],
            {"rust", "helm-and-contracts", "node-image-profile", "release-bundle"},
        )


if __name__ == "__main__":
    unittest.main()
