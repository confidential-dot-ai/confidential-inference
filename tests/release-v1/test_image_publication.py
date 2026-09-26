from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/image-publication-manifest.py"
SPEC = importlib.util.spec_from_file_location("image_publication_manifest", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
FINDER_SCRIPT = ROOT / "scripts/find-image-publication-run.py"
FINDER_SPEC = importlib.util.spec_from_file_location("find_image_publication_run", FINDER_SCRIPT)
FINDER = importlib.util.module_from_spec(FINDER_SPEC)
assert FINDER_SPEC.loader is not None
FINDER_SPEC.loader.exec_module(FINDER)


class ImagePublicationTests(unittest.TestCase):
    def record(self, image: str = "gateway", digest: str = "sha256:" + "a" * 64):
        return MODULE.record(
            image=f"ghcr.io/confidential-dot-ai/confidential-inference/{image}",
            pushed_digest=digest,
            reproducibility_digest=digest,
            source_commit="b" * 40,
            release_version="v0.14.0-staging",
        )

    def test_record_proves_the_pushed_digest(self):
        value = self.record()
        self.assertEqual(value["images"][0]["pushedDigest"], value["images"][0]["reproducibilityDigest"])
        MODULE.validate(value)

    def test_record_rejects_a_different_pushed_digest(self):
        with self.assertRaisesRegex(MODULE.PublicationError, "differs"):
            MODULE.record(
                image="ghcr.io/confidential-dot-ai/confidential-inference/gateway",
                pushed_digest="sha256:" + "a" * 64,
                reproducibility_digest="sha256:" + "c" * 64,
                source_commit="b" * 40,
                release_version="v0.14.0",
            )

    def test_merge_requires_the_exact_selected_image_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = []
            for name, character in (("gateway", "a"), ("sglang", "c")):
                path = root / f"{name}.json"
                path.write_text(json.dumps(self.record(name, "sha256:" + character * 64)))
                records.append(path)
            merged = MODULE.merge(records, ["gateway", "sglang"])
            self.assertEqual(
                [entry["name"] for entry in merged["images"]],
                [
                    "ghcr.io/confidential-dot-ai/confidential-inference/gateway",
                    "ghcr.io/confidential-dot-ai/confidential-inference/sglang",
                ],
            )
            with self.assertRaisesRegex(MODULE.PublicationError, "image set"):
                MODULE.merge(records, ["gateway"])

    def test_workflows_bind_publication_to_reproducibility_and_signing(self):
        images = (ROOT / ".github/workflows/release-images.yml").read_text()
        bundle = (ROOT / ".github/workflows/release-bundle.yml").read_text()
        self.assertIn("needs: [select-images, reproducibility, reproducibility-sglang-compare]", images)
        self.assertIn("--reproducibility-digest", images)
        self.assertIn("--pushed-digest", images)
        self.assertIn("release-image-publication-${{ needs.select-images.outputs.production_version }}", images)
        self.assertIn("release-image-publication-${{ needs.select-images.outputs.staging_version }}", images)
        self.assertIn("--source-commit \"$image_source_commit\"", bundle)
        self.assertIn("scripts/find-image-publication-run.py", bundle)
        self.assertIn("--image-publication dist/image-publication-manifest.json", bundle)
        self.assertIn("dist/image-publication-manifest.json#Image publication evidence", bundle)

    def test_publication_schema_is_valid(self):
        import jsonschema
        schema = json.loads((ROOT / "contracts/image-publication-manifest.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)


class PublicationRunLookupTests(unittest.TestCase):
    def test_only_a_successful_release_workflow_on_main_is_accepted(self):
        def response(url, _token):
            if "actions/artifacts" in url:
                return {"artifacts": [{
                    "name": "release-image-publication-v0.14.0",
                    "expired": False,
                    "workflow_run": {"id": 73},
                }]}
            return {
                "event": "workflow_dispatch",
                "path": ".github/workflows/release-images.yml",
                "conclusion": "success",
                "head_branch": "main",
                "head_sha": "b" * 40,
                "repository": {"full_name": "confidential-dot-ai/confidential-inference"},
            }
        original = FINDER.request_json
        FINDER.request_json = response
        try:
            self.assertEqual(FINDER.find_run(
                "https://api.github.test",
                "confidential-dot-ai/confidential-inference",
                "token",
                "release-image-publication-v0.14.0",
                "b" * 40,
            ), 73)
        finally:
            FINDER.request_json = original

    def test_duplicate_publication_runs_fail_closed(self):
        def response(url, _token):
            if "actions/artifacts" in url:
                return {"artifacts": [
                    {"name": "release-image-publication-v0.14.0", "expired": False,
                     "workflow_run": {"id": 73}},
                    {"name": "release-image-publication-v0.14.0", "expired": False,
                     "workflow_run": {"id": 74}},
                ]}
            return {
                "event": "workflow_dispatch",
                "path": ".github/workflows/release-images.yml",
                "conclusion": "success",
                "head_branch": "main",
                "head_sha": "b" * 40,
                "repository": {"full_name": "confidential-dot-ai/confidential-inference"},
            }
        original = FINDER.request_json
        FINDER.request_json = response
        try:
            with self.assertRaisesRegex(FINDER.LookupError, "expected one"):
                FINDER.find_run(
                    "https://api.github.test",
                    "confidential-dot-ai/confidential-inference",
                    "token",
                    "release-image-publication-v0.14.0",
                    "b" * 40,
                )
        finally:
            FINDER.request_json = original

    def test_stale_same_version_run_is_ignored(self):
        def response(url, _token):
            if "actions/artifacts" in url:
                return {"artifacts": [
                    {"name": "release-image-publication-v0.14.0", "expired": False,
                     "workflow_run": {"id": 72}},
                    {"name": "release-image-publication-v0.14.0", "expired": False,
                     "workflow_run": {"id": 73}},
                ]}
            run_id = int(url.rsplit("/", 1)[-1])
            return {
                "event": "workflow_dispatch",
                "path": ".github/workflows/release-images.yml",
                "conclusion": "success",
                "head_branch": "main",
                "head_sha": ("a" if run_id == 72 else "b") * 40,
                "repository": {"full_name": "confidential-dot-ai/confidential-inference"},
            }
        original = FINDER.request_json
        FINDER.request_json = response
        try:
            self.assertEqual(FINDER.find_run(
                "https://api.github.test",
                "confidential-dot-ai/confidential-inference",
                "token",
                "release-image-publication-v0.14.0",
                "b" * 40,
            ), 73)
        finally:
            FINDER.request_json = original

    def test_one_run_can_own_normal_and_staging_artifacts(self):
        def response(url, _token):
            if "actions/artifacts" in url:
                name = "release-image-publication-v0.14.0-staging" if "staging" in url else \
                    "release-image-publication-v0.14.0"
                return {"artifacts": [{
                    "name": name, "expired": False, "workflow_run": {"id": 73},
                }]}
            return {
                "event": "workflow_dispatch",
                "path": ".github/workflows/release-images.yml",
                "conclusion": "success",
                "head_branch": "main",
                "head_sha": "b" * 40,
                "repository": {"full_name": "confidential-dot-ai/confidential-inference"},
            }
        original = FINDER.request_json
        FINDER.request_json = response
        try:
            for version in ("v0.14.0", "v0.14.0-staging"):
                self.assertEqual(FINDER.find_run(
                    "https://api.github.test",
                    "confidential-dot-ai/confidential-inference",
                    "token",
                    f"release-image-publication-{version}",
                    "b" * 40,
                ), 73)
        finally:
            FINDER.request_json = original


if __name__ == "__main__":
    unittest.main()
