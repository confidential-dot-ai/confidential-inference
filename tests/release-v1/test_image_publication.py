from __future__ import annotations

import importlib.util
import json
import subprocess
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
            base_ref="v0.13.28-rc.2",
            base_ref_commit="c" * 40,
        )

    def test_record_proves_the_pushed_digest(self):
        value = self.record()
        self.assertEqual(value["images"][0], {
            "name": "ghcr.io/confidential-dot-ai/confidential-inference/gateway",
            "digest": "sha256:" + "a" * 64,
        })
        self.assertNotIn("releaseVersion", value)
        MODULE.validate(value)

    def test_record_rejects_a_different_pushed_digest(self):
        with self.assertRaisesRegex(MODULE.PublicationError, "differs"):
            MODULE.record(
                image="ghcr.io/confidential-dot-ai/confidential-inference/gateway",
                pushed_digest="sha256:" + "a" * 64,
                reproducibility_digest="sha256:" + "c" * 64,
                source_commit="b" * 40,
                base_ref="v0.13.28-rc.2",
                base_ref_commit="c" * 40,
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
        self.assertIn("needs: [select-images, reproducibility]\n", images)
        self.assertIn("needs: [select-images, reproducibility-sglang-compare]\n", images)
        self.assertIn("needs: [select-images, publish-standard, publish-sglang]\n", images)
        self.assertEqual(images.count("--reproducibility-digest"), 2)
        self.assertEqual(images.count("--pushed-digest"), 2)
        self.assertIn("name: release-image-publication-${{ github.sha }}", images)
        self.assertNotIn("inputs.release_version", images)
        self.assertIn('--release-commit "$(git rev-parse HEAD)" \\\n            --tag "$RELEASE_TAG" >> "$GITHUB_OUTPUT"', bundle)
        self.assertIn("scripts/find-image-publication-run.py", bundle)
        self.assertIn("name: ${{ steps.publication.outputs.artifact_name }}", bundle)
        self.assertIn("run-id: ${{ steps.publication.outputs.run_id }}", bundle)
        self.assertIn("--image-publication dist/image-publication-manifest.json", bundle)
        self.assertIn("dist/image-publication-manifest.json#Image publication evidence", bundle)
        self.assertIn("dist/allowlist.json#c8s allowlist", bundle)
        self.assertIn("dist/release-values.yaml#Release image values", bundle)
        self.assertNotIn("--base-release", bundle)
        build = bundle[bundle.index("- name: Build the release at the tag commit"):]
        self.assertIn("GH_TOKEN: ${{ github.token }}", build[:build.index("run: |")])

    def test_standard_images_publish_the_audited_archive(self):
        images = (ROOT / ".github/workflows/release-images.yml").read_text()
        standard = images[images.index("  publish-standard:"):images.index("  publish-sglang:")]
        self.assertIn("name: release-oci-${{ matrix.image }}", standard)
        self.assertIn("crane push /tmp/layout", standard)
        self.assertIn("sha256sum --check --strict", standard)
        self.assertNotIn("docker/build-push-action", standard)
        self.assertNotIn("reproducibility-sglang", standard)

    def test_publication_schema_is_valid(self):
        import jsonschema
        schema = json.loads((ROOT / "contracts/image-publication-manifest.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)


def run_response(runs: dict[int, str], artifacts: dict[str, list[int]], tag_message: str | None = None):
    """A GitHub API stub: successful release-images runs on main by id and head commit.

    With tag_message, the release tag is annotated with that message.
    """
    def response(url, _token):
        if "/git/ref/tags/" in url:
            return {"object": {"type": "tag" if tag_message is not None else "commit", "sha": "1" * 40}}
        if "/git/tags/" in url:
            return {"message": tag_message}
        if "actions/artifacts" in url:
            name = url.split("name=", 1)[1].split("&", 1)[0]
            return {"artifacts": [
                {"name": name, "expired": False, "workflow_run": {"id": run_id}}
                for run_id in artifacts.get(name, [])
            ]}
        run_id = int(url.rsplit("/", 1)[-1])
        return {
            "event": "workflow_dispatch",
            "path": ".github/workflows/release-images.yml",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": runs[run_id],
            "repository": {"full_name": "confidential-dot-ai/confidential-inference"},
        }
    return response


class PublicationRunLookupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Test")
        # image: changes the gateway; docs: changes no image.
        self.image = self.commit("images/gateway/Dockerfile", "FROM scratch\n")
        self.docs = self.commit("docs/notes.md", "notes\n")
        self.head = self.commit("docs/notes.md", "more notes\n")
        self.original = FINDER.request_json

    def tearDown(self):
        FINDER.request_json = self.original
        self.temporary.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def commit(self, path: str, text: str) -> str:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        self.git("add", ".")
        self.git("commit", "-qm", path)
        return self.git("rev-parse", "HEAD")

    def find(self, runs, artifacts):
        FINDER.request_json = run_response(runs, artifacts)
        return FINDER.find_nearest("https://api.github.test", "confidential-dot-ai/confidential-inference",
                                   "token", self.head, self.repo)

    def test_the_release_commit_uses_its_own_evidence(self):
        name = FINDER.artifact_name(self.head)
        self.assertEqual(self.find({73: self.head}, {name: [73]}), (self.head, 73))

    def test_a_later_commit_without_image_changes_uses_the_earlier_evidence(self):
        name = FINDER.artifact_name(self.image)
        self.assertEqual(self.find({73: self.image}, {name: [73]}), (self.image, 73))

    def test_the_walk_stops_at_an_image_change_without_evidence(self):
        with self.assertRaisesRegex(FINDER.LookupError, "changes an image build input"):
            self.find({}, {})

    def test_duplicate_publication_runs_fail_closed(self):
        name = FINDER.artifact_name(self.docs)
        with self.assertRaisesRegex(FINDER.LookupError, "more than one"):
            self.find({73: self.docs, 74: self.docs}, {name: [73, 74]})

    def named(self, runs, artifacts, message):
        FINDER.request_json = run_response(runs, artifacts, message)
        api, repository = "https://api.github.test", "confidential-dot-ai/confidential-inference"
        selected = FINDER.named_run(api, repository, "token", "v0.14.6-staging")
        return FINDER.find_nearest(api, repository, "token", self.head, self.repo, selected_run=selected)

    def test_the_tag_selects_one_of_duplicate_runs(self):
        # Staging run 37609539592: a run by hand and a staging run of one
        # commit, with other bases.
        name = FINDER.artifact_name(self.docs)
        message = "Release v0.14.6-staging\n\nImage-Publication-Run: 74\n"
        self.assertEqual(self.named({73: self.docs, 74: self.docs}, {name: [73, 74]}, message), (self.docs, 74))

    def test_the_tag_cannot_name_an_untrusted_run(self):
        name = FINDER.artifact_name(self.docs)
        for runs, artifacts in (({73: self.docs, 74: self.docs}, {name: [73, 74]}),
                                ({73: self.docs, 75: self.image}, {name: [73, 75]})):
            with self.subTest(runs=runs), self.assertRaisesRegex(FINDER.LookupError, "not a trusted"):
                self.named(runs, artifacts, "Release\n\nImage-Publication-Run: 75\n")

    def test_a_tag_without_the_trailer_keeps_duplicates_closed(self):
        name = FINDER.artifact_name(self.docs)
        for message in ("Release v0.14.6-staging", None):
            with self.subTest(message=message), self.assertRaisesRegex(FINDER.LookupError, "more than one"):
                self.named({73: self.docs, 74: self.docs}, {name: [73, 74]}, message)

    def test_a_tag_that_names_two_runs_is_refused(self):
        with self.assertRaisesRegex(FINDER.LookupError, "more than one image publication run"):
            self.named({}, {}, "Release\n\nImage-Publication-Run: 73\nImage-Publication-Run: 74\n")

    def test_a_run_at_another_commit_is_ignored(self):
        name = FINDER.artifact_name(self.head)
        self.assertEqual(self.find({72: self.docs, 73: self.head}, {name: [72, 73]}), (self.head, 73))


if __name__ == "__main__":
    unittest.main()
