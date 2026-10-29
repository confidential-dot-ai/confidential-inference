#!/usr/bin/env python3
"""Focused tests for the draft DeepSeek-V4.1 prefill/decode worker image recipe."""

from __future__ import annotations

import hashlib
import json
import re
import runpy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RECIPE = ROOT / "images" / "sglang-dsv41"
LOCK = json.loads((RECIPE / "source.lock").read_text(encoding="utf-8"))
DOCKERFILE = (RECIPE / "Dockerfile").read_text(encoding="utf-8")
REQUIREMENTS = (RECIPE / "requirements.lock").read_text(encoding="utf-8")
fetch_source = runpy.run_path(str(RECIPE / "fetch_source.py"))
affected = runpy.run_path(str(ROOT / "scripts" / "affected-release-images.py"))


def instructions() -> list[str]:
    """Dockerfile instructions with continuation lines joined."""
    joined = re.sub(r"\\\n\s*", " ", DOCKERFILE)
    return [line.strip() for line in joined.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def labels() -> dict[str, str]:
    found = {}
    for line in instructions():
        match = re.fullmatch(r'LABEL (\S+)="([^"]*)"', line)
        if match:
            found[match.group(1)] = match.group(2)
    return found


class DraftRecipeTests(unittest.TestCase):
    def test_base_images_are_the_locked_amd64_digests(self) -> None:
        from_lines = [line for line in instructions() if line.startswith("FROM ")]
        self.assertEqual(
            [
                f"FROM {LOCK['uv']['reference']}@{LOCK['uv']['digest']} AS uv",
                f"FROM {LOCK['image']['reference']}@{LOCK['image']['digest']} AS base",
                "FROM base AS source",
                "FROM base",
            ],
            from_lines,
        )
        for pin in (LOCK["uv"], LOCK["image"]):
            self.assertRegex(pin["digest"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(pin["indexDigest"], r"^sha256:[0-9a-f]{64}$")

    def test_labels_mirror_the_lock(self) -> None:
        found = labels()
        expected = {
            "org.opencontainers.image.base.name": LOCK["image"]["reference"],
            "org.opencontainers.image.base.digest": LOCK["image"]["digest"],
            "ai.confidential.sglang.source": LOCK["source"]["repository"],
            "ai.confidential.sglang.revision": LOCK["source"]["commit"],
            "ai.confidential.upstream.source": LOCK["source"]["upstream"]["repository"],
            "ai.confidential.upstream.revision": LOCK["source"]["upstream"]["commit"],
            "ai.confidential.ubuntu.snapshot": LOCK["ubuntuSnapshot"],
            "ai.confidential.python.requirements.sha256": LOCK["python"]["requirementsLockSha256"],
            "ai.confidential.uv.digest": LOCK["uv"]["digest"],
        }
        for name, value in expected.items():
            self.assertEqual(value, found.get(name), name)
        self.assertFalse([name for name in found if "patch" in name])
        self.assertNotIn("org.opencontainers.image.created", DOCKERFILE)

    def test_apt_reads_only_the_locked_snapshot(self) -> None:
        self.assertRegex(LOCK["ubuntuSnapshot"], r"^\d{8}T\d{6}Z$")
        self.assertIn(f"https://snapshot.ubuntu.com/ubuntu/{LOCK['ubuntuSnapshot']} %s main universe", DOCKERFILE)
        commands = re.findall(r"apt-get[^&]*", " ".join(instructions()))
        self.assertEqual(2, len(commands))
        for command in commands:
            self.assertIn("-o Dir::Etc::SourceList=/tmp/snapshot.list -o Dir::Etc::SourceParts=/dev/null", command)
        install = commands[1].split("--no-install-recommends", 1)[1].split()
        self.assertEqual(LOCK["aptPackages"], install)

    def test_python_environment_is_installed_by_hash(self) -> None:
        self.assertEqual(LOCK["python"]["requirementsLockSha256"], hashlib.sha256(REQUIREMENTS.encode()).hexdigest())
        self.assertIn("uv pip install --no-deps --require-hashes -r /inputs/recipe/requirements.lock", " ".join(instructions()))
        entries = re.split(r"\n(?=\S)", re.sub(r"(?m)^#.*\n", "", REQUIREMENTS).strip())
        self.assertGreater(len(entries), 200)
        for entry in entries:
            pin, *hashes = [part.strip() for part in entry.split("\\\n")]
            # flashinfer-cubin is not on PyPI: a pinned release URL.
            self.assertRegex(pin, r"^[A-Za-z0-9_.\-]+(==[A-Za-z0-9_.+\-!]+| @ https://github\.com/flashinfer-ai/flashinfer/releases/download/\S+\.whl)$")
            self.assertTrue(hashes, pin)
            for value in hashes:
                self.assertRegex(value, r"^--hash=sha256:[0-9a-f]{64}$")

    def test_no_baked_cache_entrypoint_or_root_runtime(self) -> None:
        lines = instructions()
        used = {line.split(maxsplit=1)[0] for line in lines}
        self.assertTrue({"ADD", "CMD", "ENTRYPOINT"}.isdisjoint(used))
        self.assertEqual("USER 1001:1001", lines[-1])
        # Only the uv binary, the fork's source and the holder script are copied in.
        self.assertEqual(
            [
                "COPY --from=uv /uv /usr/local/bin/uv",
                "COPY --from=source /src/python /opt/sglang/python",
                "COPY --from=source /src/recipes/deepseek-v41/launcher/hold_engram_cache.py "
                "/opt/sglang/recipes/deepseek-v41/launcher/hold_engram_cache.py",
                "COPY --from=source /src/SOURCE_RECORD.json /opt/sglang/SOURCE_RECORD.json",
            ],
            [line for line in lines if line.startswith("COPY")],
        )
        self.assertIn("UV_NO_CACHE=1", DOCKERFILE)
        self.assertNotIn("type=cache", DOCKERFILE)

    def test_source_is_one_pinned_commit_of_the_fork(self) -> None:
        source = LOCK["source"]
        self.assertEqual("https://github.com/confidential-dot-ai/Sglang-public", source["repository"])
        self.assertRegex(source["commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(source["upstream"]["commit"], r"^[0-9a-f]{40}$")
        self.assertNotIn("patches", source)
        fetch_source["check_lock"](LOCK)
        # The fork is public: the fetch takes no credentials.
        self.assertNotIn("type=secret", DOCKERFILE)
        self.assertNotIn("sglang_source_token", (RECIPE / "fetch_source.py").read_text(encoding="utf-8"))
        self.assertIn("python3.12 -I /inputs/recipe/fetch_source.py --recipe /inputs/recipe --out /src", " ".join(instructions()))

    def test_draft_stays_out_of_release_builds(self) -> None:
        # Registering the image ends the draft: drop the status and this test then.
        self.assertEqual("draft", LOCK["status"])
        self.assertNotIn("sglang-dsv41", {image.image for image in affected["IMAGES"]})

    def test_wait_for_model_is_the_public_worker_gate(self) -> None:
        self.assertIn("source=images/sglang/wait_for_model.py,target=/run-src/wait-for-model", DOCKERFILE)
        ignore = (RECIPE / "Dockerfile.dockerignore").read_text(encoding="utf-8")
        self.assertIn("!images/sglang/wait_for_model.py", ignore)

    def test_build_removes_non_serving_http_routes(self) -> None:
        self.assertIn("source=images/sglang/harden_http.py,target=/run-src/harden-http.py", DOCKERFILE)
        self.assertIn("python /run-src/harden-http.py --root /opt/sglang/python/sglang --variant pd", DOCKERFILE)
        ignore = (RECIPE / "Dockerfile.dockerignore").read_text(encoding="utf-8")
        self.assertIn("!images/sglang/harden_http.py", ignore)


class FetchSourceLockTests(unittest.TestCase):
    """fetch_source.py refuses a source that is not one pinned commit, before any fetch."""

    def lock(self, **source: object) -> dict:
        pinned = {"repository": "https://github.com/confidential-dot-ai/Sglang-public", "commit": "a" * 40}
        return {"source": {**pinned, **source}}

    def test_a_pinned_commit_is_accepted(self) -> None:
        fetch_source["check_lock"](self.lock())

    def test_a_moving_reference_is_refused(self) -> None:
        with self.assertRaisesRegex(fetch_source["LockError"], "40-hex"):
            fetch_source["check_lock"](self.lock(commit="main"))

    def test_a_repository_off_github_is_refused(self) -> None:
        with self.assertRaisesRegex(fetch_source["LockError"], "github.com"):
            fetch_source["check_lock"](self.lock(repository="https://example.com/sglang"))

    def test_patches_are_refused(self) -> None:
        with self.assertRaisesRegex(fetch_source["LockError"], "patches"):
            fetch_source["check_lock"](self.lock(patches=[{"path": "patches/dsv41.patch", "sha256": "0" * 64}]))


if __name__ == "__main__":
    unittest.main()
