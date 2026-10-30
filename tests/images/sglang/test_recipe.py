#!/usr/bin/env python3
"""Focused tests for the DeepSeek-V4.1 prefill/decode worker image recipe."""

from __future__ import annotations

import hashlib
import json
import re
import runpy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RECIPE = ROOT / "images" / "sglang"
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


class RecipeTests(unittest.TestCase):
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

    def test_release_build_tracks_all_worker_inputs(self) -> None:
        self.assertNotIn("status", LOCK)
        self.assertEqual("ghcr.io/confidential-dot-ai/confidential-inference/sglang", LOCK["deploymentImage"]["reference"])
        for path in ("images/sglang/Dockerfile", "images/sglang/source.lock",
                     "images/sglang/requirements.lock", "images/sglang/fetch_source.py",
                     "images/sglang/simulator-upstream/src/usercustomize.py",
                     "images/sglang/harden_http.py", "images/sglang/wait_for_model.py"):
            self.assertIn("sglang", {i.image for i in affected["affected_images"]([path])})

    def test_staging_simulator_source_and_patches_are_pinned(self) -> None:
        simulator = LOCK["simulator"]
        found = labels()
        self.assertEqual(simulator["commit"], found["ai.confidential.sglang.simulator.revision"])
        self.assertEqual(simulator["patch"]["sha256"], found["ai.confidential.sglang.simulator.patch.sha256"])
        self.assertEqual(simulator["parserFlagsNoopPatch"]["sha256"],
                         found["ai.confidential.sglang.simulator.parser-flags-noop-patch.sha256"])
        self.assertEqual(simulator["prefixLengthPatch"]["sha256"],
                         found["ai.confidential.sglang.simulator.prefix-length-patch.sha256"])
        source = ROOT / simulator["path"]
        files = sorted(path for path in source.rglob("*")
                       if path.is_file() and path.name not in {"UPSTREAM.md", "LICENSE"})
        content = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
                          f"{path.relative_to(source).as_posix()}\n" for path in files).encode()
        self.assertEqual(simulator["contentSha256"], hashlib.sha256(content).hexdigest())
        for key in ("patch", "parserFlagsNoopPatch", "prefixLengthPatch"):
            patch = ROOT / simulator[key]["path"]
            self.assertEqual(simulator[key]["sha256"], hashlib.sha256(patch.read_bytes()).hexdigest())
            self.assertIn(f"git apply --check /run-src/patches/{patch.name}", DOCKERFILE)
        self.assertIn("/opt/confidential-inference/sglang-simulator", DOCKERFILE)
        # Production uses its existing environment; staging opts into the simulator.
        self.assertNotRegex(DOCKERFILE, r"(?m)^ENV PYTHONPATH=")

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
