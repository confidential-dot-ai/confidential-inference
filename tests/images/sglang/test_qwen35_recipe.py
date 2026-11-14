#!/usr/bin/env python3
"""The Qwen3.5-0.8B staging image runs the production worker's engine."""

from __future__ import annotations

import hashlib
import json
import re
import runpy
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PRODUCTION = (ROOT / "images/sglang/Dockerfile").read_text(encoding="utf-8")
RECIPE = ROOT / "images/sglang-qwen35"
DOCKERFILE = (RECIPE / "Dockerfile").read_text(encoding="utf-8")
IGNORE = (RECIPE / "Dockerfile.dockerignore").read_text(encoding="utf-8")
affected = runpy.run_path(str(ROOT / "scripts" / "affected-release-images.py"))

REPOSITORY = "Qwen/Qwen3.5-0.8B"
REVISION = "2fc06364715b967f1860aea9cf38778875588b17"
MANIFEST_SHA256 = "625963f6a7f159fd2a3e8ad97642a11ac275d1735adaadca8df39452b9fbd8fa"


def engine_stages(text: str) -> str:
    """From the first FROM to the final stage's FROM: the environment and source stages."""
    return text[text.index("FROM ghcr.io/astral-sh/uv@"):text.index("\nFROM base\n")]


def run_block(text: str, marker: str) -> str:
    """The RUN instruction that contains marker, with its continuation lines."""
    joined = re.sub(r"\\\n\s*", " ", text)
    return next(line.strip() for line in joined.splitlines() if line.startswith("RUN ") and marker in line)


class Qwen35RecipeTests(unittest.TestCase):
    def test_engine_stages_are_the_production_stages(self) -> None:
        self.assertEqual(engine_stages(PRODUCTION), engine_stages(DOCKERFILE))

    def test_sglang_install_and_hardening_are_the_production_step(self) -> None:
        # Every build-time hardening step of the production image (harden_*.py)
        # also runs here, on the same source.
        marker = "uv pip install --no-deps --no-build-isolation -e /opt/sglang/python"
        self.assertEqual(run_block(PRODUCTION, marker), run_block(DOCKERFILE, marker))
        self.assertEqual(run_block(PRODUCTION, "/run-dcgm/usr/bin/dcgm-exporter"),
                         run_block(DOCKERFILE, "/run-dcgm/usr/bin/dcgm-exporter"))
        for name in re.findall(r"images/sglang/(harden_\w+\.py)", PRODUCTION):
            self.assertIn(f"!images/sglang/{name}", IGNORE)

    def test_build_context_holds_every_mounted_input(self) -> None:
        for source in re.findall(r"source=(images/[^,\s]+)", DOCKERFILE):
            if source == "images/sglang":
                for name in ("source.lock", "requirements.lock", "fetch_source.py"):
                    self.assertIn(f"!images/sglang/{name}", IGNORE)
            else:
                self.assertIn(f"!{source}", IGNORE)

    def test_no_simulator_entrypoint_or_root_runtime(self) -> None:
        self.assertNotIn("sglang-simulator", DOCKERFILE)
        self.assertNotIn("simulator-upstream", DOCKERFILE)
        lines = [line for line in DOCKERFILE.splitlines() if line and not line.startswith(("#", " "))]
        self.assertTrue({"ADD", "CMD", "ENTRYPOINT"}.isdisjoint(line.split()[0] for line in lines))
        self.assertEqual("USER 1001:1001", lines[-1])
        self.assertIn("ENV HOME=/tmp", lines)

    def test_model_manifest_is_the_pinned_revision(self) -> None:
        data = (RECIPE / "model-manifest.json").read_bytes()
        self.assertEqual(MANIFEST_SHA256, hashlib.sha256(data).hexdigest())
        manifest = json.loads(data)
        self.assertEqual(f"{REPOSITORY}@{REVISION}", manifest["immutable_ref"])
        self.assertIn(f'LABEL ai.confidential.model.manifest.sha256="{MANIFEST_SHA256}"', DOCKERFILE)
        self.assertIn(f'LABEL ai.confidential.model.revision="{REVISION}"', DOCKERFILE)
        serve = (RECIPE / "serve.sh").read_text(encoding="utf-8")
        self.assertIn(f"MANIFEST_SHA256={MANIFEST_SHA256}", serve)
        self.assertIn(f"REVISION={REVISION}", serve)
        files = {entry["path"]: entry["content_sha256"] for entry in manifest["files"]}
        self.assertIn(f"CONFIG_SHA256={files['config.json']}", serve)
        self.assertIn(f"TOKENIZER_CONFIG_SHA256={files['tokenizer_config.json']}", serve)

    def test_serve_helper_prints_its_argv(self) -> None:
        argv = subprocess.run(["bash", str(RECIPE / "serve.sh"), "args"], check=True,
                              capture_output=True, text=True).stdout.split()
        self.assertIn("--tool-call-parser=qwen3_coder", argv)
        self.assertIn("--tp=1", argv)

    def test_release_build_tracks_every_input(self) -> None:
        image = next(i for i in affected["IMAGES"] if i.image == "sglang-qwen35")
        self.assertEqual("Confidential Inference SGLang Qwen3.5-0.8B staging", image.title)
        self.assertIn(f'LABEL org.opencontainers.image.title="{image.title}"', DOCKERFILE)
        self.assertIn("sglang-qwen35", affected["LARGE_IMAGES"])
        mounted = set(re.findall(r"source=(images/[^,\s]+)", DOCKERFILE)) - {"images/sglang"}
        mounted |= {"images/sglang/source.lock", "images/sglang/requirements.lock", "images/sglang/fetch_source.py",
                    "images/sglang-qwen35/Dockerfile", "images/sglang-qwen35/Dockerfile.dockerignore"}
        for path in sorted(mounted):
            self.assertIn("sglang-qwen35", {i.image for i in affected["affected_images"]([path])}, path)
        # The simulator is not an input: a simulator change does not rebuild it.
        self.assertEqual(["sglang"], [i.image for i in affected["affected_images"](
            ["images/sglang/simulator-upstream/src/usercustomize.py"])])


if __name__ == "__main__":
    unittest.main()
