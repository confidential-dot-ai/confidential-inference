#!/usr/bin/env python3
"""The Qwen3.5-0.8B staging image is the production image plus one weights layer."""

from __future__ import annotations

import hashlib
import json
import re
import runpy
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PRODUCTION_RECIPE = ROOT / "images/sglang-dsv41-flash"
PRODUCTION = (PRODUCTION_RECIPE / "Dockerfile").read_text(encoding="utf-8")
PRODUCTION_IGNORE = (PRODUCTION_RECIPE / "Dockerfile.dockerignore").read_text(encoding="utf-8")
RECIPE = ROOT / "images/sglang-qwen35-0.8b"
DOCKERFILE = (RECIPE / "Dockerfile").read_text(encoding="utf-8")
IGNORE = (RECIPE / "Dockerfile.dockerignore").read_text(encoding="utf-8")
affected = runpy.run_path(str(ROOT / "scripts" / "affected-release-images.py"))

REPOSITORY = "Qwen/Qwen3.5-0.8B"
REVISION = "2fc06364715b967f1860aea9cf38778875588b17"
MANIFEST_SHA256 = "625963f6a7f159fd2a3e8ad97642a11ac275d1735adaadca8df39452b9fbd8fa"
MODEL_PATH = "/opt/confidential-inference/models/qwen35-0.8b"
BEGIN = "# ---- begin images/sglang-dsv41-flash/Dockerfile (verbatim) ----\n"
END = "# ---- end images/sglang-dsv41-flash/Dockerfile ----\n"

# Model weights and tokenizer blobs are build-time downloads, never Git files.
WEIGHT_SUFFIXES = (".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".gguf", ".onnx", ".msgpack", ".h5", ".npz")
LARGE_FILE_BYTES = 1024 * 1024


def staging_stage() -> str:
    return DOCKERFILE[DOCKERFILE.index(END) + len(END):]


def instructions(text: str) -> list[str]:
    joined = re.sub(r"\\\n\s*", " ", text)
    return [line.strip() for line in joined.splitlines() if line.strip() and not line.startswith("#")]


def lfs_tracked_paths() -> list[str]:
    """Tracked files whose Git attributes name the LFS filter."""
    output = subprocess.run(["git", "-C", str(ROOT), "check-attr", "--stdin", "-z", "filter"],
                            input="\0".join(tracked_files()), capture_output=True, text=True, check=True).stdout
    fields = output.split("\0")
    return [fields[i] for i in range(0, len(fields) - 2, 3) if fields[i + 2] == "lfs"]


def tracked_files() -> list[str]:
    listing = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout
    return [name for name in listing.decode().split("\0") if name]


class Qwen35RecipeTests(unittest.TestCase):
    def test_production_dockerfile_is_held_verbatim(self) -> None:
        self.assertEqual(1, DOCKERFILE.count(BEGIN))
        self.assertEqual(1, DOCKERFILE.count(END))
        held = DOCKERFILE[DOCKERFILE.index(BEGIN) + len(BEGIN):DOCKERFILE.index(END)]
        self.assertEqual(PRODUCTION, held)
        # Nothing but comments before the copy: every engine instruction is production's.
        self.assertEqual([], instructions(DOCKERFILE[:DOCKERFILE.index(BEGIN)]))

    def test_staging_stage_is_one_layer_from_the_production_stage(self) -> None:
        self.assertIn("\nFROM base AS engine\n", PRODUCTION)
        lines = instructions(staging_stage())
        self.assertEqual("FROM engine AS qwen35-0.8b", lines[0])
        self.assertEqual("USER 0:0", lines[1])
        self.assertEqual("USER 1001:1001", lines[-1])
        kinds = [line.split()[0] for line in lines]
        # One filesystem layer: one RUN, and no COPY or ADD. LABEL and USER only set the config.
        self.assertEqual(1, kinds.count("RUN"))
        self.assertTrue({"COPY", "ADD", "CMD", "ENTRYPOINT", "FROM"}.isdisjoint(kinds[1:]))
        self.assertEqual({"USER", "RUN", "LABEL"}, set(kinds[1:]))

    def test_weights_are_fetched_against_the_pinned_manifest(self) -> None:
        run = next(line for line in instructions(staging_stage()) if line.startswith("RUN "))
        self.assertIn("/usr/local/bin/fetch-model fetch", run)
        self.assertIn(f'--path="$models/qwen35-0.8b"', run)
        self.assertIn("models=/opt/confidential-inference/models", run)
        self.assertIn("--manifest=/run-src/model-manifest.json", run)
        self.assertIn(f"--manifest-sha256={MANIFEST_SHA256}", run)
        self.assertIn("--revision-metadata=.model-lock-local-manifest.json", run)
        self.assertIn("source=images/sglang-qwen35-0.8b/model-manifest.json", run)
        # The production image installs the fetch-model it runs.
        self.assertIn("install -D -m 0555 /run-src/fetch-model /usr/local/bin/fetch-model", PRODUCTION)

    def test_weights_layer_has_fixed_owner_modes_and_times(self) -> None:
        run = next(line for line in instructions(staging_stage()) if line.startswith("RUN "))
        for step in ('chown -R 0:0 "$models"', 'find "$models" -type d -exec chmod 0555 {} +',
                     'find "$models" -type f -exec chmod 0444 {} +', 'find "$models" -exec touch -h -d @0 {} +',
                     "--mount=type=tmpfs,target=/tmp"):
            self.assertIn(step, run)
        # The ownership and times run after every file is written.
        self.assertLess(run.index("fetch-model fetch"), run.index("chown -R"))
        self.assertLess(run.index("install -D -m 0555 /run-src/serve.sh"), run.index("touch -h -d @0 /opt"))

    def test_build_context_is_production_context_plus_this_recipe(self) -> None:
        production = [line for line in PRODUCTION_IGNORE.splitlines() if line and not line.startswith("#")]
        recipe = [line for line in IGNORE.splitlines() if line and not line.startswith("#")]
        self.assertEqual(production, recipe[:len(production)])
        self.assertEqual(["!images/sglang-qwen35-0.8b/Dockerfile", "!images/sglang-qwen35-0.8b/model-manifest.json",
                          "!images/sglang-qwen35-0.8b/serve.sh"], recipe[len(production):])
        for source in re.findall(r"source=(images/sglang-qwen35-0.8b/[^,\s]+)", DOCKERFILE):
            self.assertIn(f"!{source}", IGNORE)

    def test_model_manifest_is_the_pinned_revision(self) -> None:
        data = (RECIPE / "model-manifest.json").read_bytes()
        self.assertEqual(MANIFEST_SHA256, hashlib.sha256(data).hexdigest())
        manifest = json.loads(data)
        self.assertEqual(f"{REPOSITORY}@{REVISION}", manifest["immutable_ref"])
        self.assertIn(f'LABEL ai.confidential.model.manifest.sha256="{MANIFEST_SHA256}"', DOCKERFILE)
        self.assertIn(f'LABEL ai.confidential.model.revision="{REVISION}"', DOCKERFILE)
        self.assertIn(f'LABEL ai.confidential.model.path="{MODEL_PATH}"', DOCKERFILE)
        serve = (RECIPE / "serve.sh").read_text(encoding="utf-8")
        self.assertIn(f"MANIFEST_SHA256={MANIFEST_SHA256}", serve)
        self.assertIn(f"REVISION={REVISION}", serve)
        self.assertIn(f"MODEL_PATH=${{MODEL_PATH:-{MODEL_PATH}}}", serve)
        files = {entry["path"]: entry["content_sha256"] for entry in manifest["files"]}
        self.assertIn(f"CONFIG_SHA256={files['config.json']}", serve)
        self.assertIn(f"TOKENIZER_CONFIG_SHA256={files['tokenizer_config.json']}", serve)

    def test_serve_helper_verifies_the_image_files(self) -> None:
        serve = (RECIPE / "serve.sh").read_text(encoding="utf-8")
        self.assertIn("--image-files", serve)
        self.assertNotIn("--plain-cache", serve)
        self.assertNotIn("fetch-model", serve)
        argv = subprocess.run(["bash", str(RECIPE / "serve.sh"), "args"], check=True,
                              capture_output=True, text=True).stdout.split()
        self.assertIn(f"--model-path={MODEL_PATH}", argv)
        self.assertIn("--tool-call-parser=qwen3_coder", argv)
        self.assertIn("--tp=1", argv)

    def test_release_build_tracks_every_input(self) -> None:
        image = next(i for i in affected["IMAGES"] if i.image == "sglang-qwen35-0.8b")
        self.assertEqual("Confidential Inference SGLang Qwen3.5-0.8B staging", image.title)
        self.assertIn(f'LABEL org.opencontainers.image.title="{image.title}"', DOCKERFILE)
        self.assertIn("sglang-qwen35-0.8b", affected["LARGE_IMAGES"])
        production = next(i for i in affected["IMAGES"] if i.image == "sglang-dsv41-flash")
        # A change to any production input rebuilds both images.
        self.assertTrue(set(production.paths) <= set(image.paths))
        for path in ("images/sglang-dsv41-flash/wait_for_model.py", "images/sglang-dsv41-flash/dcgm-counters.csv",
                     "images/sglang-dsv41-flash/simulator-upstream/src/usercustomize.py",
                     "images/sglang-dsv41-flash/Dockerfile"):
            self.assertEqual(["sglang-dsv41-flash", "sglang-qwen35-0.8b"],
                             [i.image for i in affected["affected_images"]([path])], path)
        for path in ("images/sglang-qwen35-0.8b/Dockerfile", "images/sglang-qwen35-0.8b/Dockerfile.dockerignore",
                     "images/sglang-qwen35-0.8b/model-manifest.json", "images/sglang-qwen35-0.8b/serve.sh"):
            self.assertEqual(["sglang-qwen35-0.8b"], [i.image for i in affected["affected_images"]([path])], path)
        for line in IGNORE.splitlines():
            if line.startswith("!images/sglang-qwen35-0.8b/"):
                self.assertIn(line[1:], image.paths)

    def test_recipe_holds_only_build_inputs(self) -> None:
        names = sorted(path.name for path in RECIPE.iterdir())
        self.assertEqual(["Dockerfile", "Dockerfile.dockerignore", "README.md", "build.sh",
                          "model-manifest.json", "serve.sh"], names)


class NoModelWeightsInGitTests(unittest.TestCase):
    """The repository holds the byte manifest of a model, never its files (no Git LFS either)."""

    def test_no_weight_file_is_tracked(self) -> None:
        weights = [name for name in tracked_files() if name.lower().endswith(WEIGHT_SUFFIXES)]
        self.assertEqual([], weights)

    def test_no_large_model_file_is_tracked(self) -> None:
        manifest = json.loads((RECIPE / "model-manifest.json").read_bytes())
        model_names = {Path(entry["path"]).name for entry in manifest["files"]}
        model_digests = {entry["content_sha256"] for entry in manifest["files"] if entry["size"] > LARGE_FILE_BYTES}
        found = []
        for name in tracked_files():
            path = ROOT / name
            if not path.is_file() or path.is_symlink():
                continue
            size = path.stat().st_size
            tokenizer = Path(name).name.startswith(("tokenizer", "vocab", "merges")) or Path(name).name in model_names
            if size > LARGE_FILE_BYTES and (tokenizer or hashlib.sha256(path.read_bytes()).hexdigest() in model_digests):
                found.append(name)
        self.assertEqual([], found)

    def test_no_git_lfs(self) -> None:
        self.assertEqual([], lfs_tracked_paths())
        for name in tracked_files():
            if Path(name).name == ".gitattributes":
                self.assertNotIn("lfs", (ROOT / name).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
