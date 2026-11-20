#!/usr/bin/env python3
"""The repository holds the byte manifest of a model, never its files (no Git LFS either).

A worker gets its model from a model server (inference.model.download) or a
C8s model volume, never from Git and never from the engine image.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
# The byte manifests of the model recipes in the deployment values layers.
MANIFESTS = (ROOT / "tests/fixtures/deployments/qwen35-0.8b-model-manifest.json",)
WEIGHT_SUFFIXES = (".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".gguf", ".onnx", ".msgpack", ".h5", ".npz")
LARGE_FILE_BYTES = 1024 * 1024


def tracked_files() -> list[str]:
    listing = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout
    return [name for name in listing.decode().split("\0") if name]


def lfs_tracked_paths() -> list[str]:
    """Tracked files whose Git attributes name the LFS filter."""
    output = subprocess.run(["git", "-C", str(ROOT), "check-attr", "--stdin", "-z", "filter"],
                            input="\0".join(tracked_files()), capture_output=True, text=True, check=True).stdout
    fields = output.split("\0")
    return [fields[i] for i in range(0, len(fields) - 2, 3) if fields[i + 2] == "lfs"]


class NoModelWeightsInGitTests(unittest.TestCase):
    def test_no_weight_file_is_tracked(self) -> None:
        weights = [name for name in tracked_files() if name.lower().endswith(WEIGHT_SUFFIXES)]
        self.assertEqual([], weights)

    def test_no_large_model_file_is_tracked(self) -> None:
        entries = [entry for manifest in MANIFESTS for entry in json.loads(manifest.read_bytes())["files"]]
        model_names = {Path(entry["path"]).name for entry in entries}
        model_digests = {entry["content_sha256"] for entry in entries if entry["size"] > LARGE_FILE_BYTES}
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
