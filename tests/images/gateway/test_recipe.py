#!/usr/bin/env python3
"""Build contracts for the two Python gateway images."""

import importlib.util
import json
import re
import shlex
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("affected_images", ROOT / "scripts/affected-release-images.py")
selector = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = selector
spec.loader.exec_module(selector)


class GatewayImageRecipeTests(unittest.TestCase):
    def test_locked_base_and_runtime_identity(self):
        lock = json.loads((ROOT / "images/gateway/source.lock").read_text())
        for name, module in (("gateway", "gateway"), ("maintenance-gateway", "gateway.maintenance")):
            with self.subTest(image=name):
                text = (ROOT / "images" / name / "Dockerfile").read_text()
                base = re.findall(r"^FROM (.+)$", text, re.MULTILINE)
                self.assertEqual(base, [lock["runtime"]["image"] + "@" + lock["runtime"]["digest"]])
                self.assertRegex(lock["runtime"]["digest"], r"^sha256:[0-9a-f]{64}$")
                self.assertIn("USER 65532:65532", text)
                self.assertIn('ENTRYPOINT ' + json.dumps(["python", "-m", module]), text)
                self.assertIn("--require-hashes --only-binary=:all:", text)
                self.assertIn("--no-compile", text)
                self.assertIn("PYTHONDONTWRITEBYTECODE=1", text)
                self.assertIn('LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"', text)
                self.assertIn('LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"', text)
                self.assertIn('test "${#SOURCE_REVISION}" -eq 40', text)

    def test_every_copied_input_selects_its_image(self):
        for name in ("gateway", "maintenance-gateway"):
            recipe = ROOT / "images" / name
            text = (recipe / "Dockerfile").read_text().replace("\\\n", " ")
            whitelist = (recipe / "Dockerfile.dockerignore").read_text().splitlines()
            self.assertEqual(whitelist[0], "**")
            copied = []
            for instruction in text.splitlines():
                if instruction.startswith("COPY "):
                    copied.extend(shlex.split(instruction)[1:-1])
            self.assertTrue(copied)
            for path in copied:
                with self.subTest(image=name, source=path):
                    self.assertTrue((ROOT / path).is_file())
                    self.assertIn("!" + path, whitelist)
                    self.assertIn(name, [image.image for image in selector.affected_images([path])])
            self.assertFalse(any(path.endswith((".rs", "Cargo.lock", "Cargo.toml")) for path in copied))
            self.assertNotIn("services/gateway/gateway/keys.py", copied if name == "maintenance-gateway" else [])

    def test_build_script_requires_committed_inputs(self):
        text = (ROOT / "images/gateway/build.sh").read_text()
        self.assertIn("rev-parse --verify 'HEAD^{commit}'", text)
        self.assertIn("status --porcelain --untracked-files=all", text)
        self.assertIn("SOURCE_REVISION=$source_revision", text)
        self.assertIn("SOURCE_DATE_EPOCH=$source_date_epoch", text)
        self.assertNotIn("Cargo", text)


if __name__ == "__main__":
    unittest.main()
