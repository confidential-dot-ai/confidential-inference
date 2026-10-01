from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SELECTOR = load("affected_release_images", "scripts/affected-release-images.py")
REBUILD = load("rebuild_release_images", "scripts/rebuild-release-images.py")


class ImageTitleTests(unittest.TestCase):
    """The image title is a label, so every build of one image must use the same title."""

    def test_rebuild_audit_uses_the_publish_titles(self) -> None:
        for image in SELECTOR.IMAGES:
            if image.image in REBUILD.IMAGE_TITLES:
                self.assertEqual(REBUILD.IMAGE_TITLES[image.image], image.title, image.image)

    def test_sglang_reproducibility_build_uses_the_publish_title(self) -> None:
        workflow = (ROOT / ".github/workflows/release-images.yml").read_text(encoding="utf-8")
        literal = re.findall(r"org\.opencontainers\.image\.title=(?!\$\{\{)(.+)", workflow)
        sglang = next(image for image in SELECTOR.IMAGES if image.image == "sglang")
        self.assertEqual(literal, [sglang.title])


if __name__ == "__main__":
    unittest.main()
