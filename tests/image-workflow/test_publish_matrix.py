from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "select-publish-image-matrix.py"
SPEC = importlib.util.spec_from_file_location("select_publish_matrix", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublishMatrixTests(unittest.TestCase):
    def test_one_target_creates_one_matrix_entry(self) -> None:
        result = MODULE.matrix("sglang")
        self.assertEqual(["sglang"], [item["image"] for item in result["include"]])

    def test_all_creates_every_matrix_entry(self) -> None:
        result = MODULE.matrix("all")
        self.assertEqual(5, len(result["include"]))

    def test_unknown_target_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown publish target"):
            MODULE.matrix("unknown")


if __name__ == "__main__":
    unittest.main()
