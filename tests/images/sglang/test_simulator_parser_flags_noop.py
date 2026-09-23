from __future__ import annotations

import ast
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "images" / "sglang" / "simulator-upstream"
PATCH = (
    ROOT
    / "images"
    / "sglang"
    / "patches"
    / "sglang-simulator-parser-flags-noop.patch"
)


def load_remove_function(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "remove_noop_parser_options"
    )
    module = ast.Module(body=[function], type_ignores=[])
    namespace: dict[str, object] = {}
    exec(compile(module, str(path), "exec"), namespace)
    return namespace["remove_noop_parser_options"]


class SimulatorParserFlagsNoopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="sglang-parser-flags-noop-"))
        shutil.copytree(SOURCE, cls.tmp, dirs_exist_ok=True)
        subprocess.run(["git", "apply", "--check", str(PATCH)], cwd=cls.tmp, check=True)
        subprocess.run(["git", "apply", str(PATCH)], cwd=cls.tmp, check=True)
        launch_server = (
            cls.tmp
            / "src"
            / "sglang_simulator"
            / "simulation"
            / "sglang"
            / "launch_server.py"
        )
        cls.remove_options = staticmethod(load_remove_function(launch_server))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_equals_form_is_removed(self) -> None:
        self.assertEqual(
            ["--host=0.0.0.0", "--port=30000"],
            self.remove_options(
                [
                    "--host=0.0.0.0",
                    "--reasoning-parser=deepseek-v4",
                    "--tool-call-parser=deepseekv4",
                    "--port=30000",
                ]
            ),
        )

    def test_separate_value_form_is_removed(self) -> None:
        self.assertEqual(
            ["--host", "0.0.0.0"],
            self.remove_options(
                [
                    "--reasoning-parser",
                    "deepseek-v4",
                    "--host",
                    "0.0.0.0",
                    "--tool-call-parser",
                    "deepseekv4",
                ]
            ),
        )

    def test_unrelated_options_are_unchanged(self) -> None:
        argv = ["--model-path=/tmp/model", "--enable-metrics"]
        self.assertEqual(argv, self.remove_options(argv))


if __name__ == "__main__":
    unittest.main()
