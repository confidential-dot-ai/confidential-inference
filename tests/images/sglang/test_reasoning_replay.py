from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "images" / "sglang" / "simulator-upstream"
TOOL_PATCH = ROOT / "images" / "sglang" / "patches" / "sglang-simulator-tool-calls.patch"
REASONING_PATCH = ROOT / "images" / "sglang" / "patches" / "sglang-simulator-reasoning.patch"
LOCK = json.loads((ROOT / "images" / "sglang" / "source.lock").read_text())


def apply_patches(target: Path) -> Path:
    shutil.copytree(SOURCE, target, dirs_exist_ok=True)
    for patch in (TOOL_PATCH, REASONING_PATCH):
        subprocess.run(
            ["git", "apply", "--check", str(patch)], cwd=target, check=True
        )
        subprocess.run(["git", "apply", str(patch)], cwd=target, check=True)
    return target


def load_adapter(path: Path):
    module_name = "reasoning_adapter_under_test"
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class FakeJSONResponse:
    def __init__(self, content):
        self.content = content


class FakeResponses:
    JSONResponse = FakeJSONResponse


class ReasoningAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="sglang-reasoning-adapter-"))
        patched = apply_patches(cls.tmp)
        cls.sglang_dir = (
            patched / "src" / "sglang_simulator" / "simulation" / "sglang"
        )
        cls.adapter = load_adapter(cls.sglang_dir / "openai_reasoning.py")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_patch_installs_only_the_http_reasoning_adapter(self) -> None:
        bootstrap = (self.sglang_dir / "hook_bootstrap.py").read_text()
        model_runner = (self.sglang_dir / "model_runner.py").read_text()
        scheduler = (self.sglang_dir / "scheduler.py").read_text()
        self.assertIn("C_OpenAIServingChatReasoningHook", bootstrap)
        self.assertFalse((self.sglang_dir / "reasoning_replay.py").exists())
        self.assertNotIn("reasoning_replay", model_runner)
        self.assertNotIn("reasoning_replay", scheduler)

    def test_source_lock_pins_the_patch(self) -> None:
        expected = LOCK["optimizations"]["sglang"]["simulator"][
            "reasoningPatch"
        ]["sha256"]
        actual = hashlib.sha256(REASONING_PATCH.read_bytes()).hexdigest()
        self.assertEqual(expected, actual)

    def test_explicit_thinking_flag_controls_the_adapter(self) -> None:
        request = types.SimpleNamespace(chat_template_kwargs={"thinking": True})
        self.assertTrue(self.adapter._thinking(request))
        request.chat_template_kwargs = {"thinking": False}
        self.assertFalse(self.adapter._thinking(request))
        request.chat_template_kwargs = {}
        self.assertIsNone(self.adapter._thinking(request))

    def test_non_streaming_reasoning_response_has_contract_fields(self) -> None:
        request = types.SimpleNamespace(
            model="deepseek-ai/DeepSeek-V4-Flash-0731"
        )
        response = self.adapter._non_streaming_response(
            request, True, FakeResponses
        ).content
        choice = response["choices"][0]
        self.assertEqual("stop", choice["finish_reason"])
        self.assertTrue(choice["message"]["reasoning_content"])
        self.assertTrue(choice["message"]["content"])
        self.assertGreater(
            response["usage"]["completion_tokens_details"]["reasoning_tokens"],
            0,
        )

    def test_non_reasoning_response_omits_reasoning_content(self) -> None:
        request = types.SimpleNamespace(
            model="deepseek-ai/DeepSeek-V4-Flash-0731"
        )
        response = self.adapter._non_streaming_response(
            request, False, FakeResponses
        ).content
        self.assertNotIn(
            "reasoning_content", response["choices"][0]["message"]
        )


if __name__ == "__main__":
    unittest.main()
