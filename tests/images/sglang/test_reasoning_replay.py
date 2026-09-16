#!/usr/bin/env python3
"""Unit tests for the sglang-simulator-reasoning.patch's replay logic.

The patched files (reasoning_replay.py, openai_reasoning.py) are not part of
the pinned, hash-checked simulator-upstream tree -- they are added by
images/sglang/patches/sglang-simulator-reasoning.patch at image build time.
The reasoning patch is written against the tree as it stands after the
Dockerfile's earlier sglang-simulator-replay-only.patch and
sglang-simulator-tool-calls.patch, so these tests apply all three patches,
in the Dockerfile's order, to a scratch copy of the pinned tree, then import
the patched-in module directly (it has no dependency on a running SGLang
process) to check its pure logic: which requests get replayed, and how the
per-request token cursor advances and terminates.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RECIPE = ROOT / "images" / "sglang"
LOCK = json.loads((RECIPE / "source.lock").read_text(encoding="utf-8"))
SIMULATOR_SOURCE = RECIPE / "simulator-upstream"
REPLAY_ONLY_PATCH = RECIPE / "patches" / "sglang-simulator-replay-only.patch"
TOOL_CALLS_PATCH = RECIPE / "patches" / "sglang-simulator-tool-calls.patch"
REASONING_PATCH = RECIPE / "patches" / "sglang-simulator-reasoning.patch"
TOKENIZER_PATH = SIMULATOR_SOURCE / "examples" / "assets" / "tokenizer"


def _apply_patched_simulator(tmp_path: Path) -> Path:
    """Copy the pinned simulator source and apply the reasoning patch to it.

    Applies sglang-simulator-replay-only.patch and
    sglang-simulator-tool-calls.patch first, in the Dockerfile's order,
    because sglang-simulator-reasoning.patch is written against the tree
    those two patches leave behind (both edit hook_bootstrap.py).
    """
    target = tmp_path / "sglang-simulator"
    shutil.copytree(SIMULATOR_SOURCE, target)
    for patch in (REPLAY_ONLY_PATCH, TOOL_CALLS_PATCH, REASONING_PATCH):
        subprocess.run(
            ["git", "apply", "--check", str(patch)],
            cwd=target,
            check=True,
        )
        subprocess.run(
            ["git", "apply", str(patch)],
            cwd=target,
            check=True,
        )
    return target


def _load_module(name: str, path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class FakeSamplingParams:
    def __init__(self, custom_params=None):
        self.custom_params = custom_params


class FakeReq:
    def __init__(self, rid, custom_params=None):
        self.rid = rid
        self.sampling_params = FakeSamplingParams(custom_params)


class FakeNextTokenIds(list):
    """Mimics enough of a torch.Tensor for apply_reasoning_replay: supports
    len() and item assignment."""


class ReasoningReplayPatchTests(unittest.TestCase):
    """The patch itself: applies cleanly, and source.lock/Dockerfile pin it."""

    def test_patch_applies_to_the_pinned_simulator_tree(self) -> None:
        with self._tmp_dir() as tmp_path:
            patched = _apply_patched_simulator(tmp_path)
            sglang_dir = patched / "src" / "sglang_simulator" / "simulation" / "sglang"
            self.assertTrue((sglang_dir / "reasoning_replay.py").is_file())
            self.assertTrue((sglang_dir / "openai_reasoning.py").is_file())
            hook_bootstrap = (sglang_dir / "hook_bootstrap.py").read_text(encoding="utf-8")
            self.assertIn("openai_reasoning", hook_bootstrap)
            self.assertIn(
                "openai_reasoning.C_OpenAIServingChatReasoningHook", hook_bootstrap
            )
            scheduler = (sglang_dir / "scheduler.py").read_text(encoding="utf-8")
            self.assertIn("apply_reasoning_replay", scheduler)

    def test_source_lock_pins_the_reasoning_patch(self) -> None:
        import hashlib

        simulator = LOCK["optimizations"]["sglang"]["simulator"]
        self.assertEqual(
            simulator["reasoningPatch"]["sha256"],
            hashlib.sha256(REASONING_PATCH.read_bytes()).hexdigest(),
        )

    def _tmp_dir(self):
        import tempfile

        class _Ctx:
            def __enter__(self_inner):
                self_inner.d = tempfile.mkdtemp(prefix="sglang-reasoning-patch-")
                return Path(self_inner.d)

            def __exit__(self_inner, *exc):
                shutil.rmtree(self_inner.d, ignore_errors=True)

        return _Ctx()


class ReasoningReplayLogicTests(unittest.TestCase):
    """Pure logic in reasoning_replay.py, loaded from the patched tree."""

    @classmethod
    def setUpClass(cls) -> None:
        import tempfile

        cls._tmp = tempfile.mkdtemp(prefix="sglang-reasoning-logic-")
        patched = _apply_patched_simulator(Path(cls._tmp))
        module_path = (
            patched
            / "src"
            / "sglang_simulator"
            / "simulation"
            / "sglang"
            / "reasoning_replay.py"
        )
        cls.reasoning_replay = _load_module("reasoning_replay_under_test", module_path)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def setUp(self) -> None:
        # Each test gets an isolated cursor table so tests cannot see each
        # other's requests.
        self.reasoning_replay._cursor_by_rid = {}
        self.reasoning_replay._token_ids = None
        self.reasoning_replay._eos_token_id = None

    def test_wants_reasoning_replay_reads_the_custom_param(self) -> None:
        flagged = FakeReq("req-1", custom_params={"reasoning_thinking": True})
        unflagged_absent = FakeReq("req-2")
        unflagged_false = FakeReq("req-3", custom_params={"reasoning_thinking": False})
        self.assertTrue(self.reasoning_replay.wants_reasoning_replay(flagged))
        self.assertFalse(self.reasoning_replay.wants_reasoning_replay(unflagged_absent))
        self.assertFalse(self.reasoning_replay.wants_reasoning_replay(unflagged_false))

    def test_next_token_id_advances_and_then_returns_eos(self) -> None:
        req = FakeReq("req-4", custom_params={"reasoning_thinking": True})
        token_ids = self.reasoning_replay.next_token_id(req, str(TOKENIZER_PATH))
        canned = self.reasoning_replay._load_token_ids(str(TOKENIZER_PATH))
        self.assertEqual(canned[0], token_ids)
        # Walk the cursor to the end of the canned sequence.
        for expected in canned[1:]:
            self.assertEqual(expected, self.reasoning_replay.next_token_id(req, str(TOKENIZER_PATH)))
        # Past the end, every call returns EOS (or the last id, if the
        # tokenizer has no EOS token) and never raises or repeats content.
        past_end = self.reasoning_replay.next_token_id(req, str(TOKENIZER_PATH))
        expected_past_end = (
            self.reasoning_replay._eos_token_id
            if self.reasoning_replay._eos_token_id is not None
            else canned[-1]
        )
        self.assertEqual(expected_past_end, past_end)

    def test_decoded_canned_text_has_the_think_tags(self) -> None:
        self.reasoning_replay._load_token_ids(str(TOKENIZER_PATH))
        self.assertTrue(self.reasoning_replay.CANNED_TEXT.startswith("<think>"))
        self.assertIn("</think>", self.reasoning_replay.CANNED_TEXT)
        self.assertTrue(
            self.reasoning_replay.CANNED_TEXT.endswith(self.reasoning_replay.ANSWER_TEXT)
        )

    def test_apply_reasoning_replay_only_touches_flagged_requests(self) -> None:
        flagged = FakeReq("req-5", custom_params={"reasoning_thinking": True})
        plain = FakeReq("req-6")
        batch = types.SimpleNamespace(reqs=[flagged, plain])
        ret = types.SimpleNamespace(next_token_ids=FakeNextTokenIds([1, 1]))
        self.reasoning_replay.apply_reasoning_replay(batch, ret, str(TOKENIZER_PATH))
        canned = self.reasoning_replay._load_token_ids(str(TOKENIZER_PATH))
        self.assertEqual(canned[0], ret.next_token_ids[0])
        # The unflagged request's constant-token-id replay is untouched.
        self.assertEqual(1, ret.next_token_ids[1])

    def test_apply_reasoning_replay_is_a_no_op_for_mismatched_batches(self) -> None:
        batch = types.SimpleNamespace(reqs=[FakeReq("req-7", custom_params={"reasoning_thinking": True})])
        ret = types.SimpleNamespace(next_token_ids=FakeNextTokenIds([1, 1]))
        # len(next_token_ids) != len(batch.reqs): the simulator's overlap-
        # scheduling deferred-sample case looks nothing like this, so this
        # must be a safe no-op rather than an out-of-range write.
        self.reasoning_replay.apply_reasoning_replay(batch, ret, str(TOKENIZER_PATH))
        self.assertEqual([1, 1], list(ret.next_token_ids))

    def test_apply_reasoning_replay_is_a_no_op_without_next_token_ids(self) -> None:
        batch = types.SimpleNamespace(
            reqs=[FakeReq("req-8", custom_params={"reasoning_thinking": True})]
        )
        ret = types.SimpleNamespace(next_token_ids=None)
        # Must not raise.
        self.reasoning_replay.apply_reasoning_replay(batch, ret, str(TOKENIZER_PATH))


if __name__ == "__main__":
    unittest.main()
