#!/usr/bin/env python3
"""Focused tests for the SGLang simulator's tool-call answer path.

The simulator does not load model weights, so it cannot run a real model's
tool-call grammar. images/sglang/simulator-upstream/src/sglang_simulator/
simulation/sglang/openai_tool_calls.py adds one deterministic path instead:
when a chat completion request carries `tools` and asks for one of them,
the simulator answers with a fixed OpenAI-shaped `tool_calls` entry. These
tests exercise that module directly, with small stand-ins for the pieces
that only exist inside the real, pip-installed `sglang` and `fastapi`
packages (protocol classes and StreamingResponse), so they run without
either dependency installed.
"""

from __future__ import annotations

import asyncio
import atexit
import json
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SIMULATOR_UPSTREAM = ROOT / "images" / "sglang" / "simulator-upstream"
TOOL_CALLS_PATCH = ROOT / "images" / "sglang" / "patches" / "sglang-simulator-tool-calls.patch"

# The module under test does not live in the checked-in, pristine copy of
# the upstream simulator (images/sglang/simulator-upstream): like the
# existing sglang-simulator-replay-only.patch, it is added by
# sglang-simulator-tool-calls.patch, which the Dockerfile applies at image
# build time. Apply that same patch to a throwaway copy of the tree so the
# test exercises exactly what the image build produces, and so the patch
# itself -- not just the module -- is covered by a test.
_WORKDIR = tempfile.mkdtemp(prefix="sglang-simulator-tool-calls-")
atexit.register(shutil.rmtree, _WORKDIR, ignore_errors=True)
_PATCHED_TREE = Path(_WORKDIR) / "simulator-upstream"
shutil.copytree(SIMULATOR_UPSTREAM, _PATCHED_TREE)
subprocess.run(
    ["git", "apply", str(TOOL_CALLS_PATCH)],
    cwd=_PATCHED_TREE,
    check=True,
)

SIMULATOR_SRC = _PATCHED_TREE / "src"
if str(SIMULATOR_SRC) not in sys.path:
    sys.path.insert(0, str(SIMULATOR_SRC))

from sglang_simulator.simulation.sglang import openai_tool_calls as tool_calls  # noqa: E402


WEATHER_TOOL = {
    "type": "function",
    "function": {
        "name": "get_weather",
        "description": "Get the current weather for a city.",
        "parameters": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
    },
}


def make_request(**overrides):
    request = {
        "model": "sim-model",
        "messages": [
            {
                "role": "user",
                "content": "What is the weather in Boston? Use the get_weather tool.",
            }
        ],
        "tools": [WEATHER_TOOL],
        "tool_choice": "auto",
        "stream": False,
    }
    request.update(overrides)
    return request


class _FakeBase:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def _to_jsonable(obj):
    if isinstance(obj, _FakeBase):
        return {k: _to_jsonable(v) for k, v in obj.__dict__.items() if v is not None}
    if isinstance(obj, list):
        return [_to_jsonable(v) for v in obj]
    return obj


def install_fake_sglang_protocol():
    """Register a stand-in for sglang.srt.entrypoints.openai.protocol."""

    class ToolCall(_FakeBase):
        pass

    class FunctionResponse(_FakeBase):
        pass

    class ChatMessage(_FakeBase):
        pass

    class ChatCompletionResponseChoice(_FakeBase):
        pass

    class UsageInfo(_FakeBase):
        pass

    class ChatCompletionResponse(_FakeBase):
        pass

    class DeltaMessage(_FakeBase):
        pass

    class ChatCompletionResponseStreamChoice(_FakeBase):
        pass

    class ChatCompletionStreamResponse(_FakeBase):
        def model_dump_json(self, exclude_none=True):
            return json.dumps(_to_jsonable(self))

    protocol = types.ModuleType("sglang.srt.entrypoints.openai.protocol")
    protocol.ToolCall = ToolCall
    protocol.FunctionResponse = FunctionResponse
    protocol.ChatMessage = ChatMessage
    protocol.ChatCompletionResponseChoice = ChatCompletionResponseChoice
    protocol.UsageInfo = UsageInfo
    protocol.ChatCompletionResponse = ChatCompletionResponse
    protocol.DeltaMessage = DeltaMessage
    protocol.ChatCompletionResponseStreamChoice = ChatCompletionResponseStreamChoice
    protocol.ChatCompletionStreamResponse = ChatCompletionStreamResponse

    openai_pkg = types.ModuleType("sglang.srt.entrypoints.openai")
    openai_pkg.protocol = protocol
    entrypoints_pkg = types.ModuleType("sglang.srt.entrypoints")
    entrypoints_pkg.openai = openai_pkg
    srt_pkg = types.ModuleType("sglang.srt")
    srt_pkg.entrypoints = entrypoints_pkg
    sglang_pkg = types.ModuleType("sglang")
    sglang_pkg.srt = srt_pkg

    modules = {
        "sglang": sglang_pkg,
        "sglang.srt": srt_pkg,
        "sglang.srt.entrypoints": entrypoints_pkg,
        "sglang.srt.entrypoints.openai": openai_pkg,
        "sglang.srt.entrypoints.openai.protocol": protocol,
    }
    sys.modules.update(modules)
    return modules


def install_fake_fastapi():
    class StreamingResponse:
        def __init__(self, generator, media_type=None):
            self.generator = generator
            self.media_type = media_type

    responses = types.ModuleType("fastapi.responses")
    responses.StreamingResponse = StreamingResponse
    fastapi = types.ModuleType("fastapi")
    fastapi.responses = responses

    modules = {"fastapi": fastapi, "fastapi.responses": responses}
    sys.modules.update(modules)
    return modules


class ToolDetectionTests(unittest.TestCase):
    def test_no_tools_means_no_tool_call(self) -> None:
        request = make_request(tools=[])
        self.assertIsNone(tool_calls._requested_tool(request, []))

    def test_prompt_naming_the_tool_triggers_it(self) -> None:
        request = make_request()
        tools = request["tools"]
        self.assertIs(tool_calls._requested_tool(request, tools), tools[0])

    def test_prompt_not_naming_any_tool_does_not_trigger(self) -> None:
        request = make_request(
            messages=[{"role": "user", "content": "Say hello."}],
            tool_choice="auto",
        )
        tools = request["tools"]
        self.assertIsNone(tool_calls._requested_tool(request, tools))

    def test_tool_choice_naming_a_function_triggers_it(self) -> None:
        request = make_request(
            messages=[{"role": "user", "content": "Say hello."}],
            tool_choice={"type": "function", "function": {"name": "get_weather"}},
        )
        tools = request["tools"]
        self.assertIs(tool_calls._requested_tool(request, tools), tools[0])

    def test_tool_choice_required_triggers_it(self) -> None:
        request = make_request(
            messages=[{"role": "user", "content": "Say hello."}],
            tool_choice="required",
        )
        tools = request["tools"]
        self.assertIs(tool_calls._requested_tool(request, tools), tools[0])

    def test_tool_choice_none_does_not_trigger(self) -> None:
        request = make_request(
            messages=[{"role": "user", "content": "Say hello."}],
            tool_choice="none",
        )
        tools = request["tools"]
        self.assertIsNone(tool_calls._requested_tool(request, tools))


class FirstRequiredParamTests(unittest.TestCase):
    def test_uses_required_list_first_entry(self) -> None:
        self.assertEqual(tool_calls._first_required_param(WEATHER_TOOL), "city")

    def test_falls_back_to_properties(self) -> None:
        tool = {
            "type": "function",
            "function": {
                "name": "noop",
                "parameters": {
                    "type": "object",
                    "properties": {"first": {}, "second": {}},
                    "required": [],
                },
            },
        }
        self.assertEqual(tool_calls._first_required_param(tool), "first")

    def test_falls_back_to_value_with_no_schema(self) -> None:
        tool = {"type": "function", "function": {"name": "noop"}}
        self.assertEqual(tool_calls._first_required_param(tool), "value")


class FakeServingChat:
    async def handle_request(self, request, raw_request):
        return "fallback-response"


class HookIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._protocol_modules = install_fake_sglang_protocol()
        self._fastapi_modules = install_fake_fastapi()
        self.addCleanup(self._uninstall, self._protocol_modules)
        self.addCleanup(self._uninstall, self._fastapi_modules)

        self.target = FakeServingChat
        tool_calls.C_OpenAIServingChatHook.hook(self.target)
        self.instance = self.target()

    @staticmethod
    def _uninstall(modules) -> None:
        for name in modules:
            sys.modules.pop(name, None)

    def test_no_tools_falls_back_to_original_handler(self) -> None:
        request = make_request(tools=[])
        result = asyncio.run(self.instance.handle_request(request, raw_request=None))
        self.assertEqual(result, "fallback-response")

    def test_non_streaming_tool_call_response(self) -> None:
        request = make_request(stream=False)
        response = asyncio.run(
            self.instance.handle_request(request, raw_request=None)
        )
        self.assertEqual(response.model, "sim-model")
        choice = response.choices[0]
        self.assertEqual(choice.finish_reason, "tool_calls")
        self.assertIsNone(choice.message.content)
        tool_call = choice.message.tool_calls[0]
        self.assertEqual(tool_call.function.name, "get_weather")
        self.assertEqual(json.loads(tool_call.function.arguments), {"city": "simulated"})

    def test_streaming_tool_call_response(self) -> None:
        request = make_request(stream=True)
        streaming_response = asyncio.run(
            self.instance.handle_request(request, raw_request=None)
        )

        async def collect():
            return [chunk async for chunk in streaming_response.generator]

        chunks = asyncio.run(collect())
        self.assertEqual(len(chunks), 3)
        self.assertTrue(chunks[0].startswith("data: "))
        first_payload = json.loads(chunks[0][len("data: ") : -2])
        first_delta = first_payload["choices"][0]["delta"]
        self.assertEqual(first_delta["role"], "assistant")
        self.assertEqual(
            first_delta["tool_calls"][0]["function"]["name"], "get_weather"
        )
        self.assertNotIn("finish_reason", first_payload["choices"][0])

        final_payload = json.loads(chunks[1][len("data: ") : -2])
        self.assertEqual(final_payload["choices"][0]["finish_reason"], "tool_calls")

        self.assertEqual(chunks[2], "data: [DONE]\n\n")

    def test_deterministic_ids_and_repeatable_shape(self) -> None:
        request = make_request(stream=False)
        first = asyncio.run(self.instance.handle_request(request, raw_request=None))
        second = asyncio.run(self.instance.handle_request(request, raw_request=None))
        # Not the same id (each call mints a fresh one), but the same shape.
        self.assertNotEqual(first.id, second.id)
        self.assertEqual(
            first.choices[0].message.tool_calls[0].function.name,
            second.choices[0].message.tool_calls[0].function.name,
        )
        self.assertEqual(
            first.choices[0].message.tool_calls[0].function.arguments,
            second.choices[0].message.tool_calls[0].function.arguments,
        )


if __name__ == "__main__":
    unittest.main()
