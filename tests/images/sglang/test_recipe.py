#!/usr/bin/env python3
"""Focused tests for the public production SGLang image recipe."""

from __future__ import annotations

import json
import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RECIPE = ROOT / "images" / "sglang"
LOCK = json.loads((RECIPE / "source.lock").read_text(encoding="utf-8"))
DOCKERFILE = (RECIPE / "Dockerfile").read_text(encoding="utf-8")

EXPECTED_IMAGE = "docker.io/lmsysorg/sglang"
EXPECTED_DIGEST = "sha256:bde16a8447b19e89056b9eea06c72be6c02801dc89d528c9ea90c53368fd74bf"
EXPECTED_SOURCE = "https://github.com/sgl-project/sglang"
EXPECTED_COMMIT = "71de97b264b04dcd514cf904003028aefe9775c8"
EXPECTED_PATCH_DIGEST = "da0afb59209a6bce8a910b21c6e63fcde768f5b82675bfa2bd22ae230c978570"


def instructions() -> list[str]:
    return [
        line.strip()
        for line in DOCKERFILE.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


class SGLangImageRecipeTests(unittest.TestCase):
    def test_source_lock_has_the_approved_upstream_pins(self) -> None:
        self.assertEqual(1, LOCK["schemaVersion"])
        self.assertEqual(EXPECTED_IMAGE, LOCK["image"]["reference"])
        self.assertEqual(EXPECTED_DIGEST, LOCK["image"]["digest"])
        self.assertEqual(EXPECTED_SOURCE, LOCK["source"]["repository"])
        self.assertEqual(EXPECTED_COMMIT, LOCK["source"]["commit"])

    def test_from_uses_the_exact_digest_without_a_tag(self) -> None:
        from_lines = [line for line in instructions() if line.upper().startswith("FROM ")]
        self.assertEqual([f"FROM {EXPECTED_IMAGE}@{EXPECTED_DIGEST}"], from_lines)
        self.assertNotRegex(from_lines[0], r"lmsysorg/sglang:[^@\s]+")

    def test_labels_record_the_source_and_base_pins(self) -> None:
        required = {
            'LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"',
            'LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"',
            f'LABEL ai.confidential.upstream.source="{EXPECTED_SOURCE}"',
            f'LABEL ai.confidential.upstream.revision="{EXPECTED_COMMIT}"',
            f'LABEL org.opencontainers.image.base.name="{EXPECTED_IMAGE}"',
            f'LABEL org.opencontainers.image.base.digest="{EXPECTED_DIGEST}"',
        }
        self.assertTrue(required.issubset(set(instructions())))
        self.assertNotIn("org.opencontainers.image.created", DOCKERFILE)

    def test_recipe_applies_only_the_reviewed_patch_and_model_gate(self) -> None:
        forbidden = {"ADD", "CMD", "ENTRYPOINT"}
        used = {line.split(maxsplit=1)[0].upper() for line in instructions()}
        self.assertTrue(forbidden.isdisjoint(used))
        copy_lines = [line for line in instructions() if line.startswith("COPY ")]
        self.assertEqual([], copy_lines)
        run_lines = [line for line in instructions() if line.startswith("RUN ")]
        self.assertEqual(1, len(run_lines))
        for source in (
            "patches/cc-optimizations-v0518.patch",
            "patch_flashinfer_cuda_ipc.py",
            "wait_for_model.py",
            "gpu_metrics.py",
            "patches/sglang-simulator-tool-calls.patch",
        ):
            self.assertIn(f"source={source}", DOCKERFILE)
        self.assertIn("install -D -m 0555 /run-src/wait-for-model", DOCKERFILE)
        self.assertIn("install -D -m 0555 /run-src/gpu-metrics", DOCKERFILE)
        self.assertIn("git apply --check --directory=python", DOCKERFILE)
        self.assertIn("git apply --directory=python", DOCKERFILE)

    def test_patch_and_dependency_pins_are_exact(self) -> None:
        patch = RECIPE / "patches" / "cc-optimizations-v0518.patch"
        self.assertEqual(EXPECTED_PATCH_DIGEST, hashlib.sha256(patch.read_bytes()).hexdigest())
        optimizations = LOCK["optimizations"]
        self.assertEqual(EXPECTED_PATCH_DIGEST, optimizations["patch"]["sha256"])
        self.assertEqual("0.6.17", optimizations["flashInfer"]["version"])
        cuda_ipc_patch = RECIPE / "patch_flashinfer_cuda_ipc.py"
        self.assertEqual(
            hashlib.sha256(cuda_ipc_patch.read_bytes()).hexdigest(),
            optimizations["flashInfer"]["cudaIpcPatch"]["sha256"],
        )
        self.assertEqual(
            "aea6d45cde342a1455186e7b9e3c3191b8c97f8d",
            optimizations["sglang"]["asyncDeviceToHostCommit"],
        )
        self.assertEqual(
            "64121c62a8dca7f5d1fdd39c8155ac3b8fc9da70",
            optimizations["sglang"]["flashInferConfidentialComputeCommit"],
        )
        simulator = optimizations["sglang"]["simulator"]
        self.assertEqual(33824, simulator["pullRequest"])
        self.assertEqual(
            "5e6af31ae3fe8d95f83bab8c78e4db834142b313",
            simulator["commit"],
        )
        simulator_patch = ROOT / simulator["patch"]["path"]
        self.assertEqual(
            simulator["patch"]["sha256"],
            hashlib.sha256(simulator_patch.read_bytes()).hexdigest(),
        )
        tool_calls_patch = ROOT / simulator["toolCallsPatch"]["path"]
        self.assertEqual(
            simulator["toolCallsPatch"]["sha256"],
            hashlib.sha256(tool_calls_patch.read_bytes()).hexdigest(),
        )
        self.assertIn(
            f'LABEL ai.confidential.sglang.simulator.tool-calls-patch.sha256='
            f'"{simulator["toolCallsPatch"]["sha256"]}"',
            instructions(),
        )
        simulator_reasoning_patch = ROOT / simulator["reasoningPatch"]["path"]
        self.assertEqual(
            simulator["reasoningPatch"]["sha256"],
            hashlib.sha256(simulator_reasoning_patch.read_bytes()).hexdigest(),
        )

    def test_worker_and_simulator_argv_enable_the_reasoning_parser(self) -> None:
        # The staging simulator turns the reasoning parser on now. The
        # production model role turns it on only when a production release
        # sets helm/confidential-inference/values.yaml's
        # inference.reasoningParser, so source.lock keeps the flag off the
        # real-model roles until that release.
        for role_name in ("inference-worker-0", "inference-worker-1"):
            self.assertNotIn("--reasoning-parser=deepseek-v4", LOCK["roles"][role_name]["argv"])
            self.assertIn(
                "--reasoning-parser=deepseek-v4",
                LOCK["simulatorRoles"][role_name]["argv"],
            )
        self.assertIn(
            'LABEL ai.confidential.sglang.simulator.reasoning-patch.sha256='
            f'"{LOCK["optimizations"]["sglang"]["simulator"]["reasoningPatch"]["sha256"]}"',
            DOCKERFILE,
        )

    def test_one_image_supports_each_locked_role(self) -> None:
        modules = {
            "sglang.launch_server" if "sglang.launch_server" in role["argv"] else "sglang_router.launch_router"
            for role in LOCK["roles"].values()
        }
        self.assertEqual({"sglang.launch_server", "sglang_router.launch_router"}, modules)
        for worker_index, role_name in enumerate(("inference-worker-0", "inference-worker-1")):
            argv = LOCK["roles"][role_name]["argv"]
            self.assertEqual("/usr/local/bin/wait-for-model", argv[0])
            self.assertIn("sglang.launch_server", argv)
            # Each worker has a separate pod network, so both can use one port.
            self.assertIn("--gpu-metrics-port=29000", argv)
            self.assertIn(f"--gpu-metrics-worker=sglang-{worker_index}", argv)
            for argument in (
                "--tp=4",
                "--moe-runner-backend=flashinfer_mxfp4",
                "--speculative-algorithm=DSPARK",
                "--mem-fraction-static=0.90",
                "--chunked-prefill-size=4096",
                "--swa-full-tokens-ratio=0.1",
            ):
                self.assertIn(argument, argv)
            for old_argument in ("--dp=4", "--enable-dp-attention", "--moe-a2a-backend=megamoe"):
                self.assertNotIn(old_argument, argv)

        simulator_roles = LOCK["simulatorRoles"]
        worker_simulator_roles = {"inference-worker-0", "inference-worker-1"}
        # simulatorRoles also carries the sglang-router role's one alternate
        # argv, for the integration-staging service-discovery namespace.
        self.assertEqual(
            worker_simulator_roles | {"sglang-router"},
            set(simulator_roles),
        )
        for name in worker_simulator_roles:
            argv = simulator_roles[name]["argv"]
            self.assertEqual("python3", argv[0])
            self.assertIn(
                "sglang_simulator.simulation.sglang.launch_server", argv
            )
            self.assertIn("--max-running-requests=48", argv)

        router_staging_argv = simulator_roles["sglang-router"]["argv"]
        self.assertEqual(
            LOCK["roles"]["sglang-router"]["argv"][0],
            router_staging_argv[0],
        )
        self.assertIn("sglang_router.launch_router", router_staging_argv)
        self.assertIn(
            "--service-discovery-namespace=confidential-inference-staging",
            router_staging_argv,
        )
        # Every other argument matches production's role exactly.
        production_argv = LOCK["roles"]["sglang-router"]["argv"]
        differences = {
            argument
            for argument in set(production_argv) ^ set(router_staging_argv)
        }
        self.assertEqual(
            {
                "--service-discovery-namespace=confidential-inference",
                "--service-discovery-namespace=confidential-inference-staging",
            },
            differences,
        )

    def test_recipe_directory_has_only_public_build_material(self) -> None:
        expected = {
            "Dockerfile",
            "README.md",
            "build.sh",
            "source.lock",
            "wait_for_model.py",
            "gpu_metrics.py",
            "patch_flashinfer_cuda_ipc.py",
        }
        actual = {path.name for path in RECIPE.iterdir() if path.is_file()}
        self.assertEqual(expected, actual)
        self.assertEqual(
            {
                "cc-optimizations-v0518.patch",
                "sglang-simulator-replay-only.patch",
                "sglang-simulator-tool-calls.patch",
                "sglang-simulator-reasoning.patch",
            },
            {path.name for path in (RECIPE / "patches").iterdir() if path.is_file()},
        )
        self.assertNotRegex(DOCKERFILE, re.compile(r"candidate-private|private[-_]optimization", re.I))


if __name__ == "__main__":
    unittest.main()
