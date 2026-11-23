#!/usr/bin/env python3
"""Check a recipe and render its Helm values for the confidential-inference chart.

A recipe (recipes/<name>/recipe.yaml, schema confidential.ai/recipe/v1) says
how one model runs: the engine image, one replica's GPUs, the model and its
byte manifest, the worker arguments, the routing, and the API behavior that
validation and warm-up expect. recipes/README.md documents every field.

The values hold no environment setting: no model server address
(inference.model.download.hosts), no node, no router API server address, no
replica identity. Apply them before the environment values files. The
framework release supplies the image digests (scripts/render-allowlist.py);
the recipe names the chart image key only.

    python3 scripts/recipe-values.py recipes/qwen35-0.8b-1xb200/recipe.yaml \\
      [--release release-bundle.json] [--output values.yaml]

Without --release, the image keys are checked against release/spec.yaml.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RECIPES = ROOT / "recipes"
SCHEMA = "confidential.ai/recipe/v1"
MODEL_MANIFEST_SCHEMA = "confidential-benchmark/local-model-byte-manifest/v1"
# wait-for-model reads the byte manifest under this name (values.yaml
# inference.model.mountVerification.revisionMetadata).
REVISION_METADATA = ".model-lock-local-manifest.json"
NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
PARSER = re.compile(r"[a-z0-9_]{0,64}")
FLAG = re.compile(r"--[a-z0-9][a-z0-9-]*(=.*)?")
# The files of a recipe directory.
FILES = {"recipe.yaml", "model-manifest.json"}
ENGINE_IMAGES = ("sglangConfidential", "confidentialSglangEngine")
ROUTER_IMAGES = ("sglangRouter", "confidentialSglangRouter")
GPU_ARCHITECTURES = ("HOPPER", "BLACKWELL")
APIS = ("chat", "completions", "responses", "messages")
# The SGLang flags that the chart sets itself (templates/inference-workers.yaml).
# A recipe sets them through their own fields or not at all.
CHART_FLAGS = {
    "--model-path", "--served-model-name", "--revision", "--tool-call-parser", "--reasoning-parser", "--tp",
    "--tensor-parallel-size", "--moe-runner-backend", "--speculative-algorithm", "--context-length",
    "--max-running-requests", "--mem-fraction-static", "--chunked-prefill-size", "--swa-full-tokens-ratio",
    "--enable-metrics", "--enable-cache-report", "--enable-trace", "--trace-modules", "--otlp-traces-endpoint",
    "--host", "--port", "--log-dir", "--log-requests", "--log-requests-level", "--warmups",
}
# The chart's router runs this one routing policy (templates/sglang-router.yaml).
ROUTING_POLICIES = ("cache_aware",)


class RecipeError(ValueError):
    """The recipe is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecipeError(message)


def fields(value: Any, where: str, required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    require(isinstance(value, dict), f"{where} must be a mapping")
    missing, extra = required - set(value), set(value) - required - set(optional)
    require(not missing, f"{where} needs {sorted(missing)}")
    require(not extra, f"{where} has unknown fields {sorted(extra)}")
    return value


def integer(value: Any, where: str, low: int, high: int) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and low <= value <= high,
            f"{where} must be an integer from {low} to {high}")
    return value


def number(value: Any, where: str, low: float, high: float) -> float:
    require(isinstance(value, (int, float)) and not isinstance(value, bool) and low <= value <= high,
            f"{where} must be a number from {low} to {high}")
    return value


def text(value: Any, where: str, pattern: re.Pattern[str]) -> str:
    require(isinstance(value, str) and pattern.fullmatch(value) is not None, f"{where} is invalid: {value!r}")
    return value


def load(path: Path) -> dict[str, Any]:
    """Read and check the recipe at `path` and its directory. Return it with its model manifest text."""
    directory = path.parent
    require(path.name == "recipe.yaml", f"{path} is not a recipe.yaml")
    present = {item.relative_to(directory).as_posix() for item in directory.rglob("*") if item.is_file()}
    require(present == FILES, f"{directory.name} holds exactly {sorted(FILES)}, not {sorted(present)}")
    try:
        recipe = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise RecipeError(f"cannot read {path}: {error}") from error
    check(recipe, directory.name)
    manifest = (directory / recipe["model"]["manifest"]).read_bytes()
    check_model_manifest(recipe["model"], manifest)
    return {**recipe, "_modelManifest": manifest.decode("utf-8")}


def check(recipe: Any, directory_name: str) -> None:
    fields(recipe, "recipe", {"schema", "name", "description", "engine", "replica", "model", "worker", "routing",
                              "behavior"})
    require(recipe["schema"] == SCHEMA, f"recipe schema must be {SCHEMA}")
    text(recipe["name"], "name", NAME)
    require(recipe["name"] == directory_name, f"name {recipe['name']} differs from its directory {directory_name}")
    require(isinstance(recipe["description"], str) and 0 < len(recipe["description"]) <= 500,
            "description must be 1 to 500 characters")

    engine = fields(recipe["engine"], "engine", {"image", "flashinferDisableJit"})
    require(engine["image"] in ENGINE_IMAGES, f"engine.image must be one of {list(ENGINE_IMAGES)}")
    require(isinstance(engine["flashinferDisableJit"], bool), "engine.flashinferDisableJit must be true or false")

    replica = fields(recipe["replica"], "replica", {"workers", "gpusPerWorker", "gpuArchitectures"},
                     {"attestedGpuCount"})
    integer(replica["workers"], "replica.workers", 1, 64)
    gpus = integer(replica["gpusPerWorker"], "replica.gpusPerWorker", 1, 8)
    architectures = replica["gpuArchitectures"]
    require(isinstance(architectures, list) and architectures and len(set(architectures)) == len(architectures)
            and all(item in GPU_ARCHITECTURES for item in architectures),
            f"replica.gpuArchitectures must be distinct values of {list(GPU_ARCHITECTURES)}")
    if "attestedGpuCount" in replica:
        integer(replica["attestedGpuCount"], "replica.attestedGpuCount", gpus, 8)

    model = fields(recipe["model"], "model", {"repository", "revision", "manifest", "manifestSha256", "checkFiles",
                                              "contextLength"})
    text(model["repository"], "model.repository", REPOSITORY)
    text(model["revision"], "model.revision", COMMIT)
    require(model["manifest"] == "model-manifest.json", "model.manifest must be model-manifest.json")
    text(model["manifestSha256"], "model.manifestSha256", SHA256)
    check_files = model["checkFiles"]
    require(isinstance(check_files, list) and len(set(check_files)) == len(check_files)
            and all(isinstance(item, str) and item and item != REVISION_METADATA for item in check_files),
            "model.checkFiles must be distinct file paths of the model")
    context = integer(model["contextLength"], "model.contextLength", 1, 16777216)

    worker = fields(recipe["worker"], "worker", {"toolCallParser", "reasoningParser", "moeRunnerBackend",
                                                 "speculativeAlgorithm", "maxRunningRequests", "extraArgs"})
    for key in ("toolCallParser", "reasoningParser", "speculativeAlgorithm"):
        text(worker[key], f"worker.{key}", PARSER if key != "speculativeAlgorithm" else re.compile(r"[A-Z0-9_]{0,32}"))
    require(worker["toolCallParser"] != "", "worker.toolCallParser is required")
    text(worker["moeRunnerBackend"], "worker.moeRunnerBackend", re.compile(r"[a-z0-9_]{1,64}"))
    integer(worker["maxRunningRequests"], "worker.maxRunningRequests", 0, 65536)
    extra = worker["extraArgs"]
    require(isinstance(extra, list), "worker.extraArgs must be a list")
    for argument in extra:
        text(argument, "worker.extraArgs item", FLAG)
        flag = argument.split("=", 1)[0]
        # SGLang's argparse also accepts a unique prefix of a flag (--warmup for --warmups).
        taken = sorted(chart for chart in CHART_FLAGS if len(flag) > 2 and chart.startswith(flag))
        require(not taken, f"worker.extraArgs sets {taken[0] if taken else flag}, which the chart sets: use its recipe field")

    routing = fields(recipe["routing"], "routing", {"kind", "policy"}, {"image"})
    require(routing["kind"] == "sglang-router", "routing.kind must be sglang-router")
    require(routing["policy"] in ROUTING_POLICIES, f"routing.policy must be one of {list(ROUTING_POLICIES)}")
    if "image" in routing:
        require(routing["image"] in ROUTER_IMAGES, f"routing.image must be one of {list(ROUTER_IMAGES)}")

    behavior = fields(recipe["behavior"], "behavior", {"apis"})
    apis = behavior["apis"]
    require(isinstance(apis, dict) and apis and set(apis) <= set(APIS), f"behavior.apis keys must be from {list(APIS)}")
    for name, api in apis.items():
        fields(api if api is not None else {}, f"behavior.apis.{name}", set(), {"minOutputTokens"})
        if api and "minOutputTokens" in api:
            integer(api["minOutputTokens"], f"behavior.apis.{name}.minOutputTokens", 1, context)
    # No warm-up field: the chart runs confidential-sglang's warmup on every worker
    # (--warmups=confidential_cold_path), before the server listens.

def check_model_manifest(model: dict[str, Any], data: bytes) -> None:
    require("sha256:" + hashlib.sha256(data).hexdigest() == "sha256:" + model["manifestSha256"],
            "model-manifest.json differs from model.manifestSha256")
    try:
        manifest = json.loads(data)
    except json.JSONDecodeError as error:
        raise RecipeError(f"model-manifest.json is not JSON: {error}") from error
    require(isinstance(manifest, dict) and manifest.get("schema") == MODEL_MANIFEST_SCHEMA,
            f"model-manifest.json schema must be {MODEL_MANIFEST_SCHEMA}")
    require(manifest.get("repository") == model["repository"], "model-manifest.json names another repository")
    require(manifest.get("immutable_revision") == model["revision"], "model-manifest.json names another revision")
    files = {item.get("path"): item.get("content_sha256") for item in manifest.get("files", [])
             if isinstance(item, dict)}
    for path in model["checkFiles"]:
        require(isinstance(files.get(path), str) and SHA256.fullmatch(files[path]) is not None,
                f"model-manifest.json has no SHA-256 for {path}")


def expected_files(recipe: dict[str, Any]) -> list[dict[str, str]]:
    """wait-for-model's first checks: the byte manifest, then the recipe's checkFiles."""
    files = {item["path"]: item["content_sha256"] for item in json.loads(recipe["_modelManifest"])["files"]}
    return [{"path": REVISION_METADATA, "sha256": recipe["model"]["manifestSha256"]},
            *({"path": path, "sha256": files[path]} for path in recipe["model"]["checkFiles"])]


def values(recipe: dict[str, Any], images: dict[str, Any]) -> dict[str, Any]:
    """The chart values of a loaded recipe. `images` holds the chart image keys of the release."""
    engine, replica, model, worker, routing = (recipe[key] for key in ("engine", "replica", "model", "worker",
                                                                       "routing"))
    require(engine["image"] in images, f"the release has no image {engine['image']} (engine.image)")
    if "image" in routing:
        require(routing["image"] in images, f"the release has no image {routing['image']} (routing.image)")
    inference = {
        "mode": "model",
        "engineImage": engine["image"],
        "flashinferDisableJit": engine["flashinferDisableJit"],
        "replicas": replica["workers"],
        "gpusPerReplica": replica["gpusPerWorker"],
        "gpuArchitectures": list(replica["gpuArchitectures"]),
        "attestedGpuCount": replica.get("attestedGpuCount", replica["gpusPerWorker"]),
        "contextLength": model["contextLength"],
        "maxRunningRequests": worker["maxRunningRequests"],
        "toolCallParser": worker["toolCallParser"],
        "reasoningParser": worker["reasoningParser"],
        "speculativeAlgorithm": worker["speculativeAlgorithm"],
        "moeRunnerBackend": worker["moeRunnerBackend"],
        "workerExtraArgs": list(worker["extraArgs"]),
        "model": {
            "name": model["repository"],
            "revision": model["revision"],
            "mountVerification": {"revisionMetadata": REVISION_METADATA, "expectedFileList": expected_files(recipe)},
            "download": {"manifest": recipe["_modelManifest"]},
        },
    }
    rendered: dict[str, Any] = {"inference": inference}
    if "image" in routing:
        rendered["router"] = {"image": routing["image"]}
    return rendered


def release_image_keys(release: Path | None) -> dict[str, Any]:
    """The chart image keys of a framework release manifest, or of release/spec.yaml."""
    if release is not None:
        return json.loads(release.read_text(encoding="utf-8"))["images"]
    sys.path.insert(0, str(ROOT / "scripts"))
    import confidential_sglang_release
    import release_spec

    spec = release_spec.read_spec()
    return {**spec["images"], **{key: None for key in confidential_sglang_release.CHART_KEYS.values()}}


def dump(rendered: dict[str, Any]) -> str:
    return yaml.safe_dump(rendered, sort_keys=False, width=1 << 20)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("recipe", type=Path)
    parser.add_argument("--release", type=Path, help="a framework release manifest (release-bundle.json)")
    parser.add_argument("--output", type=Path, help="the values file to write (default: stdout)")
    args = parser.parse_args()
    try:
        output = dump(values(load(args.recipe), release_image_keys(args.release)))
    except (RecipeError, OSError, KeyError, json.JSONDecodeError) as error:
        print(f"recipe-values: {error}", file=sys.stderr)
        return 1
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
