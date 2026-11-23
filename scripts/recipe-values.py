#!/usr/bin/env python3
"""Check a recipe and render its Helm values for the confidential-inference chart.

A recipe (recipes/<name>/recipe.yaml, schema confidential.ai/recipe/v2) says
how one model runs: the engine image, what one replica is and its hardware,
the model and its byte manifest, the worker arguments, the routing between
replicas, and the API behavior that validation and warm-up expect.
recipes/README.md documents every field.

A replica is one of two layouts:

- `worker`: one aggregated SGLang worker pod. The recipe gives its flags.
- `pair`: one prefill/decode pair. The recipe names a launch plan that the
  engine image bakes (/opt/sglang/layouts/<plan>.json); the release pins its
  bytes (release/inputs/confidential-sglang/layouts/<record>/). The values
  carry the plan's worker and PD router arguments, less the flags the chart
  sets itself.

The values hold no environment setting: no replica count (inference.replicas),
no model server address (inference.model.download.hosts), no node, no router
API server address, no replica identity, no pod requests. Apply them before
the environment values files. The framework release supplies the image
digests (scripts/render-allowlist.py); the recipe names the chart image key
only.

    python3 scripts/recipe-values.py recipes/qwen35-0.8b-1xb200/recipe.yaml \\
      [--release release-bundle.json] [--output values.yaml]

Without --release, the image keys and the layouts are those of release/spec.yaml.
With --release, a pair recipe's layout must have the SHA-256 that the
release manifest binds (confidentialSglang.layouts).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
RECIPES = ROOT / "recipes"
sys.path.insert(0, str(ROOT / "scripts"))
import confidential_sglang_release  # noqa: E402

SCHEMA = "confidential.ai/recipe/v2"
MODEL_MANIFEST_SCHEMA = "confidential-benchmark/local-model-byte-manifest/v1"
# wait-for-model reads the byte manifest under this name (values.yaml
# inference.model.mountVerification.revisionMetadata).
REVISION_METADATA = ".model-lock-local-manifest.json"
NAME = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
PARSER = re.compile(r"[a-z0-9_-]{0,64}")
# A request body field, such as n or top_logprobs.
PARAMETER = re.compile(r"[a-z0-9_]{1,64}")
SPECULATIVE = re.compile(r"[A-Z0-9_]{0,32}")
FLAG = re.compile(r"--[a-z0-9][a-z0-9-]*(=.*)?")
# The files of a recipe directory.
FILES = {"recipe.yaml", "model-manifest.json"}
ENGINE_IMAGES = ("sglangConfidential", "confidentialSglangEngine")
ROUTER_IMAGES = ("sglangRouter", "confidentialSglangRouter")
GPU_ARCHITECTURES = ("HOPPER", "BLACKWELL")
APIS = ("chat", "completions", "responses", "messages")
LAYOUTS = ("worker", "pair")
# The SGLang flags that the chart sets itself (templates/inference-workers.yaml).
# A recipe sets them through their own fields or not at all.
CHART_FLAGS = {
    "--model-path", "--served-model-name", "--revision", "--tool-call-parser", "--reasoning-parser", "--tp",
    "--tensor-parallel-size", "--moe-runner-backend", "--speculative-algorithm", "--context-length",
    "--max-running-requests", "--mem-fraction-static", "--chunked-prefill-size", "--swa-full-tokens-ratio",
    "--enable-metrics", "--enable-cache-report", "--enable-trace", "--trace-modules", "--otlp-traces-endpoint",
    "--host", "--port", "--log-dir", "--log-requests", "--log-requests-level", "--warmups",
}
# The worker flags of a pair plan that the chart sets itself
# (templates/inference-pairs.yaml): the model path and name of the chart, the
# pod address the replica's PD router reaches, and the cold-path warmup.
PAIR_CHART_FLAGS = ("--model-path", "--served-model-name", "--host", "--warmups")
# The cold-path warmup the chart runs on every worker (confidential-sglang
# python/sglang/srt/entrypoints/warmup.py).
WARMUP = "confidential_cold_path"
# PD router flags of a plan that the chart sets itself (templates/pd-routers.yaml).
PAIR_ROUTER_CHART_FLAGS = ("--pd-disaggregation", "--prefill", "--decode", "--host", "--port",
                           "--prometheus-host", "--prometheus-port", "--request-timeout-secs",
                           "--worker-startup-timeout-secs", "--service-discovery", "--log-dir", "--log-level")
# Worker env names that sglang-pair sets (confidential-sglang pair_supervisor.py).
PAIR_ENV = ("CUDA_VISIBLE_DEVICES", "SGLANG_HOST_IP")
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

    replica = recipe["replica"]
    require(isinstance(replica, dict), "replica must be a mapping")
    require("workers" not in replica, "replica.workers was removed (recipe/v2): the deployment sets the replica "
            "count (inference.replicas), not the recipe")
    require(replica.get("layout") in LAYOUTS, f"replica.layout must be one of {list(LAYOUTS)}")
    pair = replica["layout"] == "pair"
    fields(replica, "replica", {"layout", "gpus", "gpuArchitectures"} | ({"plan"} if pair else set()),
           {"attestedGpuCount"})
    gpus = integer(replica["gpus"], "replica.gpus", 2 if pair else 1, 8)
    if pair:
        text(replica["plan"], "replica.plan", NAME)
        require(engine["image"] == "confidentialSglangEngine",
                "a pair replica needs engine.image confidentialSglangEngine, the image that bakes its plan")
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

    if pair:
        # The plan holds every worker flag; these say what it must hold.
        worker = fields(recipe["worker"], "worker", {"toolCallParser", "reasoningParser", "speculativeAlgorithm"})
    else:
        worker = fields(recipe["worker"], "worker", {"toolCallParser", "reasoningParser", "moeRunnerBackend",
                                                     "speculativeAlgorithm", "maxRunningRequests", "extraArgs"})
    text(worker["toolCallParser"], "worker.toolCallParser", PARSER)
    text(worker["reasoningParser"], "worker.reasoningParser", PARSER)
    text(worker["speculativeAlgorithm"], "worker.speculativeAlgorithm", SPECULATIVE)
    require(worker["toolCallParser"] != "", "worker.toolCallParser is required")
    if not pair:
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
    if pair:
        require(routing.get("image") == "confidentialSglangRouter",
                "a pair replica needs routing.image confidentialSglangRouter: its PD router runs that image")

    behavior = fields(recipe["behavior"], "behavior", {"apis"}, {"unsupportedParameters"})
    apis = behavior["apis"]
    require(isinstance(apis, dict) and apis and set(apis) <= set(APIS), f"behavior.apis keys must be from {list(APIS)}")
    for name, api in apis.items():
        fields(api if api is not None else {}, f"behavior.apis.{name}", set(), {"minOutputTokens"})
        if api and "minOutputTokens" in api:
            integer(api["minOutputTokens"], f"behavior.apis.{name}.minOutputTokens", 1, context)
    if "unsupportedParameters" in behavior:
        unsupported_parameters(behavior["unsupportedParameters"])
    # No warm-up field: the chart runs confidential-sglang's warmup on every worker
    # (--warmups=confidential_cold_path), before the server listens.


def unsupported_parameters(items: Any) -> None:
    """behavior.unsupportedParameters: what services/gateway/src/settings.rs accepts."""
    where = "behavior.unsupportedParameters"
    require(isinstance(items, list) and 0 < len(items) <= 64, f"{where} must be a list of 1 to 64 entries")
    names = []
    for index, item in enumerate(items):
        entry = fields(item, f"{where}[{index}]", {"name"}, {"allowed"})
        text(entry["name"], f"{where}[{index}].name", PARAMETER)
        names.append(entry["name"])
        if "allowed" in entry:
            allowed = entry["allowed"]
            require(isinstance(allowed, list) and 0 < len(allowed) <= 16
                    and all(isinstance(value, (bool, int, str)) or isinstance(value, float) and math.isfinite(value)
                            for value in allowed),
                    f"{where}[{index}].allowed must be a list of 1 to 16 booleans, numbers or strings")
    require(len(set(names)) == len(names), f"{where} names a parameter twice")


def check_model_manifest(model: dict[str, Any], data: bytes) -> None:
    require(hashlib.sha256(data).hexdigest() == model["manifestSha256"],
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


def split_flags(argv: list[str], where: str) -> list[tuple[str, list[str]]]:
    """An argv of flags as (flag, values) items, in order. `--flag=value` is one item with one value."""
    items: list[tuple[str, list[str]]] = []
    for argument in argv:
        require(isinstance(argument, str), f"{where}: an argument is not a string")
        if argument.startswith("--"):
            flag, equals, value = argument.partition("=")
            items.append((flag, [value] if equals else []))
        else:
            require(bool(items), f"{where}: {argument!r} follows no flag")
            items[-1][1].append(argument)
    return items


def join_flags(items: list[tuple[str, list[str]]]) -> list[str]:
    return [part for flag, values in items for part in (flag, *values)]


def one(items: list[tuple[str, list[str]]], flag: str, where: str) -> str | None:
    """The one value of `flag`, None when absent. A flag given twice or without one value is refused."""
    found = [values for name, values in items if name == flag]
    require(len(found) <= 1, f"{where} sets {flag} twice")
    if not found:
        return None
    require(len(found[0]) == 1, f"{where}: {flag} needs one value")
    return found[0][0]


def pair_worker(worker: Any, role: str, layout: dict[str, Any], recipe: dict[str, Any]) -> dict[str, Any]:
    """The chart values of one worker of a pair plan."""
    where = f"layout {layout['layout']} worker {role}"
    require(isinstance(worker, dict) and worker.get("name") == role, f"layout {layout['layout']}: the workers "
            "must be one prefill and one decode, prefill first")
    python = layout["paths"]["python"]
    command = worker.get("command")
    require(isinstance(command, list) and command[:3] == [python, "-m", "sglang.launch_server"],
            f"{where}: the command is not {python} -m sglang.launch_server")
    items = split_flags(command[3:], where)
    require(one(items, "--model-path", where) == layout["paths"]["model"], f"{where}: --model-path is not paths.model")
    require(one(items, "--disaggregation-mode", where) == role, f"{where}: --disaggregation-mode is not {role}")
    warmups = one(items, "--warmups", where)
    require(warmups in (None, WARMUP), f"{where} runs warmups {warmups}; the chart runs {WARMUP}")
    tp = int(one(items, "--tp-size", where) or "1")
    pp = int(one(items, "--pp-size", where) or "1")
    require(one(items, "--dp-size", where) in (None, "1"), f"{where}: a pair worker runs DP size 1")
    port = int(one(items, "--port", where) or "0")
    require(1024 <= port <= 65534, f"{where}: --port is not a port from 1024 to 65534")
    model, spec = recipe["model"], recipe["worker"]
    for flag, expected, field in (("--context-length", str(model["contextLength"]), "model.contextLength"),
                                  ("--tool-call-parser", spec["toolCallParser"], "worker.toolCallParser"),
                                  ("--reasoning-parser", spec["reasoningParser"] or None, "worker.reasoningParser"),
                                  ("--speculative-algorithm", spec["speculativeAlgorithm"] or None,
                                   "worker.speculativeAlgorithm")):
        found = one(items, flag, where)
        require(found == expected, f"{where} sets {flag} {found}; the recipe's {field} is {expected}")
    blocked = ("--log-requests", "--log-dir", "--enable-trace", "--crash-dump-folder", "--debug-tensor-dump-output-folder")
    for flag, _ in items:
        require(not any(flag == name for name in blocked), f"{where} sets {flag}, which the pair refuses")
    env = worker.get("env")
    require(isinstance(env, dict) and all(isinstance(key, str) and isinstance(value, str)
                                         for key, value in env.items()), f"{where}: env is not a string map")
    require(not any(key.startswith("SGLANG_PAIR_") for key in env), f"{where}: env sets an sglang-pair control")
    entry = {
        "gpus": tp * pp,
        "port": port,
        # Every flag but those of PAIR_CHART_FLAGS, in plan order.
        "args": join_flags([(flag, values) for flag, values in items if flag not in PAIR_CHART_FLAGS]),
        # sglang-pair gives each worker its GPUs and its loopback address.
        "env": {key: value for key, value in sorted(env.items()) if key not in PAIR_ENV},
    }
    if role == "prefill":
        bootstrap = one(items, "--disaggregation-bootstrap-port", where)
        require(bootstrap is not None and bootstrap.isdigit(), f"{where}: no --disaggregation-bootstrap-port")
        entry["bootstrapPort"] = int(bootstrap)
    if role == "decode":
        entry["maxRunningRequests"] = int(one(items, "--max-running-requests", where) or "0")
    return entry


def pair_router(router: Any, layout: dict[str, Any], prefill: dict[str, Any], decode: dict[str, Any]) -> dict[str, Any]:
    """The chart values of a pair plan's PD router: its arguments less the chart's, its ports."""
    where = f"layout {layout['layout']} router"
    python = layout["paths"]["python"]
    command = router.get("command") if isinstance(router, dict) else None
    require(isinstance(command, list) and command[:3] == [python, "-m", "sglang_router.launch_router"],
            f"{where}: the command is not {python} -m sglang_router.launch_router")
    items = split_flags(command[3:], where)
    require([values for flag, values in items if flag == "--pd-disaggregation"] == [[]],
            f"{where} does not run --pd-disaggregation once")
    loopback = "http://127.0.0.1:{}"
    require([values for flag, values in items if flag == "--prefill"]
            == [[loopback.format(prefill["port"]), str(prefill["bootstrapPort"])]],
            f"{where}: --prefill is not the plan's one prefill")
    require([values for flag, values in items if flag == "--decode"] == [[loopback.format(decode["port"])]],
            f"{where}: --decode is not the plan's one decode")
    port = int(one(items, "--port", where) or "0")
    metrics = int(one(items, "--prometheus-port", where) or "0")
    require(1024 <= port <= 65534 and 1024 <= metrics <= 65534 and port != metrics,
            f"{where}: --port and --prometheus-port must be two ports from 1024 to 65534")
    return {"port": port, "metricsPort": metrics,
            "args": join_flags([(flag, values) for flag, values in items if flag not in PAIR_ROUTER_CHART_FLAGS])}


def pair_values(recipe: dict[str, Any], layout: dict[str, Any]) -> dict[str, Any]:
    """The inference.pair values of a pair recipe and its checked layout."""
    plan, replica = layout.get("plan"), recipe["replica"]
    name = replica["plan"]
    require(isinstance(plan, dict) and isinstance(plan.get("workers"), list) and len(plan["workers"]) == 2,
            f"layout {name} is not one prefill/decode pair")
    require(layout.get("target", {}).get("gpu_count") == replica["gpus"],
            f"layout {name} uses {layout.get('target', {}).get('gpu_count')} GPUs; replica.gpus is {replica['gpus']}")
    paths = layout.get("paths")
    require(isinstance(paths, dict) and all(isinstance(paths.get(key), str) and paths[key].startswith("/")
                                            for key in ("python", "model", "engram_holder", "kernel_cache_dir")),
            f"layout {name}: paths.python, paths.model, paths.engram_holder and paths.kernel_cache_dir must be "
            "absolute paths")
    # The chart seeds this directory (inference.pair.kernelCache.seed). It is
    # in the pair's /tmp emptyDir, the only writable place of the pod.
    require(re.fullmatch(r"/tmp/[A-Za-z0-9._/-]+", paths["kernel_cache_dir"]) is not None
            and "/../" not in paths["kernel_cache_dir"] + "/",
            f"layout {name}: paths.kernel_cache_dir {paths['kernel_cache_dir']} is not below /tmp")
    prefill = pair_worker(plan["workers"][0], "prefill", layout, recipe)
    decode = pair_worker(plan["workers"][1], "decode", layout, recipe)
    require(prefill["gpus"] + decode["gpus"] == replica["gpus"],
            f"layout {name}: the workers use {prefill['gpus'] + decode['gpus']} GPUs; replica.gpus is {replica['gpus']}")
    # sglang-pair gives prefill the first GPUs of the pod, then decode. The
    # plan must agree, or its NVLink pairing would be another one.
    visible = [plan["workers"][index].get("env", {}).get("CUDA_VISIBLE_DEVICES") for index in (0, 1)]
    expected = [",".join(map(str, range(prefill["gpus"]))),
                ",".join(map(str, range(prefill["gpus"], replica["gpus"])))]
    require(visible == expected, f"layout {name}: the workers see GPUs {visible}; sglang-pair gives {expected}")
    require(len({prefill["port"], decode["port"], prefill["bootstrapPort"]}) == 3,
            f"layout {name}: the worker and bootstrap ports must differ")
    router = pair_router(plan.get("router"), layout, prefill, decode)
    require(router["port"] not in (prefill["port"], decode["port"]), f"layout {name}: the router port is a worker port")
    return {
        "plan": name,
        "layoutSha256": layout["_sha256"],
        "python": paths["python"],
        "engramHolder": paths["engram_holder"],
        "kernelCache": {"planDirectory": paths["kernel_cache_dir"].rstrip("/")},
        "prefill": prefill,
        "decode": decode,
        "router": router,
    }


def release_layout(name: str, release: dict[str, Any] | None) -> dict[str, Any]:
    """The checked layout `name` of the release's engine image."""
    if release is not None:
        section = release.get("confidentialSglang", {})
        record = section.get("record")
        bound = section.get("layouts", {}).get(name)
        require(bound is not None, f"the release binds no layout {name} (confidentialSglang.layouts)")
    else:
        record = yaml.safe_load((ROOT / "release/spec.yaml").read_text(encoding="utf-8"))["confidentialSglang"]["record"]
        bound = None
    try:
        layout = confidential_sglang_release.read_layout(record, name)
    except confidential_sglang_release.RecordError as error:
        raise RecipeError(str(error)) from error
    require(bound is None or layout["_sha256"] == bound,
            f"layout {name} of the checkout differs from the release ({layout['_sha256']}, not {bound})")
    return layout


def values(recipe: dict[str, Any], images: dict[str, Any], layout: dict[str, Any] | None = None) -> dict[str, Any]:
    """The chart values of a loaded recipe. `images` holds the chart image keys of the release, and
    `layout` the checked layout of a pair recipe (release_layout)."""
    engine, replica, model, worker, routing = (recipe[key] for key in ("engine", "replica", "model", "worker",
                                                                       "routing"))
    require(engine["image"] in images, f"the release has no image {engine['image']} (engine.image)")
    if "image" in routing:
        require(routing["image"] in images, f"the release has no image {routing['image']} (routing.image)")
    pair = replica["layout"] == "pair"
    inference: dict[str, Any] = {
        "mode": "model",
        "layout": replica["layout"],
        "engineImage": engine["image"],
        "flashinferDisableJit": engine["flashinferDisableJit"],
        "gpusPerReplica": replica["gpus"],
        "gpuArchitectures": list(replica["gpuArchitectures"]),
        "attestedGpuCount": replica.get("attestedGpuCount", replica["gpus"]),
        "contextLength": model["contextLength"],
        "toolCallParser": worker["toolCallParser"],
        "reasoningParser": worker["reasoningParser"],
        "speculativeAlgorithm": worker["speculativeAlgorithm"],
    }
    if pair:
        require(layout is not None and layout.get("layout") == replica["plan"],
                f"the pair recipe needs the layout {replica['plan']}")
        inference["pair"] = pair_values(recipe, layout)
    else:
        inference.update({
            "maxRunningRequests": worker["maxRunningRequests"],
            "moeRunnerBackend": worker["moeRunnerBackend"],
            "workerExtraArgs": list(worker["extraArgs"]),
        })
    inference["model"] = {
        "name": model["repository"],
        "revision": model["revision"],
        "mountVerification": {"revisionMetadata": REVISION_METADATA, "expectedFileList": expected_files(recipe)},
        "download": {"manifest": recipe["_modelManifest"]},
    }
    rendered: dict[str, Any] = {"inference": inference}
    parameters = recipe["behavior"].get("unsupportedParameters")
    if parameters:
        # The gateway refuses them (GATEWAY_RUNTIME_CONFIG unsupportedParameters).
        rendered["gateway"] = {"unsupportedParameters": [
            {"name": item["name"], **({"allowed": list(item["allowed"])} if "allowed" in item else {})}
            for item in parameters]}
    if "image" in routing:
        rendered["router"] = {"image": routing["image"]}
    return rendered


def recipe_values(recipe: dict[str, Any], images: dict[str, Any], release: dict[str, Any] | None = None) -> dict[str, Any]:
    """values() with the layout of a pair recipe read from the checkout (and checked against `release`)."""
    replica = recipe["replica"]
    layout = release_layout(replica["plan"], release) if replica["layout"] == "pair" else None
    return values(recipe, images, layout)


def release_image_keys(release: dict[str, Any] | None) -> dict[str, Any]:
    """The chart image keys of a framework release manifest, or of release/spec.yaml."""
    if release is not None:
        return release["images"]
    import release_spec

    spec = release_spec.read_spec()
    return {**spec["images"], **{key: None for key in confidential_sglang_release.CHART_KEYS.values()}}


# Helm reads YAML 1.1, where these bare words are booleans (a parameter n).
YAML11_BOOLEANS = re.compile(r"y|Y|yes|Yes|YES|n|N|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF")


class Dumper(yaml.SafeDumper):
    def represent_str(self, data: str) -> yaml.Node:
        if YAML11_BOOLEANS.fullmatch(data):
            return self.represent_scalar("tag:yaml.org,2002:str", data, style='"')
        return super().represent_str(data)


Dumper.add_representer(str, Dumper.represent_str)


def dump(rendered: dict[str, Any]) -> str:
    return yaml.dump(rendered, Dumper=Dumper, sort_keys=False, width=1 << 20)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("recipe", type=Path)
    parser.add_argument("--release", type=Path, help="a framework release manifest (release-bundle.json)")
    parser.add_argument("--output", type=Path, help="the values file to write (default: stdout)")
    args = parser.parse_args()
    try:
        release = json.loads(args.release.read_text(encoding="utf-8")) if args.release else None
        output = dump(recipe_values(load(args.recipe), release_image_keys(release), release))
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
