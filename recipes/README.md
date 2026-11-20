# Recipes

A recipe says how one model runs on the framework: the engine image, the
GPUs of one replica, the model and its byte manifest, the worker arguments,
the routing, and the API behavior that validation and warm-up expect. It
holds no environment value: no model server address, no node, no router API
server address, no allowlist entry name.

Each recipe is one directory, `recipes/<name>/`, with exactly two files:

- `recipe.yaml`: the recipe, schema `confidential.ai/recipe/v1` (below).
- `model-manifest.json`: the byte manifest of the model (`fetch-model
  manifest`). fetch-model and wait-for-model check every model byte against
  it. `model.manifestSha256` pins it.

`scripts/recipe-values.py` checks a recipe and renders its Helm values for
`helm/confidential-inference`:

```sh
python3 scripts/recipe-values.py recipes/qwen35-0.8b-1xb200/recipe.yaml \
  --release release-bundle.json --output recipe-values.yaml
```

Apply the recipe values first, then the environment values files (model
server hosts, nodes, router API server), then the release values that
`scripts/render-allowlist.py` writes (the image digests). The recipe names
a chart image key; the framework release gives its digest.

Every framework release ships every recipe. The release build checks each
recipe against the release images and writes the asset `recipes.json`:
`{"schema": "confidential.ai/recipes/v1", "recipes": {<name>: {<file>:
<text>}}}`. The signed manifest binds its SHA-256 (`recipes.sha256`) and the
SHA-256 of each `recipe.yaml` (`recipes.recipes.<name>`).

## Schema `confidential.ai/recipe/v1`

Every field is required unless it says optional. An unknown field is an
error.

| Field | Meaning | Chart value |
| --- | --- | --- |
| `schema` | `confidential.ai/recipe/v1` | |
| `name` | The directory name: lowercase letters, digits, `.` and `-`, at most 63 characters | |
| `description` | One line, at most 500 characters | |
| `engine.image` | The chart image key of the engine: `confidentialSglangEngine` (confidential-sglang) or `sglangConfidential` (this repository, until its removal) | `inference.engineImage` |
| `engine.flashinferDisableJit` | `true` when the engine image carries every FlashInfer kernel the model needs. FlashInfer then fails a missing kernel instead of compiling it inside the scheduler | `inference.flashinferDisableJit` |
| `replica.workers` | The worker pods, 1 to 64 | `inference.replicas` |
| `replica.gpusPerWorker` | The GPUs of one worker (its tensor parallel size), 1 to 8 | `inference.gpusPerReplica` |
| `replica.gpuArchitectures` | `HOPPER`, `BLACKWELL`: the GPU evidence policy | `inference.gpuArchitectures` |
| `replica.attestedGpuCount` | Optional. The devices one worker's GPU evidence shows. Default: `gpusPerWorker` | `inference.attestedGpuCount` |
| `model.repository` | The Hugging Face repository | `inference.model.name` |
| `model.revision` | The full commit of the model revision | `inference.model.revision` |
| `model.manifest` | `model-manifest.json` | `inference.model.download.manifest` |
| `model.manifestSha256` | The SHA-256 hex of `model-manifest.json` | first `expectedFileList` entry |
| `model.checkFiles` | Model files that wait-for-model checks first, by their manifest SHA-256 | `expectedFileList` |
| `model.contextLength` | `--context-length`, in tokens | `inference.contextLength` |
| `worker.toolCallParser` | `--tool-call-parser` | `inference.toolCallParser` |
| `worker.reasoningParser` | `--reasoning-parser`, or empty | `inference.reasoningParser` |
| `worker.moeRunnerBackend` | `--moe-runner-backend` | `inference.moeRunnerBackend` |
| `worker.speculativeAlgorithm` | `--speculative-algorithm`, or empty | `inference.speculativeAlgorithm` |
| `worker.maxRunningRequests` | `--max-running-requests`; 0 lets SGLang size it | `inference.maxRunningRequests` |
| `worker.extraArgs` | Other SGLang flags, each `--flag` or `--flag=value`. A flag that the chart sets itself is refused (`CHART_FLAGS` in the script) | `inference.workerExtraArgs` |
| `routing.kind` | `sglang-router` | |
| `routing.policy` | `cache_aware`, the policy the chart's router runs | |
| `routing.image` | Optional. The router chart image key: `confidentialSglangRouter` or `sglangRouter` | `router.image` |
| `behavior.apis` | The public APIs the model serves: any of `chat`, `completions`, `responses`, `messages`. Each maps to `{}` or `{minOutputTokens: N}`, the least `max_tokens` a request of that API must ask for | |
| `behavior.warmup` | The request shapes that warm a worker before it takes traffic: `{api, promptTokens, maxTokens, sampling: {temperature, topP (optional), topK (optional)}}`. `maxTokens` is at least the API's `minOutputTokens`, and the shape fits in `contextLength`. At least one shape sets `topK` or `topP`: the first such request can compile a FlashInfer sampling kernel (67 s on 2026-11-19) | |

`behavior` has no chart value. Validation and warm-up tools read it from the
recipe in the release.
