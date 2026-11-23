# Recipes

A recipe says how one model runs on the framework, in three parts:

1. the routing layer between replicas (`routing`: the chart's cache-aware
   SGLang router);
2. what one replica is (`replica.layout`: one aggregated worker, or one
   prefill/decode pair);
3. the hardware of one replica (`replica.gpus`, `replica.gpuArchitectures`).

It also names the engine image, the model and its byte manifest, and the API
behavior that validation and warm-up expect. It holds no environment value:
no replica count, no model server address, no node, no router API server
address, no allowlist entry name, no pod requests. The deployment sets the
replica count (`inference.replicas`).

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

Apply the recipe values first, then the environment values files (replica
count, model server hosts, nodes, router API server, pod requests), then the
release values that
`scripts/render-allowlist.py` writes (the image digests). The recipe names
a chart image key; the framework release gives its digest.

Every framework release ships every recipe. The release build checks each
recipe against the release images and writes the asset `recipes.json`:
`{"schema": "confidential.ai/recipes/v1", "recipes": {<name>: {<file>:
<text>}}}`. The signed manifest binds its SHA-256 (`recipes.sha256`) and the
SHA-256 of each `recipe.yaml` (`recipes.recipes.<name>`). A pair recipe must
also match its launch plan, whose SHA-256 the manifest binds
(`confidentialSglang.layouts.<plan>`).

## Replica layouts

- `worker`: one replica is one aggregated SGLang worker pod
  (`templates/inference-workers.yaml`). The recipe gives its flags (`worker`).
- `pair`: one replica is one prefill/decode pair pod and its own PD router pod
  (`templates/inference-pairs.yaml`). The pair pod runs the prefill and the
  decode worker in one `sglang-pair` container, so prefill writes KV into
  decode's GPU memory over NVLink. The recipe names a launch plan that the
  engine image bakes (`/opt/sglang/layouts/<plan>.json`, confidential-sglang
  `confidential/layouts/README.md`) and copies none of its flags.
  `scripts/confidential_sglang_release.py pin` commits the plans of the pinned
  engine image to `release/inputs/confidential-sglang/layouts/<record>/`;
  `recipe-values.py` renders the plan's worker and PD router arguments into
  `inference.pair`, less the flags the chart sets (`--model-path`,
  `--served-model-name`, `--host`, `--warmups`), and checks that the plan
  sets the recipe's context length, parsers and speculative algorithm.

## Schema `confidential.ai/recipe/v2`

v2 removed `replica.workers` (the replica count is a deployment value) and
added `replica.layout`; `replica.gpusPerWorker` became `replica.gpus`.

Every field is required unless it says optional. An unknown field is an
error.

| Field | Meaning | Chart value |
| --- | --- | --- |
| `schema` | `confidential.ai/recipe/v2` | |
| `name` | The directory name: lowercase letters, digits, `.` and `-`, at most 63 characters | |
| `description` | One line, at most 500 characters | |
| `engine.image` | The chart image key of the engine: `confidentialSglangEngine` (confidential-sglang) or `sglangConfidential` (this repository, until its removal) | `inference.engineImage` |
| `engine.flashinferDisableJit` | `true` when the engine image carries every FlashInfer kernel the model needs. FlashInfer then fails a missing kernel instead of compiling it inside the scheduler | `inference.flashinferDisableJit` |
| `replica.layout` | `worker` or `pair` (above) | `inference.layout` |
| `replica.plan` | `pair` only: the launch plan the engine image bakes, `/opt/sglang/layouts/<plan>.json` | `inference.pair` |
| `replica.gpus` | The GPUs of one replica: of its worker (its tensor parallel size), 1 to 8, or of its pair pod (the plan's prefill and decode GPUs together), 2 to 8 | `inference.gpusPerReplica` |
| `replica.gpuArchitectures` | `HOPPER`, `BLACKWELL`: the GPU evidence policy | `inference.gpuArchitectures` |
| `replica.attestedGpuCount` | Optional. The devices one replica pod's GPU evidence shows. Default: `gpus` | `inference.attestedGpuCount` |
| `model.repository` | The Hugging Face repository | `inference.model.name` |
| `model.revision` | The full commit of the model revision | `inference.model.revision` |
| `model.manifest` | `model-manifest.json` | `inference.model.download.manifest` |
| `model.manifestSha256` | The SHA-256 hex of `model-manifest.json` | first `expectedFileList` entry |
| `model.checkFiles` | Model files that wait-for-model checks first, by their manifest SHA-256 | `expectedFileList` |
| `model.contextLength` | `--context-length`, in tokens | `inference.contextLength` |
| `worker.toolCallParser` | `--tool-call-parser` (`pair`: what the plan sets) | `inference.toolCallParser` |
| `worker.reasoningParser` | `--reasoning-parser`, or empty (`pair`: what the plan sets) | `inference.reasoningParser` |
| `worker.speculativeAlgorithm` | `--speculative-algorithm`, or empty (`pair`: what the plan sets) | `inference.speculativeAlgorithm` |
| `worker.moeRunnerBackend` | `worker` only: `--moe-runner-backend` | `inference.moeRunnerBackend` |
| `worker.maxRunningRequests` | `worker` only: `--max-running-requests`; 0 lets SGLang size it | `inference.maxRunningRequests` |
| `worker.extraArgs` | `worker` only: other SGLang flags, each `--flag` or `--flag=value`. A flag that the chart sets itself is refused (`CHART_FLAGS` in the script) | `inference.workerExtraArgs` |
| `routing.kind` | `sglang-router` | |
| `routing.policy` | `cache_aware`, the policy the chart's router runs | |
| `routing.image` | Optional (`pair`: `confidentialSglangRouter`, which also runs each replica's PD router). The router chart image key: `confidentialSglangRouter` or `sglangRouter` | `router.image` |
| `behavior.apis` | The public APIs the model serves: any of `chat`, `completions`, `responses`, `messages`. Each maps to `{}` or `{minOutputTokens: N}`, the least `max_tokens` a request of that API must ask for | |
| `behavior.unsupportedParameters` | Optional. The request parameters the model does not support, 1 to 64 entries `{name: <body field>, allowed: [<value>, ...]}`. The gateway answers a request that sets one to any value but `null` or an `allowed` value with HTTP 400 `unsupported_parameter`, before the router. `allowed` is optional (none: every non-null value is refused) and holds booleans, numbers or strings; numbers compare by value. On the Responses API, an `include` of `message.output_text.logprobs` counts as `logprobs: true`. Example: `{name: n, allowed: [1]}` refuses `n` > 1 | `gateway.unsupportedParameters` |

`behavior.apis` has no chart value. Validation tools read it from the recipe in
the release. A recipe sets no warm-up: the chart runs confidential-sglang's
`confidential_cold_path` warmup on every worker (`--warmups`, both workers of
a pair too), before the server listens, so a worker (and a pair) is Ready only
once it is warm.
