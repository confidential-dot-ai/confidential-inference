#!/usr/bin/env bash
# Qwen3.5-0.8B on one GPU, outside Kubernetes (installed as qwen35-serve).
# The worker command is the one the chart renders with
# tests/fixtures/deployments/qwen35-staging-values.yaml, so `docker run`
# exercises the same path as staging: wait-for-model checks every byte of the
# model against the manifest, then starts SGLang.
#
#   qwen35-serve fetch        download the pinned revision into $MODEL_PATH
#                             (needs a writable mount; run the container as root)
#   qwen35-serve serve [ARGS] verify $MODEL_PATH (mounted read-only) and serve;
#                             ARGS are appended to the sglang.launch_server argv
#   qwen35-serve args         print the sglang.launch_server argv
#
# tests/helm/test_qwen35_staging.py checks that `args` equals the chart's argv.
set -euo pipefail

manifest=${MANIFEST:-/opt/confidential-inference/qwen35-0.8b/model-manifest.json}

REPOSITORY=Qwen/Qwen3.5-0.8B
REVISION=2fc06364715b967f1860aea9cf38778875588b17
# SHA-256 of model-manifest.json (written as .model-lock-local-manifest.json)
# and of the two files wait-for-model checks first.
MANIFEST_SHA256=625963f6a7f159fd2a3e8ad97642a11ac275d1735adaadca8df39452b9fbd8fa
CONFIG_SHA256=b90b86f35c8e6925ef74ee04d0e758f0a845c83a42089ad82bbaa948de9b4204
TOKENIZER_CONFIG_SHA256=49e2b6e395f959f077f1e992b338919c0d4a9732fc6e613995e06557f843500c

MODEL_PATH=${MODEL_PATH:-/models/qwen35-0.8b}
PORT=${PORT:-30000}
GPU_METRICS_PORT=${GPU_METRICS_PORT:-}

# The chart's argv for one aggregated worker, in order. Parsers per SGLang's
# Qwen3.5 cookbook page; the context length is the model's default. The chart
# always passes --moe-runner-backend and --swa-full-tokens-ratio; this dense
# model ignores both. The chart also passes --private-server-output to
# wait-for-model, which discards server logs; this helper keeps them.
server_args() {
  printf '%s\n' \
    --model-path="$MODEL_PATH" \
    --served-model-name="$REPOSITORY" \
    --revision="$REVISION" \
    --tool-call-parser=qwen3_coder \
    --reasoning-parser=qwen3 \
    --tp=1 \
    --moe-runner-backend=auto \
    --mem-fraction-static=0.90 \
    --chunked-prefill-size=4096 \
    --swa-full-tokens-ratio=0.1 \
    --enable-metrics \
    --enable-cache-report \
    --host=0.0.0.0 \
    --port="$PORT"
}

case "${1:-serve}" in
  fetch)
    exec fetch-model fetch \
      --path="$MODEL_PATH" \
      --manifest="$manifest" \
      --manifest-sha256="$MANIFEST_SHA256" \
      --revision-metadata=.model-lock-local-manifest.json
    ;;
  args)
    server_args
    ;;
  serve)
    shift || true
    mapfile -t argv < <(server_args)
    metrics=()
    [[ -n "$GPU_METRICS_PORT" ]] && metrics=(--gpu-metrics-port="$GPU_METRICS_PORT")
    exec wait-for-model \
      --path="$MODEL_PATH" \
      --plain-cache \
      --timeout-seconds=900 \
      --expected-repository="$REPOSITORY" \
      --expected-revision="$REVISION" \
      --revision-metadata=.model-lock-local-manifest.json \
      --expected-file=.model-lock-local-manifest.json="$MANIFEST_SHA256" \
      --expected-file=config.json="$CONFIG_SHA256" \
      --expected-file=tokenizer_config.json="$TOKENIZER_CONFIG_SHA256" \
      "${metrics[@]}" \
      -- python3 -m sglang.launch_server "${argv[@]}" "$@"
    ;;
  *)
    echo "usage: qwen35-serve fetch | serve [ARGS] | args" >&2
    exit 2
    ;;
esac
