#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
source_lock="$repo_root/images/sglang/source.lock"
run_id="${$}-$(date +%s)"
network_name="v0-router-test-${run_id}"
worker_zero="v0-router-worker-0-${run_id}"
worker_one="v0-router-worker-1-${run_id}"
router_name="v0-sglang-router-${run_id}"
stub_image="confidential-inference/stub-router-test:${run_id}"
error_file="/tmp/v0-router-error-${run_id}.json"

router_digest=$(python3 - "$source_lock" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    lock = json.load(source)
print(lock["image"]["digest"])
PY
)
router_image="docker.io/lmsysorg/sglang@${router_digest}"

cleanup() {
  docker rm --force "$router_name" "$worker_zero" "$worker_one" >/dev/null 2>&1 || true
  docker network rm "$network_name" >/dev/null 2>&1 || true
  docker image rm "$stub_image" >/dev/null 2>&1 || true
  rm -f "$error_file"
}
trap cleanup EXIT

fail() {
  echo "ERROR: $*" >&2
  docker logs "$router_name" >&2 2>/dev/null || true
  exit 1
}

wait_for_router() {
  for _attempt in $(seq 1 60); do
    if curl --fail --silent "http://127.0.0.1:${router_port}/health" >/dev/null 2>&1; then
      readiness=$(curl --fail --silent "http://127.0.0.1:${router_port}/readiness")
      if python3 - "$readiness" <<'PY'
import json
import sys

body = json.loads(sys.argv[1])
assert body == {"status": "ready", "healthy_workers": 2, "total_workers": 2}
PY
      then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

# Fail instead of downloading an unverified router image.
docker image inspect "$router_image" >/dev/null 2>&1 || {
  if [[ "${V0_ALLOW_MISSING_PINNED_ROUTER_IMAGE:-0}" == "1" ]]; then
    echo "SKIP: The GitHub runner does not cache the large pinned SGLang image." >&2
    echo "Run this integration test on a prepared runner before release." >&2
    exit 0
  fi
  echo "ERROR: The exact pinned router image is absent: $router_image" >&2
  echo "Load or build the pinned image before this offline integration test." >&2
  exit 1
}

# The Dockerfile pins its base image. The build cache supplies it without a download.
docker build --pull=false \
  --tag "$stub_image" \
  --file "$repo_root/tests/router-v0/stub-upstream.Dockerfile" \
  "$repo_root/tests/router-v0" >/dev/null

docker network create "$network_name" >/dev/null
docker run --detach --pull=never \
  --network "$network_name" \
  --network-alias stub-upstream-0.stub-upstream \
  --name "$worker_zero" \
  "$stub_image" >/dev/null
docker run --detach --pull=never \
  --network "$network_name" \
  --network-alias stub-upstream-1.stub-upstream \
  --name "$worker_one" \
  "$stub_image" >/dev/null

# This test drives the pinned router binary directly with --worker-urls. The
# Helm chart instead uses --service-discovery against real inference-worker
# pods; this script only exercises the router's proxy and health-check logic.
docker run --detach --pull=never \
  --network "$network_name" \
  --name "$router_name" \
  --publish 127.0.0.1::30000 \
  --entrypoint python3 \
  "$router_image" \
  -m sglang_router.launch_router \
  --worker-urls \
  http://stub-upstream-0.stub-upstream:1080 \
  http://stub-upstream-1.stub-upstream:1080 \
  --policy=round_robin \
  --health-check-endpoint=/health \
  --host=0.0.0.0 \
  --port=30000 \
  --prometheus-host=0.0.0.0 \
  --prometheus-port=29000 >/dev/null

router_port=$(docker port "$router_name" 30000/tcp | sed 's/.*://')
wait_for_router || fail "The router did not report two healthy workers."

health=$(curl --fail --silent "http://127.0.0.1:${router_port}/health")
test "$health" = "OK" || fail "The health response is incorrect."

models=$(curl --fail --silent "http://127.0.0.1:${router_port}/v1/models")
python3 - "$models" <<'PY'
import json
import sys

body = json.loads(sys.argv[1])
assert [model["id"] for model in body["data"]] == ["staging-mock"]
PY

completion_request='{"model":"staging-mock","messages":[{"role":"user","content":"test"}]}'
for _attempt in 1 2 3 4; do
  completion=$(curl --fail --silent \
    --header 'Content-Type: application/json' \
    --data "$completion_request" \
    "http://127.0.0.1:${router_port}/v1/chat/completions")
  python3 - "$completion" <<'PY'
import json
import sys

body = json.loads(sys.argv[1])
assert body["model"] == "staging-mock"
assert body["choices"][0]["message"]["content"] == "staging mock response"
PY
done

stream=$(curl --fail --silent --no-buffer \
  --header 'Content-Type: application/json' \
  --data '{"model":"staging-mock","stream":true,"messages":[{"role":"user","content":"test"}]}' \
  "http://127.0.0.1:${router_port}/v1/chat/completions")
python3 - "$stream" <<'PY'
import json
import sys

lines = [line for line in sys.argv[1].splitlines() if line.startswith("data: ")]
assert lines[-1] == "data: [DONE]"
chunks = [json.loads(line.removeprefix("data: ")) for line in lines[:-1]]
text = "".join(chunk["choices"][0]["delta"].get("content", "") for chunk in chunks)
assert text == "staging mock response"
assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
PY

error_code=$(curl --silent --output "$error_file" --write-out '%{http_code}' \
  --header 'Content-Type: application/json' \
  --data '{"model":"staging-mock","messages":[{"role":"system","content":"mock-mode:error"},{"role":"user","content":"test"}]}' \
  "http://127.0.0.1:${router_port}/v1/chat/completions")
test "$error_code" = "503" || fail "The routed error did not return HTTP 503."
python3 - "$error_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    body = json.load(source)
assert body["error"]["message"] == "Deterministic mock upstream error."
assert body["error"]["type"] == "server_error"
PY
for worker in "$worker_zero" "$worker_one"; do
  docker logs "$worker" 2>&1 | grep -Fq '"path":"/v1/chat/completions"' || {
    fail "Round-robin routing did not send a completion to $worker."
  }
done

echo "The pinned SGLang router integration test passed."
