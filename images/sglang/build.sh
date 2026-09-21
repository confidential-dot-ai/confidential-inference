#!/usr/bin/env bash
set -euo pipefail

recipe_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image_name="${IMAGE_NAME:-confidential-inference/sglang:local}"
repo_root=$(cd "$recipe_dir/../.." && pwd)
source_revision=$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}')
source_date_epoch=$(git -C "$repo_root" show -s --format=%ct "$source_revision")

python3 - "${recipe_dir}/source.lock" "${recipe_dir}/Dockerfile" <<'PY'
import json
import pathlib
import sys

lock_path = pathlib.Path(sys.argv[1])
dockerfile_path = pathlib.Path(sys.argv[2])
lock = json.loads(lock_path.read_text(encoding="utf-8"))
dockerfile = dockerfile_path.read_text(encoding="utf-8")

expected_from = f'FROM {lock["image"]["reference"]}@{lock["image"]["digest"]}'
expected_source = f'LABEL ai.confidential.upstream.source="{lock["source"]["repository"]}"'
expected_revision = f'LABEL ai.confidential.upstream.revision="{lock["source"]["commit"]}"'
expected_patch = f'LABEL ai.confidential.sglang.patch.sha256="{lock["optimizations"]["patch"]["sha256"]}"'
expected_simulator = f'LABEL ai.confidential.sglang.simulator.revision="{lock["optimizations"]["sglang"]["simulator"]["commit"]}"'
expected_simulator_patch = f'LABEL ai.confidential.sglang.simulator.patch.sha256="{lock["optimizations"]["sglang"]["simulator"]["patch"]["sha256"]}"'
expected_simulator_parser_flags_noop_patch = f'LABEL ai.confidential.sglang.simulator.parser-flags-noop-patch.sha256="{lock["optimizations"]["sglang"]["simulator"]["parserFlagsNoopPatch"]["sha256"]}"'
expected_flashinfer = f'LABEL ai.confidential.flashinfer.version="{lock["optimizations"]["flashInfer"]["version"]}"'
for expected in (expected_from, expected_source, expected_revision, expected_patch, expected_simulator, expected_simulator_patch, expected_simulator_parser_flags_noop_patch, expected_flashinfer):
    if expected not in dockerfile.splitlines():
        raise SystemExit(f"the Dockerfile does not match source.lock: {expected}")

patch_path = lock_path.parents[2] / lock["optimizations"]["patch"]["path"]
if not patch_path.is_file():
    raise SystemExit(f"the locked patch does not exist: {patch_path}")
import hashlib
actual_patch_digest = hashlib.sha256(patch_path.read_bytes()).hexdigest()
if actual_patch_digest != lock["optimizations"]["patch"]["sha256"]:
    raise SystemExit("the optimization patch digest does not match source.lock")

simulator = lock["optimizations"]["sglang"]["simulator"]
simulator_path = lock_path.parents[2] / simulator["path"]
if not simulator_path.is_dir():
    raise SystemExit(f"the locked simulator source does not exist: {simulator_path}")
files = sorted(
    path for path in simulator_path.rglob("*")
    if path.is_file() and path.name not in {"UPSTREAM.md", "LICENSE"}
)
content = "".join(
    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(simulator_path).as_posix()}\n"
    for path in files
).encode("utf-8")
actual_simulator_digest = hashlib.sha256(content).hexdigest()
if actual_simulator_digest != simulator["contentSha256"]:
    raise SystemExit(
        f"the simulator source digest does not match source.lock: {actual_simulator_digest}"
    )

simulator_patch_path = lock_path.parents[2] / simulator["patch"]["path"]
if not simulator_patch_path.is_file():
    raise SystemExit(f"the locked simulator patch does not exist: {simulator_patch_path}")
actual_simulator_patch_digest = hashlib.sha256(simulator_patch_path.read_bytes()).hexdigest()
if actual_simulator_patch_digest != simulator["patch"]["sha256"]:
    raise SystemExit("the simulator patch digest does not match source.lock")

simulator_parser_flags_noop_patch_path = lock_path.parents[2] / simulator["parserFlagsNoopPatch"]["path"]
if not simulator_parser_flags_noop_patch_path.is_file():
    raise SystemExit(f"the locked simulator parser-flags no-op patch does not exist: {simulator_parser_flags_noop_patch_path}")
actual_simulator_parser_flags_noop_patch_digest = hashlib.sha256(simulator_parser_flags_noop_patch_path.read_bytes()).hexdigest()
if actual_simulator_parser_flags_noop_patch_digest != simulator["parserFlagsNoopPatch"]["sha256"]:
    raise SystemExit("the simulator parser-flags no-op patch digest does not match source.lock")
PY

docker build \
  --build-arg "SOURCE_REVISION=${source_revision}" \
  --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
  --file "${recipe_dir}/Dockerfile" \
  --tag "${image_name}" \
  "${recipe_dir}"

printf 'Built %s\n' "${image_name}"
