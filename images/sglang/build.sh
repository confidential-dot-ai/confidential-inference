#!/usr/bin/env bash
set -euo pipefail

recipe_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root=$(cd "$recipe_dir/../.." && pwd)
image_name="${IMAGE_NAME:-confidential-inference/sglang:local}"
source_revision=$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}')
source_date_epoch=$(git -C "$repo_root" show -s --format=%ct "$source_revision")
cd "$repo_root"
python3 -m unittest discover -s tests/images/sglang -p test_recipe.py

docker build \
  --build-arg "SOURCE_REVISION=${source_revision}" \
  --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
  --file "${recipe_dir}/Dockerfile" \
  --tag "${image_name}" \
  "$repo_root"

printf 'Built %s\n' "${image_name}"
