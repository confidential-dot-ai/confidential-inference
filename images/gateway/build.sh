#!/usr/bin/env bash
set -euo pipefail

recipe_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$recipe_dir/../.." && pwd)

for required in Cargo.toml Cargo.lock rust-toolchain.toml services/gateway/Cargo.toml; do
  test -f "$repo_root/$required" || {
    printf 'The gateway build input is absent: %s\n' "$required" >&2
    exit 66
  }
done

source_revision=$(git -C "$repo_root" rev-parse --verify 'HEAD^{commit}')
source_date_epoch=$(git -C "$repo_root" show -s --format=%ct "$source_revision")
[[ $source_revision =~ ^[0-9a-f]{40}$ ]] || {
  printf 'The source revision is not one full Git commit SHA.\n' >&2
  exit 65
}

source_status=$(git -C "$repo_root" status --porcelain --untracked-files=all -- \
  Cargo.toml Cargo.lock rust-toolchain.toml services/gateway images/gateway)
[[ -z $source_status ]] || {
  printf 'The gateway build input contains uncommitted changes.\n' >&2
  exit 65
}

exec docker buildx build \
  --file "$recipe_dir/Dockerfile" \
  --build-arg "SOURCE_REVISION=$source_revision" \
  --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
  "$@" \
  "$repo_root"
