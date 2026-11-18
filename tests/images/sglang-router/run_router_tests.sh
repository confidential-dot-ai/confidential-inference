#!/usr/bin/env bash
# Build the patched SGLang router and run its Rust tests.
#
#   tests/images/sglang-router/run_router_tests.sh [WORK_DIR]
#
# The same source as the image: the upstream commit in
# images/sglang-router/source.lock, then each patch in the order source.lock
# lists it (each is checked against its SHA-256 first), then the locked
# Cargo.lock. The tests run in the Rust image of the Dockerfile's build stage.
# The patches carry their own tests (for example the circuit-breaker rules of
# pd-router.patch and client-errors.patch); this is what runs them.
#
# Needs git, python3 and docker. WORK_DIR (default: a new temporary directory)
# holds the source and the Cargo caches; reuse it to make a second run fast.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RECIPE="${ROOT}/images/sglang-router"
WORK="${1:-$(mktemp -d)}"
mkdir -p "${WORK}"
SRC="${WORK}/sglang"

commit="$(python3 -c 'import json,re,sys; c=json.load(open(sys.argv[1]))["source"]["commit"]; assert re.fullmatch("[0-9a-f]{40}", c); print(c)' "${RECIPE}/source.lock")"
image="$(sed -n 's/^FROM \(docker\.io\/library\/rust@sha256:[0-9a-f]\{64\}\) AS build$/\1/p' "${RECIPE}/Dockerfile")"
[ -n "${image}" ] || { echo "no pinned Rust build image in ${RECIPE}/Dockerfile" >&2; exit 1; }

echo "==> upstream ${commit}"
rm -rf "${SRC}"
git init -q "${SRC}"
git -C "${SRC}" remote add origin https://github.com/sgl-project/sglang
git -C "${SRC}" fetch -q --depth=1 origin "${commit}"
git -C "${SRC}" checkout -q --detach FETCH_HEAD
[ "$(git -C "${SRC}" rev-parse HEAD)" = "${commit}" ]

python3 - "${RECIPE}" > "${WORK}/patches.txt" <<'EOF'
import hashlib, json, sys
from pathlib import Path
recipe = Path(sys.argv[1])
lock = json.loads((recipe / "source.lock").read_text())
for patch in lock["patches"]:
    path = recipe / patch["path"]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != patch["sha256"]:
        sys.exit(f"{patch['path']}: sha256 {digest}, source.lock says {patch['sha256']}")
    print(path)
EOF
while read -r patch; do
  echo "==> apply ${patch#"${ROOT}/"}"
  git -C "${SRC}" apply --check "${patch}"
  git -C "${SRC}" apply "${patch}"
done < "${WORK}/patches.txt"
cp "${RECIPE}/Cargo.lock" "${SRC}/sgl-model-gateway/Cargo.lock"

echo "==> cargo test in ${image}"
mkdir -p "${WORK}/cargo-registry"
docker run --rm \
  -e SOURCE_DATE_EPOCH=0 \
  -v "${SRC}:/src" \
  -v "${WORK}/cargo-registry:/usr/local/cargo/registry" \
  -w /src/sgl-model-gateway \
  "${image}" \
  bash -euo pipefail -c '
    apt-get update -qq >/dev/null
    apt-get install -y -qq protobuf-compiler redis-server >/dev/null
    cargo test --locked --features vendored-openssl --lib
    cargo test --locked --features vendored-openssl --test reliability_tests
  '
