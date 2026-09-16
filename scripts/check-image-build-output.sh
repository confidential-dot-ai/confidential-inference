#!/usr/bin/env bash
set -euo pipefail

digest=${1:-}
archive=${2:-}

if [[ ! $digest =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "FAIL: the image build did not return an immutable SHA-256 digest" >&2
  exit 1
fi

if [[ -n $archive && ! -s $archive ]]; then
  echo "FAIL: the image build did not create the OCI archive: $archive" >&2
  exit 1
fi

printf 'PASS: the image build returned %s\n' "$digest"
