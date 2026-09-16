#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
python3 "$repo_root/tests/helm/test_render.py"
exec python3 "$repo_root/tests/helm/test_named_workload_proxy.py"
