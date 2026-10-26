#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
python3 "$repo_root/tests/helm/test_render.py"
python3 "$repo_root/tests/helm/test_staging_validation_agent.py"
python3 "$repo_root/tests/helm/test_pd_layout.py"
exit 0
