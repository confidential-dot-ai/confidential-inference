#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

python3 -m unittest discover -s tests/contracts -p 'test_*.py'
python3 -m unittest discover -s tests/c8s-install-v0 -p 'test_*.py'
python3 -m unittest discover -s tests/attestation-v0 -p 'test_*.py'
python3 -m unittest discover -s tests/attestation-receipts-v0 -p 'test_*.py'
python3 -m unittest discover -s tests/image-workflow -p 'test_*.py'
python3 -m unittest discover -s tests/network-v0 -p 'test_*.py'
python3 -m unittest discover -s tests/images/gateway -p 'test_*.py'
python3 -m unittest discover -s tests/images/control-plane-node -p 'test_*.py'
python3 -m unittest discover -s tests/images/sglang -p 'test_*.py'
python3 -m unittest discover -s tests/model-mount-v0 -p 'test_*.py'
python3 -m unittest discover -s tests/release-v0 -p 'test_*.py'
python3 -m unittest discover -s tests/source-boundary -p 'test_*.py'
python3 -m unittest discover -s tests/ci-workflow -p 'test_*.py'
python3 scripts/validate-json.py
python3 scripts/validate-source-boundary.py
# inference.mode has no chart default, so this neutral lint must state a
# mode. The choice does not matter here; it only proves the chart lints.
helm lint helm/confidential-inference --set inference.mode=simulator
helm lint helm/maintenance-gateway
helm template maintenance helm/maintenance-gateway --namespace maintenance >/dev/null
bash tests/helm/run.sh
scripts/validate-kubernetes.sh
bash tests/router-v0/test_sglang_router.sh
cargo test --locked --package confidential-gateway
cargo clippy --locked --package confidential-gateway --all-targets -- -D warnings
cargo test --locked --package maintenance-gateway
cargo clippy --locked --package maintenance-gateway --all-targets -- -D warnings
