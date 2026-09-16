#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
chart="$repo_root/helm/confidential-inference"
kubeconform_image="ghcr.io/yannh/kubeconform@sha256:85dbef6b4b312b99133decc9c6fc9495e9fc5f92293d4ff3b7e1b30f5611823c"

# inference.mode has no chart default, so this neutral render must state a
# mode. The choice does not matter here; it only proves the manifests validate.
helm template example "$chart" --set inference.mode=simulator |
  docker run --rm --interactive "$kubeconform_image" -strict -summary

helm template maintenance "$repo_root/helm/maintenance-gateway" --namespace maintenance |
  docker run --rm --interactive "$kubeconform_image" -strict -summary
