#!/usr/bin/env python3
"""Print the image publication matrix for one workflow-dispatch target."""

from __future__ import annotations

import argparse
import json


IMAGES = [
    {
        "image": "sglang",
        "context": "images/sglang",
        "dockerfile": "images/sglang/Dockerfile",
        "title": "Confidential Inference stock SGLang",
    },
    {
        "image": "gateway",
        "context": ".",
        "dockerfile": "images/gateway/Dockerfile",
        "title": "Confidential Inference gateway",
    },
    {
        "image": "maintenance-gateway",
        "context": ".",
        "dockerfile": "images/maintenance-gateway/Dockerfile",
        "title": "Confidential Inference maintenance gateway",
    },
    {
        "image": "metrics-collector",
        "context": "images/metrics-collector",
        "dockerfile": "images/metrics-collector/Dockerfile",
        "title": "Confidential Inference metrics collector",
    },
    {
        "image": "kube-state-metrics",
        "context": "images/kube-state-metrics",
        "dockerfile": "images/kube-state-metrics/Dockerfile",
        "title": "Confidential Inference kube-state metrics",
    },
]


def matrix(target: str) -> dict[str, list[dict[str, str]]]:
    if target == "all":
        selected = IMAGES
    else:
        selected = [item for item in IMAGES if item["image"] == target]
        if not selected:
            raise ValueError(f"unknown publish target: {target}")
    return {"include": selected}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    args = parser.parse_args()
    print(json.dumps(matrix(args.target), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
