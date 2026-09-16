#!/usr/bin/env python3
"""Test adapter for the external TDX quote verifier interface."""

from __future__ import annotations

import argparse
import json
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quote", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    if os.environ.get("FAKE_QUOTE_VERIFIER_FAIL") == "1":
        return 1
    if open(args.quote, "rb").read() != b"sample-tdx-quote":
        return 1
    with open(args.evidence, encoding="utf-8") as source:
        evidence = json.load(source)
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
