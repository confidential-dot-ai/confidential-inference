#!/usr/bin/env python3
"""Verify an externally supplied Sigstore release signature without network access."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from release_signature import ReleaseSignatureError, verify_release_signature


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--bundle", type=Path, required=True)
    result.add_argument("--signature-bundle", type=Path, required=True)
    result.add_argument("--cosign", type=Path)
    result.add_argument("--timeout-seconds", type=int, default=60)
    return result


def main() -> int:
    args = parser().parse_args()
    cosign = args.cosign or (Path(value) if (value := shutil.which("cosign")) else None)
    if cosign is None:
        print("verification failed: the required Cosign verifier is not installed", file=sys.stderr)
        return 1
    try:
        output = verify_release_signature(
            args.bundle,
            args.signature_bundle,
            cosign,
            args.timeout_seconds,
        )
    except (OSError, ReleaseSignatureError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
