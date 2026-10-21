#!/usr/bin/env python3
"""Build the C8s CLI at the exact commit that a release bundle pins.

Usage: build-c8s-cli.py RELEASE_BUNDLE OUTPUT
The binary is stamped with the commit so the metadata verifier can check it.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    bundle, output = Path(sys.argv[1]), Path(sys.argv[2]).resolve()
    commit = json.loads(bundle.read_text())["c8s"]["sourceCommit"]
    with tempfile.TemporaryDirectory() as source:
        subprocess.run(["git", "clone", "--quiet", "--no-checkout",
                        "https://github.com/confidential-dot-ai/c8s.git", source], check=True)
        subprocess.run(["git", "-C", source, "checkout", "--quiet", "--detach", commit], check=True)
        subprocess.run(["go", "build", "-ldflags",
                        f"-X github.com/confidential-dot-ai/c8s/internal/version.Version={commit}",
                        "-o", str(output), "./cmd/c8s"], cwd=source, check=True)
    print(f"built {output} at C8s commit {commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
