#!/usr/bin/env python3
"""Check a Confidential Inference endpoint against a signed release.

Downloads the release files and TEErminator, runs each check, and prints
PASS or FAIL for each one. Exits 0 only when every check passes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

REPO = "https://github.com/confidential-dot-ai/confidential-inference"
TEERMINATOR = "https://github.com/confidential-dot-ai/TEErminator"
SCRIPTS = Path(__file__).resolve().parent
RELEASE_FILES = ("release-bundle.json", "release-bundle.sigstore.json", "allowlist.json")


class CheckFailed(Exception):
    pass


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def run(command: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, **kwargs)


def check_release(endpoint: str, release: str, out: Path) -> str:
    metadata = json.loads(fetch(f"{endpoint}/attestation"))
    (out / "attestation.json").write_text(json.dumps(metadata, indent=2))
    served = metadata["release"]
    if served["id"] != release:
        raise CheckFailed(f"the endpoint serves {served['id']}, not {release}")
    for name in RELEASE_FILES:
        (out / name).write_bytes(fetch(f"{REPO}/releases/download/{release}/{name}"))
    if sha256((out / "release-bundle.json").read_bytes()) != served["bundleSha256"]:
        raise CheckFailed("the release bundle on GitHub is not the bundle the endpoint reports")
    return f"{release}, bundle {served['bundleSha256'][7:19]}..."


def check_signature(out: Path) -> str:
    cosign = shutil.which("cosign")
    if cosign is None:
        raise CheckFailed("install Cosign v3 and put it on PATH")
    venv = out / "venv"
    python = venv / "bin" / "python"
    if not python.exists():
        if sys.version_info < (3, 11):
            raise CheckFailed("run this script with Python 3.11 or later")
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        install = run([str(python), "-m", "pip", "install", "--quiet", "--require-hashes",
                       "-r", str(SCRIPTS / "requirements-release-signing.txt")])
        if install.returncode:
            shutil.rmtree(venv)
            raise CheckFailed("pip install failed: " + install.stderr.strip()[-300:])
    result = run([str(python), str(SCRIPTS / "verify-release-bundle-signature.py"),
                  "--bundle", str(out / "release-bundle.json"),
                  "--signature-bundle", str(out / "release-bundle.sigstore.json"),
                  "--cosign", str(Path(cosign).resolve())])
    if result.returncode:
        raise CheckFailed(result.stderr.strip())
    return "signed by " + json.loads(result.stdout)["certificateIdentity"].split("/.github/")[1]


def check_policy(endpoint: str, out: Path) -> str:
    metadata = json.loads((out / "attestation.json").read_text())
    bundle = json.loads((out / "release-bundle.json").read_text())
    live = fetch(f"{endpoint}/allowlist")
    (out / "live-allowlist.json").write_bytes(live)
    digests = {
        "live policy": sha256(live),
        "reported policy": metadata["c8s"]["activeAllowlist"]["sha256"],
        "signed policy": bundle["allowlist"]["sha256"],
        "release allowlist.json": sha256((out / "allowlist.json").read_bytes()),
    }
    if len(set(digests.values())) != 1:
        raise CheckFailed("policies differ: " + ", ".join(f"{k} {v[7:19]}" for k, v in digests.items()))
    return f"live policy = signed policy {digests['live policy'][7:19]}..."


def download_teerminator(version: str, out: Path) -> str:
    system = platform.system().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}[platform.machine().lower()]
    archive = f"teerminator_{version.lstrip('v')}_{system}_{arch}.tar.gz"
    base = f"{TEERMINATOR}/releases/download/{version}"
    data = fetch(f"{base}/{archive}")
    sums = dict(line.split()[::-1] for line in fetch(f"{base}/checksums.txt").decode().splitlines() if line)
    if sums.get(archive) != hashlib.sha256(data).hexdigest():
        raise CheckFailed(f"{archive} does not match checksums.txt")
    (out / archive).write_bytes(data)
    with tarfile.open(out / archive) as tar:
        (out / "teerminator").write_bytes(tar.extractfile("teerminator").read())
    (out / "teerminator").chmod(0o755)
    return f"{archive} matches checksums.txt"


def check_connection(endpoint: str, out: Path) -> str:
    bundle = json.loads((out / "release-bundle.json").read_text())
    (out / "image-pin.json").write_text(json.dumps({k: bundle[k] for k in ("mrtd", "rtmr1", "rtmr2")}))
    workloads = json.loads((out / "allowlist.json").read_text())["workloads"]
    routers = [name for name in workloads if name.startswith("c8s-router-")]
    if len(routers) != 1:
        raise CheckFailed(f"expected one c8s-router-* workload, found {routers}")
    home = out / "teerminator-home"
    shutil.rmtree(home, ignore_errors=True)
    home.mkdir()
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"), "PATH": "/usr/bin:/bin"}
    teerminator = str(out / "teerminator")
    added = run([teerminator, "remote", "add", "127.0.0.1:8080", f"{endpoint}/",
                 "--mode", "attest-lb", "--server-name", endpoint.split("://", 1)[1],
                 "--image-manifest", str(out / "image-pin.json"),
                 "--allowlist", str(out / "live-allowlist.json"),
                 "--workload", routers[0], "--tdx-tcb-status", "UpToDate"], env=env)
    if added.returncode:
        raise CheckFailed(added.stderr.strip())
    status = run([teerminator, "status"], env=env).stdout
    if "Verified" not in status:
        detail = status.strip().splitlines()[-1]
        if "tcbInfo" in detail and sys.platform == "darwin":
            detail += " (see 'Intel PCS certificate on macOS' in docs/verification.md)"
        raise CheckFailed(detail)
    return f"Verified: workload {routers[0]}, image pinned, Intel TCB UpToDate"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("endpoint", help="for example https://api.confidential.ai")
    parser.add_argument("release", help="the release you approve, for example v0.15.15")
    parser.add_argument("--teerminator", default="v0.0.4", help="TEErminator release")
    parser.add_argument("--dir", type=Path, default=Path("client-review"), help="output directory")
    args = parser.parse_args()
    endpoint = args.endpoint.rstrip("/")
    out = args.dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    checks = [
        ("Release", lambda: check_release(endpoint, args.release, out)),
        ("Signature", lambda: check_signature(out)),
        ("Policy", lambda: check_policy(endpoint, out)),
        ("TEErminator", lambda: download_teerminator(args.teerminator, out)),
        ("Connection", lambda: check_connection(endpoint, out)),
    ]
    failed = False
    for name, check in checks:
        if failed:
            print(f"SKIP  {name}")
            continue
        try:
            print(f"PASS  {name}: {check()}")
        except (CheckFailed, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
            print(f"FAIL  {name}: {error}")
            failed = True
    if failed:
        return 1
    print(f"\nAll checks passed. Files are in {out}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
