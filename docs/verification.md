# Verify Confidential Inference

## What verification proves

Verification shows that the endpoint runs a release that we signed and
published. It checks that the server runs the exact node image of that release
inside an Intel TDX confidential VM with current Intel security updates. It
checks that the server only allows the workloads listed in the release
policy. You can run these checks before you send an API key or a prompt.

This guide covers release `v0.15.15` (C8s `v0.59.1`, TEErminator `v0.0.4`).

## Quick check

You need `git`, Python 3.11 or later, and
[Cosign](https://github.com/sigstore/cosign) v3 on your `PATH`. The commands
work on macOS and Linux.

```sh
git clone https://github.com/confidential-dot-ai/confidential-inference.git
python3 confidential-inference/scripts/quick-verify.py https://api.confidential.ai v0.15.15
```

The script downloads the release files and TEErminator into `client-review/`.
It runs each check and prints one line per check. You should see:

```text
PASS  Release: v0.15.15, bundle 3c875412b8fd...
PASS  Signature: signed by workflows/release-bundle.yml@refs/tags/v0.15.15
PASS  Policy: live policy = signed policy 8de45cdb8f12...
PASS  TEErminator: teerminator_0.0.4_darwin_arm64.tar.gz matches checksums.txt
PASS  Connection: Verified: workload c8s-router-fb21f5cac23c, image pinned, Intel TCB UpToDate

All checks passed. Files are in .../client-review.
```

If the endpoint serves a different release, the Release check fails. Use this
guide at that release's tag instead.

> **macOS:** if the Connection check fails with `unable to receive tcbInfo`,
> your Mac lacks a certificate that Intel's server needs. Run
> `confidential-inference/scripts/macos-add-intel-pcs-intermediate.sh`, then
> run the check again. See [Intel PCS certificate on macOS](#intel-pcs-certificate-on-macos).

### Send requests through the verified connection

TEErminator is a local proxy. It checks the server again on each new
connection and blocks the request if a check fails. The script keeps
TEErminator's settings in `client-review/teerminator-home`, apart from your own.
Start the proxy:

```sh
cd client-review
HOME="$PWD/teerminator-home" ./teerminator start
```

Set your application's OpenAI base URL to `http://127.0.0.1:8080/v1` and use
your API key as usual.

## What each check means

- **Release:** the endpoint reports the release you chose, and its bundle
  digest matches the bundle published on GitHub.
- **Signature:** the release bundle was signed by this repository's release
  workflow for that tag, as recorded in the public Sigstore log.
- **Policy:** the allowlist that the endpoint enforces is byte for byte the
  allowlist signed in the release.
- **TEErminator:** the TEErminator download matches the published checksum.
- **Connection:** a fresh Intel TDX quote, bound to the server's TLS
  certificate, matches the release's node image (MRTD, RTMR1, RTMR2), the
  front-door workload, and the policy. Intel reports the platform as
  `UpToDate`.

The quick check does not review source code or every policy entry. It also
skips the C8s discovery check in step 5 below. For those, use the manual steps.

## Manual verification (advanced)

These steps do the same checks one by one, plus a few more. Run them in an
empty directory. They use `https://api.confidential.ai`. To check another
endpoint, replace that URL.

### 1. Read the public metadata

The endpoint reports which release and policy it uses. This needs no API key.

```sh
curl --fail --silent --show-error https://api.confidential.ai/attestation -o attestation.json
python3 -c 'import json; r = json.load(open("attestation.json"))["release"]; print(r["id"], r["bundleSha256"])'
```

You should see `v0.15.15 sha256:3c875412...`. A 503 means the gateway could
not refresh its metadata; retry later. Metadata is discovery only. It does not
prove the connection.

### 2. Download the release

The release files hold the pins that every later step checks against. The
checkout of `main` has the verification scripts.

```sh
git clone https://github.com/confidential-dot-ai/confidential-inference.git
cd confidential-inference
mkdir client-review
for file in release-bundle.json release-bundle.sigstore.json allowlist.json; do
  curl --fail --silent --show-error --location -o "client-review/$file" \
    "https://github.com/confidential-dot-ai/confidential-inference/releases/download/v0.15.15/$file"
done
shasum -a 256 client-review/release-bundle.json
```

The hash must equal `bundleSha256` from step 1.

### 3. Verify the release signature

The signature proves that this repository's release workflow built the bundle
for this tag.

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r scripts/requirements-release-signing.txt
.venv/bin/python scripts/verify-release-bundle-signature.py \
  --bundle client-review/release-bundle.json \
  --signature-bundle client-review/release-bundle.sigstore.json \
  --cosign "$(python3 -c 'import os, shutil; print(os.path.realpath(shutil.which("cosign")))')"
```

You should see JSON with `"verified":true` and a `certificateIdentity` that
ends in `release-bundle.yml@refs/tags/v0.15.15`. Cosign must be given as the
real file, not a symlink, which is what the `python3 -c` part finds.

The bundle names the product source commit, the C8s commit, the node image
measurements, the image digests, and the policy digest. Review the source at
those commits. Start with [release/README.md](../release/README.md).

### 4. Check and review the policy

The policy (allowlist) lists every workload that the cluster may run.

```sh
curl --fail --silent --show-error https://api.confidential.ai/allowlist -o client-review/live-allowlist.json
shasum -a 256 client-review/live-allowlist.json client-review/allowlist.json
```

Both hashes must be equal, and equal to `c8s.activeAllowlist.sha256` in
`attestation.json`. Do not reformat the JSON before you hash it.

Then read the policy. Check each entry's image, init containers, command,
arguments, environment, mounts, and secret grants. Some settings come from
runtime files; see [the gateway contract](../services/gateway/ATTESTATION.md#runtime-release-selection).
An authorized operator can change the policy, and a rollout can allow old and
new entries at the same time.

### 5. Check the C8s discovery data

This check compares the endpoint's C8s discovery data with the signed release.
It needs the C8s CLI at the exact commit that the release pins, built with the
Go version that commit requires, and the release's node manifest.

```sh
.venv/bin/python scripts/build-c8s-cli.py client-review/release-bundle.json client-review/c8s
git show v0.15.15:release/node-manifest.json > client-review/node-manifest.json
.venv/bin/python scripts/verify-public-attestation.py --metadata-only \
  --endpoint https://api.confidential.ai/attestation \
  --trusted-bundle client-review/release-bundle.json \
  --release-signature-bundle client-review/release-bundle.sigstore.json \
  --cosign "$(python3 -c 'import os, shutil; print(os.path.realpath(shutil.which("cosign")))')" \
  --node-manifest client-review/node-manifest.json \
  --allowlist client-review/live-allowlist.json \
  --deployment-target production --c8s client-review/c8s
```

You should see `"metadataMatchesTrustedInputs":true` and
`"connectionVerified":false`. The connection is checked in step 7.

### 6. Install TEErminator

TEErminator checks the connection and then acts as a local proxy. Pick the
archive for your system: `darwin_arm64`, `darwin_amd64`, `linux_amd64`, or
`linux_arm64`. This example uses `darwin_arm64`.

```sh
curl --fail --silent --show-error --location -O \
  https://github.com/confidential-dot-ai/TEErminator/releases/download/v0.0.4/checksums.txt
curl --fail --silent --show-error --location -O \
  https://github.com/confidential-dot-ai/TEErminator/releases/download/v0.0.4/teerminator_0.0.4_darwin_arm64.tar.gz
shasum -a 256 -c --ignore-missing checksums.txt
tar -xzf teerminator_0.0.4_darwin_arm64.tar.gz teerminator
```

You should see `teerminator_0.0.4_darwin_arm64.tar.gz: OK`. On Linux,
`sha256sum` works the same way. `checksums.txt` is not signed, so it only
catches a damaged download. For more assurance, build TEErminator from its
tagged source.

### 7. Check the connection

TEErminator gets a fresh Intel TDX quote and checks it against the release's
node image, front-door workload, and policy. First write the node image
measurements to a file, and find the front-door workload name in the signed
policy:

```sh
python3 -c 'import json; b = json.load(open("client-review/release-bundle.json")); json.dump({k: b[k] for k in ("mrtd", "rtmr1", "rtmr2")}, open("client-review/image-pin.json", "w"))'
grep -o '"c8s-router-[0-9a-f]*"' client-review/allowlist.json | sort -u
```

You should see `"c8s-router-fb21f5cac23c"`. This is the public front door.
Do not use an inference worker or `router-*` name. Now add the endpoint and
check it:

```sh
./teerminator remote add 127.0.0.1:8080 https://api.confidential.ai/ \
  --mode attest-lb --server-name api.confidential.ai \
  --image-manifest client-review/image-pin.json \
  --allowlist client-review/live-allowlist.json \
  --workload c8s-router-fb21f5cac23c \
  --tdx-tcb-status UpToDate
./teerminator status
```

You should see `Verified` and `tdx tcb status UpToDate`. `teerminator status`
exits with 0 even when a check fails, so read the output. Do not drop a pin or
accept more TCB statuses just to get `Verified`.

> **macOS:** `unable to receive tcbInfo: ... context deadline exceeded` means
> your Mac lacks a certificate for Intel's server. Run
> `scripts/macos-add-intel-pcs-intermediate.sh` and check again.

TEErminator saves this endpoint in
`~/Library/Application Support/teerminator/config.json` on macOS and
`~/.config/teerminator/config.json` on Linux.

### 8. Send requests

Start the proxy with `./teerminator start`. Set your application's OpenAI base
URL to `http://127.0.0.1:8080/v1` and use your API key. To let the proxy add
the key instead, run `./teerminator remote auth 127.0.0.1:8080 -` and type the
key on standard input. Do not put the key in a shell argument.

## Intel PCS certificate on macOS

With `--tdx-tcb-status`, TEErminator downloads Intel's TCB data from
`api.trustedservices.intel.com`. That server's certificate chains to Sectigo
Public Server Authentication Root R46. Some macOS versions, including macOS 13,
do not have this root, and the server does not send the link to an older root.
`SSL_CERT_FILE` does not help: TEErminator `v0.0.4` is built with Go 1.26,
which ignores it on macOS.

`scripts/macos-add-intel-pcs-intermediate.sh` downloads Sectigo's
cross-certificate for R46, which is signed by `AAA Certificate Services`, a
root that macOS trusts. It checks the SHA-256 fingerprint
`ce75580b...3d9419e4` and adds the certificate to your login keychain as an
intermediate. It does not change any trust setting. To remove it, run
`security delete-certificate -Z B84733486BA4F61D833FCD3F2C81804989373118 ~/Library/Keychains/login.keychain-db`.

On Linux, Go reads the system CA bundle. If the check fails there, update the
`ca-certificates` package.

## What TEErminator checks

TEErminator obtains fresh nonce-bound C8s evidence and binds it to the exact
public TLS certificate. It verifies the full image tuple and the matched
workload and policy claims. The mesh CA is authenticated through that evidence;
learning an unverified CA from discovery is not sufficient.

TCB means Trusted Computing Base: platform security versions such as firmware
and microcode. With `--tdx-tcb-status`, TEErminator fetches Intel's TCB
information, QE identity, and revocation lists. It rejects revoked
credentials, statuses that you did not accept, and missing Intel data. Without
that flag it checks only the quote signature and PCK chain.

TEErminator also reports the route digest that the front door attests.
Without `--route-digest` or `--route-operator-key`, it accepts any digest and
reports it as `unverified`.

**Deployment check, 2026-10-21, from macOS 13 (arm64) and Linux:**
`candidate.api.confidential.ai`, a test deployment, reported `v0.15.15`. The
live policy matched the signed policy. The quick check and the manual steps
passed, with TEErminator `v0.0.4` reporting `Verified` and Intel TCB
`UpToDate`. This is a dated check, not a permanent claim about an endpoint.

## Policy updates and verification scope

TEErminator caches a passing verdict for one minute, bounded by the
serving certificate's expiry and exact certificate identity. A workload stamp
states the policy used at certificate issuance. Fresh connection evidence does
not turn that stamp into an instantaneous read of the current CDS policy.
Do not claim that an allowlist write immediately closes all existing streams.

Review changes before replacing your local policy file. If you use direct
HTTPS and periodic checks instead, you accept the interval between checks.
A direct request does not enforce the TEErminator pins.

The front-door proof is not a census of all workers. The approved C8s and
application code must enforce admission and the protected internal request
path. An allowlisted image with a permissive entry deserves separate review.

## GPU verification

The pinned node image runs a measured GPU confidential-computing boot gate.
It verifies the passed-through NVIDIA GPUs before RKE2 can start. A failed
check prevents node admission and powers off the node. Review the gate,
systemd dependency, and source lock at the release's C8s commit.

This contract verifies the enforcement code through the node measurements.
It does not require clients to verify raw GPU reports, and version 3 does not
return those reports. TEErminator does not claim to be a separate NVIDIA
verifier. The serving workers must remain inside that measured enforcement
boundary.

## Configuration negative tests

At the exact C8s commit pinned by your selected release, inspect:

- `internal/cmds/nri-image-policy/env_test.go`: final environment admission.
- `internal/cmds/nri-image-policy/mount_phase_test.go`: final mount admission.
- `pkg/allowlist/mountenv_test.go`,
  `TestMountPolicyRefusesAnUndeclaredDestination`: a bind over an undeclared
  image executable path is rejected without changing the image digest.
- `internal/cmds/cds/attest_matchedworkload_test.go`: workload stamps require
  matching environment and mount evidence.

These checks run at different layers. A policy must declare the restrictions
for those checks to reject changes. A launch input outside the permitted
policy needs a reviewed policy change. Settings in approved runtime files
can change within the limits enforced by the approved application code.
Runtime application admin routes are separate from launch configuration.
