# Verify Confidential Inference

Review the release and permitted workloads before you send an API key or a
prompt. Public discovery needs no API key. Use TEErminator when you want to enforce the
reviewed policy on inference connections. You can instead connect directly
and verify periodically, accepting the interval between checks.

## 1. Read the public metadata

Set the endpoint that you intend to call. The commands below work on macOS and
Linux.

```sh
ENDPOINT=https://api.confidential.ai
HOST="${ENDPOINT#https://}"
curl --fail --silent --show-error "$ENDPOINT/attestation" -o attestation.json
python3 -c 'import json; r = json.load(open("attestation.json"))["release"]; print(r["id"], r["bundleSha256"])'
```

Schema version 3 returns the selected release ID, release URL, bundle digest,
active allowlist document and byte digest, native C8s discovery, and active
operator public keys. It needs no nonce. It has no worker receipts or raw GPU
reports. A successful response is discovery, not a verified connection or a
list of every running pod.

Use the endpoint that you intend to call. Production and a test deployment
can select different releases and policies. Do not combine their inputs.
A 503 means the gateway could not refresh its verified CDS metadata. Retry
with backoff. Do not accept a partial response as verification.

## 2. Select and verify a release

The `release.id` from step 1 is the release that the endpoint serves. Verify
that release, and approve it only after your review. The server's report is
not an automatic approval. Each release has its own pins: node image
measurements, allowlist, front-door workload name, and the TEErminator release
that can check it. Take every pin from the release that the endpoint serves.
When the endpoint moves to a new release, repeat this guide for the new
release.

| Release | C8s | TEErminator | Front-door workload |
|---|---|---|---|
| `v0.14.29` | `v0.44.6` | `v0.0.2` or `v0.0.3` | `c8s-router` |
| `v0.15.15` | `v0.59.1` | `v0.0.4` | `c8s-router-fb21f5cac23c` |

TEErminator `v0.0.4` requires a front door that attests a route digest.
`v0.14.29` does not, so `v0.0.4` rejects it with `bundle carries no
route_digest`. TEErminator `v0.0.3` rejects `v0.15.15`.

You need `git`, the GitHub CLI `gh`, Python 3.11 or later, Go, and
[Cosign](https://github.com/sigstore/cosign) v3. The default `python3` on
macOS 13 is 3.9. Use a newer Python, for example from python.org or Homebrew.

```sh
RELEASE=v0.15.15   # the release.id from step 1, after you approve it
git clone https://github.com/confidential-dot-ai/confidential-inference.git
cd confidential-inference
git checkout "$RELEASE"
mkdir -p client-review
gh release download "$RELEASE" \
  --repo confidential-dot-ai/confidential-inference \
  --pattern release-bundle.json --pattern release-bundle.sigstore.json \
  --pattern allowlist.json --pattern image-publication-manifest.json \
  --pattern release-tag-commit.txt --dir client-review
shasum -a 256 client-review/release-bundle.json
```

The bundle hash must equal `release.bundleSha256` from step 1.

Install the verifier dependencies from the lock file on `main`. The lock file
in `v0.15.15` and earlier tags has hashes only for Linux wheels, so it fails
on macOS. The package versions are the same.

```sh
git show origin/main:scripts/requirements-release-signing.txt \
  > client-review/requirements.txt
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --require-hashes -r client-review/requirements.txt
COSIGN="$(python3 -c 'import os, shutil; print(os.path.realpath(shutil.which("cosign")))')"
python3 scripts/verify-release-bundle-signature.py \
  --bundle client-review/release-bundle.json \
  --signature-bundle client-review/release-bundle.sigstore.json \
  --cosign "$COSIGN"
```

Use the actual Cosign executable path, not a symlink. Select the release-signing
policy and Sigstore root from an independently trusted checkout. The signature
must match the repository, workflow, release tag, and exact bundle bytes.

The signed manifest identifies the product source commit, exact C8s commit,
node image and MRTD/RTMR1/RTMR2, application image digests, image publication
evidence, and initial allowlist digest. Compare each downloaded asset with its
manifest digest. Review the source and image publication evidence at those
commits. Start with [release/README.md](../release/README.md) for build and
publication details. Public source does not establish that reviewed code has
no defects.

Do not use the old PEM files under `releases/production/trust/` as current
production inputs. They belong to historical releases. The current release
manifest does not require a fixed deployment mesh CA or operator key.

## 3. Review the active policy

Fetch the exact policy bytes from the native allowlist URL reported in the
metadata:

```sh
curl --fail --silent --show-error "$ENDPOINT/allowlist" \
  -o client-review/live-allowlist.json
shasum -a 256 client-review/live-allowlist.json client-review/allowlist.json
```

Compare that byte hash with `c8s.activeAllowlist.sha256`. Do not reformat the
JSON before hashing or pinning it. Review every permitted entry, including
core images, init containers, environment values, mounts, and secret grants.
Application entries constrain commands, arguments, environment, and mounts.
These checks constrain launch inputs. Some approved settings are read from
runtime configuration files; the allowed fields and validation are documented
in [the gateway contract](../services/gateway/ATTESTATION.md#runtime-release-selection).
A pinned mount does not make every file in that mount immutable.
Application restrictions do not imply that every core entry has the same
restrictions; inspect the policy.

The allowlist states what may run. Several old and new definitions can be
permitted during a rollout. Review their source and artifact history too.
An authorized operator can change the policy. Production does not promise
zero Kubernetes API rights or zero RTMR3.

Build the C8s CLI at `c8s.sourceCommit` in the signature-verified manifest.
The CLI build needs the Go version required by that checkout. Stamp the exact
source commit so the metadata verifier can check the CLI version:

```sh
C8S_COMMIT="$(python3 -c 'import json; print(json.load(open("client-review/release-bundle.json"))["c8s"]["sourceCommit"])')"
git clone --no-checkout https://github.com/confidential-dot-ai/c8s.git \
  client-review/c8s-source
git -C client-review/c8s-source checkout --detach "$C8S_COMMIT"
(
  cd client-review/c8s-source
  go build -ldflags "-X github.com/confidential-dot-ai/c8s/internal/version.Version=$C8S_COMMIT" \
    -o ../c8s ./cmd/c8s
)
```

Use the exact node manifest for the release. The tagged checkout contains it at
`release/node-manifest.json`. Compare its hash with
`nodeImage.manifestSha256` before use.

```sh
python3 scripts/verify-public-attestation.py --metadata-only \
  --endpoint "$ENDPOINT/attestation" \
  --trusted-bundle client-review/release-bundle.json \
  --release-signature-bundle client-review/release-bundle.sigstore.json \
  --cosign "$COSIGN" \
  --node-manifest release/node-manifest.json \
  --release-allowlist client-review/allowlist.json \
  --allowlist client-review/live-allowlist.json \
  --deployment-target production --c8s client-review/c8s
```

`--release-allowlist` verifies the signed initial policy separately from the
live policy that you reviewed. It does not make later policy changes signed
release assets. Without this option, the live policy must equal the signed
initial policy. The separate-policy option is needed only when you
deliberately review a different live policy.

A successful result contains `metadataMatchesTrustedInputs: true` and
`connectionVerified: false`. Continue with the connection check.

## 4. Enforce the policy with TEErminator

Use the TEErminator release from the table in step 2, or a later release that
you review and that supports your selected release. Download the archive for
your platform and check it against the published `checksums.txt`:

```sh
TEERMINATOR_VERSION=v0.0.4   # v0.0.3 for v0.14.29
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"   # darwin or linux
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  arm64 | aarch64) ARCH=arm64 ;;
esac
ARCHIVE="teerminator_${TEERMINATOR_VERSION#v}_${OS}_${ARCH}.tar.gz"
mkdir -p client-review/teerminator
(
  cd client-review/teerminator
  BASE="https://github.com/confidential-dot-ai/TEErminator/releases/download/$TEERMINATOR_VERSION"
  curl --fail --silent --show-error --location -O "$BASE/checksums.txt"
  curl --fail --silent --show-error --location -O "$BASE/$ARCHIVE"
  grep "  $ARCHIVE\$" checksums.txt | shasum -a 256 -c -
  tar -xzf "$ARCHIVE" teerminator
)
export PATH="$PWD/client-review/teerminator:$PATH"
teerminator --version
```

`shasum -a 256 -c` must print `OK`. On Linux, `sha256sum -c -` works the same
way. The `checksums.txt` file is not signed. It detects a damaged download,
not a changed release. To check the binary further, build it from the tagged
TEErminator source.

Create the flat TDX image tuple from the signature-verified manifest:

```sh
python3 - <<'PIN'
import json
from pathlib import Path
bundle = json.loads(Path('client-review/release-bundle.json').read_text())
Path('client-review/image-pin.json').write_text(json.dumps(
    {name: bundle[name] for name in ('mrtd', 'rtmr1', 'rtmr2')}))
PIN
```

Read the front-door workload name from the signed release allowlist. C8s names
the public front door `c8s-router`. Newer C8s releases add an image digest
suffix, for example `c8s-router-fb21f5cac23c` in `v0.15.15`. Do not substitute
an inference-worker or `router-*` name for the public front door.

```sh
WORKLOAD="$(python3 -c 'import json; names = [n for n in json.load(open("client-review/allowlist.json"))["workloads"] if n == "c8s-router" or n.startswith("c8s-router-")]; assert len(names) == 1, names; print(names[0])')"
echo "$WORKLOAD"
```

Add the remote and check it:

```sh
teerminator remote add 127.0.0.1:8080 "$ENDPOINT/" \
  --mode attest-lb --server-name "$HOST" \
  --image-manifest client-review/image-pin.json \
  --allowlist client-review/live-allowlist.json \
  --workload "$WORKLOAD" \
  --tdx-tcb-status UpToDate
teerminator status
```

Require `Verified` before sending inference traffic. `teerminator status`
exits with status 0 even when a remote shows `Failed`, so read its output.
Do not omit a failed pin or broaden accepted TCB statuses merely to obtain
that result. You can inspect metadata and perform connection verification
without an inference API key. TEErminator stores its remotes in
`~/Library/Application Support/teerminator/config.json` on macOS and in
`~/.config/teerminator/config.json` on Linux.

### Intel PCS certificate on macOS

With `--tdx-tcb-status`, TEErminator fetches Intel collateral from
`api.trustedservices.intel.com`. That server's certificate chains to Sectigo
Public Server Authentication Root R46, and the server does not send the
cross-certificate. Some macOS versions, including macOS 13, do not have that
root. The check then fails with:

```text
DCAP verification failed: unable to receive tcbInfo: could not receive tcbInfo response: context deadline exceeded
```

`SSL_CERT_FILE` does not fix this. TEErminator `v0.0.4` is built with Go 1.26,
which uses the macOS trust store and ignores that variable on macOS. Instead,
add Sectigo's cross-certificate to your login keychain. The cross-certificate
is R46 signed by `AAA Certificate Services`, which macOS already trusts.
Adding it as an intermediate certificate does not change any trust setting.

```sh
curl --fail --silent --show-error --location \
  http://crt.sectigo.com/SectigoPublicServerAuthenticationRootR46.p7c \
  -o client-review/sectigo-r46.p7c
python3 - <<'CERT'
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
certs = pkcs7.load_der_pkcs7_certificates(Path('client-review/sectigo-r46.p7c').read_bytes())
cross = next(c for c in certs if c.issuer != c.subject)
print(cross.issuer.rfc4514_string())
print(cross.fingerprint(hashes.SHA256()).hex())
Path('client-review/sectigo-r46-cross.pem').write_bytes(cross.public_bytes(serialization.Encoding.PEM))
CERT
security add-certificates -k ~/Library/Keychains/login.keychain-db \
  client-review/sectigo-r46-cross.pem
```

The script must print `CN=AAA Certificate Services,...` and the SHA-256
fingerprint `ce75580bc6796d3b3ea2c3e74259d0d403072408e960c77139c2fb5a3d9419e4`.
Then run `teerminator status` again. To remove the certificate later, run
`security delete-certificate -Z B84733486BA4F61D833FCD3F2C81804989373118 ~/Library/Keychains/login.keychain-db`.

On Linux, Go reads the system CA bundle. If that bundle lacks the R46 root,
update the `ca-certificates` package or set `SSL_CERT_FILE` to a current CA
bundle file.

### What TEErminator checks

TEErminator obtains fresh nonce-bound C8s evidence and binds it to the exact
public TLS certificate. It verifies the full image tuple and the matched
workload and policy claims. The mesh CA is authenticated through that evidence;
learning an unverified CA from discovery is not sufficient. A fixed mesh CA
is optional when your policy accepts the measured deployment class.

TCB means Trusted Computing Base. It includes platform security versions
such as firmware and microcode. Revocation checks identify credentials that
Intel has withdrawn. Collateral is the signed Intel data used for these checks.

Online Intel checks fetch TCB information, QE identity, and revocation lists.
They reject revoked credentials, unacceptable TCB statuses, and unavailable
collateral. Without `--tdx-tcb-status`, TEErminator checks the quote signature
and PCK chain offline; it does not evaluate current Intel TCB status. Review
any additional accepted status and its required mitigations explicitly.

TEErminator `v0.0.4` also reports the route digest that the front door
attests. Without `--route-digest` or `--route-operator-key`, it accepts any
digest and reports it as `unverified`.

**Deployment checks, 2026-10-21, from macOS 13 (arm64):**

- `api.confidential.ai` reported `v0.14.29`. The live policy matched the
  signed initial policy. TEErminator `v0.0.3` passed with the complete
  node-image tuple, exact policy bytes, the `c8s-router` workload, the
  production TLS name, and an online Intel policy accepting only `UpToDate`.
- `candidate.api.confidential.ai`, a test deployment, reported `v0.15.15`.
  TEErminator `v0.0.4` passed the same checks with the
  `c8s-router-fb21f5cac23c` workload.

These are dated connection checks, not permanent assertions about an endpoint.

### Send requests through the proxy

After a passing result, start the proxy with `teerminator start`. Set your
application's OpenAI base URL to `http://127.0.0.1:8080/v1` and supply its API
key. Alternatively, let the proxy attach the key: `teerminator remote auth
127.0.0.1:8080 -` reads the key from standard input. Do not put the key in a
shell argument.

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
