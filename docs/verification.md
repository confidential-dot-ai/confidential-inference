# Verify Confidential Inference

Review the release and permitted workloads before you send an API key or a
prompt. Public discovery needs no API key. Use TEErminator to enforce the
reviewed policy on the inference connection.

## 1. Read the public metadata

```sh
curl --fail --silent --show-error https://api.confidential.ai/attestation \
  -o attestation.json
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

Select a release that you approve. Do not automatically approve the version
reported by the server. The following example uses `v0.14.16`, which the
production endpoint reported on 2026-10-10.

```sh
RELEASE=v0.14.16
git clone https://github.com/confidential-dot-ai/confidential-inference.git
cd confidential-inference
git checkout "$RELEASE"
mkdir -p client-review
gh release download "$RELEASE" \
  --repo confidential-dot-ai/confidential-inference \
  --pattern release-bundle.json --pattern release-bundle.sigstore.json \
  --pattern allowlist.json --pattern image-publication-manifest.json \
  --pattern release-tag-commit.txt --dir client-review
python3 -m pip install -r scripts/requirements-release-signing.txt
python3 scripts/verify-release-bundle-signature.py \
  --bundle client-review/release-bundle.json \
  --signature-bundle client-review/release-bundle.sigstore.json \
  --cosign /path/to/real/cosign-binary
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
metadata. For the production origin:

```sh
curl --fail --silent --show-error https://api.confidential.ai/allowlist \
  -o client-review/live-allowlist.json
sha256sum client-review/live-allowlist.json
```

Compare that byte hash with `c8s.activeAllowlist.sha256`. Do not reformat the
JSON before hashing or pinning it. Review every permitted entry, including
core images, init containers, environment values, mounts, and secret grants.
Application entries constrain environment and mounts. This does not imply
that every core entry has those restrictions; inspect the policy.

The allowlist states what may run. Several old and new definitions can be
permitted during a rollout. Review their source and artifact history too.
An authorized operator can change the policy. Production does not promise
zero Kubernetes API rights or zero RTMR3.

Build or obtain the C8s CLI at `c8s.sourceCommit` in the selected manifest.
Use its exact node manifest. The example release contains that manifest at
`release/node-manifest.json` in the tagged checkout. Compare its hash with
`nodeImage.manifestSha256` before use.

```sh
python3 scripts/verify-public-attestation.py --metadata-only \
  --endpoint https://api.confidential.ai/attestation \
  --trusted-bundle client-review/release-bundle.json \
  --release-signature-bundle client-review/release-bundle.sigstore.json \
  --cosign /path/to/real/cosign-binary \
  --node-manifest release/node-manifest.json \
  --release-allowlist client-review/allowlist.json \
  --allowlist client-review/live-allowlist.json \
  --deployment-target production --c8s /path/to/pinned/c8s
```

`--release-allowlist` verifies the signed initial policy separately from the
live policy that you reviewed. It does not make later policy changes signed
release assets. Without this option, the live policy must equal the signed
initial policy. On 2026-10-10 the two production policies differed, and this
explicit separate-policy check passed.

A successful result contains `metadataMatchesTrustedInputs: true` and
`connectionVerified: false`. Continue with the connection check.

## 4. Enforce the policy with TEErminator

Use [TEErminator v0.0.2](https://github.com/confidential-dot-ai/TEErminator/releases/tag/v0.0.2)
or a later release that you review. Version 0.0.2 includes ACME certificate
support and optional online Intel collateral verification. Check the published
archive checksum before use. The old v0.0.1 client is not the supported example.

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

Select the reviewed front-door workload from the policy. For the production
policy checked on 2026-10-10 it was `nginx-unprivileged-3af0c10d960c`.
Do not substitute an inference-worker name for the public front door.

```sh
teerminator remote add 127.0.0.1:8080 https://api.confidential.ai/ \
  --mode attest-lb --server-name api.confidential.ai \
  --image-manifest client-review/image-pin.json \
  --allowlist client-review/live-allowlist.json \
  --workload nginx-unprivileged-3af0c10d960c \
  --tdx-tcb-status UpToDate
teerminator status
```

Require `Verified` before sending inference traffic. Do not omit a failed pin
or broaden accepted TCB statuses merely to obtain that result. You can inspect
metadata and perform connection verification without an inference API key.

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
collateral. Without `--tdx-tcb-status`, v0.0.2 checks the quote signature and
PCK chain offline; it does not evaluate current Intel TCB status. Review any
additional accepted status and its required mitigations explicitly.

**Deployment check, 2026-10-10:** the current production image, workload, and
allowlist checks passed. Online Intel verification reported platform TCB
`OutOfDate`, so the example requiring `UpToDate` failed closed. The cluster
needs a platform remediation or a separately justified client policy before
it meets that strict requirement. This is not an API-key or parser failure.

After a passing result, set your application's OpenAI base URL to
`http://127.0.0.1:8080/v1` and supply its API key. Start the proxy with
`teerminator start`. Alternatively, use the documented TEErminator token-input
command to let the proxy attach the key. Do not put the key in a shell argument.

## Policy updates and verification scope

TEErminator v0.0.2 caches a passing verdict for one minute, bounded by the
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

At the C8s commit pinned by `v0.14.16`, inspect:

- `internal/cmds/nri-image-policy/env_test.go`: final environment admission.
- `internal/cmds/nri-image-policy/mount_phase_test.go`: final mount admission.
- `pkg/allowlist/mountenv_test.go`,
  `TestMountPolicyRefusesAnUndeclaredDestination`: a bind over an undeclared
  image executable path is rejected without changing the image digest.
- `internal/cmds/cds/attest_matchedworkload_test.go`: workload stamps require
  matching environment and mount evidence.

These checks run at different layers. A policy must declare the restrictions
for those checks to reject changes. An explicitly permitted tuning value can
run; a different value needs a reviewed policy change. Runtime application
admin routes are a separate review item from launch configuration.
