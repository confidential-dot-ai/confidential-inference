# Confidential Inference

This repository contains the public confidential-inference product. It is the
source for the OCI workloads, the TDX node image, the Kubernetes chart, the c8s
policy tools, and the attestation verifier.

Before you contribute or create a release, read the
[developer workflow](docs/runbooks/developer-workflow.md).

Live environment configuration does not belong here. Operators keep machine
names, addresses, domains, resource sizes, secret paths, and deployment
receipts in a separate private repository.

## Components

- `services/gateway`: API-key checks, request limits, routing, and attestation.
- `images/sglang`: the pinned SGLang worker and router build. The same image
  runs a real model in production and a GPU-free simulator in staging.
- `services/maintenance-gateway`: the fallback API.
- `images/control-plane-node`: the reproducible ConfOS node-image inputs.
- `helm/confidential-inference`: the generic Kubernetes application chart.
- `scripts/regenerate-c8s-allowlist.py`: c8s policy generation.
- `scripts/verify-public-attestation.py`: receipt-set verification.
- `contracts`: public API, attestation, release, network, and metrics contracts.

## Build and publish

The manual image workflow takes an intended release candidate and a prior
release ref. It builds and publishes only images whose build inputs changed
between that ref and `main`. The release record must use each Linux AMD64 image
digest. It must not use a multi-platform index digest.

```sh
./images/gateway/build.sh
./images/sglang/build.sh
```

The fallback image uses its Dockerfile in `services/`. The node-image build
inputs and measured TDX values are in `images/control-plane-node/`.

## Run locally

This section builds and starts the gateway on your own machine. Use it for
local development only. It does not enable attestation, and it does not
enable the persistent state disk that production uses.

The `GATEWAY_C8S_RECEIPT_TARGETS` value below names the same inference-worker
targets that integration staging uses. This quickstart never calls
`/attestation`, so nothing needs to listen on those addresses; the gateway
only checks that the value parses.

Install a stable Rust toolchain, then build the gateway:

```sh
cargo build -p confidential-gateway
```

The gateway needs a P-256 admin certificate file to start, even in local
development mode. Generate one:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/admin-client.key
openssl req -x509 -new -key /tmp/admin-client.key -sha256 -days 1 \
  -subj "/CN=admin-client" -out /tmp/admin-client.crt
```

Start the gateway in a second terminal. The values below are local-development
placeholders. They are not real attestation or release identities:

```sh
GATEWAY_MODEL=staging-simulator \
GATEWAY_C8S_RECEIPT_TARGETS="gateway|gateway|gateway=http://127.0.0.1:8800,sglang-router|sglang-router|sglang-router=http://sglang-router:8801,inference-worker-0|inference-worker-0|inference-worker-0=http://inference-worker-0-0.inference-workers:8802,inference-worker-1|inference-worker-1|inference-worker-1=http://inference-worker-1-0.inference-workers:8802" \
GATEWAY_C8S_EVIDENCE_BASE_URL=https://api.example.test \
GATEWAY_RELEASE_ID=local-dev \
GATEWAY_RELEASE_BUNDLE_SHA256=sha256:1111111111111111111111111111111111111111111111111111111111111111 \
GATEWAY_EXPECTED_OPERATOR_PUBLIC_KEY_SHA256=sha256:2222222222222222222222222222222222222222222222222222222222222222 \
GATEWAY_EXPECTED_OPERATOR_KEY_SET_SHA256=sha256:3333333333333333333333333333333333333333333333333333333333333333 \
DEPLOYMENT_ENVIRONMENT=integration-staging \
GATEWAY_ADMIN_SIGNER_CERTIFICATE_FILE=/tmp/admin-client.crt \
./target/debug/confidential-gateway
```

Confirm the gateway is up:

```sh
curl -s http://127.0.0.1:9443/health
```

This returns `{"status":"ok"}`.

The gateway is fail-closed by design. It refuses every request, including
`/v1/chat/completions`, until it can read a real, mounted, production-style
state disk. A bare local build has no such disk, so a request to
`/v1/chat/completions` here correctly returns a `429` with the code
`gateway_state_unavailable`. This is intended security behavior, not a bug,
and this quickstart does not attempt to bypass it.

To see one full chat completion answered by the real gateway code, run the
gateway's own test. This test builds the same request router, points it at a
real HTTP upstream, and asserts a genuine `200` chat completion response:

```sh
cargo test -p confidential-gateway --test fake_upstream \
  gateway_forwards_to_the_internal_router_without_the_caller_key
```

## What attestation proves

The `/attestation` route returns signed c8s receipts for the workloads that are
part of the release. A successful verification proves these facts:

- The responding nodes started in Intel TDX confidential virtual machines.
- The measured ConfOS base image matches the approved node manifest.
- c8s admitted each reported container image and command.
- Each reported image digest is in the signed c8s allowlist.
- The response is bound to the nonce that the verifier supplied.

It does not prove that the service is healthy now. Use `/health` for that
check.

See `docs/threat-model.md` for the full trust boundary, the residual risks,
and the known gaps under remediation.
See [`docs/client-verification.md`](docs/client-verification.md) for the full client verification flow.

## Verify one live attestation

Install Python 3, `jsonschema`, and `cryptography`. Build the c8s command from
the exact public c8s commit in
`contracts/c8s-admission-source-lock.json`:

```sh
git clone https://github.com/confidential-dot-ai/c8s /tmp/c8s
git -C /tmp/c8s checkout 079aeb48c4d523aa7500b4bd78f0283b2d12e317
make -C /tmp/c8s VERSION="$(git -C /tmp/c8s rev-parse HEAD)" build
```

Check out the selected public release tag. Download `release-bundle.json` and
`release-bundle.sigstore.json` from its GitHub Release. Do not use a
source-tree bundle without its matching signature file. Fetch the current
signed allowlist. Create a new random nonce. Then run the public verifier:

```sh
curl -fsS https://api.confidential.ai/allowlist -o /tmp/allowlist.json
NONCE="$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode())')"
python3 scripts/verify-public-attestation.py \
  --endpoint https://api.confidential.ai/attestation \
  --nonce "$NONCE" \
  --trusted-bundle /tmp/release-bundle.json \
  --release-signature-bundle /tmp/release-bundle.sigstore.json \
  --cosign /usr/local/bin/cosign \
  --node-manifest images/control-plane-node/manifest-production.json \
  --node-source-lock images/sglang/source.lock \
  --allowlist /tmp/allowlist.json \
  --operator-public-key releases/production/trust/operator-public-key.pem \
  --mesh-ca releases/production/trust/mesh-ca.pem \
  --environment production \
  --c8s /tmp/c8s/build/c8s
```

The command uses the source-controlled Sigstore root. It does not use the
network for signature verification. It fails if the release bytes, GitHub
Actions OIDC issuer, workflow identity, tag, repository claims, transparency
proof, or any attestation value differs. It prints `"verified":true` only
after all checks pass.

The example above verifies production. Each environment seals its own
allowlist into its own measured node image, so each environment has its own
node manifest. Pass
`--node-manifest images/control-plane-node/manifest-integration-staging.json`
and `--environment integration-staging` to verify integration-staging.
`images/sglang/source.lock` pins one node image per environment under
`nodeImages`, and the verifier selects the entry the release names.

`--operator-public-key` is required in both c8s policy modes, not only
operator mode. The verifier passes it to c8s as `--operator-pkey` on every
call, so c8s pins RTMR3 to the hash of that key. This proves the node
launched bound to the published operator public key and no other, even in
static policy mode, where the sealed allowlist alone does not pin RTMR3.

`scripts/verify-public-attestation.py` always requires
`--operator-public-key`, because every current release attaches an operator
key at launch. If a future environment attaches no operator key at launch,
the guest never extends RTMR3, so it stays at its boot reset value: 96 zero
hex characters. Verifying such a release needs the raw c8s binary, not this
script: run `c8s verify` directly with `--rtmr 3=` followed by 96 zeros, in
place of `--operator-pkey`.

## Rebuild the reported product images

This is a separate release audit. It is not part of normal deployment. Normal
deployment builds and publishes each image once.

The audit needs Git, Docker Buildx, and enough Docker storage. The SGLang
image is large. Keep at least 50 GiB free. The audit extracts each recorded
source commit, builds each repository-owned image once, and compares its Linux
AMD64 digest with the digest in the trusted release bundle:

```sh
python3 scripts/rebuild-release-images.py \
  --bundle releases/production/release-bundle.json \
  --output /tmp/confidential-inference-rebuild
```

Use `--image gateway` to check only one image. The command writes
`report.json`. It exits with an error if a rebuilt digest differs. This check,
together with the receipt check above, links the live workload to its public
source commit.

## Attestation trust inputs

The gateway `/attestation?nonce=<32-byte-base64url>` response is an evidence
envelope, not a trust decision. It includes c8s discovery, the active allowlist,
the active operator-key set, and one nonce-bound receipt per configured
workload. The exact release bundle and matching c8s verifier are required to
verify it offline. See
[`services/gateway/ATTESTATION.md`](services/gateway/ATTESTATION.md) and
[`scripts/verify-public-attestation.py`](scripts/verify-public-attestation.py).

The release bundle pins the node measurements, workloads, image digests,
commands, allowlist digest, c8s commit, and trust-anchor fingerprints. It keeps
the individual c8s operator-key SPKI digest and the separate canonical key-set
digest (`operatorKeySetSha256`). The PEM
files in `releases/production/trust/` contain only public material. They do not
contain private keys.

The release bundle also pins `releases/trust/release-signing-policy.json`.
This is a separate Sigstore keyless identity policy for public releases. It is
not the c8s operator key. The public verifier requires the matching Sigstore
bundle and fails closed when it is absent. See [releases/README.md](releases/README.md)
for the tag, signing, download, and offline verification process.

## Configuration ownership

- Put reusable behavior in this repository.
- Put non-secret live settings in a private environment overlay.
- Put secret values in a secret manager. Pass only secret names here.
- Deliver confidential application secrets through c8s CDS.
- Do not use Kubernetes Secrets for values that CDS must protect.

See the [c8s documentation](https://confidential.ai/docs/c8s) for the trust
model and application-secret flow.

## Continuous integration

`.github/workflows/pr.yml` runs one required check on each pull request. It
tests and lints only changed Rust components, checks Python syntax only after a
Python change, tests release rules only after a release-tooling change, lints
only changed Helm charts, and parses only changed configuration. Documentation
changes do not start documentation checks.

`.github/workflows/release-images.yml` is manual. It selects affected images for
an intended release candidate. It does not run on pull requests or pushes to
`main`. `.github/workflows/release-bundle.yml` runs only for protected release
tags.

## Project policy

- Read `SECURITY.md` before you report a security defect.
- Read `CONTRIBUTING.md` before you send a change.
- Read `CODE_OF_CONDUCT.md` for the community standards of this project.
- The source is licensed under `Apache-2.0`. See `LICENSE`.
