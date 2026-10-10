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
- `scripts/verify-public-attestation.py`: policy metadata checks and historical receipt verification.
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

## Local development

Install a stable Rust toolchain and build the gateway:

```sh
cargo build -p confidential-gateway
```

A standalone production-style gateway needs verified CDS access, release
configuration, an admin certificate, and its protected state volume. A local
binary alone does not supply these dependencies.

For a local forwarding check, use the gateway integration test. It creates
the request router and an HTTP test upstream:

```sh
cargo test -p confidential-gateway --test fake_upstream \
  gateway_forwards_to_the_internal_router_without_the_caller_key
```

This test does not establish hardware attestation or production readiness.

## Review and verify the endpoint

`GET /attestation` returns version 3 release and policy metadata. It needs no
API key or nonce. It contains the active permitted-workload policy, release
location and bundle hash, native C8s discovery, and operator public keys.
It does not collect a worker census or prove an inference connection.

Read [the client verification procedure](docs/verification.md). Review the
signed release and exact active allowlist bytes, then configure TEErminator to
reject an unexpected image, policy, workload, or TLS certificate before it
forwards sensitive data. Online Intel collateral checks are a separate,
explicit client setting. Direct HTTPS with periodic checks is also possible,
but does not enforce those pins on each inference connection.

Production uses an operator-managed policy. Current release manifests do not
pin one deployment's operator key or mesh CA. Clients can make those additional
acceptance decisions. Do not use historical static-mode instructions for a
new release.

See [the threat model](docs/threat-model.md) for enforcement, update authority,
and verification limits. Schema version 2 and the old receipt verifier remain
available for historical evidence only.

## Rebuild the reported product images

This is a separate release audit. It is not part of normal deployment. Normal
deployment builds and publishes each image once.

The audit needs Git, Docker Buildx, and enough Docker storage. The SGLang
image is large. Keep at least 50 GiB free. The audit extracts each recorded
source commit, builds each repository-owned image once, and compares its Linux
AMD64 digest with the digest in the trusted release bundle:

```sh
python3 scripts/rebuild-release-images.py \
  --bundle client-review/release-bundle.json \
  --output /tmp/confidential-inference-rebuild
```

Use `--image gateway` to check only one image. The command writes
`report.json`. It exits with an error if a rebuilt digest differs. Use the release format supported by that audit tool. Connection verification
and image rebuild verification answer separate questions. Current publication
evidence is described in `release/README.md`.

## Attestation trust inputs

The release bundle is an independently verified release artifact. The active
allowlist is the exact policy that the client reviews and pins. In an operator
managed deployment, that policy can differ from the signed initial policy.
The metadata verifier checks them separately only with the explicit
`--release-allowlist` option. It never signs or approves later changes for you.

The public operator keys describe CDS update authority. The gateway reads them
through an attested, certificate-pinned CDS connection. They do not prove who
holds the corresponding private keys. The release-signing policy is a separate
Sigstore policy under `releases/trust/`; it is not the C8s operator key.

Use [services/gateway/ATTESTATION.md](services/gateway/ATTESTATION.md) for the
version 3 fields and gateway checks, and [release/README.md](release/README.md)
for source and publication evidence. The files under `releases/production/`
and `c8s/` preserve historical inputs; they are not the active production trust
files.

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
