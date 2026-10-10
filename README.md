# Confidential Inference

This repository contains the public confidential-inference product. It is the
source for the OCI workloads, Kubernetes chart, c8s policy tools, release
inputs, and attestation verifier. Current releases pin a c8s TDX node image.

Before you contribute or create a release, read the
[developer workflow](docs/runbooks/developer-workflow.md).

Live environment configuration does not belong here. Operators keep machine
names, addresses, domains, resource sizes, secret paths, and deployment
receipts in a separate private repository.

## Components

- `services/gateway`: API-key checks, request limits, routing, and attestation.
- `images/sglang`: the pinned SGLang worker build. The same image
  runs a real model in production and a GPU-free simulator in staging.
- `images/sglang-router`: the separate router image and build inputs.
- `services/maintenance-gateway`: the fallback API.
- `images/control-plane-node`: historical consumer node profiles. Current
  releases pin the c8s node image through `release/spec.yaml`.
- `helm/confidential-inference`: the generic Kubernetes application chart.
- `scripts/regenerate-c8s-allowlist.py`: c8s policy generation.
- `scripts/verify-public-attestation.py`: policy metadata checks and historical receipt verification.
- `contracts`: public API, attestation, release, network, and metrics contracts.

## Build and publish

Use the approved `Release images` workflow on public `main`. It selects
images changed since a reviewed prior release or commit. Publication requires
clean rebuild comparisons and recorded evidence. The signed release binds
each Linux AMD64 platform digest and the selected publication record.
See [release publication](release/README.md) and
[the developer workflow](docs/runbooks/developer-workflow.md).

Local builds are for development tests. Do not use them for production or
for a candidate prepared for production.

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

## Review build evidence

Current publication requires clean rebuild comparisons before an image can
be published. Deployment consumes the verified artifacts. It does not build
application images locally. Review the image publication record bound by the
signed release. See [release publication](release/README.md).

`scripts/rebuild-release-images.py` retains independent rebuild checks for
older release inventories with a `workloads` list. Do not pass a current
v0.14 release manifest to that historical inventory tool.

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
