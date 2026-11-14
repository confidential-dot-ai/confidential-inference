# Confidential Inference

This repository contains the public confidential-inference product. It is the
source for the OCI workloads, Kubernetes chart, C8s policy tools, and release
inputs. Current releases pin a C8s TDX node image and a C8s CDS guest image.

Before you contribute or create a release, read the
[developer workflow](docs/runbooks/developer-workflow.md).

Live environment configuration does not belong here. Operators keep machine
names, addresses, domains, resource sizes, secret paths, and deployment
receipts in a separate private deployment repository.

## Terms

- **Framework release**: a signed version of this repository, `vX.Y.Z`. It
  names the software: image digests, the chart, and the C8s pins.
- **Environment**: one configuration, for example `staging` or `production`.
  The deployment repository keeps it: Helm values and an allowlist policy.
- **Deployment**: an immutable snapshot of one environment at one commit. It
  has its own cluster.
- **Alias**: a name (`staging`, `candidate`, or `production`) that points to
  one deployment.

## Components

- `services/gateway`: API-key checks, request limits, and routing.
- `images/sglang`: the pinned SGLang worker build. The same image
  runs a real model in production and a GPU-free simulator in staging.
- `images/sglang-router`: the separate router image and build inputs.
- `services/maintenance-gateway`: the fallback API.
- `helm/confidential-inference`: the generic Kubernetes application chart.
- `api`: public API and release schemas.

## Build and publish

Use the approved `Release images` workflow on public `main`. It selects
images changed since a reviewed prior release or commit. Publication requires
clean rebuild comparisons and recorded evidence. The signed release binds
each Linux AMD64 platform digest and the selected publication record.
See [release publication](release/README.md) and
[the developer workflow](docs/runbooks/developer-workflow.md).

Local builds are for development tests. Do not use them for production or
for a deployment that the `candidate` or `production` alias will point to.

## Local development

Install a stable Rust toolchain and build the gateway:

```sh
cargo build -p confidential-gateway
```

A standalone production-style gateway needs an admin certificate and the admin that serves its API keys. A local
binary alone does not supply these dependencies.

For a local forwarding check, use the gateway integration test. It creates
the request router and an HTTP test upstream:

```sh
cargo test -p confidential-gateway --test fake_upstream \
  gateway_forwards_to_the_internal_router_without_the_caller_key
```

This test does not establish hardware attestation or production readiness.

## Review and verify the endpoint

Read [the client verification procedure](docs/verification.md). Review the
signed release and exact active allowlist bytes, then configure TEErminator to
reject an unexpected image, policy, workload, or TLS certificate before it
forwards sensitive data. Online Intel collateral checks are a separate,
explicit client setting. Direct HTTPS with periodic checks is also possible,
but does not enforce those pins on each inference connection.

Production uses an operator-managed policy. Release manifests do not pin a
deployment's mesh CA. Clients can add that pin. Do not use historical
static-mode instructions for a new release.

See [the threat model](docs/threat-model.md) for enforcement, update authority,
and verification limits.

## Review build evidence

Current publication requires clean rebuild comparisons before an image can
be published. Deployment consumes the verified artifacts. It does not build
application images locally. Review the image publication record bound by the
signed release. See [release publication](release/README.md).

## Attestation trust inputs

The framework release is an independently verified release artifact. It
names every image digest, but no environment configuration. Each deployment
renders its own allowlist from it and the configuration of its environment. The active allowlist is the exact policy that the
client checks against the signed release, reviews, and pins.

The release-signing policy is a Sigstore policy under `release/trust/`.

Use [release/README.md](release/README.md) for source and publication
evidence. Release signing rules and the Sigstore trusted root are under
`release/trust/`. Historical release snapshots and C8s deployment inputs
are available in Git history. Published assets remain on GitHub Releases.

## Configuration ownership

- Put reusable behavior in this repository.
- Put non-secret live settings in the environment, in the deployment repository.
- Put secret values in a secret manager. Pass only secret names here.
- Deliver confidential application secrets through C8s CDS.
- Do not use Kubernetes Secrets for values that CDS must protect.

See the [C8s documentation](https://confidential.ai/docs/c8s) for the trust
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
