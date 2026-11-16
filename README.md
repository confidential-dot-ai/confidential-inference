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
- `images/sglang-confidential`: the one SGLang engine image (plain upstream
  SGLang). It holds no model: each worker gets its model from a model server
  or a C8s model volume, and the chart values choose the model (DeepSeek-V4.1
  in production, Qwen3.5-0.8B in a staging recipe). It can also run a GPU-free
  simulator for tests.
- `images/sglang-router`: the separate router image and build inputs.
- `services/gateway/gateway/maintenance.py`: the fallback API.
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

Use Python 3.13 and install the locked runtime dependencies:

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: \
  -r services/gateway/requirements.lock
.venv/bin/python -m unittest discover -s tests/gateway -q
```

The tests start real HTTP listeners with local admin and inference peers.
A standalone gateway needs the configured admin endpoint and credentials.

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

`.github/workflows/pr.yml` tests the Python gateway containers after gateway
changes. It also checks changed Python syntax, Helm charts, and configuration.
The test job covers the API, image recipes, release rules, and rendered
workloads on every pull request.

`.github/workflows/release-images.yml` is manual. It selects affected images for
an intended release candidate. It does not run on pull requests or pushes to
`main`. `.github/workflows/release-bundle.yml` runs only for protected release
tags.

## Project policy

- Read `SECURITY.md` before you report a security defect.
- Read `CONTRIBUTING.md` before you send a change.
- Read `CODE_OF_CONDUCT.md` for the community standards of this project.
- The source is licensed under `Apache-2.0`. See `LICENSE`.
