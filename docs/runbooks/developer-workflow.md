# Developer workflow

## 1. Overview

This repository contains the public Confidential Inference software and its
workload definitions. It produces releases that the private deployment
repository can install.

Keep these concepts separate:

- A **source commit** is one version of the source code.
- An **artifact** is a built image or another fixed build output.
- A **release** is a signed record of the exact artifacts and dependencies that
  belong together.
- A **deployment target** is a place where a release runs. Staging, a candidate
  slot, and production are deployment terms. They are not source branches.

The public repository creates a release. It does not define which private
cluster receives that release or when that cluster receives production traffic.

## 2. Branch model

Use `main` as the only long-lived branch. Use a short-lived branch for each
change, and merge the change into `main` when it is ready.

Do not create permanent staging, candidate, or production branches. A commit on
`main` can become a release. The same release can then move through different
deployment targets without another source branch.

## 3. Release model

A release starts from one commit on `main`. It identifies the exact application
images, workload definitions, contracts, and dependency versions for that
commit. Published artifact digests do not change.

Use semantic versions such as `v0.14.3`:

- A **major** change requires an existing client, verifier, or operator to
  change.
- A **minor** change adds compatible behavior or capability.
- A **patch** change fixes or changes behavior without breaking an existing
  interface.

Compatibility includes the HTTP API, streaming events, tool calls,
authentication, attestation evidence, release schemas, and operator interfaces.
Internal implementation changes do not require a major version when these
interfaces remain compatible.

Use a version such as `v0.14.3-rc.1` when a release needs deployment validation
before final publication. If validation succeeds, `v0.14.3` must reference the
same artifact digests. If any artifact changes, create another release
candidate.

C8s, TEEriminator, and other release dependencies are exact release inputs. A
dependency update enters a cluster only through a new Confidential Inference
release. Classify its version change by its effect on clients, verifiers, and
operators, not by the dependency's own version number.

## 4. Repository boundary

Keep product software, workload definitions, public contracts, build inputs,
and release definitions in this repository. The maintenance gateway is part of
this public product boundary.

Keep private topology, DNS state, secret references, traffic state, deployment
receipts, the admin system, and private infrastructure controls in
`confidential-inference-internal`.

The interface between the repositories is a signed release reference. The
private repository selects it by exact digest and does not rebuild its product
artifacts.

## 5. Example workflow

1. Create `feature/better-streaming` from `main`.
2. Make the change and merge it into `main`.
3. Create `v0.14.3-rc.1` from that exact commit.
4. Build and sign the release with exact artifact and dependency digests.
5. Give the signed release reference to `confidential-inference-internal`.
6. Validate those artifacts in staging and in the candidate production slot.
7. If validation succeeds, publish `v0.14.3` with the same artifact digests.
8. If code or an artifact changes, return to `main` and create `v0.14.3-rc.2`.
