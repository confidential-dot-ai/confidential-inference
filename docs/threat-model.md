# Threat model

This document describes the current version 3 discovery and client-verification
contract. For exact commands, read [verification.md](verification.md).
Historical files under `releases/production/`, `c8s/`, and the old node profile
do not describe the current serving cluster.

## Request path and trust boundary

Public TLS terminates inside the measured confidential environment. C8s's
`attest-lb` proof binds the exact public TLS certificate to accepted node
measurements and the mesh identity. The gateway authenticates API keys and
forwards inference to the router and workers. It does not forward the API key
to the inference engine.

Trust the CPU and GPU hardware security mechanisms, their vendor attestation
chains, the accepted measured node image, and the software and policies that
you review. Host management and Kubernetes declarations are not proof of
approved execution. Measured admission and connection controls must enforce
those declarations.

Release-signing and policy-update authority remain part of the review.
A signature identifies an authorized release; it does not prove that its code
has no defects or that every signed future release is acceptable to you.

## Discovery and connection verification

`/attestation` is public and needs no API key or nonce. Version 3 returns release
and permitted-workload metadata, native C8s discovery, and operator public keys.
The gateway verifies CDS and pins its TLS certificate before it reads policy
and keys. See [gateway attestation](../services/gateway/ATTESTATION.md).

Metadata is not a connection proof or a complete running-workload inventory.
TEErminator separately obtains fresh C8s evidence. With the full image tuple,
exact reviewed allowlist, workload, and TLS name configured, it rejects a
connection that does not meet those pins before forwarding application data.
The internal request path must remain protected by the reviewed C8s and
application controls. Front-door verification alone is not a receipt from
every serving worker.

## Policy and configuration protection

Production retains an operator-managed allowlist and Kubernetes update rights.
It does not promise an immutable static policy, zero RTMR3, or zero API writes.
Clients can reject that authority model, or approve and pin a policy.

Application policies constrain image digests, commands, arguments, environment,
mounts, and secret grants. C8s checks the final launch specification and uses
admitted inventory when issuing workload identity. The release source lock
pins that implementation. Review core entries too: an application restriction
does not make an unrestricted core entry restrictive.

The active policy can contain multiple release definitions during an update.
It can differ from the signed initial allowlist. The client must review that
live policy separately; a release signature does not cover later operator
changes. Keep your approved bytes until you explicitly accept an update.

A workload certificate records a policy decision at issuance. A new connection
proof does not establish that CDS has not changed the policy since issuance.
TEErminator caches verdicts and checks certificate identity and expiry. Do not
claim immediate disconnection of every stream after a policy update.

Launch restrictions do not disable runtime logging or model-administration
APIs by themselves. Review those application routes and their access controls
in the exact approved worker source.

## Hardware and storage

The node measurements identify the firmware, kernel, boot configuration, and
verified root filesystem. Pin MRTD, RTMR1, and RTMR2 together; MRTD alone does
not identify the full TDX guest image.

The accepted GPU node image uses a measured confidential-computing boot gate.
Every passed-through GPU must satisfy that gate before RKE2 starts. Failure
blocks node admission and powers off the node. This is the supported GPU
verification contract, not a public raw-GPU-evidence collection.

Current C8s node storage uses encrypted scratch state with a per-boot key held
inside the guest, and encrypted application volumes supplied through CDS.
The historical plain control-plane state disk is not a current production
requirement. For a selected release, review its exact node image and storage
implementation. Encryption alone does not imply authenticated disk contents;
model integrity uses the release's verified model-volume checks.

Hardware memory protection excludes host reads of guest and GPU memory. It
does not stop approved application code from deliberately exposing data.
TLS and the internal mesh protect transport; peer selection and application
egress policy remain security-sensitive configuration.

## Operator keys and client policy

`c8s.operatorKeys` reports actual CDS public update keys. It is not a proof of
exclusive private-key custody. The gateway obtains the list through verified
CDS access. An independently accessible direct CDS check is a separate
integration; do not treat the gateway's public `/operator-keys` route as CDS.

A release-signing key, CDS policy-update key, mesh CA, and Kubernetes client CA
have different roles. Do not use the old production PEM files as new release
anchors. New manifests do not require one fixed deployment mesh CA or operator
key. A client can choose additional pins and must understand their scope.

## Verification limits

- Quote signatures alone do not establish current revocation or accepted TCB
  status. Enable TEErminator's online Intel collateral policy explicitly.
- A vendor TCB status that your policy rejects must stop acceptance. Do not
  silently fall back to offline verification.
- Public discovery and `/health` do not prove model correctness, availability,
  or absence of software defects.
- Kubernetes update rights remain. A blocked interactive execution path is
  useful, but is not proof that every possible operator path is closed.
- Public source and build evidence support independent review. Customers
  select the releases, policy, and update authority that they accept.

The exact current verification procedure and dated deployment findings are in
[verification.md](verification.md). Historical version 2 proofs remain useful
for audits of those releases; they do not substitute for version 3 connection
verification.
