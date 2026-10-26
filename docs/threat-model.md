# Threat model

This document describes the current client-verification contract. For exact commands, read [verification.md](verification.md).
Historical files under `releases/production/`, `c8s/`, and the old node profile
do not describe the current serving cluster.

## Request path and trust boundary

Public TLS terminates inside the measured confidential environment. C8s's
`attest-lb` proof binds the exact public TLS certificate to accepted node
measurements and the mesh identity. The gateway authenticates API keys and
forwards inference to the router and workers. It does not forward the API key
to the inference engine. It sends the router an opaque per-conversation
routing key, an HMAC under a secret drawn at gateway start, so the router can
tell which requests belong to one conversation but cannot recover the API key,
the caller's own key value, or prompt text from it.

Trust the CPU and GPU hardware security mechanisms, their vendor attestation
chains, the accepted measured node image, and the software and policies that
you review. Host management and Kubernetes declarations are not proof of
approved execution. Measured admission and connection controls must enforce
those declarations.

Release-signing and policy-update authority remain part of the review.
A signature identifies an authorized release; it does not prove that its code
has no defects or that every signed future release is acceptable to you.

## Connection verification

TEErminator obtains fresh C8s evidence from the front door. With the full
image tuple, exact reviewed allowlist, workload, and TLS name configured, it
rejects a connection that does not meet those pins before forwarding
application data. The internal request path must remain protected by the
reviewed C8s and application controls. Front-door verification alone is not a
receipt from every serving worker.

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

## Restricted Kubernetes credentials

The C8s operator authentication key authorizes credential release and policy
updates. The `c8s-operator` workload is a different component. Do not confuse
CDS policy-update authority with Kubernetes permissions.

The C8s node image pinned by the `v0.14.29` example issues Kubernetes user
`operator` in group `c8s:node-operators`, rather than `system:masters`.
The measured [role and binding](https://github.com/confidential-dot-ai/c8s/blob/deca64d1f5bf6c70e00c1a42ad0638bdf654efbc/node-guest-image/c8s/mkosi.extra/var/lib/rancher/rke2/server/manifests/cred-release-rbac.yaml)
permit application management and restrict access to the security controls.
Measured admission guards deny exec, attach, port-forward, and ephemeral
containers. They also protect system namespaces and prevent operator changes
to the guards and cluster-wide permissions. Credential release waits for its
measured readiness checks before serving credentials. Review these controls
at the C8s commit in your selected release; group names alone grant no rights.

The operator role can read pod logs, Kubernetes Secrets, and ConfigMaps.
Protect request data and confidential keys from those readable resources.
The gateway's admin credentials are Kubernetes Secrets: the admin signer
certificate (`gateway-admin-mtls`) and the SHA-256 of each admin API key
(`gateway-admin-api-key`). Reading the hashes does not give a usable key, but
whoever can write either Secret and restart the gateway holds the gateway
admin channel. The gateway refuses an API-key snapshot with
a lower revision than the one it holds, so that channel cannot roll the key
set back through the snapshot route; it can still remove keys, which is a
denial of service, not a loss of confidentiality.
The gateway keeps its keys in memory only. It pulls them from the admin over
HTTPS: the admin URL, its CA and the gateway's admin token are a CDS
application secret, so only the attested gateway reads them. A restarted
gateway holds no revision, so it accepts the admin's current snapshot at any
revision; the admin that owns the registry is trusted for the key set either
way.
CDS application secrets are distinct from Kubernetes Secrets. Launch checks
do not establish that approved application code never writes sensitive data
to a log or exposes it through an API.

RTMR3 binds launch configuration, including the operator public key. It does
not define Kubernetes permissions. Those permissions and guards are part of
the measured node implementation. Retaining a launch-bound operator key does
not require issuing an unrestricted administrator credential.

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
[verification.md](verification.md).
