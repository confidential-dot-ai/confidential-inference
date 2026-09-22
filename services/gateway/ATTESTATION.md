# Gateway c8s evidence collector

The gateway accepts one canonical 32-byte base64url nonce. It rejects padding,
duplicate nonce sources, reuse, malformed values, and incorrect lengths.

Each reported workload pod runs the pinned standard `c8s cds-attest` sidecar.
The sidecar reads the c8s certificate files. Its `--expected-workload` option
requires the exact admitted workload identity before it becomes ready.

`GATEWAY_C8S_RECEIPT_TARGETS` supplies the complete target set. Each item has
this form:

```text
target-name|c8s-workload-name=http://internal-host:port
```

The gateway sorts targets by name. It fails closed when a target is missing,
unready, malformed, or bound to another nonce. A release bundle records the
same target-to-workload bindings. The independent verifier compares the full
response with those bindings.

`GATEWAY_C8S_EVIDENCE_BASE_URL` names the c8s TLS-LB front door. The gateway
reads `/v1/discovery` and `/allowlist` from this URL. These routes must be
served by the c8s evidence front door. The gateway does not read pod
status or other Kubernetes control-plane claims.

The gateway accepts both c8s allowlist document shapes. The branch-pinned c8s
serves a top-level `digests` floor map; c8s main line (c8s#551) folds those
digests into per-workload entries and serves no `digests` key. In both shapes
the static policy digest commits to the exact served document, and each
admitted launch is read from the per-workload entries.

The response also includes:

- The selected public release identifier and bundle digest.
- The exact active allowlist and its canonical digest.
- The exact admitted image and command policy for each receipt.
- The mesh CA fingerprint carried by each nonce-bound receipt.
- The active policy mode: `operator` or `static`.
- Operator public-key evidence when operator policy is active.
- The expected and active allowlist digests when static policy is active.
- The GPU evidence status exposed by the selected c8s protocol.

Set `GATEWAY_C8S_POLICY_MODE` to `static` for the sealed production policy.
Set `GATEWAY_EXPECTED_STATIC_ALLOWLIST_SHA256` to the canonical digest of the
allowlist that is sealed into the measured c8s node image. In this mode, c8s
has no operator key for admission policy and does not permit policy updates.
The node still measures the published operator public key into RTMR3 at
launch, and the offline verifier still pins RTMR3 to that key's hash. This
proves the node launched bound to that key and no other, even though the
key plays no role in admission decisions.

Legacy operator mode remains available. Set
`GATEWAY_EXPECTED_OPERATOR_PUBLIC_KEY_SHA256` to the expected member key's
SPKI digest and `GATEWAY_EXPECTED_OPERATOR_KEY_SET_SHA256` to the release's
canonical key-set digest. Both values are required. They are public policy
identifiers, not private keys.

The response carries raw evidence. It is not a verification result. Use
`scripts/verify-public-attestation.py` with separately held release data.
The verifier runs the exact pinned c8s verifier. It parses and checks MRTD,
RTMR1, RTMR2, RTMR3, the debug flag, the mesh chain, and each workload stamp.

For `public_tls.mode: acme`, c8s creates the TLS key inside the TEE and gets a
public certificate through ACME. c8s binds the serving certificate and the
front-door mode into a separate `/.well-known/c8s/attest-lb` receipt. The
gateway keeps this receipt separate from each workload receipt. The offline
verifier compares this evidence with the TLS certificate from the live
connection. The older `cds` and `tee-webpki` modes use the same receipt path.

In static policy mode, the c8s verifier checks that the mesh CA contains the
expected sealed allowlist digest and valid TEE evidence. In operator mode, the
gateway also checks the same operator key set in every receipt. It calculates
the key-set digest as `SHA256("c8s-operator-key-set-v1\\0" || sorted unique
SHA256(SPKI-DER))`.

A GPU release target must declare `gpu` in its release workload. The source
lock states how its c8s version enforces that policy.

Older c8s entries use `receipt-evidence`. The gateway copies `gpu_attested`
and `nvidia_gpu` from each worker receipt. The offline verifier calls the c8s
GPU verifier with the CPU-report-derived nonce. It requires `gpu_verified` and
`nonce_binding_ok`.

c8s v0.26.5 uses `measured-boot-gate`. The measured node image checks every
passed-through GPU before RKE2 starts. The required systemd unit blocks RKE2
and powers off the node if the check fails. The verdict stays inside the node,
so the gateway reports `not-exposed-by-c8s`. The offline verifier verifies the
measured node image and does not require raw NVIDIA evidence or an external
GPU attestation CLI for this mode. The c8s source lock pins the boot-gate
script, unit, and preset.

The response proves launch or admission facts. It does not prove current
liveness, request routing, mounts, environment values, or model use.
