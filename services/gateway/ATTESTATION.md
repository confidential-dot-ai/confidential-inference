# Public attestation metadata

`GET /attestation` and `GET /v1/attestation` use the same handler.
They need no API key or nonce. The current response format is version 3.
The schema also accepts version 2 during gateway replacement.

## Response fields

| Field | Source and purpose |
| --- | --- |
| `schemaVersion` | Gateway format version: `3`. |
| `release.id` | Selected release identifier. |
| `release.url` | Public release URL. |
| `release.bundleSha256` | Digest of the release bundle. |
| `releaseSelection` | Desired release and its match with the reported CDS policy, when the release selection file is set. |
| `c8s.activeAllowlist.document` | Parsed JSON from CDS `/allowlist`. |
| `c8s.activeAllowlist.sha256` | SHA-256 of the exact CDS response bytes. |
| `c8s.activeAllowlist.url` | Public allowlist download URL. |
| `c8s.discovery` | Native C8s discovery, passed through unchanged. |
| `c8s.operatorKeys` | Active operator public keys, in PEM format. |

When `GATEWAY_INSTANCE_ID` is set, public responses include the
`X-Confidential-Gateway` header. The rollout monitor uses it to identify the
answering gateway. It is an operational identifier, not an attestation proof.
It adds no fields to the JSON response.

There are no workload receipts, GPU fields, nonce, worker list, or separate
front-door evidence fields. The handler does not contact inference workers,
SGLang Router, or monitoring pods.

This response helps a client select and review its policy. It does not replace
verification of the inference connection. Clients that require fail-closed
enforcement pin their reviewed policy and verify connections through
TEErminator. Direct HTTPS with periodic verification
is also possible, but does not enforce those pins on each inference connection.
See [client verification](../../docs/verification.md) for commands and trust inputs.

For a dynamic deployment, the reviewed live policy can differ from the initial
policy in the signed software release. Use `--metadata-only --release-allowlist`
with the signed release's `allowlist.json`. Give the separately reviewed live
policy to `--allowlist`. The verifier still checks the release signature, node
measurements, source lock, and signed initial policy. It checks the live
response against the exact reviewed live policy bytes. It does not claim that
the release signature covers later policy changes. Without this explicit
option, the live policy must equal the signed initial policy.

## CDS verification

`GATEWAY_C8S_CDS_URL` selects the CDS HTTPS origin. It is required; the
gateway has no other attestation source.
`GATEWAY_C8S_IMAGE_POLICY` selects the control-node-only image-policy file.
`GATEWAY_C8S_IMAGE_POLICY_SHA256` pins its exact bytes in the admitted inputs.
`GATEWAY_C8S_SERVED_IMAGE_POLICY` selects the full policy that CDS enforces.
`GATEWAY_C8S_SERVED_IMAGE_POLICY_SHA256` pins that file.
The two pins may instead come from the release identity file
(`cdsImagePolicySha256` and `cdsServedImagePolicySha256`, both or neither,
and not together with the environment). A deployment whose served policy
carries a per-rebuild launch anchor cannot pin the files in its exact
allowlist; the identity file already carries its operator-key pins, so the
policy pins are then as trusted as those.
The target policy must contain one reviewed control-node identity. Agent keys
must not identify CDS. Both files have byte limits. The verifier reads private
copies of the checked bytes. A later ConfigMap change cannot change those pins.
The gateway rejects changed files before it starts the verifier.

The gateway uses the pinned C8s verifier to verify CDS hardware evidence and
the image policy. It reads policy and public keys only over a connection whose
TLS certificate equals the verified CDS certificate. Redirects are refused.
The public-key fingerprints must equal the set read by the verifier.
A missing key set is accepted only when CDS reports that writes are disabled.
A connection or verification error is not an empty key set.

The settings file's `evidence` object selects the front door for native discovery.
`baseUrl` is an HTTPS origin. Its hostname remains the expected TLS name.
The optional `connectHost` selects a connection address without changing that
name or the TLS port. Omitting `connectHost` uses normal DNS for the origin.
Discovery keeps certificate checks enabled and refuses redirects.

Without a settings file `evidence` object, `GATEWAY_C8S_EVIDENCE_BASE_URL`
and `GATEWAY_C8S_EVIDENCE_CONNECT_HOST` supply the addresses. One of the two
is required.

## Load protection

The handler reuses the gateway request-rate, address-concurrency, and
attestation-concurrency limits. Its cache lasts 10 seconds by default, with a
maximum of 30 seconds. Concurrent requests share one refresh. A failed refresh
has a one-second cooldown. Expired successful data is never returned on error.
Refresh waits, upstream requests, verifier output, policy files, and response
bodies have limits. A failed refresh returns 503 with `Retry-After: 1`.
The response has `Cache-Control: no-store, max-age=0`.

## Release selection and settings files

The gateway reads both files once at start. The chart renders them into
ConfigMaps and puts a `checksum/config` annotation on the gateway pod
template, so a change rolls the gateway pods (`RollingUpdate`). Invalid data
stops startup.

`GATEWAY_RELEASE_SELECTION_FILE` selects the release selection file.
It contains `schemaVersion: 1`, `selectedBundleSha256`, and `releaseBundles`.
Each bundle is a JSON string that preserves the exact bytes of its signed
release asset. Deployment tools verify signatures and build evidence before
they write this configuration. The gateway derives the release name, public
URL, bundle hash, and policy hash from these bytes. It does not download an
asset during a request.

The selected bundle takes precedence when several releases share a policy.
If the reported CDS policy matches another unique configured bundle, the
gateway reports that release and marks the desired selection as pending.
If no unique bundle matches, `release` is null and `releaseSelection.status`
is `pending`. The client verifier rejects that state. The CDS allowlist stays
in the response. A desired release is not a claim that its policy is enforced.

`GATEWAY_RUNTIME_CONFIG_FILE` selects the gateway settings file. It sets the
model catalog and admitted models, body limit, request timeouts, capacity and
queue limits, request rate, attestation cache duration, and evidence
addresses. Its values replace the matching startup arguments, and the same
argument bounds apply. For example, `settings.json` can contain:

```json
"evidence": {
  "baseUrl": "https://candidate.api.example.test",
  "connectHost": "c8s-router.c8s-system.svc.cluster.local"
}
```

An unreachable address or a TLS failure returns 503; it does not disable
verification. CDS trust pins and TLS roots do not depend on these addresses.

The optional `routerService` setting selects `sglang-router` or a Service
whose name starts with `router-`. It needs the fixed startup input
`GATEWAY_ROUTER_NAMESPACE` and direct-router mode. It cannot select another
namespace, port, or external URL. The target keeps the protocol and port of
`GATEWAY_INFERENCE_URL`.

`gateway_router_requests_active` counts authenticated requests that hold the
router target. This includes body reads, queued requests, and open streams.

Mount configuration directories
without `subPath`. Use `<mount>/file.json`, not a timestamp directory, as the
configured path. ConfigMap contents are not C8s image measurements. Clients
must still verify the signed release and the inference connection.

The existing metrics endpoint reports attestation response counts, response
duration, cache hits, refresh results, and failure cooldowns. Rejections use the
existing rejection counters. No client keys or policy bytes are metric labels.
These controls limit gateway load. They do not prevent network saturation.

## Metadata verification

Use `scripts/verify-public-attestation.py --metadata-only` with the trusted
release and exact policy bytes to check version 3 metadata. The tool verifies
the release signature and compares the reported release and policy with the
held inputs. Operator-key pins are optional client inputs.

The output reports `metadataMatchesTrustedInputs: true` and
`connectionVerified: false`. A metadata match is not proof of an inference
connection. Use TEErminator for that separate check. The tool refuses version
3 in its old receipt-verification mode. It does not report a missing receipt
as a successful cryptographic verification.

## Version 2 overlap

The contract retains version 2 for checks against an old gateway during an
update. That format includes nonce-bound workload receipts. This gateway no
longer contains the version 2 receipt collector and serves version 3 only. Rollout checks must select verification by response
version and must keep inference-connection verification independent of the
metadata response.

## Customer procedure

Read [client verification](../../docs/verification.md) for release downloads,
metadata checks, full allowlist pinning, Intel collateral policy, and the GPU
boot gate. A workload certificate binds the policy at issuance. The metadata
cache and fresh connection proof do not make policy updates instantaneous.
The current contract retains operator-managed updates; it does not promise
zero Kubernetes API rights.
