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
verification of the inference connection. The client must pin the reviewed
policy and verify that connection with TEErminator or the native C8s verifier.

For a dynamic deployment, the reviewed live policy can differ from the initial
policy in the signed software release. Use `--metadata-only --release-allowlist`
with the signed release's `allowlist.json`. Give the separately reviewed live
policy to `--allowlist`. The verifier still checks the release signature, node
measurements, source lock, and signed initial policy. It checks the live
response against the exact reviewed live policy bytes. It does not claim that
the release signature covers later policy changes. Without this explicit
option, the live policy must equal the signed initial policy.

## CDS verification

`GATEWAY_C8S_CDS_URL` selects the CDS HTTPS origin.
`GATEWAY_C8S_IMAGE_POLICY` selects the control-node-only image-policy file.
`GATEWAY_C8S_IMAGE_POLICY_SHA256` pins its exact bytes in the admitted inputs.
`GATEWAY_C8S_SERVED_IMAGE_POLICY` selects the full policy that CDS enforces.
`GATEWAY_C8S_SERVED_IMAGE_POLICY_SHA256` pins that file.
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

`GATEWAY_C8S_EVIDENCE_BASE_URL` selects the front door for native discovery.
`GATEWAY_C8S_EVIDENCE_CONNECT_HOST` can select its connection address while
preserving the expected TLS name. Discovery uses normal certificate checks.

## Load protection

The handler reuses the gateway request-rate, address-concurrency, and
attestation-concurrency limits. Its cache lasts 10 seconds by default, with a
maximum of 30 seconds. Concurrent requests share one refresh. A failed refresh
has a one-second cooldown. Expired successful data is never returned on error.
Refresh waits, upstream requests, verifier output, policy files, and response
bodies have limits. A failed refresh returns 503 with `Retry-After: 1`.
The response has `Cache-Control: no-store, max-age=0`.

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
update. That format includes nonce-bound workload receipts. The new process
uses version 3 only. Rollout checks must select verification by response
version and must keep inference-connection verification independent of the
metadata response.

## Customer procedure

Read [client verification](../../docs/verification.md) for release downloads,
metadata checks, full allowlist pinning, Intel collateral policy, and the GPU
boot gate. A workload certificate binds the policy at issuance. The metadata
cache and fresh connection proof do not make policy updates instantaneous.
The current contract retains operator-managed updates; it does not promise
zero Kubernetes API rights.
