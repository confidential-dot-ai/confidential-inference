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
| `releaseSelection` | Desired release and its match with the reported CDS policy, when runtime selection is enabled. |
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

`GATEWAY_C8S_CDS_URL` selects the CDS HTTPS origin.
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

The runtime `evidence` object selects the front door for native discovery.
`baseUrl` is an HTTPS origin. Its hostname remains the expected TLS name.
The optional `connectHost` selects a connection address without changing that
name or the TLS port. Omitting `connectHost` uses normal DNS for the origin.
Discovery keeps certificate checks enabled and refuses redirects.

Without runtime `evidence`, `GATEWAY_C8S_EVIDENCE_BASE_URL` and
`GATEWAY_C8S_EVIDENCE_CONNECT_HOST` remain startup fallbacks for existing
installations. If no startup URL is set, runtime `evidence` is required and
cannot be removed by a later update. CDS addresses and trust pins remain
startup inputs.

## Load protection

The handler reuses the gateway request-rate, address-concurrency, and
attestation-concurrency limits. Its cache lasts 10 seconds by default, with a
maximum of 30 seconds. Concurrent requests share one refresh. A failed refresh
has a one-second cooldown. Expired successful data is never returned on error.
Refresh waits, upstream requests, verifier output, policy files, and response
bodies have limits. A failed refresh returns 503 with `Retry-After: 1`.
The response has `Cache-Control: no-store, max-age=0`.

## Runtime release selection

`GATEWAY_RELEASE_SELECTION_FILE` selects a mounted configuration file.
It contains `schemaVersion: 1`, an increasing `revision`,
`selectedBundleSha256`, and `releaseBundles`. Each bundle is a JSON string
that preserves the exact bytes of its signed release asset. Deployment tools
verify signatures and build evidence before they write this configuration.
The gateway derives the release name, public URL, bundle hash, and policy hash
from these bytes. It does not download an asset during a request.

The selected bundle takes precedence when several releases share a policy.
If the reported CDS policy matches another unique configured bundle, the
gateway reports that release and marks the desired selection as pending.
If no unique bundle matches, `release` is null and `releaseSelection.status`
is `pending`. The client verifier rejects that state. The CDS allowlist stays
in the response. A desired release is not a claim that its policy is enforced.

The file watcher watches the mount directory. A five-second polling fallback
handles missed events. Configuration status is available at `/release-config`
on the private metrics listener. It shows desired and accepted revisions,
hashes, and errors. These fields are operational information, not TEE evidence.
Invalid updates retain the accepted configuration. Invalid startup data stops
startup. A rollback writes the previous contents with a new revision.

`GATEWAY_RUNTIME_CONFIG_FILE` selects the gateway settings file. It controls
the model catalog and admitted models, body limit, request timeouts, capacity
and queue limits, request rate, attestation cache duration, and evidence addresses. The accepted
status is at `/runtime-config` on the same private listener. Each request
keeps its model and timeout snapshot. A capacity decrease preserves active
permits and blocks new admission until usage falls. Queued requests keep
their deadline and use the current execution capacity. HTTP clients, rate
windows, and request counters are not replaced on reload.

To change the evidence address during candidate promotion, update the existing
runtime ConfigMap. Keep all other settings and increase `revision`. For example,
the `settings.json` document can contain:

```json
"evidence": {
  "baseUrl": "https://candidate.api.example.test",
  "connectHost": "c8s-router.c8s-system.svc.cluster.local"
}
```

After the front door has a valid certificate for the production hostname,
change `baseUrl` to `https://api.example.test` with another increased revision.
Use the existing Kubernetes API access to apply the ConfigMap. Do not put the
file under a `subPath` mount. Check the accepted revision and errors at the
private `/runtime-config` endpoint, then check public `/attestation`.
No reload request or temporary pod is needed.

The next metadata request after an accepted address change drops the old
successful cache or failure cooldown and creates a client for the new address.
Later refreshes reuse that client. A refresh already in progress finishes with
its old address snapshot. A change to another setting retains the client and
cache. Invalid configuration retains the last accepted settings. An unreachable
address or a TLS failure returns 503; it does not disable verification or
silently use the old address. The runtime status reports configuration
acceptance, not a successful network or attestation check. CDS trust pins and
startup TLS roots do not change with these addresses.

The optional `routerService` setting selects `sglang-router` or a Service
whose name starts with `router-`. It needs the fixed startup input
`GATEWAY_ROUTER_NAMESPACE` and direct-router mode. It cannot select another
namespace, port, or external URL. New requests use the new Service hostname.
Active requests keep their old target and HTTP connection. The HTTP client
keeps separate connection pools for the two hostnames.
The target keeps the startup protocol and port.

`gateway_router_requests_active` counts authenticated requests that retain
each router target. This includes body reads, queued requests, and open
streams. Deployment must check this counter as well as the old router's
active-request counter before removal. A ready new router alone does not
prove that the old route has drained.

Runtime status also reports `retiredSnapshotReaders`. Old requests and streams
keep their configuration snapshot until they close. When removing a model,
stop new gateway admission first. Wait until the previous snapshot readers
reach zero before removing its router alias. This allows traffic for other
models to continue. Reload waits if 64 old snapshots still have readers; the
polling fallback retries after requests drain.

Secrets, CDS trust pins, authentication settings, listener settings, and
worker initialization remain startup inputs. Mount configuration directories
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
