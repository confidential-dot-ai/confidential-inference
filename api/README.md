# Release and API contracts

Use [client verification](../docs/verification.md) for the current public
endpoint and [release documentation](../release/README.md) for publication.

## Current release and discovery

- `release-manifest-v2.schema.json`: signed framework release manifest. It
  records source, every image digest, the C8s pins, node measurements, the
  chart, and publication evidence. It holds no policy and no environment value.
- `release-manifest.schema.json`: the earlier signed release manifest
  (v0.14.0 to v0.16.x), which also bound an initial policy.
- `environment-spec.schema.json`: environment input format.

Each deployment renders its own policy from a framework release and its
environment. Clients
check its image digests against the signed release, review the rest, and pin
the exact active bytes.

## Gateway APIs

- `gateway-inference.openapi.json`: public inference, model catalog, health,
  and native C8s routes served by the C8s router.
- `gateway-admin.openapi.json`: the key registry snapshot. The gateway pulls
  it from the admin (`GET /api/gateway/key-snapshot`); the admin may also
  push it to the gateway's signed admin API.
- `product-usage.md`: per-request usage events the gateway sends to the admin.
- `maintenance-gateway.openapi.json`: public responses during an outage.

The gateway keeps no state on disk. The admin key registry is the only key
store. A snapshot carries peppered key hashes and a pepper fingerprint, never
the pepper or a plaintext API key.

### Per-key limits

The admin can set two optional limits on each key row of the snapshot. An
absent or `null` limit means "no limit". A snapshot from an older admin is
still valid, and all its keys have no limits.

- `rateLimit` (`requestsPerMinute`, optional `burst`): a token bucket.
  **Each gateway replica keeps its own bucket in memory.** The chart has no
  shared gateway state, so N replicas admit up to N times the rate. A
  restart refills the bucket. A refused request gets `429
  rate_limit_exceeded` and `Retry-After`.
- `tokenBudget` (`tokens`, `window` = `day` or `month`): the largest sum of
  input and output tokens in one UTC calendar window. A refused request
  gets `429 insufficient_quota` and `Retry-After` until the window ends.
  We use 429, not 402, because the OpenAI API uses 429 with this code, and
  OpenAI clients know it.

The gateway checks both limits after authentication and before it reads the
request body or forwards anything upstream. The error body has only `code`
and `message`. It never names the key, a limit value, or the spend.

The gateway learns the spend from the admin. The envelope field
`tokenUsage` holds, per key with a budget, the tokens of all stored usage
events in the current window at time `asOf`. This count includes all
replicas and all earlier gateway processes, so it stays correct after a
restart. The gateway pulls a snapshot every 30 s and applies a newer
`asOf` also when the revision does not change. Between two pulls, each
replica adds the tokens of the requests it finished itself. The budget is
therefore a soft limit: the spend can go over the budget by the requests in
flight and by the tokens other replicas used since the last pull. The
spend needs usage events; without them the gateway does not enforce the
budget.

## Maintenance

- `maintenance-dns-receipt.schema.json`: secret-free DNS change receipts.

The network port and observability references moved to
[docs/network-ports.yaml](../docs/network-ports.yaml) and
[docs/observability-metrics.yaml](../docs/observability-metrics.yaml). The C8s
source lock (pinned C8s commits and source hashes) moved to
[release/inputs/c8s-source-lock.json](../release/inputs/c8s-source-lock.json),
and the C8s attestation protocol captures to
[release/inputs/c8s-attestation-protocols](../release/inputs/c8s-attestation-protocols).
The signed release still records the lock path and digest; releases before
the move name `contracts/c8s-admission-source-lock.json`.
