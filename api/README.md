# Release and API contracts

Use [client verification](../docs/verification.md) for the current public
endpoint and [release documentation](../release/README.md) for publication.

## Current release and discovery

- `release-manifest.schema.json`: signed release manifest for v0.14.0 and
  later. It records source, image digests, node measurements, publication
  evidence, and the initial policy.
- `environment-spec.schema.json`: deployment environment input format.

The active policy can differ from the signed initial policy. Clients review
and pin the exact active bytes separately.

## Gateway APIs

- `gateway-inference.openapi.json`: public inference, model catalog, health,
  and native c8s routes served by TLS-LB.
- `gateway-admin.openapi.json`: the key registry snapshot. The gateway pulls
  it from the admin (`GET /api/gateway/key-snapshot`); the admin may also
  push it to the gateway's signed admin API.
- `product-usage.md`: per-request usage events the gateway sends to the admin.
- `maintenance-gateway.openapi.json`: public responses during an outage.

The gateway keeps no state on disk. The admin key registry is the only key
store. A snapshot carries peppered key hashes and a pepper fingerprint, never
the pepper or a plaintext API key.

## Maintenance

- `maintenance-dns-receipt.schema.json`: secret-free DNS change receipts.

## Historical contracts

- `release-bundle.schema.json`: release inventory format before v0.14.0.
  The release signature check still validates old releases against it.

The network port and observability references moved to
[docs/network-ports.yaml](../docs/network-ports.yaml) and
[docs/observability-metrics.yaml](../docs/observability-metrics.yaml). The c8s
source lock (pinned c8s commits and source hashes) moved to
[release/inputs/c8s-source-lock.json](../release/inputs/c8s-source-lock.json),
and the c8s attestation protocol captures to
[release/inputs/c8s-attestation-protocols](../release/inputs/c8s-attestation-protocols).
The signed release still records the lock path and digest; releases before
the move name `contracts/c8s-admission-source-lock.json`.
