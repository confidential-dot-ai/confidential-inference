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

- `inference-serving.md`: inference engine integration requirements, lifecycle,
  metrics, and confidentiality checks. The existing SGLang image-build migration
  is tracked in [SGLang separation](../docs/sglang-separation.md).
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
