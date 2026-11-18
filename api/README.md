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
- `maintenance-gateway.openapi.json`: public responses during an outage.

The gateway keeps no state on disk and holds no API key. Confidential Cloud
keeps the inference keys and the credits. The gateway asks it whose each key
is and reports the tokens of each request it served
([telemetry egress](../docs/telemetry-egress.md), section 3.3). An org out of
prepaid credits gets `429 insufficient_quota`, the code OpenAI-compatible
clients expect for an exhausted quota.

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
