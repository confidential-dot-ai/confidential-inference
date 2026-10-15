# Release and API contracts

Use [client verification](../docs/verification.md) for the current public
endpoint and [release documentation](../release/README.md) for publication.

## Current release and discovery

- `release-manifest.schema.json`: signed release manifest for v0.14.0 and
  later. It records source, image digests, node measurements, publication
  evidence, and the initial policy.
- `workload-attestation.schema.json`: schema 3 release and active-policy
  metadata. It also retains schema 2 for historical responses. Schema 3
  requires no API key or nonce and has no aggregate workload receipts.
- `c8s-admission-source-lock.json`: pinned c8s commits and source hashes.
  The signed release identifies the selected commit and lock digest.
- `environment-spec.schema.json`: deployment environment input format.

The gateway reads the active policy and operator public keys through verified
CDS access. See [the gateway contract](../services/gateway/ATTESTATION.md).
The active policy can differ from the signed initial policy. Clients review
and pin the exact active bytes separately.

## Gateway APIs

- `gateway-inference.openapi.json`: public inference, model catalog, health,
  schema 3 discovery, and native c8s routes served by TLS-LB.
- `gateway-admin.openapi.json`: signed API-key administration, key-store
  export and import, and a temporary key-store freeze.
- `maintenance-gateway.openapi.json`: public responses during an outage.

Key-store export includes a pepper fingerprint, never the pepper or a
plaintext API key. Import requires a matching pepper fingerprint. Conflicting
records refuse the transaction. A freeze stops mint and revoke operations
and expires after ten minutes.

## Network and observability

- `network-ports.yaml`: port, protocol, scope, and access rules.
- `observability-metrics.yaml`: scrape jobs, labels, and recording rules.
- `maintenance-dns-receipt.schema.json`: secret-free DNS change receipts.

## Historical contracts

The old schemas, policies, and fixtures remain because scripts and tests use
them. They do not define the current customer verification procedure.

- `release-bundle.schema.json`: earlier release inventory format.
- [Schema 2 receipt verification](historical/schema-2-receipt-verification.md):
  old protocols, fixed target sets, and deployment trust inputs.
- [Schema 2 admission receipts](historical/c8s-admission-receipts.md): former
  per-workload receipt procedure.
