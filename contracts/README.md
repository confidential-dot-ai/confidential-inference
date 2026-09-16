# Release and attestation contracts

`release-bundle.schema.json` defines the public release inventory.

`workload-attestation.schema.json` defines the gateway response with one receipt for each real c8s workload pod.

`environment-spec.schema.json` defines the shape of one confidential inference deployment environment, including its confidential-compute boot images, network settings, and GPU count.

Use `scripts/verify-public-attestation.py` for the complete public verification flow.

The command fetches the HTTPS endpoint with a fresh nonce. It verifies the exact
receipt target set from the trusted release bundle with the c8s verifier.

The command requires the trusted release bundle and its trusted OCI digest.

It also requires the node manifest, operator public key, held mesh CA, and environment.

The command checks Intel TDX collateral through c8s `attestation-go`. It does not claim workload liveness.

Kettle provenance remains optional. Add it only when a release produces a Kettle statement.

## Public inference gateway

`gateway-inference.openapi.json` defines the real public API of the Rust gateway. It covers health, the model catalog, the OpenAI-compatible chat and completions routes, and the nonce-bound attestation routes, plus the static paths that the tls-lb nginx process serves without the gateway.

## Admin gateway

`gateway-admin.openapi.json` defines the signed admin API that manages gateway API keys through c8s tls-lb.

The admin API also exports and imports the full key store. A blue-green switch uses these two operations
to carry the key store from the old cluster to the new one without a disk move or a restart. The export
envelope carries a fingerprint of the pepper, never the pepper, and never a plaintext key. The import
operation refuses a copy whose pepper fingerprint does not match its own, and inserts records
idempotently by id in one transaction: an identical existing record is skipped, and a conflicting
existing record refuses the entire import.

The admin API also freezes and unfreezes the key store. A freeze refuses new mints and revocations so
the export-import-switch sequence cannot lose a key minted mid-copy. A freeze auto-lifts after 10
minutes.

## Network and observability

`network-ports.yaml` lists every network port the deployment uses, with its scope, protocol, direction, and access rule.

`observability-metrics.yaml` defines the metrics contract: the remote-write target, the scrape jobs, the forbidden sensitive labels, and the recording rules.

## Maintenance gateway

`maintenance-gateway.openapi.json` defines exact public responses during an inference outage.

The public TLS layer handles TLS before it forwards a request to the maintenance service.

`maintenance-dns-receipt.schema.json` defines secret-free DNS cutover and rollback receipts.
