# Release and attestation contracts

`release-bundle.schema.json` defines the public release inventory.

`workload-attestation.schema.json` defines the gateway response with one receipt for each real c8s workload pod.

`environment-spec.schema.json` defines the shape of one confidential inference deployment environment, including its confidential-compute boot images, network settings, and GPU count.

`c8s-admission-source-lock.json` pins the c8s source commit a signed release may
use. Each environment can cut its release from a different c8s commit, so the
lock keeps its original single-entry shape at the top level (one commit, its
digest-pinned node and operator images, its required verifier flags, and its
per-file source hashes) and adds an optional `commits` list of further entries
in the same shape. The verifier selects the entry whose `commit` field equals
the release bundle's recorded `c8s.sourceCommit`, and fails closed if no entry
matches — an unlisted c8s commit must never verify. `scripts/verify-c8s-admission-source.py`
accepts `--commit` to check the c8s source tree against one specific pinned
entry (the top-level one, or one from `commits`); without it, it checks the
top-level entry, as before.

### The two c8s attestation protocols

c8s serves two `attest-pq` protocols, both with the receipt `version` string
`c8s/attest-pq/v1`, so the response cannot say which one it used. The gateway
declares it instead, in the optional `c8s.attestationProtocol` field:

- `c8s/attest-pq/v1` (old, production only, c8s `079aeb48`): the receipt
  carries `session_pubkey`. The gateway must not send this value; its absence
  means the old protocol.
- `c8s/attest-pq/v1+xwing` (new, c8s `466ce79` and `2ef376a8`): the receipt
  carries `xwing_ek`, `xwing_ct`, and `session_id` instead of
  `session_pubkey`. c8s also removed `gpu_attested`/`nvidia_gpu` from the
  receipt, so `gpuEvidence.status` may be `not-exposed-by-c8s`, and it folded
  `GET /allowlist`, so `c8s.activeAllowlist.document` may omit `digests`.

`contracts/c8s-admission-source-lock.json` names the protocol each pinned c8s
commit speaks in a new `attestationProtocol` field on the top-level entry and
on each `commits` entry. `scripts/verify-public-attestation.py` reads that
field, not the response, to pick its branch, and then checks that the
response's own `c8s.attestationProtocol` agrees.

c8s never binds the allowlist-write operator key set to hardware evidence at
either commit (see `docs/ratls.md`), so on the new protocol the gateway can
only report `requires-attested-cds-read` in `c8s.operatorTrust.activeKeySetStatus`
— never `evidence-present-and-release-matched`, which the verifier now
rejects outright on that protocol. The verifier still requires the response's
`activeKeySetSha256` to equal the release's pinned `operatorKeySetSha256`.

`scripts/check-c8s-protocol-lockstep.py` guards the pairing itself. For each
lock entry it reads the matching manifest under
`contracts/c8s-attestation-protocols/<commit>.json` (the `cdsattest` route
table and the `AttestationBundle`/receipt field names at that c8s commit,
captured read-only from the `c8s` source) and fails the build if those fields
disagree with the gateway's own declared protocol constant and test fixture
field set. It runs offline, from files already committed to this repo, in
`.github/workflows/v0-validation.yml`.

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
