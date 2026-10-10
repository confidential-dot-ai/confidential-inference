# Historical schema 2 receipt verification

This document records the former aggregate-proof contract. It is not a
procedure for the current public endpoint. Version 3 uses release and policy
discovery and separate c8s connection verification.

Read [current client verification](../../docs/verification.md) and
[the gateway contract](../../services/gateway/ATTESTATION.md).

The descriptions below apply only to the older commits named here. Claims
about a gateway that cannot read operator keys describe that older gateway.
The current gateway reads operator keys over a verified CDS connection.

The following protocol, placeholder-key, and receipt-set descriptions apply to
version 2. Version 3 instead returns keys obtained by the gateway over a
verified CDS connection. Do not apply these historical requirements to the
current metadata response.

## The two historical c8s attestation protocols

c8s serves two `attest-pq` protocols, both with the receipt `version` string
`c8s/attest-pq/v1`, so the response cannot say which one it used. The gateway
declares it instead, in the optional `c8s.attestationProtocol` field:

- `c8s/attest-pq/v1` (old, production only, c8s `079aeb48`): the receipt
  carries `session_pubkey`. The gateway must not send this value; its absence
  means the old protocol.
- `c8s/attest-pq/v1+xwing` (new, c8s `466ce79`, `152d583`, and `2ef376a8`): the receipt
  carries `xwing_ek`, `xwing_ct`, and `session_id` instead of
  `session_pubkey`. It also folded `GET /allowlist`, so
  `c8s.activeAllowlist.document` may omit `digests`.

`contracts/c8s-admission-source-lock.json` names the protocol each pinned c8s
commit speaks in a new `attestationProtocol` field on the top-level entry and
on each `commits` entry. `scripts/verify-public-attestation.py` reads that
field, not the response, to pick its branch, and then checks that the
response's own `c8s.attestationProtocol` agrees.

GPU enforcement is a separate source-lock capability. Older entries use
`receipt-evidence`. The verifier requires raw NVIDIA evidence from each GPU
worker and verifies it with the pinned c8s GPU verifier. c8s v0.26.5 uses
`measured-boot-gate`. Its measured node image checks every passed-through GPU
before RKE2 starts. The systemd dependency blocks RKE2 on failure and powers
off the node. This mode does not expose raw NVIDIA evidence to the relying
party. The verifier therefore checks the measured node image and reports the
boot-gate mode. It does not require raw NVIDIA receipt fields or the external
attestation CLI. The source lock pins the boot-gate script, unit, and systemd
preset so this rule fails closed if their source changes.

c8s never binds the allowlist-write operator key set to hardware evidence at
either commit (see `docs/ratls.md`), so on the new protocol the gateway can
only report `requires-attested-cds-read` in `c8s.operatorTrust.activeKeySetStatus`
— never `evidence-present-and-release-matched`, which the verifier now
rejects outright on that protocol.

The gateway also does not read the key set. c8s serves it on the CDS route
`GET /operator-keys`, and CDS presents a self-signed RA-TLS certificate whose
trust comes from a TEE evidence extension and a pinned launch measurement, not
from any certificate authority. No CA-trusting TLS client can verify that
certificate, so a gateway read cannot work at all. On the new protocol the
gateway therefore publishes two fields and no live value:
`expectedKeySetSha256`, the pinned c8s key-set commitment this deployment was
built against, and `cdsAttestedReadHint`, the CDS route the reader must fetch.
A `requires-attested-cds-read` response must carry `cdsAttestedReadHint` and
must carry none of `activeKeySetSha256`, `activeKeySetPem` or
`activeKeySetC8sSha256`. The schema enforces both halves.

The verifier performs that read itself. `scripts/verify-public-attestation.py
--cds-url <CDS RA-TLS base URL>` runs the pinned c8s CLI:

    c8s verify <cds-url> --kind cds --mode ratls-cert \
        --image-manifest <node manifest> -o json

That command dials the CDS RA-TLS certificate, verifies its TEE evidence
against the hardware signature chain, pins the launch measurement to the node
image manifest, and returns the `/operator-keys` set it read over that same
attested session as `operator_keys` — one SHA-256 SPKI fingerprint per key.
The verifier recomputes the c8s key-set commitment from those fingerprints
with the canonical formula (`pkg/operatorauth.KeySetDigest`: SHA-256 over
`c8s-operator-key-set-v1\0` followed by the sorted, de-duplicated
fingerprints) and requires it to equal **both** the release bundle's
`operatorKeySetSha256` and the response's `expectedKeySetSha256`. The held
operator public key must be a member of the set the attested read returned.

Without `--cds-url` the verifier fails closed on the new protocol. It never
skips the check.

The response schema accepts exactly three receipt-set shapes: all six
targets; the same six without `inference-worker-1` (staging, which runs one
inference worker and both observability workloads); and the four core targets
without `metrics-collector` and `kube-state-metrics`. Any other subset fails
closed.

`scripts/check-c8s-protocol-lockstep.py` guards the pairing itself. For each
lock entry it reads the matching manifest under
`contracts/c8s-attestation-protocols/<commit>.json` (the `cdsattest` route
table and the `AttestationBundle`/receipt field names at that c8s commit,
captured read-only from the `c8s` source) and fails the build if those fields
disagree with the gateway's own declared protocol constant and test fixture
field set. It runs offline, from files already committed to this repo, from
`scripts/bump-c8s.py` after each c8s bump.

A manifest also covers the commits in its `sharedWithCommits`. `scripts/bump-c8s.py`
adds a new c8s commit there when the captured source files did not change, or
changed only in Go comments (`tools/go-strip-comments`). After another change it
stops, or with `--protocol-review` it adds the commit and writes the source diff
for the pull request: a person reviews that diff and merges the pull request, or
captures a new manifest.

Use `scripts/verify-public-attestation.py` for the complete public verification flow.

The command fetches the HTTPS endpoint with a fresh nonce. It verifies the exact
receipt target set from the trusted release bundle with the c8s verifier.

The command requires the trusted release bundle and its trusted OCI digest.

It also requires the node manifest, operator public key, held mesh CA, and environment.

Do not infer online collateral verification from the use of `attestation-go`.
The caller must enable those checks. For the current customer path, configure
TEErminator with an explicit `--tdx-tcb-status` policy.

Kettle provenance remains optional. Add it only when a release produces a Kettle statement.

