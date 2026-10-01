# Client verification

This document is the source of truth for how a client verifies a Confidential
Inference cluster before the client sends private data. It gives the intended
state first. Each part then marks what exists **today** and what is
**planned**.

- **Today** means that the function is in a released tool or on `main`.
- **Planned** means that the function is in an open pull request only.

This is a living document. Update it when a tool, a release, or a limit
changes. The sources were last compared with this text on 2026-09-26.

## 1. Terms

- **Client**: the party that sends private data. The client runs the
  verification tools on its own machine.
- **TDX quote**: a statement that Intel TDX hardware signs. It contains the
  node image measurements and 64 bytes of report data that the software in the
  confidential virtual machine (CVM) chooses.
- **Node image measurements**: the TDX registers that identify the node
  image. MRTD measures the firmware. RTMR1 measures the kernel. RTMR2 measures
  the kernel command line, which carries the dm-verity root of the root file
  system. RTMR3 records events after boot (the operator key and workload
  chain). A complete image identity is MRTD+RTMR1+RTMR2 (TEErminator README,
  "Platform-complete pinning").
- **Node manifest**: the JSON file in this repository that records the
  measurements of one node image build:
  `images/control-plane-node/manifest-<environment>.json`. The three values
  are in its `tdx` object.
- **Front door**: the c8s router. It terminates public TLS inside the TEE for
  `https://api.confidential.ai`.
- **Attest-lb quote**: the evidence bundle that the front door serves at
  `/.well-known/c8s/attest-lb`. Its report data is
  `SHA-384(LP(version) || LP(front_door_mode) || LP(nonce) ||
  LP(SHA-256(serving_leaf)) || LP(SHA-256(mesh_leaf)) || LP(SHA-256(mesh_CA)))`.
  The client supplies the nonce (TEErminator README, "Attestation modes").
- **Mesh CA**: the certificate authority that c8s CDS creates inside the TEE.
  It signs every workload certificate. A CDS restart creates a new mesh CA
  (`docs/threat-model.md`, section 5).
- **Workload certificate**: the mesh leaf certificate that the mesh CA issues
  to one pod.
- **Allowlist**: the c8s policy document. It names each admitted image digest
  and its command-line arguments. Newer c8s versions also add environment and
  mount policy (c8s v0.33.2 `docs/allowlist-and-capabilities.md`). The file
  for each environment is `c8s/allowlists/<environment>.json`.
- **Workload stamp**: an extension (OID `1.3.6.1.4.1.66378.1.5`) in a
  workload certificate. It holds the workload name, the allowlist version, and
  the SHA-256 digest of the allowlist that CDS used for the match. The mesh CA
  signature vouches for the stamp. The hardware does not (c8s v0.33.2
  `docs/ratls.md`, "What vouches for the name").
- **Release manifest**: the signed JSON file on the GitHub release. Its name
  today is `release-bundle.json`. Its Sigstore signature is
  `release-bundle.sigstore.json`. The manifest records the node measurements,
  the workloads, the image digests, the mesh CA digest, and `allowlistDigest`
  (`contracts/release-bundle.schema.json`, `releases/README.md`).
- **`/attestation`**: the gateway route
  `GET /attestation?nonce=<32-byte base64url>`. It returns raw evidence, not a
  verdict: c8s discovery, the active allowlist, `c8s.meshCaSha256`, and one
  receipt per workload (`services/gateway/ATTESTATION.md`,
  `contracts/workload-attestation.schema.json`).
- **Aggregate verifier**: `scripts/verify-public-attestation.py`. It verifies
  one `/attestation` response against the signed release.
- **TEErminator**: a proxy that runs on the client machine. It verifies the
  front door on each new TLS connection before it forwards any bytes
  (github.com/confidential-dot-ai/TEErminator).

## 2. The chain of proof

The intended chain has six links. Each link depends on the link before it.

1. **Fresh TDX quote.** The client sends a new random nonce. The TDX quote
   over the report data includes that nonce. An old quote cannot match a new
   nonce.
2. **Node image.** The client compares MRTD, RTMR1, and RTMR2 in the quote
   with the node manifest at the release tag.
3. **Mesh CA in report data.** The report data includes `SHA-256(mesh_CA)`.
   The measured node image generated that report data, so the hardware binds
   the mesh CA to the measured image.
4. **Workload certificate.** The mesh CA signs the workload certificate. The
   report data also includes the hash of that certificate.
5. **Workload stamp.** The stamp in the workload certificate names the
   allowlist digest that CDS used to admit the workload.
6. **Allowlist and release.** The client computes SHA-256 over the
   allowlist file at the release tag. The digest must equal the stamp digest.
   The digest must also equal `allowlistDigest` in the release manifest. A
   GitHub Actions workflow on the protected tag signs that manifest
   (`releases/README.md`).

Note on bytes: `allowlistDigest` covers the canonical c8s bytes. The files in
`c8s/allowlists/` end with one newline character. The digest does not include
that newline. The aggregate verifier accepts both forms
(`validate_allowlist`). TEErminator hashes the exact file bytes. Remove the
final newline, or use `teerminator allowlist fetch`, before you give the file
to TEErminator.

## 3. Client flow today

Today the client must pass two separate gates. Both gates are required. A
client that passes only one gate has not verified the cluster.

The reason is one current limit. The front-door certificate carries no
workload stamp. So TEErminator can verify the front-door session and the full
node image, but not the allowlist (links 5 and 6). The aggregate verifier
verifies the workload allowlist from the `/attestation` receipts.

### 3.1 Get the trusted inputs

Get all inputs from the public release tag, not from the cluster.

1. Check out the release tag of this repository.
2. Download `release-bundle.json` and `release-bundle.sigstore.json` from the
   GitHub release.
3. Use `images/control-plane-node/manifest-<environment>.json` and
   `c8s/allowlists/<environment>.json` from the tag.
4. Use `releases/<environment>/trust/mesh-ca.pem` and
   `operator-public-key.pem` from the tag. Both files hold public material
   only.
5. Build the c8s CLI from the commit that
   `contracts/c8s-admission-source-lock.json` pins for the release.

### 3.2 Gate 1: review the cluster

Run the aggregate verifier. `README.md`, "Verify one live attestation", gives
the full command. The verifier makes these checks in order:

1. It verifies the Sigstore signature of the release manifest. It uses the
   signer identity policy in `releases/trust/release-signing-policy.json`.
2. It compares the node manifest with the release measurements and the node
   source lock (`validate_source_policy`).
3. It canonicalizes the allowlist and compares its digest with
   `allowlistDigest` (`validate_allowlist`).
4. It fetches `/attestation` with a fresh nonce. It requires the response to
   echo the nonce.
5. It requires the active allowlist in the response to equal the release
   allowlist, byte for byte (`validate_response_evidence`).
6. It requires `c8s.meshCaSha256` to equal the held mesh CA in static policy
   mode. In operator policy mode, it compares the held mesh CA with the release
   manifest.
7. In operator policy mode, it compares the operator key set with the release.
   On the `c8s/attest-pq/v1+xwing` protocol, this also needs an attested read
   from CDS (`--cds-url`).
8. It runs `c8s verify` on each workload receipt with `--image-manifest`,
   `--mesh-ca`, `--allowlist`, and `--workload`. It requires
   `workload_verified`, a pinned mesh CA chain, and pins on RTMR1, RTMR2, and
   RTMR3 (`verify_receipt`).
9. For a GPU release in `measured-boot-gate` mode, it requires
   `gpuEvidence.status` to be `not-exposed-by-c8s`. The measured node image
   stops the node before RKE2 starts if a GPU check fails.

The verifier prints `"verified":true` only after all checks pass. The result
has the scope `launch-or-admission-only`. It does not prove current liveness,
request routing, or model use (`services/gateway/ATTESTATION.md`).

### 3.3 Gate 2: connect through TEErminator

Send private data only through TEErminator. Use TEErminator commit `8d30234`
or later.

```sh
jq .tdx images/control-plane-node/manifest-production.json > image-manifest.json
teerminator remote add 127.0.0.1:8443 https://api.confidential.ai/ \
  --mode attest-lb --server-name api.confidential.ai \
  --image-manifest ./image-manifest.json
teerminator certs add releases/production/trust/mesh-ca.pem   # optional
teerminator status
```

- The `jq` step is necessary. TEErminator reads `mrtd`, `rtmr1`, and `rtmr2`
  at the top level of the file. The node manifest keeps them in `tdx`.
- For `public_tls.mode: acme`, `--server-name` must be the public host name
  on the certificate.
- Without `certs add`, the verdict is **deployment-class**: a measured c8s
  front door on the pinned image. With the mesh CA pin, the verdict is
  **specific-cluster**: this cluster, not a copy.
- Do not add `--workload` or `--allowlist` for this front door today. The
  front-door certificate has no stamp, so the handshake fails.

### 3.4 Fail-closed behavior

Each gate fails closed. The aggregate verifier exits with a non-zero code on
the first failed check. It fails if a required input is missing. It fails if
the source lock does not list the c8s commit of the release.

TEErminator verifies each new TLS connection before application bytes flow.
It pins the verdict to the exact serving certificate. A different
certificate, even with the same key, stops the handshake. An empty
measurement policy is a configuration error.

## 4. Planned: one gate

The planned state has one gate. TEErminator alone will verify the image, the
session, and the workload policy.

- **c8s #705** (open, stacked on c8s #704): CDS signs a rollout state with
  the mesh CA key. The state includes `bound`, the list of every allowlist
  digest that can still run. The attest-lb transcript commits SHA-384 of that
  state, so the state becomes part of the report data. `c8s verify` gets
  `--pin-policy sha256:<hex>` and `--fetch-allowlists DIR`.
- **TEErminator #24** (open, `feat/pinned-allowlist`): `remote add
  --pin-policy sha256:<hex>` fails attestation when `bound` holds a digest
  that the client did not pin. It also fails when CDS runs without an
  activation lease. `allowlist fetch --bound-dir DIR --pin` fetches each
  bound policy over the attested connection.
- With the planned router option `router.attest.pinnedAllowlist`, the router
  forwards only to an upstream whose stamp digest is in `bound`.

Neither pull request is in c8s v0.33.2 or in a TEErminator release. Gate 1
stays required until both merge, ship, and this repository pins the new c8s
release.

Planned client command:

```sh
teerminator remote add 127.0.0.1:8443 https://api.confidential.ai/ \
  --mode attest-lb --server-name api.confidential.ai \
  --image-manifest ./image-manifest.json \
  --pin-policy sha256:<allowlistDigest from the release manifest>
```

## 5. What each check stops

| Attack | Check that stops it | Today |
|---|---|---|
| Different OS image or kernel | MRTD+RTMR1+RTMR2 pin (`--image-manifest`) | Both gates |
| Different workload image or arguments | Stamp digest equals the release allowlist; `c8s verify --allowlist` | Gate 1 only |
| Different environment or mounts | The same allowlist check, when the pinned c8s version enforces `env` and `mounts` | Gate 1 only; see `docs/threat-model.md` section 5 |
| Fake CA that stamps any name | Mesh CA hash in hardware report data on a pinned image; optional mesh CA pin | Both gates |
| Replayed quote | Fresh client nonce in the report data | Gate 2 per connection; Gate 1 for the response nonce |

## 6. What the client does not need

- **The operator public key as an identity.** TEErminator pins RTMR3 only
  with the optional `--expected-rtmr3`, and only with `--image-manifest`.
  c8s `verify --operator-pkey` help calls RTMR3 "a deployment property, NOT a
  cluster identity": the host chooses the image and can reproduce the chain.
  Today the aggregate verifier still requires `--operator-public-key` from the
  release tag. The file is public.
- **GPU evidence.** In `measured-boot-gate` mode, the measured node image
  verifies each GPU before RKE2 starts. It powers off the node on failure. The
  node image pin covers this gate. The client does not need raw NVIDIA
  evidence or the attestation CLI (`contracts/README.md`).
- **Trust in the operator or the host.** The client trusts Intel TDX, the
  measured node image, the pinned c8s verifier, and the signed release
  (`docs/threat-model.md`, section 2).

## 7. Open items

1. Add a workload stamp to the front-door certificate, or ship c8s #705 and
   TEErminator #24, so that one gate covers the allowlist.
2. Pin the c8s release that contains c8s #703 to #705 in
   `contracts/c8s-admission-source-lock.json`.
3. Publish a TEErminator-format image manifest (top-level `mrtd`, `rtmr1`,
   `rtmr2`) with each release, so the `jq` step is not necessary.
4. Decide how a client gets a new mesh CA pin after a CDS restart.
5. Decide if the aggregate verifier can make `--operator-public-key`
   optional.
6. Decide if Gate 1 must also prove freshness of each workload receipt. Today
   the verifier checks the response nonce and runs `c8s verify` on each
   receipt from a file.
7. Confirm which environments enforce `env` and `mounts` policy, and update
   the table in section 5.
8. Rename `release-bundle.json` to match the term "release manifest", or
   keep the file name and this definition.
