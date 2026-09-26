# Threat model

Some file references in this document describe the historical v0 release
format under `releases/production/`. Use the signed GitHub Release assets and
`contracts/release-manifest.schema.json` for the current public release
contract. The historical references remain for old receipt verification.

This document states who and what this deployment trusts, what a verified
attestation proves, and the residual risks and known gaps. Every claim below
cites the file it comes from. Read `README.md` and
`scripts/verify-public-attestation.py` for the exact verification steps.

## 1. System summary and request path

A client sends a request to the public HTTPS endpoint. The c8s tls-lb nginx
process terminates public TLS inside the TEE and forwards plain HTTP to the
Rust gateway over the cluster network (`services/gateway/src/main.rs`).
The gateway checks the bearer
API key and request limits, then proxies the request through the c8s
workload-proxy loopback to the sglang-router workload
(`services/gateway/src/main.rs`, `INFERENCE_UPSTREAM_URL`). The router sends
the request to one of the sglang inference workers.

- The inference engine is SGLang v0.5.18, at commit `71de97b264b0` of
  `github.com/sgl-project/sglang`, with confidential-compute patches
  (`images/sglang/source.lock`).
- The served model is `deepseek-ai/DeepSeek-V4-Flash-0731`
  (`releases/production/release-bundle.json`). This is the exact repository
  and revision the production release pins; use this name, not a
  generic "DeepSeek-V4-Flash" label.
- Inference workers request NVIDIA Blackwell GPUs and carry
  confidential-computing GPU evidence flags
  (`releases/production/release-bundle.json`, `gpu.architectures: ["BLACKWELL"]`,
  `--nvidia-gpu-evidence`).
- Every cluster node boots as an Intel TDX confidential virtual machine from
  one measured ConfOS image (`images/control-plane-node/README.md`,
  `README.md`, "What attestation proves").
- Production c8s runs in static policy mode: the allowlist is baked into the
  measured node image, and c8s has no operator key that can change it
  (`services/gateway/ATTESTATION.md`; `c8s/README.md`).

## 2. Trust boundary

**Untrusted:**

- The host operator and the bare-metal or cloud provider.
- The Kubernetes control plane and etcd
  (`images/control-plane-node/README.md`: "c8s treats the Kubernetes control
  plane as untrusted").
- Confidential AI staff, in their operator capacity.

**Trusted:**

- Intel TDX and its attestation chain.
- NVIDIA GPU attestation through NRAS, as verified by the c8s and
  attestation-rs verifiers.
- The measured ConfOS node image (`images/control-plane-node/README.md`).
- The Sigstore-signed release bundle (`releases/README.md`, "Trust limits").
- The c8s verifier at a pinned commit
  (`contracts/c8s-admission-source-lock.json`, which lists one entry per
  trusted c8s commit; a release naming any other c8s commit fails closed).

## 3. What a verified attestation proves, and does not prove

A successful `/attestation` verification proves that the responding nodes
started in Intel TDX confidential virtual machines, that the measured ConfOS
image matches the approved node manifest, that c8s admitted each reported
container image and command, that each image digest is in the signed c8s
allowlist, and that the response is bound to the caller's nonce
(`README.md`, "What attestation proves").

It proves launch or admission only. It does not prove that a workload is
still running, that requests route to it, what is mounted into it, its
environment variables, or that the model is in active use
(`services/gateway/ATTESTATION.md`: "The response proves launch or admission
facts. It does not prove current liveness, request routing, mounts,
environment values, or model use."). Use `/health` to check that the service
runs now (`README.md`, "What attestation proves").

## 4. Assets

- **Prompts and completions.** Carried through the RA-TLS mesh from the
  gateway to the sglang workers.
- **API keys.** The gateway stores a peppered hash, not the plaintext key.
  The pepper lives in CDS memory and reaches the gateway as a released secret
  (`services/gateway/src/main.rs`, `GATEWAY_API_KEY_PEPPER_FILE`;
  `c8s` `docs/secrets.md`, at commit `079aeb48`, describes this release path).
- **The key registry snapshot.** The admin virtual machine holds the key
  record and pushes the complete snapshot to each gateway through the
  signed admin channel (`PUT /admin/v1/api-keys/snapshot`). The snapshot
  carries one peppered hash per key. It carries no plaintext key and no
  pepper. The gateway refuses a revision lower than the one it holds, so
  the control plane cannot roll the key set back. The control plane can
  still remove a key. That is a denial of service, not a loss of
  confidentiality, and the threat model already treats the host as
  untrusted.
- **Model weights.** DeepSeek-V4-Flash-0731 is a public model. It is served
  from a dm-verity-verified, dm-crypt-encrypted volume
  (`releases/production/release-bundle.json`, `model.dmVerityRoot` and
  `model.mountVerification`).
- **The mesh CA and leaf keys.** Generated inside CDS and never leave the
  measured process (`c8s` `docs/static-allowlist.md`, at commit `079aeb48`).

## 5. Residual risks and limits

- **Pod egress on the inference path is mesh-routed, not plaintext, to
  non-mesh hosts.** c8s redirects TCP from a non-root workload into the mesh
  proxy. That redirect fails for a non-mesh destination (`c8s/README.md`,
  "Known gaps and open items": "Root workloads are intercepted but cannot
  egress to non-mesh peers... Run workloads as non-root so legitimate
  traffic is mesh-routed."). The gateway, the sglang router, and the
  inference workers all run as non-root
  (`helm/confidential-inference/templates/gateway.yaml`,
  `helm/confidential-inference/templates/inference-workers.yaml`,
  `runAsNonRoot: true`). So the inference path has no plaintext egress to a
  host outside the mesh.
- **CDS is a singleton that holds keys only in memory.** A CDS restart
  mints a new mesh CA and empties the whole secret store; every released
  secret and volume key is gone, and dependent workloads must be rolled
  (`c8s/README.md`, "Known gaps and open items": "CDS is a singleton...
  Secrets and volume keys live only in CDS memory... a CDS restart destroys
  every secret and volume key").
- **The static allowlist changes only with a new measured node image.**
  Static mode bakes the allowlist into the node image and disables every
  allowlist mutation route; a policy change requires a new sealed image
  (`c8s/README.md`; `c8s` `docs/static-allowlist.md`, at commit `079aeb48`).
- **RTMR0 is not pinnable.** The c8s verifier documents this directly: on
  TDX, `RTMR[0]` cannot be pinned by the verifier's `--rtmr` flag (c8s
  `internal/cmds/verify/verify.go`, flag help for `--rtmr`, at commit
  `079aeb48`).
- **c8s v0.26.5 enforces GPU attestation as a measured boot gate.** The node
  image checks confidential-computing mode and nonce-bound evidence for every
  passed-through NVIDIA GPU. RKE2 requires this systemd unit. A failure powers
  off the node, so a GPU workload cannot join or run after a failed check. The
  verdict stays inside the node and raw NVIDIA evidence does not reach the
  relying party. The offline verifier checks the measured node image and
  reports this enforcement mode. The source lock pins the gate script, its
  systemd unit, and the preset that enables the dependency
  (`contracts/c8s-admission-source-lock.json`, c8s commit `152d583`).
- **The tls-lb-to-gateway hop is plain HTTP inside the cluster network.**
  Public TLS terminates at tls-lb, inside the TEE; the hop to the gateway
  process is HTTP, gated by the c8s allowlist and carried over the mesh
  network (`services/gateway/src/main.rs`, `GATEWAY_LISTEN`).
- **The allowlist gates image digest and argv, not environment variables or
  mounts.** c8s enforces each container's image digest and command-line
  arguments; the rest of the pod spec, including environment variables and
  bind mounts, is not gated the same way (`c8s/README.md`, "Known gaps and
  open items": "The image allowlist gates digest and command line, not the
  rest of the pod spec... bind-mount destinations and env variable names are
  enforceable in the guest; capabilities and the remaining pod-spec fields
  are not.").

## 6. Known gaps under remediation

### The c8s operator key

Production runs c8s in static policy mode, so the operator key cannot change
the allowlist (`services/gateway/ATTESTATION.md`). The offline verifier still
pins RTMR3 to the hash of the published operator public key in this mode,
proving the node launched bound to that key and no other
(`scripts/verify-public-attestation.py`, `policy_verifier_flags`). The key
still authorizes two things it is not restricted from: it can write secrets
into CDS (c8s
`docs/secrets.md`, at commit `079aeb48`: "these keys still authorize this
secret write route" in static mode), and it can request a cluster-admin
kubeconfig from the c8s credential-release service, which issues a
certificate in the `system:masters` group (c8s
`internal/cmds/credrelease/run.go`, at commit `079aeb48`: "v1:
O=system:masters, CN=operator (cluster-admin)").

The Kubernetes control plane is not part of the trust boundary
(`images/control-plane-node/README.md`: "c8s treats the Kubernetes control
plane as untrusted"). So on node-as-CVM, a holder of the cluster-admin
credential can exec into a pod inside the TEE. That holder can then read the
workload's memory. The operator key is held in Infisical. An engineer uses
the key only at deploy time.

Removal of the operator key from production is planned. After removal, RTMR3
will be pinned to zero. RTMR3 is the register that the operator-key and
workload chain extends (c8s `internal/cmds/verify/verify.go`, flag help for
`--rtmr`: "RTMR[3] is the operator-key/workload chain extended inside
whatever image the host booted"). A pinned zero RTMR3 will prove that no
credential-release path was armed at boot.

### The control-plane state disk

The control-plane node mounts a persistent state disk at
`/var/lib/rancher/rke2/server` and formats it as plain ext4, with no disk
encryption
(`images/control-plane-node/profile/control-plane-state/mkosi.extra/usr/local/libexec/confidential-inference/control-plane-state-disk.sh`;
`images/control-plane-node/README.md`: "The persistent state disk is not
encrypted by this profile. The host can read or change its content."). This
disk holds RKE2 server state, including the RKE2 client CA key. A party with
read access to the virtual disk can mint a cluster-admin certificate from
that key.

Encryption of this disk is planned.

## 7. Verification procedure

For the exact, current verification steps, read `README.md` ("Verify one
live attestation") and run `scripts/verify-public-attestation.py`. Do not
treat this document as a substitute for that procedure.
