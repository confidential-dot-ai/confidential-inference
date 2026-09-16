# c8s admission receipts

The pinned c8s node image supplies the admission proof. Do not add a private
workload admission API.

Run `scripts/verify-c8s-admission-source.py` against the pinned c8s checkout
before deployment. The source lock reads the pinned commit. It ignores dirty
working files.

Two other scripts check different admission receipts. Use
`scripts/verify-c8s-admission-receipts.py` to check certificates already
collected from a cluster onto local disk. It does not call a live gateway.
Use `scripts/verify-workload-attestation.py` to check one live gateway
attestation response with a fresh nonce.

Each workload pod uses a `confidential.ai/cw` annotation. The c8s webhook gives
the pod a certificate under `/etc/c8s/certs`. The default `tls.crt` file contains
the leaf certificate and its mesh CA chain. A receipt reader must not export the
private key.

Use a standard `c8s cds-attest` sidecar with a fresh nonce. The proof chain is:

1. The NRI policy checks each container image digest and effective `argv`.
2. The NRI inventory records the admitted digest and `argv` pairs.
3. The c8s sidecar requests a certificate with a fresh sandbox token.
4. CDS reads the inventory through mutually attested RA-TLS.
5. CDS finds one exact workload entry in the canonical allowlist.
6. CDS signs the certificate with the workload name and allowlist digest.
7. The receipt reader returns the certificate. It does not return its private key.
8. `c8s verify` checks the TDX image, operator key, mesh CA, workload, and allowlist.

The release bundle `c8s.attestationTargets` list binds each public target name to
one c8s workload identity. The gateway must return that exact ordered list. This
makes the verifier independent of a specific cluster topology.

The verifier must hold the mesh CA independently. A mesh CA supplied only by the
target is not a trusted anchor. It must run this check for each certificate:

```text
c8s verify --from-file <certificate> --kind workload \
  --image-manifest <manifest.json> --operator-pkey <operator.pub> \
  --mesh-ca <held-mesh-ca.pem> --allowlist <canonical-allowlist.json> \
  --workload <workload-name> -o json
```

The allowlist must use exact command and argument policies. The release bundle
must contain the same image digest and complete `argv`. A retained allowlist can
verify an unchanged workload during a safe rolling update.

The certificate proves admission history during its certificate lifetime. It
does not prove current process health, request routing, environment values,
mounts, or model use. Separate readiness and route tests prove those facts.
