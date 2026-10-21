# Verify Confidential Inference

## What verification proves

TEErminator checks the server before your request leaves your machine. It
checks that the endpoint runs the exact node image of a release that we signed
and published, inside an Intel TDX confidential VM with current Intel security
updates. It checks that the server only allows the workloads in that release's
policy. If a check fails, TEErminator blocks the request.

This guide covers release `v0.15.15` (C8s `v0.59.1`) with TEErminator `v0.0.4`.

## 1. Install TEErminator

Download TEErminator `v0.0.4` and check it against the published checksums.

macOS (Apple silicon; for Intel Macs use `darwin_amd64`):

```sh
curl -fsSL --remote-name-all https://github.com/confidential-dot-ai/TEErminator/releases/download/v0.0.4/{checksums.txt,teerminator_0.0.4_darwin_arm64.tar.gz}
shasum -a 256 -c --ignore-missing checksums.txt && tar -xzf teerminator_0.0.4_darwin_arm64.tar.gz teerminator
```

Linux (x86-64; for ARM use `linux_arm64`):

```sh
curl -fsSL --remote-name-all https://github.com/confidential-dot-ai/TEErminator/releases/download/v0.0.4/{checksums.txt,teerminator_0.0.4_linux_amd64.tar.gz}
sha256sum -c --ignore-missing checksums.txt && tar -xzf teerminator_0.0.4_linux_amd64.tar.gz teerminator
```

The checksum line must print `OK`. `checksums.txt` is not signed, so it only
catches a damaged download.

## 2. Get the pins for the release

The signed release publishes the node image measurements (in
`release-bundle.json`) and the workload policy (`allowlist.json`):

```sh
curl -fsSL --remote-name-all https://github.com/confidential-dot-ai/confidential-inference/releases/download/v0.15.15/{release-bundle.json,allowlist.json}
curl -fsS https://api.confidential.ai/attestation | python3 -c 'import json, sys; print(json.load(sys.stdin)["c8s"]["operatorKeys"][0], end="")' > operator-key.pem
```

The second command saves the operator's public key from the endpoint. The
operator signs the routing table with this key. This key comes from the
endpoint itself, not from the signed release.

## 3. Verify the endpoint

```sh
./teerminator remote add 127.0.0.1:8080 https://api.confidential.ai/ \
  --mode attest-lb --image-manifest release-bundle.json --allowlist allowlist.json \
  --workload c8s-router-fb21f5cac23c --route-operator-key operator-key.pem \
  --tdx-tcb-status UpToDate
./teerminator status
```

`c8s-router-fb21f5cac23c` is the public front door in the `v0.15.15` policy.
A passing result looks like this:

```text
Local           Remote                        Auth  Mode       Status
127.0.0.1:8080  https://api.confidential.ai/  None  attest-lb  Verified

127.0.0.1:8080: measurement 9309eaae..., workload c8s-router-fb21f5cac23c, ..., allowlist version 3 ...,
rtmrs pinned 1:0e2febd1... 2:f452ccd1..., tdx tcb status UpToDate,
route digest ead545cf... (operator-signed, revision ...)
```

Require `Verified`, `tdx tcb status UpToDate`, and `operator-signed`.
`teerminator status` exits with 0 even when a check fails, so read the output.
Do not drop a pin or accept more TCB statuses just to get `Verified`. If the
endpoint serves another release, or its live policy differs from the signed
`allowlist.json`, the check fails.

> **macOS 13:** if the status shows `unable to receive tcbInfo: ... context
> deadline exceeded`, your Mac lacks the Sectigo R46 root that Intel's server
> uses. Add Sectigo's cross-certificate (R46 signed by `AAA Certificate
> Services`, which macOS trusts) to your login keychain, then check again:
>
> ```sh
> curl -fsSLO http://crt.sectigo.com/SectigoPublicServerAuthenticationRootR46_AAA.crt
> openssl x509 -inform DER -in SectigoPublicServerAuthenticationRootR46_AAA.crt -noout -fingerprint -sha256
> security add-certificates -k ~/Library/Keychains/login.keychain-db SectigoPublicServerAuthenticationRootR46_AAA.crt
> ```
>
> The fingerprint must be
> `CE:75:58:0B:C6:79:6D:3B:3E:A2:C3:E7:42:59:D0:D4:03:07:24:08:E9:60:C7:71:39:C2:FB:5A:3D:94:19:E4`.
> This adds an intermediate certificate only; it changes no trust setting.
> `SSL_CERT_FILE` does not help, because TEErminator `v0.0.4` is built with
> Go 1.26, which ignores it on macOS.

## 4. Send requests through TEErminator

Start the proxy with `./teerminator start` and point your OpenAI client at it:

```python
client = OpenAI(base_url="http://127.0.0.1:8080/v1", api_key=YOUR_API_KEY)
```

TEErminator checks the server again for new connections and blocks requests
that fail.

## 5. Optional: check the release signature

The release workflow signs `release-bundle.json` with Sigstore. To check that
the pins came from this repository's workflow for this tag, use
[Cosign](https://github.com/sigstore/cosign) v3:

```sh
curl -fsSLO https://github.com/confidential-dot-ai/confidential-inference/releases/download/v0.15.15/release-bundle.sigstore.json
cosign verify-blob --bundle release-bundle.sigstore.json \
  --certificate-identity https://github.com/confidential-dot-ai/confidential-inference/.github/workflows/release-bundle.yml@refs/tags/v0.15.15 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com release-bundle.json
```

You should see `Verified OK`. The bundle's `allowlist.sha256` must equal the
SHA-256 of `allowlist.json`. The bundle also names the source commits and
image digests to review; start with [release/README.md](../release/README.md).

## What TEErminator checks

TEErminator obtains fresh nonce-bound C8s evidence and binds it to the exact
public TLS certificate. It verifies the node image measurements (MRTD, RTMR1,
RTMR2), that the front door runs the named workload under the pinned policy,
and the operator-signed route table. With `--tdx-tcb-status`, it also fetches
Intel's TCB information, QE identity, and revocation lists, and rejects
revoked credentials and statuses that you did not accept.

The policy lists every workload that the cluster may run. Read it before you
trust it: images, commands, arguments, environment, mounts, and secret grants.
An authorized operator can change the live policy; TEErminator then fails
until you review and pin the new policy.

## Policy updates and verification scope

TEErminator caches a passing verdict for one minute, bounded by the
serving certificate's expiry and exact certificate identity. A workload stamp
states the policy used at certificate issuance. Fresh connection evidence does
not turn that stamp into an instantaneous read of the current CDS policy.
Do not claim that an allowlist write immediately closes all existing streams.

Review changes before replacing your local policy file. If you use direct
HTTPS and periodic checks instead, you accept the interval between checks.
A direct request does not enforce the TEErminator pins.

The front-door proof is not a census of all workers. The approved C8s and
application code must enforce admission and the protected internal request
path. An allowlisted image with a permissive entry deserves separate review.

## GPU verification

The pinned node image runs a measured GPU confidential-computing boot gate.
It verifies the passed-through NVIDIA GPUs before RKE2 can start. A failed
check prevents node admission and powers off the node. Review the gate,
systemd dependency, and source lock at the release's C8s commit.

This contract verifies the enforcement code through the node measurements.
It does not require clients to verify raw GPU reports, and version 3 does not
return those reports. TEErminator does not claim to be a separate NVIDIA
verifier. The serving workers must remain inside that measured enforcement
boundary.

## Configuration negative tests

At the exact C8s commit pinned by your selected release, inspect:

- `internal/cmds/nri-image-policy/env_test.go`: final environment admission.
- `internal/cmds/nri-image-policy/mount_phase_test.go`: final mount admission.
- `pkg/allowlist/mountenv_test.go`,
  `TestMountPolicyRefusesAnUndeclaredDestination`: a bind over an undeclared
  image executable path is rejected without changing the image digest.
- `internal/cmds/cds/attest_matchedworkload_test.go`: workload stamps require
  matching environment and mount evidence.

These checks run at different layers. A policy must declare the restrictions
for those checks to reject changes. A launch input outside the permitted
policy needs a reviewed policy change. Settings in approved runtime files
can change within the limits enforced by the approved application code.
Runtime application admin routes are separate from launch configuration.
