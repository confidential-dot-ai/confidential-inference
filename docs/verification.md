# Verify Confidential Inference

## Future Confidential Cloud deployment

This procedure is for a new Confidential Cloud deployment. Do not apply it to
current production or change existing client configurations. The current
deployment keeps its existing verification policy. Its instructions remain
available at [the current deployment's source commit](https://github.com/confidential-dot-ai/confidential-inference/blob/eb1249834319615e7a9464e3b34916c550e71740/docs/verification.md).

## Verification inputs

Client verification uses a signed release, an exact reviewed allowlist, the
front-door workload, an approved route digest, and Intel TCB status. It does
not require an operator public key or an operator-key seed in RTMR3.

The release downloads below use `v0.16.2` only to show the file and signature
checks. The new deployment must select its own signed release and a compatible
TEErminator version. Replace the release tag in every download and certificate
identity together. TEErminator `v0.0.4` supports the flags shown here. This
example does not establish which release is serving production today.

The deployment owner must supply the endpoint, front-door workload, and
approved route digest through a channel you already trust. Review the route
configuration before accepting its digest. Do not copy a digest from an
unverified live endpoint and treat it as approved. The signed framework
release does not approve deployment-specific routes.

## 1. Install TEErminator

Download TEErminator `v0.0.4` and check the published checksums.

macOS on Apple silicon (use `darwin_amd64` for Intel Macs):

```sh
curl -fsSL --remote-name-all https://github.com/confidential-dot-ai/TEErminator/releases/download/v0.0.4/{checksums.txt,teerminator_0.0.4_darwin_arm64.tar.gz}
shasum -a 256 -c --ignore-missing checksums.txt && tar -xzf teerminator_0.0.4_darwin_arm64.tar.gz teerminator
```

Linux on x86-64 (use `linux_arm64` for ARM):

```sh
curl -fsSL --remote-name-all https://github.com/confidential-dot-ai/TEErminator/releases/download/v0.0.4/{checksums.txt,teerminator_0.0.4_linux_amd64.tar.gz}
sha256sum -c --ignore-missing checksums.txt && tar -xzf teerminator_0.0.4_linux_amd64.tar.gz teerminator
```

Require `OK`. The checksum file is not signed. It detects download damage;
it does not independently prove who built the executable.

## 2. Verify the release and allowlist

Use [Cosign v3](https://github.com/sigstore/cosign) to verify the release
workflow identity before using the manifest:

```sh
curl -fsSL --remote-name-all https://github.com/confidential-dot-ai/confidential-inference/releases/download/v0.16.2/{release-bundle.json,release-bundle.sigstore.json,allowlist.json}
cosign verify-blob --bundle release-bundle.sigstore.json \
  --certificate-identity https://github.com/confidential-dot-ai/confidential-inference/.github/workflows/release-bundle.yml@refs/tags/v0.16.2 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com release-bundle.json
```

Require successful verification. Check the downloaded allowlist against the
digest in the verified manifest:

```sh
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

manifest = json.loads(Path("release-bundle.json").read_text())
expected = manifest["allowlist"]["sha256"]
actual = "sha256:" + hashlib.sha256(Path("allowlist.json").read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit("allowlist digest differs from the signed release")
print("Allowlist digest verified")
PY
```

Review the policy: images, commands, arguments, environment, mounts, secret
grants, and egress. Review build evidence through [release/README.md](../release/README.md).
If the installation uses a different active policy, review and approve that
policy separately. A release signature does not cover later policy changes.
Do not automatically replace a local policy with live endpoint data.

## 3. Verify the endpoint

Set `APPROVED_ROUTE_DIGEST` to the reviewed route-manifest SHA-256: 64 lowercase
hexadecimal characters without `sha256:`. This guide does not supply a trusted
route digest for the current installation. Stop until the deployment owner
supplies one. For the example release, also confirm that the selected endpoint
uses the front-door workload supplied for that deployment.

```sh
: "${APPROVED_ROUTE_DIGEST:?Set the independently approved route digest first}"
: "${FRONT_DOOR_WORKLOAD:?Set the workload from the reviewed deployment policy}"
./teerminator remote add 127.0.0.1:8080 https://inference.example.invalid/ \
  --mode attest-lb --image-manifest release-bundle.json \
  --allowlist allowlist.json --workload "$FRONT_DOOR_WORKLOAD" \
  --route-digest "$APPROVED_ROUTE_DIGEST" \
  --tdx-tcb-status UpToDate
./teerminator status
```

Require `Verified`, `tdx tcb status UpToDate`, and route check `pinned`.
`status` can exit with zero after a failed check, so read its output. Do not
remove pins or accept more TCB statuses to obtain a passing result.

TEErminator checks fresh nonce-bound C8s evidence, the public TLS certificate,
node measurements MRTD/RTMR1/RTMR2, the workload's policy stamp, and the attested
route digest. A mismatched pin must block requests.

## 4. Send requests

Start the proxy with `./teerminator start`. Point your OpenAI client at it:

```python
client = OpenAI(base_url="http://127.0.0.1:8080/v1", api_key=YOUR_API_KEY)
```

Direct HTTPS does not enforce these client pins. TEErminator checks new
connections and caches passing verdicts for up to one minute, bounded by the
serving certificate's expiry and exact identity.

## Scope and updates

The client approves exact policy and route bytes instead of trusting future
updates signed by an operator. A route change requires a new reviewed digest.
An approved set of digests can cover a planned transition. Remove old digests
when that transition ends. This mode does not track signed route revisions;
it permits any route digest that remains in the approved set.

This procedure does not pin the operator-key seed in RTMR3. It does not prove
that every policy enforced since boot was approved. A workload stamp records
the policy at certificate issuance, not an instantaneous read of current CDS
state. A policy update does not immediately close existing streams.

C8s still uses operator keys to authorize internal updates and credential
release. This procedure changes client trust inputs, not C8s update authority.
The old PEM files remain at their existing URLs for clients with older
configurations. They are not inputs to this procedure. Existing client
configurations keep their operator-key checks until their owners change them.

## Internal enforcement and GPUs

Front-door verification is not a census of serving workers. The approved C8s
and application code must enforce admission and the protected internal request
path. An allowlisted image with permissive rules needs separate review.

The accepted GPU node image runs a measured confidential-computing boot gate.
Every passed-through GPU must satisfy that gate before RKE2 starts. Failure
blocks node admission and powers off the node. Review the gate and source lock
at the release's C8s commit. TEErminator does not independently verify raw NVIDIA
GPU reports. Workers must remain inside the measured enforcement boundary.

For launch-configuration rejection tests, inspect the pinned C8s source:

- `internal/cmds/nri-image-policy/env_test.go` and `mount_phase_test.go`.
- `pkg/allowlist/mountenv_test.go`.
- `internal/cmds/cds/attest_matchedworkload_test.go`.

Policies must declare the restrictions for those checks to reject changes.
Runtime application administration is separate from launch configuration.
