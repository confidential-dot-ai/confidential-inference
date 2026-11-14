# Verify Confidential Inference

## What verification proves

TEErminator checks the server before your request leaves your machine. It
checks that the endpoint runs the exact node image of a release that we signed
and published, inside an Intel TDX confidential VM with current Intel security
updates. It checks that the server only allows the workloads in that release's
policy. If a check fails, TEErminator blocks the request.

This guide covers `https://api.confidential.ai/` with release `v0.16.2`,
C8s `v0.80.10`, and TEErminator `v0.0.4`.

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

## 2. Get and check the release pins

The signed release publishes the node image measurements (in
`release-bundle.json`) and the workload policy (`allowlist.json`). Use
[Cosign v3](https://github.com/sigstore/cosign) for the signature check:

```sh
curl -fsSL --remote-name-all https://github.com/confidential-dot-ai/confidential-inference/releases/download/v0.16.2/{release-bundle.json,release-bundle.sigstore.json,allowlist.json}
cosign verify-blob --bundle release-bundle.sigstore.json \
  --certificate-identity https://github.com/confidential-dot-ai/confidential-inference/.github/workflows/release-bundle.yml@refs/tags/v0.16.2 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com release-bundle.json
sha256sum allowlist.json
```

Require `Verified OK` from Cosign. The allowlist SHA-256 must be
`65306c56f036fdb98ec6d32610dc5ff820891baebf908b3dd3315899d703058b`.
Review the signed release and policy before connecting. The bundle names the
source commits and image digests to review; start with
[release/README.md](../release/README.md).

## 3. Get and review the route

The route manifest says which workload receives the traffic for a host name.
The allowlist says what each workload is. Pin both: then your requests go only
to the reviewed gateway image.

```sh
curl -fsSL https://api.confidential.ai/.well-known/c8s/routes | jq -r .manifest | base64 -d > routes.json
cat routes.json
ROUTE_DIGEST=$(sha256sum routes.json | cut -d' ' -f1)
```

Review `routes.json`. `api.confidential.ai` must have one route, path `/`,
to workload `gateway`. You do not need to trust this download: in step 4,
TEErminator requires the attested route digest to equal your pin.

## 4. Verify the endpoint

Configure the image, launch, route, and Intel status pins. Then fetch and pin
the live allowlist:

```sh
./teerminator remote add 127.0.0.1:8080 https://api.confidential.ai/ \
  --mode attest-lb --image-manifest release-bundle.json \
  --workload c8s-router-7210bdeb078b \
  --expected-rtmr3 256e9368dbd9aff2e28044988a756d4554c1ec5880fa4ea829cd5bc854f62842b61ab7c25c55327d048fa5c9e1666ba8 \
  --route-digest "$ROUTE_DIGEST" \
  --tdx-tcb-status UpToDate
./teerminator allowlist fetch 127.0.0.1:8080 --output allowlist-live.json --pin
cmp allowlist.json allowlist-live.json
./teerminator status
```

`c8s-router-7210bdeb078b` is the public front door in the `v0.16.2` policy.
The RTMR3 value pins the launch configuration of this deployment. Stop if
`cmp` reports a difference. Require `Verified`, `tdx tcb status UpToDate`, and
route check `pinned`. `teerminator status` exits with 0 even when a check
fails, so read the output. Do not drop a pin or accept more TCB statuses just
to get `Verified`. If the endpoint serves another release, its live policy
differs from the signed `allowlist.json`, or its route differs from your
pin, the check fails.

A route change makes the check fail until you review the new route and pin
its digest.

> **macOS:** if the TCB check times out (`unable to receive tcbInfo: ...
> context deadline exceeded`), your system may be missing the Sectigo R46
> intermediate certificate that Intel's PCS uses. Add it to your login
> keychain, then check again:
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

## 5. Send requests through TEErminator

Start the proxy with `./teerminator start` and point your OpenAI client at it:

```python
client = OpenAI(base_url="http://127.0.0.1:8080/v1", api_key=YOUR_API_KEY)
```

TEErminator checks the server again for new connections and blocks requests
that fail.

## Framework releases

Releases after `v0.16.9` are framework releases: their `release-bundle.json`
has the schema `confidential.ai/release-manifest/v2`. It names every image
digest, the C8s core images, and the C8s node seed images, but no
allowlist: each deployment renders its own allowlist from the framework
release and its environment. The release has no `allowlist.json` asset, so
`sha256sum allowlist.json` in step 2 and `cmp` in step 4 do not apply.

The live allowlist names its framework release. After `allowlist fetch` in
step 4, read the release name and the digest of its bundle from the gateway:

```sh
jq -r '.workloads.gateway.containers[0].env.values | .CI_FRAMEWORK_RELEASE, .CI_FRAMEWORK_RELEASE_BUNDLE_SHA256' allowlist-live.json
```

Use that release name in place of `v0.16.2` in step 2. Download only
`release-bundle.json` and `release-bundle.sigstore.json`, and check the
signature in the same way. Then check that the bundle has the digest that
the live allowlist names. `sha256sum` prints the hex value without the
`sha256:` prefix:

```sh
sha256sum release-bundle.json
```

Then check that the live allowlist runs only images of that release:

```sh
jq -r '[.images[], .c8s.coreImages[], .c8s.seedImages[]] | map(split("@")[1]) | unique[]' release-bundle.json > release-digests.txt
jq -r '[.workloads[] | ((.initContainers // []) + (.containers // []))[] | .digest] | unique[]' allowlist-live.json > live-digests.txt
comm -13 release-digests.txt live-digests.txt
```

`comm` must print nothing. Then review the rest of each workload in
`allowlist-live.json`: commands, arguments, environment, mounts, secret
reads, and egress. These come from the environment. They can change what the
approved code does within its own limits, so read them before you pin the
policy.

## Releases on C8s v0.99.29

No published release runs on C8s v0.99.29 yet, and the `v0.16.2` pins in
steps 2 and 4 do not apply to one. The release's MRTD, RTMR1, and RTMR2 pin
the worker image only. The worker's launch file, `worker.yaml`, selects the CDS
image and configuration, the CDS address, and the Kubernetes API server. Pin
that file too: without it, an endpoint that runs the pinned worker image under
another CDS passes.

To pin the launch file of a deployment:

1. Get the deployment's `worker.yaml` and `cds-config.yaml` from its operator.
2. Download the release's `cds-manifest.json` asset, the manifest.json of
   the CDS guest image. Its SHA-256 must equal `cdsImage.manifestSha256` of
   the release manifest you verified:

   ```sh
   test "sha256:$(sha256sum < cds-manifest.json | cut -d' ' -f1)" = "$(jq -r .cdsImage.manifestSha256 release-bundle.json)"
   ```

3. Review `worker.yaml`. Each `cds.measurements` entry must carry the MRTD,
   RTMR1, and RTMR2 of that `cds-manifest.json`, and embed the exact bytes of
   `cds-config.yaml` as `launch_file`. A worker refuses an entry that carries
   only `launch_file_digest`; that form binds the worker documents in a
   `node-images` decree, not the CDS pin.
4. Review the operator keys and node ranges in `cds-config.yaml`.
5. Compute the worker's RTMR[3] seed, `SHA-384(0x00 * 48 ‖ SHA-384(worker.yaml))`:

   ```sh
   python3 -c 'import hashlib, sys; print(hashlib.sha384(bytes(48) + hashlib.sha384(open(sys.argv[1], "rb").read()).digest()).hexdigest())' worker.yaml
   ```

6. Pass the seed as `--expected-rtmr3` in step 4, beside `--image-manifest
   release-bundle.json`, in place of the RTMR3 value of `v0.16.2`.
7. Repeat the check with the seed of a `worker.yaml` that differs by one byte.
   It must fail.

The worker extends RTMR[3] from this seed with each allowlist policy it
applies (C8s `docs/measurements.md`), and TEErminator replays that history as
before. TEErminator `v0.0.4` has not yet been run against a v0.99.29 endpoint.
`c8s verify` of the pinned C8s release takes the same pins as
`--image-manifest` and `--rtmr 3=<SEED>`.

## What TEErminator checks

TEErminator obtains fresh nonce-bound C8s evidence and binds it to the exact
public TLS certificate. It verifies the node image measurements (MRTD, RTMR1,
RTMR2) and RTMR3, that the front door runs the named workload under the
pinned policy, and that the attested route digest equals your pin. With `--tdx-tcb-status`, it also fetches
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
It verifies the passed-through NVIDIA GPUs before the node's Kubernetes
runtime can start: containerd on the C8s v0.99.29 worker, RKE2 on the node
images of earlier releases. A failed
check prevents node admission and powers off the node. Review the gate,
systemd dependency, and source lock at the release's C8s commit.

This contract verifies the enforcement code through the node measurements.
It does not require clients to verify raw GPU reports, and the endpoint does
not return those reports. TEErminator does not claim to be a separate NVIDIA
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
