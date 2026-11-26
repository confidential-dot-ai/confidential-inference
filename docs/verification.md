# Verify Confidential Inference

## Current production

Use the [v0.16.9 production profile](production-v0.16.9.json) for
`https://api.confidential.ai/`. It pins the signed release, exact policy,
front-door workload, route, RTMR3 seed and Intel TCB status. The launch
key in the profile is the exact public PEM recorded for the front-door
server on 6 November 2026. C8s v0.80.10 derives the seed as
`SHA-384(48 zero bytes ‖ SHA-384(PEM))`, including the PEM's final newline.
The pinned route sends requests for the production host at path
`/` to workload `gateway`.

Install [TEErminator v0.0.4](#1-install-teerminator), Cosign v3, GitHub CLI
and jq. Save the linked profile as `production-v0.16.9.json` beside the
TEErminator binary in a fresh directory. Run this check in Bash:

```bash
(
  set -euo pipefail
  profile=production-v0.16.9.json
  sha256() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }
  test "$(sha256 "$profile")" = b45ba3e50d2c4c984734f78f0f17004eef5e6d31556199a9489d42d5d0930978
  release=$(jq -er .release "$profile")
  gh release download "$release" -R confidential-dot-ai/confidential-inference \
    -p release-bundle.json -p release-bundle.sigstore.json -p allowlist.json
  cosign verify-blob --bundle release-bundle.sigstore.json \
    --certificate-identity "https://github.com/confidential-dot-ai/confidential-inference/.github/workflows/release-bundle.yml@refs/tags/$release" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com release-bundle.json
  test "$(sha256 release-bundle.json)" = "$(jq -er .bundleSha256 "$profile")"
  policy=$(sha256 allowlist.json)
  test "$policy" = "$(jq -er .allowlistSha256 "$profile")"
  test "sha256:$policy" = "$(jq -er .allowlist.sha256 release-bundle.json)"

  seed=$(jq -er '.expectedRTMR3 | select(test("^[0-9a-f]{96}$"))' "$profile")
  jq -jer .launchKey.pem "$profile" > launch-public.pem
  test "$(sha256 launch-public.pem)" = "$(jq -er .launchKey.pemSha256 "$profile")"
  derived=$( { dd if=/dev/zero bs=48 count=1 2>/dev/null; openssl dgst -sha384 -binary launch-public.pem; } |
    openssl dgst -sha384 -r | cut -d' ' -f1)
  test "$seed" = "$derived"

  mkdir -m 700 teerminator-home
  teerminator() { HOME="$PWD/teerminator-home" XDG_CONFIG_HOME="$PWD/teerminator-home/config" ./teerminator "$@"; }
  teerminator remote add 127.0.0.1:8080 "$(jq -er .endpoint "$profile")" \
    --mode attest-lb --image-manifest release-bundle.json --allowlist allowlist.json \
    --workload "$(jq -er .workload "$profile")" --expected-rtmr3 "$seed" \
    --route-digest "$(jq -er .routeDigest "$profile")" \
    --tdx-tcb-status "$(jq -er .tdxTCBStatus "$profile")"
  teerminator allowlist fetch 127.0.0.1:8080 --output allowlist-live.json
  cmp allowlist.json allowlist-live.json
  teerminator status | tee status.txt
  awk '$1 == "127.0.0.1:8080" && $(NF-1) == "attest-lb" && $NF == "Verified" { ok=1 } END { exit !ok }' status.txt
)
```

On 23 November 2026, TEErminator v0.0.4 printed `Verified`,
`tdx tcb status UpToDate` and the profile's route digest followed by
`(pinned)`. The fetched allowlist matched the signed release. The SHA-256
check above identifies the profile revision for this run. Changing the first
hex digit of the expected seed in the verifier invocation produced
`Failed` with an `RTMR[3]` mismatch.

After reviewing the signed allowlist and verifying the endpoint, start the
proxy with the same configuration and direct requests to `http://127.0.0.1:8080/v1`:

```sh
HOME="$PWD/teerminator-home" XDG_CONFIG_HOME="$PWD/teerminator-home/config" ./teerminator start
```

## Confidential Cloud deployments

The remaining steps apply to Confidential Cloud deployments.

## What verification proves

TEErminator checks the server before your request leaves your machine. It
checks that the endpoint runs the exact node image of a framework release
that we signed and published, inside an Intel TDX confidential VM with
current Intel security updates. It checks that the server only runs images
of that release, under the policy and route that you reviewed and pinned.
If a check fails, TEErminator blocks the request.

Client verification uses a signed framework release, an exact reviewed
allowlist, the worker's launch file, the front-door workload, an approved
route digest, and Intel TCB status. It does not require an operator public
key.

## Inputs from the deployment owner

Get these values from the deployment owner through a channel you already
trust:

- the endpoint URL, for example `https://inference.example.invalid/`;
- the framework release name;
- the front-door workload name in the deployment's policy;
- the approved route digest: the SHA-256 of the reviewed route manifest,
  64 lowercase hexadecimal characters without `sha256:`;
- the deployment's `worker.yaml` and `cds-config.yaml`.

Review the route configuration before you accept its digest. Do not copy a
digest from an unverified live endpoint and treat it as approved. The signed
framework release does not approve deployment-specific routes. Stop until the
deployment owner supplies these values.

```sh
: "${ENDPOINT:?Set the endpoint URL from the deployment owner}"
: "${RELEASE:?Set the framework release name from the deployment owner}"
: "${FRONT_DOOR_WORKLOAD:?Set the workload from the reviewed deployment policy}"
: "${APPROVED_ROUTE_DIGEST:?Set the independently approved route digest first}"
```

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
catches a damaged download. It does not independently prove who built the
executable.

## 2. Verify the framework release

Releases after `v0.16.9` are framework releases: their `release-bundle.json`
has the schema `confidential.ai/release-manifest/v2`. It names every image
digest, the C8s core images, and the C8s node seed images, but no
allowlist: each deployment renders its own allowlist from the framework
release and its environment. The release has no `allowlist.json` asset.

Use [Cosign v3](https://github.com/sigstore/cosign) to verify the release
workflow identity before you use the manifest:

```sh
curl -fsSL --remote-name-all "https://github.com/confidential-dot-ai/confidential-inference/releases/download/$RELEASE/"{release-bundle.json,release-bundle.sigstore.json}
cosign verify-blob --bundle release-bundle.sigstore.json \
  --certificate-identity "https://github.com/confidential-dot-ai/confidential-inference/.github/workflows/release-bundle.yml@refs/tags/$RELEASE" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com release-bundle.json
jq -r '.schema, .release, .c8s.release' release-bundle.json
sha256sum release-bundle.json
```

Require `Verified OK` from Cosign. `jq` must print
`confidential.ai/release-manifest/v2`, the release name that you set, and
the C8s release that the framework release pins. Keep the `sha256sum` value
for step 5. Review the source commits and image digests that the bundle
names; start with [release/README.md](../release/README.md).

## 3. Pin the worker's launch file

This step applies to every release that pins C8s v0.99.29 or later, which
includes C8s v0.101.9 of the Confidential Cloud catalog. The release's MRTD,
RTMR1, and RTMR2 pin the worker image only. The worker's launch file,
`worker.yaml`, selects the CDS image and configuration, the CDS address, and
the Kubernetes API server. Pin that file too: without it, an endpoint that
runs the pinned worker image under another CDS passes.

1. Use the deployment's `worker.yaml` and `cds-config.yaml` from the
   deployment owner.
2. Download the release's `cds-manifest.json` asset, the manifest.json of
   the CDS guest image. Its SHA-256 must equal `cdsImage.manifestSha256` of
   the release manifest you verified:

   ```sh
   curl -fsSLO "https://github.com/confidential-dot-ai/confidential-inference/releases/download/$RELEASE/cds-manifest.json"
   test "sha256:$(sha256sum < cds-manifest.json | cut -d' ' -f1)" = "$(jq -r .cdsImage.manifestSha256 release-bundle.json)"
   ```

3. Review `worker.yaml`. Each `cds.measurements` entry must carry the MRTD,
   RTMR1, and RTMR2 of that `cds-manifest.json`, and embed the exact bytes of
   `cds-config.yaml` as `launch_file`. A worker refuses an entry that carries
   only `launch_file_digest`; that form binds the worker documents in a
   `node-images` decree, not the CDS pin.
4. Review the operator keys and node ranges in `cds-config.yaml`. The
   operator keys are the deployment's C8s update authority. They are not a
   client trust anchor in this procedure.
5. Compute the worker's RTMR[3] seed, `SHA-384(0x00 * 48 ‖ SHA-384(worker.yaml))`:

   ```sh
   RTMR3_SEED=$(python3 -c 'import hashlib, sys; print(hashlib.sha384(bytes(48) + hashlib.sha384(open(sys.argv[1], "rb").read()).digest()).hexdigest())' worker.yaml)
   echo "$RTMR3_SEED"
   ```

6. In step 5, pass the seed as `--expected-rtmr3`, beside `--image-manifest
   release-bundle.json`.
7. Repeat the check in step 5 with the seed of a `worker.yaml` that differs
   by one byte. It must fail.

The worker extends RTMR[3] from this seed with each allowlist policy it
applies (C8s `docs/measurements.md`), and TEErminator replays that history.
TEErminator `v0.0.4` has not yet been run against a v0.99.29 endpoint.
`c8s verify` of the pinned C8s release takes the same pins as
`--image-manifest` and `--rtmr 3=<SEED>`.

## 4. Review the route

The route manifest says which workload receives the traffic for a host name.
The allowlist says what each workload is. Pin both: then your requests go only
to the reviewed gateway image.

Download the live route to read it, and check it against the approved digest:

```sh
curl -fsSL "${ENDPOINT%/}/.well-known/c8s/routes" | jq -r .manifest | base64 -d > routes.json
cat routes.json
test "$(sha256sum routes.json | cut -d' ' -f1)" = "$APPROVED_ROUTE_DIGEST"
```

The endpoint's host name must have one route, path `/`, to workload
`gateway`. If the digest differs, stop and ask the deployment owner. The
download is not an approval: in step 5, TEErminator requires the attested
route digest to equal the approved digest.

## 5. Verify the endpoint and the live allowlist

Configure the image, launch, route, and Intel status pins. Then fetch and pin
the live allowlist:

```sh
./teerminator remote add 127.0.0.1:8080 "$ENDPOINT" \
  --mode attest-lb --image-manifest release-bundle.json \
  --workload "$FRONT_DOOR_WORKLOAD" \
  --expected-rtmr3 "$RTMR3_SEED" \
  --route-digest "$APPROVED_ROUTE_DIGEST" \
  --tdx-tcb-status UpToDate
./teerminator allowlist fetch 127.0.0.1:8080 --output allowlist-live.json --pin
./teerminator status
```

Require `Verified`, `tdx tcb status UpToDate`, and route check `pinned`.
`teerminator status` exits with 0 even when a check fails, so read the
output. Do not drop a pin or accept more TCB statuses just to get
`Verified`.

The live allowlist names its framework release. Read the release name and
the digest of its bundle from the gateway:

```sh
jq -r '.workloads.gateway.containers[0].env.values | .CI_FRAMEWORK_RELEASE, .CI_FRAMEWORK_RELEASE_BUNDLE_SHA256' allowlist-live.json
```

The release name must equal `$RELEASE`. The digest must be `sha256:`
followed by the `sha256sum` value of `release-bundle.json` from step 2. Then check that the live allowlist runs only images of that release:

```sh
jq -r '[.images[], .c8s.coreImages[], .c8s.seedImages[]] | map(split("@")[1]) | unique[]' release-bundle.json > release-digests.txt
jq -r '[.workloads[] | ((.initContainers // []) + (.containers // []))[] | .digest] | unique[]' allowlist-live.json > live-digests.txt
comm -13 release-digests.txt live-digests.txt
```

`comm` must print nothing. Then review the rest of each workload in
`allowlist-live.json`: commands, arguments, environment, mounts, secret
reads, and egress. These come from the deployment's environment. They can
change what the approved code does within its own limits. A release
signature does not cover them. If a check in this step fails, stop: do not
start the proxy.

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

## 6. Send requests through TEErminator

Start the proxy with `./teerminator start` and point your OpenAI client at it:

```python
client = OpenAI(base_url="http://127.0.0.1:8080/v1", api_key=YOUR_API_KEY)
```

TEErminator checks the server again for new connections and blocks requests
that fail. Direct HTTPS does not enforce these client pins.

## What TEErminator checks

TEErminator obtains fresh nonce-bound C8s evidence and binds it to the exact
public TLS certificate. It verifies the node image measurements (MRTD, RTMR1,
RTMR2) and RTMR3, that the front door runs the named workload under the
pinned policy, and that the attested route digest equals your pin. With
`--tdx-tcb-status`, it also fetches Intel's TCB information, QE identity, and
revocation lists, and rejects revoked credentials and statuses that you did
not accept. A mismatched pin blocks requests.

The policy lists every workload that the cluster may run. Read it before you
trust it: images, commands, arguments, environment, mounts, and secret grants.
An authorized operator can change the live policy; TEErminator then fails
until you review and pin the new policy.

## Scope and updates

The client approves exact policy and route bytes instead of trusting future
updates signed by an operator. A route change makes the check fail until you
review the new route and pin its digest. An approved set of digests can cover
a planned transition. Remove old digests when that transition ends. This mode
does not track signed route revisions; it permits any route digest that
remains in the approved set.

This procedure does not prove that every policy enforced since boot was
approved. TEErminator caches a passing verdict for one minute, bounded by the
serving certificate's expiry and exact certificate identity. A workload stamp
states the policy used at certificate issuance. Fresh connection evidence does
not turn that stamp into an instantaneous read of the current CDS policy.
Do not claim that an allowlist write immediately closes all existing streams.

Review changes before replacing your local policy file. Do not automatically
replace a local policy with live endpoint data. If you use direct HTTPS and
periodic checks instead, you accept the interval between checks.

C8s still uses operator keys to authorize policy updates and credential
release. This procedure changes client trust inputs, not C8s update
authority. Existing client configurations keep their checks until their
owners change them.

The front-door proof is not a census of all workers. The approved C8s and
application code must enforce admission and the protected internal request
path. An allowlisted image with a permissive entry deserves separate review.

## GPU verification

The pinned node image runs a measured GPU confidential-computing boot gate.
It verifies the passed-through NVIDIA GPUs before the node's Kubernetes
runtime can start: containerd on the C8s v0.99.29 and later worker, RKE2 on
the node images of earlier releases. A failed check prevents node admission
and powers off the node. Review the gate, systemd dependency, and source lock
at the release's C8s commit.

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
