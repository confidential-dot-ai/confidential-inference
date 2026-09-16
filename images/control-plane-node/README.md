# TDX node image

This directory owns the extra Confidential OS Builder profile for the
Kubernetes CVMs. Operators can use the same measured image on each node of one
cluster. This keeps one c8s node measurement across that cluster.

Each environment gets its own node image. The build seals one allowlist into
the measured image, and the nodes enforce that sealed allowlist. Production
seals `c8s/allowlists/production.json`, and integration-staging seals
`c8s/allowlists/integration-staging.json`. The two allowlists name different
application images, so one image cannot serve both environments. See "Build
inputs" below for the per-environment file table.

The profile adds a dependency to `rke2-server.service`. It mounts RKE2 server
state in tmpfs only when a CVM starts the RKE2 server. Gateway and inference
CVMs run `rke2-agent`, so they do not mount this tmpfs, but they do run the
same profile script — see "Profile packaging" below.

## Build inputs

`builder-lock.json` pins these inputs. They do not depend on the environment:

- The Confidential OS Builder repository and commit.
- The c8s source commit.
- The TDX platform.
- The consumer profile path.

`builder-lock.json` also records the signed stage each environment's last
build produced, in one section per environment: `productionSignedStage` and
`integrationStagingSignedStage`. The published tag ends in `-sa` and the first
twelve characters of the sealed allowlist file's SHA-256, so the tag names the
policy the image enforces.

The sealed allowlist is a build input, not a constant. Each environment
selects every per-environment file from this table:

| Item | `production` | `integration-staging` |
| --- | --- | --- |
| Sealed allowlist | `c8s/allowlists/production.json` | `c8s/allowlists/integration-staging.json` |
| Policy | `c8s/production-policy.json` | `c8s/integration-staging-policy.json` |
| Builder-lock signed stage | `productionSignedStage` | `integrationStagingSignedStage` |
| Build receipt | `production-build-receipt.json` | `integration-staging-build-receipt.json` |
| Node manifest | `manifest-production.json` | `manifest-integration-staging.json` |
| Measurements config | `measurements-production.json` | `measurements-integration-staging.json` |

The internal deploy repository dispatches the build for each environment.
Record the output image digest, manifest digest, and TDX measurements in that
environment's files. An allowlist change changes the node measurement, exactly
as a profile change does.

Use clean builder and c8s checkouts at the pinned commits. Do not add the
`ssh` or `dev` profile. Those profiles are not part of the measured release.
The c8s entry point includes the measured GPU profile.
That profile locks kernel module loading and can start on a node with no GPU.
Do not use `C8S_NO_GPU`. That option is for validation only and does not lock
kernel module loading.

From the Confidential OS Builder checkout, run:

```bash
C8S_PLATFORM=tdx \
C8S_REF=079aeb4 \
C8S_NAME=confidential-inference-node \
C8S_MEMORY=32G \
CONFOS_DIR="$PWD" \
../c8s/node-guest-image/build \
  --profile-dir /absolute/path/to/confidential-inference/images/control-plane-node/profile/control-plane-state \
  --smp 4
```

In this command, `$PWD` is the clean Confidential OS Builder checkout and
`../c8s` is the clean c8s checkout. `C8S_REF` is the published seven-character
component image tag for the full c8s source commit in `builder-lock.json`.

Record the output image digest, manifest digest, and TDX measurements in the
release data before deployment. A profile change changes the node measurement.

## GPU evidence collection

The node image installs the attestation-api collector config at
`/etc/attestation-api/config.toml`. That config enables GPU evidence
collection. The production release bundle
(`releases/production/release-bundle.json`) and the production allowlist
(`c8s/allowlists/production.json`) require GPU evidence on the inference
workers. Each inference worker command in the allowlist carries the
`--nvidia-gpu-evidence` argument.

## Required disks

Attach one disk to the control-plane CVM:

- `confai-scratch`: 200 GiB. ConfOS encrypts and reformats this disk at each
  boot. It holds the writable root overlay. Its data is temporary.

The name above is a virtual disk serial. It is not a Kubernetes PVC name.

The 200 GiB above is the production size. The node image also enforces a hard
minimum. `scratch-enforce.service` in the c8s base image
(`node-guest-image/c8s/mkosi.extra/usr/local/bin/scratch-enforce.sh` at the
commit `builder-lock.json` pins) reads the size of the `scratch` device-mapper
target the initrd creates, and refuses any size below 125000000 sectors of 512
bytes, which is 64 GB. That unit carries `FailureAction=poweroff-force`, so a
CVM with a smaller `confai-scratch` disk powers off about 35 seconds after each
start, opens no port, and prints nothing on the serial console, because the
locked image has no console. Every role enforces this gate, not only the
control plane.

Request more than the minimum. A KubeVirt claim backed by a filesystem spends
part of its capacity on the disk image file, so the disk the guest sees is
smaller than the claim.

The control plane no longer uses a persistent state disk. The profile mounts
`/var/lib/rancher/rke2/server` as tmpfs, sized 4 GiB. The RKE2 server state,
including the cluster CA private keys and etcd, lives only in this tmpfs,
inside the CVM's TEE-protected memory. The host cannot read it.

On every boot, the profile copies the measured RKE2 seed files the image
ships at this path into the tmpfs, before `rke2-server` starts. This seed
step runs every boot, not only on first use, because tmpfs holds no state
across a stop.

A control-plane stop, of any kind, loses the cluster. There is no state to
resume. Recovery is a redeploy of the control-plane CVM from the signed
release. Etcd snapshots are not retained; there is no retained state disk to
hold them.

The RKE2 server requires this tmpfs mount. If the mount fails, the RKE2
server does not start. RKE2 agents are not affected.

The disk service runs on every node role: it is `WantedBy=multi-user.target`
and orders `Before=` both `rke2-server.service` and `rke2-agent.service`, and
`After=` `rke2-role.service` (the base image's role-dispatch unit). It writes
the kubelet hardening drop-in described below on every role. Only the tmpfs
mount, the Pod Security floor, and the cred-release identities are gated on
the server-role marker (`/run/confos/role-server`); an agent (gateway or
inference) node writes the hardening drop-in and stops there.

Both RKE2 roles hard-depend on the disk service, so a failed run of it stops
the node instead of leaving the node's kubelet unhardened. Three separate
wirings state that dependency:

1. The baked `rke2-server.service.d/zz-control-plane-state.conf` drop-in
   (`Requires=`). This covers the server role.
2. `RequiredBy=rke2-server.service rke2-agent.service` in the disk service's
   `[Install]` section. The bake-time unit-preset pass of the image build turns this into
   `.requires/` symlinks in the measured image, so it covers both roles.
3. A runtime drop-in the script writes into
   `/run/systemd/system/rke2-agent.service.d/` as its very first action,
   before any step that can fail. This covers the agent role without a
   sixth profile file and without depending on the bake-time preset.

Wiring 3 works on the boot transaction that is already running.
`rke2-agent.service`'s start job is queued but blocked, because the disk
service is ordered `Before=` it. systemd propagates a unit failure to the
queued jobs of every unit that `Requires=` it through the live dependency
graph at the moment of the failure, not through the graph the transaction was
built from. The `Requires=` edge therefore applies to the pending
`rke2-agent` job as soon as the script's first `daemon-reload` returns.

If the script fails on a worker node after that point, systemd cancels the
`rke2-agent` start job. The node runs no kubelet at all and never joins the
cluster. That is the fail-closed outcome. Without this wiring the worker
would start its kubelet with the debugging handlers still enabled, because
the RKE2 `config.yaml.d` drop-in that turns them off would be absent, and
RKE2 leaves the handlers on by default.

c8s treats the Kubernetes control plane as untrusted. Do not store
confidential application secrets in Kubernetes Secrets. Release those
secrets from CDS into attested workload memory.

## Profile packaging

The pinned c8s build (`builder-lock.json`, c8s commit `079aeb48`) only
accepts five profile files: its extractor
(`.github/scripts/extract-consumer-profile.py` in the c8s repository,
`EXPECTED_FILES`) fails closed on any missing or extra file, or on a
`mkosi.conf` whose content does not match its pinned checksum. This profile
now holds exactly those five files:

- `mkosi.conf`
- `mkosi.extra/etc/systemd/system/control-plane-state-disk.service`
- `mkosi.extra/etc/systemd/system/rke2-server.service.d/zz-control-plane-state.conf`
- `mkosi.extra/usr/local/libexec/confidential-inference/control-plane-state-disk.sh`
- `mkosi.extra/usr/local/libexec/confidential-inference/rke2-single-control-recovery.sh`
  (a retired no-op stub; no unit calls it — recovery is a redeploy, see
  "Required disks" above)

Everything else the profile needs — the kubelet debugging-handler lockdown,
the Pod Security floor, and both cred-release identities — is written at
boot by `control-plane-state-disk.sh`, the one measured, executable script
among those five files, instead of being baked as separate files. A
verifier can still prove every byte of it from the measured image: the
script is measured content, and every document it writes is an embedded,
literal heredoc inside it. The internal deploy repository's build dispatch
must keep listing exactly these five names; a profile test pins
`mkosi.conf`'s checksum so this cannot drift again.

`control-plane-state-disk.sh` writes:

| Document | Path it writes | Node role |
| --- | --- | --- |
| Kubelet hardening drop-in (`kubelet-arg+: [enable-debugging-handlers=false]`) | `/etc/rancher/rke2/config.yaml.d/60-confidential-inference-hardening.yaml` | every role |
| Pod Security admission config (restricted floor; `kube-system` and `local-path-storage` exempt) | `/etc/rancher/rke2/psa-config.yaml` | server |
| Pod Security floor policy (`ValidatingAdmissionPolicy` + binding) | `$MOUNT_POINT/manifests/psa-level-policy.yaml` | server |
| Restricted day-two `cred-release` identity (group `confidential-ai:operator`, 24h TTL, port 8443) | `/run/systemd/system/cred-release.service.d/50-restricted-identity.conf` | server |
| Operator RBAC (narrow `ClusterRole` + two namespaced `Role`s for the restricted identity) | `$MOUNT_POINT/manifests/confidential-ai-operator-rbac.yaml` | server |
| Bootstrap `cred-release` identity (group `confidential-ai:bootstrap`, 30m TTL, port 8444) | `/run/systemd/system/cred-release-bootstrap.service` | server |
| Platform environment for the bootstrap identity (a verbatim copy of the c8s build's `cred-release.service.d/10-platform.conf`) | `/run/systemd/system/cred-release-bootstrap.service.d/10-platform.conf` | server |
| Bootstrap RBAC (`cluster-admin` binding, revocable) | `$MOUNT_POINT/manifests/confidential-ai-bootstrap-rbac.yaml` | server |
| Bootstrap-window stop unit | `/run/systemd/system/cred-release-bootstrap-stop.service` | server |
| Bootstrap-window scheduler unit | `/run/systemd/system/cred-release-bootstrap-schedule.service` | server |
| Bootstrap-window scheduler script (reads the `BOOTSTRAP_WINDOW` constant baked into `control-plane-state-disk.sh`) | `/run/confai/cred-release-bootstrap-schedule.sh` | server |
| Agent-role hard dependency on this generator (`Requires=`) | `/run/systemd/system/rke2-agent.service.d/zz-confidential-inference-hardening.conf` | every role |
| Runtime `.wants` symlinks that pull in the two new units | `/run/systemd/system/multi-user.target.wants/` | server |

`$MOUNT_POINT` is `/var/lib/rancher/rke2/server`, the tmpfs this profile
mounts on the server role. `/etc/rancher/rke2/config.yaml.d` is already
writable at boot: the base image's `rke2-role.sh` and `gpu-node-label.sh`
both write fragments there before this unit runs, and a `tmpfiles.d` rule
in the base image creates the directory. `/etc/rancher/rke2/psa-config.yaml`
is a plain file the base image already ships at that path (its
`config.yaml` already sets `pod-security-admission-config-file` to it), so
this write replaces it wholesale, the same way `/etc` is writable
everywhere else this profile writes to it. `/run/systemd/system` is
systemd's own documented path for boot-local unit configuration: a unit or
drop-in placed there overrides the equivalent file under
`/etc/systemd/system`, takes effect after the profile script reloads the
systemd unit database, and disappears on the next reboot, when the image's
unmodified units return.

## Testing the profile

Two boot-time defects have reached a locked image bake because every
profile test used to only pattern-match the heredoc text:
`${CRED_PLATFORM}` referenced by the bootstrap identity's `ExecStart`
without its own copy of the platform drop-in (fixed by PR #31), and
`RefuseManualStart` placed in the `[Service]` section, where systemd
silently ignores it (`Unknown key ... ignoring`). Two test layers catch
both classes of mistake by asking systemd itself, not a string match,
whether the generated units are correct:

- `tests/images/control-plane-node/test_boot_units.py` (seconds). Runs
  locally with every other test in this directory through
  `scripts/ci-validate.sh`. In CI it runs in the same job as the boot
  simulation below (`control-plane-node-boot-sim` in
  `.github/workflows/v0-validation.yml`), gated to a change under this
  directory. See "Continuous integration" in the top-level README.md for
  the full category table.
  Extracts every unit `control-plane-state-disk.sh` writes and the
  profile's two baked units, assembles them with vendored, hash-checked c8s
  base units (`fixtures/c8s-base/`, checked against the commit
  `contracts/c8s-admission-source-lock.json` pins) into one tree mirroring
  the real boot-time layout, and runs `systemd-analyze verify` over it,
  plus checks with no systemd equivalent: every `${VAR}`/`$VAR` an
  `ExecStart`/`ExecStartPre` references has a matching `Environment=` in
  its own unit or one of its own drop-ins, every `After=`/`Requires=`/
  `Wants=`/`Before=` target exists somewhere in the profile, the
  generator's output, or a base unit, and the README's documented scratch
  minimum matches `scratch-enforce.sh`'s enforced `MIN_SECTORS`. Skips the
  fixture-hash check (only that check) when no local c8s checkout is
  available; run with `C8S_CHECKOUT=/path/to/c8s` to point it at one.

- `tests/images/control-plane-node/boot-sim/` (a couple of minutes, a
  separate CI job — `control-plane-node-boot-sim` in
  `.github/workflows/v0-validation.yml` — since it needs a privileged
  container, not part of `ci-validate.sh`). Runs the real generator script
  and the real two baked unit files inside a throwaway Ubuntu+systemd
  container against a fake base image, for both the server and the agent
  role, and asserts on the result: every generated unit exists,
  `daemon-reload` still succeeds, `cred-release` and
  `cred-release-bootstrap` reach `active` with the expected `--platform`,
  ports, and `--cert-org` in their argv, the bootstrap-window stop is
  scheduled, the RKE2 config drop-in and PSA files exist with the expected
  content, and the agent variant gets the kubelet drop-in and the runtime
  `rke2-agent.service.d` drop-in that requires this generator. Run it
  locally with:

  ```sh
  bash tests/images/control-plane-node/boot-sim/run.sh
  ```

  Needs Docker and a cgroup v2 host (current Ubuntu and most current Linux
  distributions qualify; GitHub's `ubuntu-24.04` runner does). Not
  achievable inside a container that is itself not privileged, and not
  achievable at all on a Docker Desktop VM without extra flags this script
  does not attempt.

## Operator credential identities

The node image's base `cred-release.service` issues group `system:masters`
by default, an unrevocable superuser identity. This profile narrows that to
two identities, both written by `control-plane-state-disk.sh` at boot (see
"Profile packaging" above):

- **Default identity**, on port 8443. The `50-restricted-identity.conf`
  drop-in clears the base `ExecStart` and restates it with group
  `confidential-ai:operator`, user `operator`, and a 24-hour certificate.
  The `confidential-ai-operator-rbac.yaml` AddOn binds that group to a
  narrow `ClusterRole` (read on pods, nodes, namespaces, and workloads;
  patch on nodes and on Deployments, StatefulSets, and DaemonSets; evict
  pods) plus two namespaced Roles (patch Services in the c8s install
  namespace; create and, by name only, get/update/patch four Secrets in the
  application namespace). Use this identity for day-two operation.
- **Bootstrap identity**, on port 8444
  (`cred-release-bootstrap.service`). It issues group
  `confidential-ai:bootstrap`, user `bootstrap`, with a 30-minute
  certificate. The `confidential-ai-bootstrap-rbac.yaml` AddOn binds that
  group to the built-in `cluster-admin` `ClusterRole` through an ordinary,
  revocable `ClusterRoleBinding` — delete it to cut off every certificate
  this identity has issued, unlike a `system:masters` certificate, which no
  binding controls. This identity can run the full install and upgrade
  pipeline. Use it only for `c8s-install`, `allowlist-upload`,
  `secret-release`, `helm-apply`, and `gateway-attach`; never for day-two
  operation.

Both units' `ExecStart` names `${CRED_PLATFORM}`. That variable is not
ambient. The c8s build renders it into
`/etc/systemd/system/cred-release.service.d/10-platform.conf`, a drop-in that
belongs to `cred-release.service` and to no other unit, because a systemd
drop-in applies to its own unit only. The script therefore copies that one
measured file into `cred-release-bootstrap.service.d/` as well. Without the
copy the bootstrap unit starts with `--platform=` empty, `c8s cred-release`
exits with "--platform is required (RA-TLS is mandatory for credential
release)", and port 8444 never opens. That is the defect the v9 node image
carried; the internal receipt
`receipts/deployments/2026-09-05-integration-staging-v9-attempt3-notes.md`
holds the full record. The script copies the file instead of restating
`tdx`, so there is one source of truth and an SNP build needs no edit.

`cred-release-bootstrap.service` sets `StartLimitIntervalSec=0` and
`RestartSec=30`, so it retries for as long as the boot lasts. Every failure
it can have is fail-closed — it releases no certificate unless the
launch-bound operator key verifies — so a retry loop hands nothing out,
while giving up permanently costs a full redeploy of the control plane. Its
sandbox paths carry the `-` prefix that makes each one optional, because
systemd builds the unit's mount namespace before `ExecStartPre` runs and
`/var/lib/rancher/rke2/server/tls` may not exist yet.

The bootstrap identity stops after a fixed window from boot.
`cred-release-bootstrap-schedule.service` runs once at boot and hands the
window to a one-shot delayed unit scheduler (systemd's transient-unit
runner, told to run once the window elapses) — a plain `.timer` unit cannot
read a variable into `OnBootSec=`. When the
window elapses, that scheduled job runs `cred-release-bootstrap-stop.service`,
which stops `cred-release-bootstrap.service` and then applies a runtime mask
to it (cleared on reboot). The stop comes first because the running process
holds port 8444 until it lands. Nothing re-enqueues the unit between the two
steps: `Restart=on-failure` does not fire on a clean stop. `RefuseManualStart=yes` on
`cred-release-bootstrap.service` is a second, independent barrier.

`RefuseManualStart=yes` also rules out a direct start command as the way to launch
the bootstrap unit at boot: that is precisely the manual job the setting
rejects. A blocking direct start would deadlock the boot in any case,
because `cred-release-bootstrap.service` is ordered after
`rke2-server.service`, which requires the disk service that would be issuing
the start. So the script writes the `.wants` symlinks systemd would have read
when it built this boot's transaction, reloads, and re-enqueues
`multi-user.target` with `--no-block`. The new transaction pulls both units
in as dependencies of the target, which `RefuseManualStart=yes` allows, and
the call returns at once.

The window duration is one constant, `BOOTSTRAP_WINDOW`, at the top of
`control-plane-state-disk.sh`. It is set to `1h` today. Integration-staging
attempt 6, on 2026-09-05, measured the real install time. The control-plane
VMI reached Running at 17:24:34Z. The `helm-apply` step finished at
17:50:13Z. That gap is 25 minutes 39 seconds.

That measured gap carries about 21 minutes of operator delay: a manual CDS
secret restore and a manual gateway pod restart. Without that delay, the
same run needs about 9 minutes. The window keeps a margin of 30 minutes on
top of the measured gap. The total rounds up to a multiple of 30 minutes,
which gives 1 hour.

The bootstrap certificate TTL stays 30 minutes. A certificate issued just
before the window stops still lives for at most 30 minutes after the
window stops.

Both cred-release identities and the timer wiring are measured content:
they are literal, embedded documents inside `control-plane-state-disk.sh`,
so changing either changes the node measurement. A certificate issued
before the stop still lives for its full TTL after the stop: at most 30
minutes for a bootstrap-identity certificate, and at most 24 hours for a
default-identity certificate.

## Kubelet and Pod Security hardening

The profile disables the kubelet debugging handlers
(`etc/rancher/rke2/config.yaml.d/60-confidential-inference-hardening.yaml`,
written on every node role). `kubectl exec`, `attach`, `port-forward`, and
`logs` do not work on any node. The kubeconfig cred-release hands out is
cluster-admin (bootstrap identity) or the restricted operator role (default
identity); this closes the one path a kubeconfig holder had into every
allowlisted pod. Liveness and readiness probes still work; they use the CRI
path, not this endpoint.

The profile also enforces the restricted Pod Security Standard for every
namespace that is not explicitly exempted (`etc/rancher/rke2/psa-config.yaml`,
which replaces the base image's file at the same path). Only `kube-system`
and `local-path-storage` are exempt. The `psa-level-policy.yaml` AddOn
stops a namespace label from lowering that floor unless the caller can
grant `podsecurityexemptions.confidential.ai`, a virtual RBAC resource no
default role includes. `cluster-admin` and `system:masters` pass this
check, so the install still labels the confidential-inference application
namespace and the c8s release namespace `privileged` (the install runs as
the bootstrap `cluster-admin` identity). A tenant holding `admin` or `edit`
in its own namespaces cannot lower its own floor.

Both changes replicate c8s main commits `b6bbbe9b` and `6013134d`.
Production stays pinned to c8s commit `079aeb48` (`builder-lock.json`), so
these two changes are written by the profile script at boot instead of
moving that pin.

## The build dispatch

The dev, staging, and production build dispatch scripts have no customer
path, so they do not live in this repository. They live in
confidential-inference-internal, at `operations/node-image/`. Each script
reads this repository's profile files, so all builds agree on which files
describe a build.
