#!/bin/bash
# Write the full confidential-inference node profile at boot.
#
# The pinned c8s build (builder-lock.json) accepts exactly five profile
# files (c8s .github/scripts/extract-consumer-profile.py, EXPECTED_FILES).
# Everything else this profile needs — the kubelet-hardening drop-in, the
# Pod Security floor, the cred-release RBAC and the two cred-release
# identities — is written here, at boot, by this one measured script, so a
# verifier can still prove every byte from the measured image even though
# none of it is baked as a separate file. See
# images/control-plane-node/README.md, "Profile packaging".
#
# This unit (control-plane-state-disk.service) runs on every node role,
# After=rke2-role.service and Before=rke2-server.service and
# rke2-agent.service, so /run/confos/role-server or /run/confos/role-agent
# already exists, and every write below lands before RKE2 or cred-release
# reads it.
set -euo pipefail

# --- Constants -------------------------------------------------------------

readonly MOUNT_POINT="/var/lib/rancher/rke2/server"
readonly SEED_DIR="/run/confai-rke2-state-seed"
readonly TMPFS_SIZE="4G"
readonly ROLE_SERVER_MARKER="/run/confos/role-server"
readonly RANCHER_DROPIN_DIR="/etc/rancher/rke2/config.yaml.d"
# systemd's documented runtime unit-config path. Units and drop-ins written
# here take effect after `systemctl daemon-reload`, override the equivalent
# path under /etc/systemd/system/ for the length of this boot, and vanish on
# reboot, because /run is tmpfs (systemd.unit(5), "Unit File Load Path": the
# /run tree has higher precedence than /etc, and a /run drop-in applies to a
# unit whose main file lives in any lower-precedence directory).
readonly RUNTIME_SYSTEMD="/run/systemd/system"
# The measured drop-in the c8s build renders from its required C8S_PLATFORM.
# It holds one line, "Environment=CRED_PLATFORM=<platform>", and it belongs
# to cred-release.service alone. Both cred-release identities need that
# value, so this script copies this one file rather than restating "tdx"
# here, which would be a second source of truth and wrong on an SNP build.
readonly CRED_PLATFORM_DROPIN="/etc/systemd/system/cred-release.service.d/10-platform.conf"
# The bootstrap credential-release window. A single variable: change only
# here. A staging measurement gave 25 minutes 39 seconds from
# control-plane VMI Running to helm-apply finish. See
# images/control-plane-node/README.md for the full measurement and margin.
readonly BOOTSTRAP_WINDOW="1h"

# --- All roles: make BOTH RKE2 roles hard-depend on this script -------------

# A failed generator must never leave a node running RKE2 without the kubelet
# hardening below. The server side is covered by a baked profile file
# (rke2-server.service.d/zz-control-plane-state.conf, Requires=). The pinned
# c8s build accepts exactly five profile files, so this profile cannot bake
# the matching rke2-agent.service.d/ drop-in; it writes it into
# /run/systemd/system instead, as the very first action, before any step that
# can fail.
#
# This works retroactively on the boot transaction that is already running:
# rke2-agent.service's start job is queued but blocked, because this unit is
# ordered Before=rke2-agent.service. systemd propagates a unit failure to the
# queued jobs of every unit that Requires= it using the LIVE dependency graph
# at the moment of the failure, not the graph the transaction was built from,
# so the Requires= edge this drop-in adds takes effect for the pending
# rke2-agent job as soon as the daemon-reload below completes. If any later
# line of this script exits non-zero, systemd fails this unit and cancels the
# rke2-agent start job with a "dependency" result. The node then has no
# kubelet at all, which is the fail-closed outcome; the alternative is a
# worker whose kubelet keeps the exec/attach/port-forward/logs handlers open.
install -d -m 0755 "$RUNTIME_SYSTEMD/rke2-agent.service.d"
cat > "$RUNTIME_SYSTEMD/rke2-agent.service.d/zz-confidential-inference-hardening.conf" <<'AGENT_REQUIRES_EOF'
[Unit]
# Written at boot by control-plane-state-disk.sh; see
# images/control-plane-node/README.md, "Profile packaging". The mirror of the
# baked rke2-server.service.d/zz-control-plane-state.conf drop-in, for the
# agent role, which the five-file build contract has no room to bake.
Requires=control-plane-state-disk.service
After=control-plane-state-disk.service
AGENT_REQUIRES_EOF
systemctl daemon-reload

# --- All roles: kubelet hardening ------------------------------------------

# Confidential Inference Hardening Upgrade, Fix 1 (replicates c8s main
# commit b6bbbe9b, PR #533; production stays pinned to c8s commit
# 079aeb48, builder-lock.json, so this profile replicates the change
# instead of moving the pin). rke2-role.sh already creates
# /etc/rancher/rke2/config.yaml.d (etc/tmpfiles.d/confos-rke2.conf in the
# base image) before this unit runs, and it and gpu-node-label.sh already
# write fragments into it at boot, so the directory is confirmed writable
# at runtime.
#
# RKE2 merges every file under config.yaml.d/ onto the baked config.yaml in
# filename order. A plain list key replaces the base value; the "+" suffix
# on a list key appends to it instead, so the base image's kubelet-arg
# entries (max-pods=200) survive.
#
# Closes the kubelet's exec/attach/port-forward/logs endpoints. The
# kubeconfig cred-release hands out is cluster-admin (or, for the
# restricted identity below, a narrow operator role), so without this any
# holder can run commands in every allowlisted pod. Liveness/readiness
# probes are unaffected: they go over the CRI path, not this endpoint.
install -d -m 0755 "$RANCHER_DROPIN_DIR"
cat > "$RANCHER_DROPIN_DIR/60-confidential-inference-hardening.yaml" <<'KUBELET_HARDENING_EOF'
# Confidential Inference Hardening Upgrade, Fix 1. Written at boot by
# control-plane-state-disk.sh; see images/control-plane-node/README.md,
# "Profile packaging".
kubelet-arg+:
  - enable-debugging-handlers=false
KUBELET_HARDENING_EOF
chmod 0644 "$RANCHER_DROPIN_DIR/60-confidential-inference-hardening.yaml"

# Agent nodes stop here: no server state to hold, no cred-release identity
# to run (the base cred-release.service and this profile's bootstrap
# identity are both server-role only).
if [[ ! -e "$ROLE_SERVER_MARKER" ]]; then
    printf 'control-plane-state-disk: agent role, kubelet hardening written, nothing else to do\n'
    exit 0
fi

# --- Server role: state tmpfs -----------------------------------------------

# The mount holds the RKE2 cluster CA private keys and etcd. tmpfs keeps this
# data only in the CVM's TEE-protected memory. The host cannot read it. The
# data does not survive a control-plane stop; a stop is a redeploy.
if ! mountpoint -q "$MOUNT_POINT"; then
    # Save the measured seed files the image ships at the mount point before
    # the tmpfs mount hides them. The base c8s image bakes three AddOn
    # manifests under manifests/ (local-path-storage.yaml,
    # nvidia-device-plugin.yaml, rke2-cilium-config.yaml); they are copied
    # out here and copied back below, so they land in the tmpfs first and
    # this script's own AddOns are written alongside them afterwards.
    rm -rf "$SEED_DIR"
    install -d -m 0700 "$SEED_DIR"
    if [[ -d "$MOUNT_POINT" ]]; then
        cp -a "$MOUNT_POINT/." "$SEED_DIR/"
    fi

    install -d -m 0700 "$MOUNT_POINT"
    mount -t tmpfs -o size="${TMPFS_SIZE}",mode=0700,nodev,nosuid tmpfs "$MOUNT_POINT"
    chmod 0700 "$MOUNT_POINT"

    # Seed the tmpfs on every boot. cp -a preserves file modes.
    cp -a "$SEED_DIR/." "$MOUNT_POINT/"
    rm -rf "$SEED_DIR"

    printf 'control-plane-state-disk: mounted tmpfs at %s\n' "$MOUNT_POINT"
fi

# --- Server role: Pod Security floor ----------------------------------------

# Confidential Inference Hardening Upgrade, Fix 1 (replicates c8s main
# commit 6013134d, PR #542). The base image's config.yaml already sets
# pod-security-admission-config-file: /etc/rancher/rke2/psa-config.yaml, and
# already bakes a file at that path (rke2-role.sh's tmpfiles rule confirms
# /etc is writable at runtime the same way config.yaml.d/ is), so this
# write replaces the base file wholesale — RKE2 does not merge this file
# the way it merges config.yaml.d/, there is one admission config,
# referenced directly.
#
# Restricted enforcement by default. kube-system and local-path-storage
# stay exempt (they ship privileged daemonsets / hostPath helpers);
# "default" is not exempt. See images/control-plane-node/README.md.
cat > /etc/rancher/rke2/psa-config.yaml <<'PSA_CONFIG_EOF'
# PodSecurity admission config applied via
# /etc/rancher/rke2/config.yaml: pod-security-admission-config-file=...
#
# Confidential Inference Hardening Upgrade, Fix 1. Written at boot by
# control-plane-state-disk.sh; see images/control-plane-node/README.md,
# "Profile packaging". Restricted enforcement by default. kube-system and
# local-path-storage stay exempt (they ship privileged daemonsets / hostPath
# helpers); "default" is not exempt. The confidential-inference application
# namespace and the c8s release namespace are NOT listed here either: the
# install opens them at runtime with an explicit
# "pod-security.kubernetes.io/enforce: privileged" namespace label, and the
# psa-level-policy.yaml AddOn written below stops any other caller from
# lowering a namespace's floor the same way.
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: PodSecurity
    configuration:
      apiVersion: pod-security.admission.config.k8s.io/v1
      kind: PodSecurityConfiguration
      defaults:
        enforce: "restricted"
        enforce-version: "latest"
        audit: "restricted"
        audit-version: "latest"
        warn: "restricted"
        warn-version: "latest"
      exemptions:
        usernames: []
        runtimeClasses: []
        namespaces:
          - kube-system
          - local-path-storage
PSA_CONFIG_EOF
chmod 0644 /etc/rancher/rke2/psa-config.yaml

# --- Server role: baked-manifest AddOns written into the state tmpfs -------

install -d -m 0700 "$MOUNT_POINT/manifests"

cat > "$MOUNT_POINT/manifests/psa-level-policy.yaml" <<'PSA_LEVEL_POLICY_EOF'
# Confidential Inference Hardening Upgrade, Fix 1. Written at boot by
# control-plane-state-disk.sh into the state tmpfs; see
# images/control-plane-node/README.md, "Profile packaging".
#
# Keeps the restricted PodSecurity floor from psa-config.yaml an invariant:
# PodSecurity admission reads its level from namespace labels, so whoever can
# label a namespace could hand its pods "privileged", or pin
# "enforce-version" to an old standard that lacks the seccomp, capability and
# non-root checks. A namespace may carry an "enforce" label other than
# "restricted", or an "enforce-version" other than "latest", only when the
# caller passes an RBAC check for a virtual resource
# ("podsecurityexemptions.confidential.ai", verb "grant") that no default
# role grants: cluster-admin (wildcard rules) and system:masters pass, a
# tenant holding "admin"/"edit" in its own namespaces does not. A write that
# leaves both labels as they were passes without the check, so a controller
# that touches an operator-labelled namespace's annotations or status is not
# denied. The status and finalize subresources are matched because their
# update strategies keep the labels a writer sends.
#
# RKE2 applies this AddOn manifest at server start, before any tenant can
# reach the API. The install runs as the bootstrap cluster-admin identity,
# so it passes the grant check and can still label the confidential-inference
# application namespace and the c8s release namespace "privileged". See
# images/control-plane-node/README.md, "Kubelet and Pod Security hardening".
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: confidential-inference-psa-level
spec:
  # Fail closed: a CEL evaluation error denies the namespace write. The
  # optional chains below cannot error on a missing label map or key.
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["namespaces", "namespaces/status", "namespaces/finalize"]
  validations:
    - expression: >-
        (object.metadata.?labels[?'pod-security.kubernetes.io/enforce'].orValue('restricted') == 'restricted' &&
         object.metadata.?labels[?'pod-security.kubernetes.io/enforce-version'].orValue('latest') == 'latest') ||
        (oldObject != null &&
         object.metadata.?labels[?'pod-security.kubernetes.io/enforce'] == oldObject.metadata.?labels[?'pod-security.kubernetes.io/enforce'] &&
         object.metadata.?labels[?'pod-security.kubernetes.io/enforce-version'] == oldObject.metadata.?labels[?'pod-security.kubernetes.io/enforce-version']) ||
        authorizer.group('confidential.ai').resource('podsecurityexemptions').check('grant').allowed()
      message: "pod-security.kubernetes.io/enforce may not be set below restricted, nor enforce-version below latest, without permission to grant podsecurityexemptions.confidential.ai"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: confidential-inference-psa-level
spec:
  policyName: confidential-inference-psa-level
  validationActions:
    - Deny
PSA_LEVEL_POLICY_EOF

cat > "$MOUNT_POINT/manifests/confidential-ai-operator-rbac.yaml" <<'OPERATOR_RBAC_EOF'
# Baked-behavior AddOn, written at boot by control-plane-state-disk.sh into
# the state tmpfs, so RKE2 grants the restricted day-two operator group
# (confidential-ai:operator, issued by cred-release.service through the
# runtime 50-restricted-identity.conf drop-in) only the access it needs to
# operate the cluster. RKE2 reapplies this AddOn on every boot; the cluster
# state is ephemeral. See images/control-plane-node/README.md for the two
# operator identities and their scope.
#
# The rules below are the full grant. Add nothing else here: no secrets
# access outside the two listed Roles, no RBAC or admission-control writes,
# no pod exec/attach/port-forward/ephemeral-containers, no node proxy, and no
# service-account token minting.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: confidential-ai-operator
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["pods/eviction"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch", "patch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["endpoints"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets"]
    verbs: ["patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: confidential-ai-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: confidential-ai-operator
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: confidential-ai:operator
---
# The c8s install namespace. Found in tests/release-v0/c8s-install.fixture.json
# (cluster.namespace) and used by the internal deploy repository's
# run-c8s-install.py.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: confidential-ai-operator
  namespace: c8s-system
rules:
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: confidential-ai-operator
  namespace: c8s-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: confidential-ai-operator
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: confidential-ai:operator
---
# The application namespace. This one image serves both environments (see
# images/control-plane-node/README.md), so this AddOn bakes a Role for each
# known application namespace: "confidential-inference" (production, see
# releases/production/release-bundle.json) and "confidential-inference-staging"
# (staging's sealed-image builds, when it ran one; staging has run
# policyMode: operator on a stock, pull-mode node image since its c8s
# v0.20.4 move, so this Role is currently unused, but the profile keeps it
# in case a sealed staging build returns; see
# images/control-plane-node/README.md).
# RKE2 reconciles this AddOn continuously, so the Role for a namespace that
# does not exist yet on this cluster simply waits until helm-apply or
# secret-release creates that namespace; it grants nothing before then.
#
# Secret names are exact and unprefixed. Found in helm/confidential-inference/
# values.yaml (secretName / imagePullSecret.name) and
# tests/c8s-install-v0/test_public_tools.py.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: confidential-ai-operator
  namespace: confidential-inference
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames:
      - gateway-admin-mtls
      - gateway-public-tls
      - metrics-remote-write-mtls
      - registry-pull
    verbs: ["get", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: confidential-ai-operator
  namespace: confidential-inference
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: confidential-ai-operator
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: confidential-ai:operator
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: confidential-ai-operator
  namespace: confidential-inference-staging
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames:
      - gateway-admin-mtls
      - gateway-public-tls
      - metrics-remote-write-mtls
      - registry-pull
    verbs: ["get", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: confidential-ai-operator
  namespace: confidential-inference-staging
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: confidential-ai-operator
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: confidential-ai:operator
OPERATOR_RBAC_EOF

cat > "$MOUNT_POINT/manifests/confidential-ai-bootstrap-rbac.yaml" <<'BOOTSTRAP_RBAC_EOF'
# Baked-behavior AddOn, written at boot by control-plane-state-disk.sh into
# the state tmpfs, so the group cred-release-bootstrap.service issues
# (--cert-org confidential-ai:bootstrap) gets cluster-admin through an
# ordinary, revocable RBAC binding, instead of the unrevocable
# system:masters group the base cred-release.service issues by default.
# This is the only privilege the bootstrap identity carries; it is the same
# shape as the default identity's confidential-ai-operator-rbac.yaml AddOn
# written alongside it, and it is revocable the same way: delete this
# binding to cut off every certificate the bootstrap identity has already
# issued. cred-release-bootstrap-stop.service also stops and disables the
# unit itself after a short boot window; see
# images/control-plane-node/README.md.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: confidential-ai-bootstrap
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: confidential-ai:bootstrap
BOOTSTRAP_RBAC_EOF

chmod 0600 "$MOUNT_POINT/manifests/psa-level-policy.yaml" \
    "$MOUNT_POINT/manifests/confidential-ai-operator-rbac.yaml" \
    "$MOUNT_POINT/manifests/confidential-ai-bootstrap-rbac.yaml"

printf 'control-plane-state-disk: wrote PSA and RBAC AddOns into %s/manifests\n' "$MOUNT_POINT"

# --- Server role: cred-release identities -----------------------------------

# Both constructions below go into $RUNTIME_SYSTEMD (see the constant at the
# top of this file), so the image's normal cred-release.service returns
# unmodified on the next boot. Both match c8s commit 079aeb48
# (etc/systemd/system/cred-release.service, pinned by
# images/control-plane-node/builder-lock.json) except for the flags this
# profile changes.
install -d -m 0755 "$RUNTIME_SYSTEMD/cred-release.service.d"

cat > "$RUNTIME_SYSTEMD/cred-release.service.d/50-restricted-identity.conf" <<'RESTRICTED_IDENTITY_EOF'
[Service]
# The baked c8s cred-release.service issues group system:masters by default.
# This drop-in narrows the default identity an operator gets from the
# standard :8443 endpoint. It clears the base ExecStart and restates it with
# a restricted group, a fixed user name, and a short TTL. The bootstrap
# identity (cred-release-bootstrap.service, a separate unit on a different
# port) still grants full cluster-admin, through a revocable
# ClusterRoleBinding this profile writes for group confidential-ai:bootstrap,
# for install and upgrade only, and stops after a short window after boot.
#
# Every other flag below is copied exactly from the base unit's ExecStart
# (c8s commit 079aeb48c4d523aa7500b4bd78f0283b2d12e317, pinned by
# images/control-plane-node/builder-lock.json). Only --cert-org, --cert-cn,
# and --cert-ttl change.
ExecStart=
ExecStart=/usr/local/bin/c8s cred-release \
    --listen :8443 \
    --attestation-api-url http://127.0.0.1:8400 \
    --platform=${CRED_PLATFORM} \
    --cert-ttl 24h \
    --cert-org confidential-ai:operator \
    --cert-cn operator
RESTRICTED_IDENTITY_EOF

cat > "$RUNTIME_SYSTEMD/cred-release-bootstrap.service" <<'BOOTSTRAP_SERVICE_EOF'
[Unit]
Description=Attested RKE2 bootstrap credential release (install and upgrade only)
Documentation=https://github.com/confidential-dot-ai/c8s
# No start limit. Every failure this unit can have is fail-closed: it
# releases no credential unless the launch-bound operator key verifies, so a
# retry loop hands nothing out. Giving up permanently costs a full redeploy
# of the control plane, because this identity is the only door the install
# and upgrade pipeline has. A bounded limit of 5 tries 10 s apart is what
# turned one early failure into a dead port for the whole boot. So retry,
# slowly (RestartSec below), for as long as the boot lasts.
StartLimitIntervalSec=0
# Needs the RKE2 client-CA (to sign operator certs) and the attestation-api
# (to fetch the RA-TLS serving cert's quote from :8400). rke2-server
# creates /var/lib/rancher/rke2/server/tls/client-ca.* only once it has
# initialised, so we order after it and gate on the key existing (the Exec
# startpre below), rather than racing a half-initialised control plane.
# Also ordered after cred-release.service, so the two units have one clear
# boot order and neither races the other for the attestation-api or the
# RKE2 client-CA.
After=network-online.target rke2-role.service rke2-server.service attestation-api.service cred-release.service
Wants=network-online.target
Requires=rke2-role.service attestation-api.service
# Only run on operator boots. A VM launched without --operator-key has no
# opkeydata disk; the condition makes systemd SKIP the unit (not fail it), so
# there's no restart-loop on non-operator nodes. The launcher attaches the
# disk with ISO label "opkeydata".
ConditionPathExists=/dev/disk/by-label/opkeydata
# Server role only: agent nodes have no client CA to sign with.
ConditionPathExists=/run/confos/role-server
# Refuse a direct `systemctl start`. This unit may only be activated as
# another unit's dependency. control-plane-state-disk.sh therefore does NOT
# run `systemctl start` on it (that is exactly the manual job this setting
# rejects); it adds a runtime multi-user.target.wants symlink and re-enqueues
# multi-user.target instead, so systemd pulls this unit in as a dependency.
# The setting is defense in depth alongside the runtime mask
# cred-release-bootstrap-stop.service applies once the bootstrap window
# ends: even if a future unmask attempt succeeded, a plain manual start
# still fails until the next reboot.
#
# This key belongs to the unit section. An earlier revision put it in the
# service section, where systemd does not know it. The guest logged
# "Unknown key ... ignoring" and the barrier was absent for the whole boot.
RefuseManualStart=yes

[Service]
Type=simple
# The operator key is bound into the platform's launch identity (TDX: the
# initrd extends its hash into RTMR[3]; SNP: the launcher commits its sha256
# as HOSTDATA); the service verifies the on-disk pubkey against that binding
# via the local attestation-api and refuses (exits non-zero) if it was
# substituted.
# Non-operator boots never reach here (ConditionPathExists skips the unit).
# Waits bounded (10 min) rather than failing fast: on a slow first boot the
# CA can take minutes to appear, and 5 quick ExecStartPre failures 10s apart
# would exhaust StartLimitBurst in under a minute and give up until reboot.
ExecStartPre=/bin/sh -c 'for _ in $(seq 1 120); do [ -r /var/lib/rancher/rke2/server/tls/client-ca.key ] && exit 0; sleep 5; done; exit 1'
TimeoutStartSec=630
# ${CRED_PLATFORM} comes from a drop-in the c8s sync hook renders from the
# build's required C8S_PLATFORM. The `=` form matters: with the variable
# unset systemd would elide a bare word, but --platform= expands to an empty
# value, which platform validation rejects — fail closed, never a default.
#
# Same binary as cred-release.service, on a different port (contracts/
# network-ports.yaml: c8s-credential-release-bootstrap, cvmPort 8444 — the
# next free port after the reserved 8400/8443/6443). Issues group
# confidential-ai:bootstrap with a 30-minute TTL. This profile's
# confidential-ai-bootstrap-rbac.yaml AddOn (written above, into the state
# tmpfs) binds that group to the built-in cluster-admin ClusterRole through
# an ordinary, revocable ClusterRoleBinding, for the install and upgrade
# pipeline only. cred-release-bootstrap-stop.service stops and runtime-masks
# this unit after the bootstrap window; see
# images/control-plane-node/README.md.
ExecStart=/usr/local/bin/c8s cred-release \
    --listen :8444 \
    --attestation-api-url http://127.0.0.1:8400 \
    --platform=${CRED_PLATFORM} \
    --cert-ttl 30m \
    --cert-org confidential-ai:bootstrap \
    --cert-cn bootstrap
Restart=on-failure
RestartSec=30
# Reads two files: the initrd-staged operator pubkey (/etc/confai) and the
# RKE2 client-CA key. No mount needed. Keep the rest of the FS read-only.
ProtectSystem=strict
# The `-` prefix makes each path optional. systemd builds this unit's mount
# namespace before ExecStartPre runs, so a path that does not exist yet
# would fail the start with 226/NAMESPACE, before the wait below could give
# rke2-server time to create it.
ReadOnlyPaths=-/etc/confai -/var/lib/rancher/rke2/server/tls
ReadWritePaths=/run
ProtectHome=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
BOOTSTRAP_SERVICE_EOF

# Give the bootstrap unit the platform value its ExecStart names.
#
# ${CRED_PLATFORM} is not an ambient variable. The c8s build renders it into
# a drop-in that belongs to cred-release.service and to nothing else
# (CRED_PLATFORM_DROPIN, above). A systemd drop-in applies to its own unit
# only, so the bootstrap unit above started with the variable unset,
# --platform= empty, and the binary refused to serve:
#
#   (c8s)[...]: cred-release-bootstrap.service: Referenced but unset
#       environment variable evaluates to an empty string: CRED_PLATFORM
#   c8s[...]: --platform is required (RA-TLS is mandatory for credential
#       release)
#
# That is why port 8444 never opened on the v9 node image. The internal
# repository keeps the full deployment record.
#
# Copy the measured file rather than restate its value: one source of truth,
# and an SNP build needs no edit here. `set -e` above fails this script if
# the file is absent, which fails the RKE2 start. That is the right outcome:
# without that file the base cred-release.service cannot serve either, so
# the node has no operator identity at all and must not join a cluster.
install -d -m 0755 "$RUNTIME_SYSTEMD/cred-release-bootstrap.service.d"
cp "$CRED_PLATFORM_DROPIN" \
    "$RUNTIME_SYSTEMD/cred-release-bootstrap.service.d/10-platform.conf"

cat > "$RUNTIME_SYSTEMD/cred-release-bootstrap-stop.service" <<'BOOTSTRAP_STOP_EOF'
[Unit]
Description=Stop and permanently disable the bootstrap credential-release identity for this boot
# This unit ends the bootstrap window. cred-release-bootstrap-schedule.service
# schedules it to run once, at the window's end (see
# images/control-plane-node/README.md). It must not depend on
# cred-release-bootstrap.service being active: the stop must still run and
# mask the unit even if the bootstrap service already exited.

[Service]
Type=oneshot
# Stop first, so no certificate is released after this point, then mask for
# the remainder of this boot. Stop before mask on purpose: `systemctl stop`
# on a unit systemd has just replaced with a mask is not a path this image
# exercises, and the running process holds port 8444 until the stop lands.
# Nothing re-enqueues the unit between the two lines: `Restart=on-failure`
# does not fire on a clean stop, and no other unit wants it in this boot's
# transaction. `--runtime` keeps the mask off the read-only measured image;
# it is a symlink to /dev/null under /run and clears itself on reboot, when
# the image's normal cred-release-bootstrap.service returns.
ExecStart=systemctl stop cred-release-bootstrap.service
ExecStart=systemctl mask --runtime cred-release-bootstrap.service
BOOTSTRAP_STOP_EOF

cat > "$RUNTIME_SYSTEMD/cred-release-bootstrap-schedule.service" <<'BOOTSTRAP_SCHEDULE_EOF'
[Unit]
Description=Schedule the end of the bootstrap credential-release window
# Runs once per boot, after the bootstrap identity starts serving, and
# schedules cred-release-bootstrap-stop.service to run once the window this
# script baked into it (see images/control-plane-node/README.md) elapses. A
# plain .timer unit's OnBootSec= cannot read a variable, so this oneshot
# hands the duration straight to `systemd-run --on-active` instead.
After=cred-release-bootstrap.service
Requires=cred-release-bootstrap.service
ConditionPathExists=/dev/disk/by-label/opkeydata
ConditionPathExists=/run/confos/role-server

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh /run/confai/cred-release-bootstrap-schedule.sh

[Install]
WantedBy=multi-user.target
BOOTSTRAP_SCHEDULE_EOF

# The schedule script cannot live under /usr/local/libexec: that tree is
# part of the read-only, dm-verity-protected root, and this file is not one
# of the five profile files the pinned c8s build accepts. /run is tmpfs and
# writable, so the script lives there instead; the schedule unit above
# references it by that path. The window value is baked into this script by
# this same boot script (the constant at the top of this file), not read
# from a separate file, so there is exactly one thing to change when the
# window changes: BOOTSTRAP_WINDOW, above.
install -d -m 0755 /run/confai
cat > /run/confai/cred-release-bootstrap-schedule.sh <<SCHEDULE_SCRIPT_EOF
#!/bin/sh
# Schedule the one action that ends the bootstrap credential-release window.
# Written at boot by control-plane-state-disk.sh; see
# images/control-plane-node/README.md, "Profile packaging". The window
# value is substituted in below from that script's BOOTSTRAP_WINDOW
# constant.
set -eu

exec systemd-run \\
    --unit=cred-release-bootstrap-stop-trigger \\
    --description="End the bootstrap credential-release window after ${BOOTSTRAP_WINDOW}" \\
    --on-active="${BOOTSTRAP_WINDOW}" \\
    /usr/bin/systemctl start cred-release-bootstrap-stop.service
SCHEDULE_SCRIPT_EOF
chmod 0755 /run/confai/cred-release-bootstrap-schedule.sh

# Pull the two new units in the way their [Install] section would have, had
# they existed when systemd computed this boot's transaction. Two facts rule
# out the obvious `systemctl start cred-release-bootstrap.service`:
#
#   1. `systemctl start` is the manual job cred-release-bootstrap.service's
#      RefuseManualStart=yes rejects. It would fail, and `set -e` would fail
#      this unit, which now fails BOTH RKE2 roles.
#   2. `systemctl start` blocks until the job finishes, and that job cannot
#      finish: cred-release-bootstrap.service is ordered
#      After=rke2-server.service, rke2-server.service is ordered after this
#      unit and Requires= it, and this unit is still inside its own
#      ExecStart. The wait would deadlock until TimeoutStartSec=30 killed
#      this script, and take the whole boot with it.
#
# So: write the .wants symlinks systemd would have read at transaction time,
# reload, then re-enqueue multi-user.target without blocking. The new
# transaction pulls both units in as dependencies of the target — not as
# manual jobs, so RefuseManualStart is satisfied — and --no-block returns at
# once, so the ordering above resolves normally after this unit finishes.
# Jobs for units multi-user.target already pulled in merge with the running
# ones; the re-enqueue restarts nothing.
#
# cred-release.service itself needs none of this: it is started by the base
# image's own [Install] wiring (WantedBy=multi-user.target,
# After=rke2-server.service) and has not started yet, because this script
# runs Before=rke2-server.service, so the daemon-reload alone is enough for
# the 50-restricted-identity.conf drop-in to take effect before it starts.
#
# ConditionPathExists on each new unit makes a non-operator boot a clean
# no-op (systemd reports the start job as "skipped"), not a failure.
install -d -m 0755 "$RUNTIME_SYSTEMD/multi-user.target.wants"
ln -sf "$RUNTIME_SYSTEMD/cred-release-bootstrap.service" \
    "$RUNTIME_SYSTEMD/multi-user.target.wants/cred-release-bootstrap.service"
ln -sf "$RUNTIME_SYSTEMD/cred-release-bootstrap-schedule.service" \
    "$RUNTIME_SYSTEMD/multi-user.target.wants/cred-release-bootstrap-schedule.service"
systemctl daemon-reload
systemctl --no-block start multi-user.target

printf 'control-plane-state-disk: wrote cred-release identities and hardening for this boot\n'
