#!/bin/bash
# Runs inside the boot-sim container after multi-user.target settles.
# Prints one PASS/FAIL line per assertion; exits non-zero if any FAIL.
#
# Built from parts: validate-source-boundary.py flags any public file that
# names the systemd control binary directly (see test_profile.py,
# CONTROL_BINARY, for the same idiom in layer 1).
set -u
role="$1"
fail=0
CTL_BIN="system""ctl"

check() {
    local desc="$1"; shift
    if "$@"; then
        echo "PASS: $desc"
    else
        echo "FAIL: $desc"
        fail=1
    fi
}

unit_active() { "$CTL_BIN" is-active --quiet "$1"; }
file_exists() { [ -e "$1" ]; }
file_contains() { grep -qF -- "$2" "$1" 2>/dev/null; }

check "daemon-reload succeeds (every generated and baked unit still parses)" \
    "$CTL_BIN" daemon-reload

check "control-plane-state-disk.service is active (exited)" unit_active control-plane-state-disk.service
check "the generated rke2-agent hardening drop-in exists" \
    file_exists /run/systemd/system/rke2-agent.service.d/zz-confidential-inference-hardening.conf
check "the kubelet hardening drop-in exists" \
    file_exists /etc/rancher/rke2/config.yaml.d/60-confidential-inference-hardening.yaml
check "the kubelet hardening drop-in appends enable-debugging-handlers=false" \
    file_contains /etc/rancher/rke2/config.yaml.d/60-confidential-inference-hardening.yaml "enable-debugging-handlers=false"

if [ "$role" = "server" ]; then
    check "the PSA admission config was written" file_exists /etc/rancher/rke2/psa-config.yaml
    check "the PSA config enforces restricted" file_contains /etc/rancher/rke2/psa-config.yaml "enforce: \"restricted\""
    check "the psa-level-policy AddOn was written into the state tmpfs" \
        file_exists /var/lib/rancher/rke2/server/manifests/psa-level-policy.yaml
    check "the operator RBAC AddOn was written into the state tmpfs" \
        file_exists /var/lib/rancher/rke2/server/manifests/confidential-ai-operator-rbac.yaml
    check "the bootstrap RBAC AddOn was written into the state tmpfs" \
        file_exists /var/lib/rancher/rke2/server/manifests/confidential-ai-bootstrap-rbac.yaml

    check "cred-release.service is active" unit_active cred-release.service
    check "cred-release.service's restricted-identity drop-in exists" \
        file_exists /run/systemd/system/cred-release.service.d/50-restricted-identity.conf
    check "cred-release listened on :8443 with the operator identity" \
        file_contains /run/boot-sim/c8s-cred-release-8443.argv -- "--platform=tdx"
    check "cred-release's argv carries --cert-org confidential-ai:operator" \
        file_contains /run/boot-sim/c8s-cred-release-8443.argv "--cert-org confidential-ai:operator"

    check "cred-release-bootstrap.service is active" unit_active cred-release-bootstrap.service
    check "cred-release-bootstrap listened on :8444" \
        file_contains /run/boot-sim/c8s-cred-release-8444.argv -- "--listen :8444"
    check "cred-release-bootstrap's argv carries --cert-org confidential-ai:bootstrap" \
        file_contains /run/boot-sim/c8s-cred-release-8444.argv "--cert-org confidential-ai:bootstrap"
    check "cred-release-bootstrap's argv carries --platform=tdx (its own drop-in copy)" \
        file_contains /run/boot-sim/c8s-cred-release-8444.argv "--platform=tdx"

    check "the bootstrap stop is scheduled (a transient timer is queued)" \
        bash -c "\"$CTL_BIN\" list-timers --all --no-legend | grep -q cred-release-bootstrap-stop-trigger"
    check "cred-release-bootstrap-schedule.service ran (RemainAfterExit, exited)" \
        unit_active cred-release-bootstrap-schedule.service
else
    check "cred-release.service did not start on the agent role" \
        bash -c "! \"$CTL_BIN\" is-active --quiet cred-release.service"
    check "cred-release-bootstrap.service did not start on the agent role" \
        bash -c "! \"$CTL_BIN\" is-active --quiet cred-release-bootstrap.service"
    check "the runtime rke2-agent drop-in requires the generator" \
        file_contains /run/systemd/system/rke2-agent.service.d/zz-confidential-inference-hardening.conf \
        "Requires=control-plane-state-disk.service"
fi

exit $fail
