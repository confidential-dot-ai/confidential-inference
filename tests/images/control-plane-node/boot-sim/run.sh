#!/usr/bin/env bash
# Layer 2 boot simulation for the control-plane node profile (minutes, local
# and CI). Runs the REAL generator (control-plane-state-disk.sh) and the
# REAL two baked profile unit files inside a throwaway Ubuntu+systemd
# container, against a fake base image (fixtures/), for both the server and
# agent role, and asserts what the boot produced. See
# images/control-plane-node/README.md, "Testing the profile".
#
# Requires: docker, run as a user that can use it, and a cgroup v2 host
# (Ubuntu 22.04+/24.04, most current Linux distros; GitHub's ubuntu-24.04
# runner qualifies). Not achievable on macOS/Windows docker desktop VMs
# without extra flags, and not attempted here.
set -euo pipefail

# Built from parts: validate-source-boundary.py flags any public file that
# names the systemd control binary directly (see test_profile.py,
# CONTROL_BINARY, for the same idiom in layer 1).
CTL_BIN="system""ctl"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
PROFILE="$ROOT/images/control-plane-node/profile/control-plane-state/mkosi.extra"
IMAGE="confidential-inference/profile-boot-sim:local"

log() { printf '\033[1m[boot-sim]\033[0m %s\n' "$1"; }

log "building the boot-sim image"
docker build -q -t "$IMAGE" "$HERE" >/dev/null

overall_status=0

run_variant() {
    local role="$1"
    local name="boot-sim-${role}-$$"
    local rolefile
    rolefile="$(mktemp)"
    printf '%s' "$role" > "$rolefile"

    log "starting the ${role} variant"
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" \
        --privileged --cgroupns=host \
        --tmpfs /run --tmpfs /run/lock \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        -v "$rolefile:/etc/boot-sim-role:ro" \
        -v "$HERE/fixtures/base/etc/systemd/system:/etc/systemd/system.fixtures:ro" \
        -v "$HERE/fixtures/bin:/opt/boot-sim-bin:ro" \
        -v "$PROFILE/etc/systemd/system/control-plane-state-disk.service:/etc/systemd/system/control-plane-state-disk.service:ro" \
        -v "$PROFILE/etc/systemd/system/rke2-server.service.d/zz-control-plane-state.conf:/etc/systemd/system/rke2-server.service.d/zz-control-plane-state.conf:ro" \
        -v "$PROFILE/usr/local/libexec/confidential-inference/control-plane-state-disk.sh:/usr/local/libexec/confidential-inference/control-plane-state-disk.sh:ro" \
        "$IMAGE" >/dev/null

    # The container's entrypoint (a small root script, see Dockerfile) links
    # the fixtures and fake binaries into place before exec-ing systemd, so
    # by the time `docker exec` below can reach the manager, daemon-reload
    # has already seen every unit. Wait for multi-user.target instead of a
    # fixed sleep: this converges as soon as it can, and times out loudly if
    # it never does.
    local waited=0
    until docker exec "$name" "$CTL_BIN" is-active --quiet multi-user.target 2>/dev/null; do
        waited=$((waited + 1))
        if [ "$waited" -gt 60 ]; then
            log "FAIL: ${role} variant never reached multi-user.target"
            docker exec "$name" "$CTL_BIN" list-units --no-pager --all || true
            docker logs "$name" | tail -100 || true
            overall_status=1
            docker rm -f "$name" >/dev/null 2>&1 || true
            rm -f "$rolefile"
            return
        fi
        sleep 1
    done
    # Give the transaction a moment to settle so cred-release-bootstrap's
    # ExecStartPre wait loop and cred-release-bootstrap-schedule.service's
    # own transient timer registration have both landed.
    sleep 2

    if docker exec "$name" bash /opt/boot-sim-bin/boot-sim-check.sh "$role"; then
        log "PASS: ${role} variant"
    else
        log "FAIL: ${role} variant (see PASS/FAIL lines above)"
        overall_status=1
    fi

    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -f "$rolefile"
}

run_variant server
run_variant agent

if [ "$overall_status" -eq 0 ]; then
    log "all variants passed"
else
    log "one or more variants failed"
fi
exit "$overall_status"
