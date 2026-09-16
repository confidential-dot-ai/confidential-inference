#!/bin/sh
# Copies the staged fixtures (bind-mounted read-only by run.sh) into their
# real boot-time paths, then execs systemd as PID 1. See run.sh for what
# gets bind-mounted where and why a copy step is needed at all.
set -eu

if [ -d /etc/systemd/system.fixtures ]; then
    cp -a /etc/systemd/system.fixtures/. /etc/systemd/system/
fi

# The [Install] symlinks a real image bake (or the systemd control binary's enable) would
# have created. Written here, at container start, rather than committed as
# git symlinks: a symlink in the public tree trips
# scripts/validate-source-boundary.py's symbolic-link rule, and there is
# nothing to review in a plain enable link anyway.
mkdir -p /etc/systemd/system/multi-user.target.wants \
    /etc/systemd/system/sysinit.target.wants \
    /etc/systemd/system/rke2-server.service.requires \
    /etc/systemd/system/rke2-agent.service.requires
ln -sf ../rke2-server.service /etc/systemd/system/multi-user.target.wants/rke2-server.service
ln -sf ../rke2-agent.service /etc/systemd/system/multi-user.target.wants/rke2-agent.service
ln -sf ../attestation-api.service /etc/systemd/system/multi-user.target.wants/attestation-api.service
ln -sf ../cred-release.service /etc/systemd/system/multi-user.target.wants/cred-release.service
ln -sf ../boot-sim-prep.service /etc/systemd/system/sysinit.target.wants/boot-sim-prep.service
# The bake-time the systemd control binary's preset-all equivalent for
# RequiredBy=rke2-server.service rke2-agent.service on
# control-plane-state-disk.service; see that unit's [Install] section and
# images/control-plane-node/README.md, "Profile packaging".
ln -sf ../control-plane-state-disk.service /etc/systemd/system/rke2-server.service.requires/control-plane-state-disk.service
ln -sf ../control-plane-state-disk.service /etc/systemd/system/rke2-agent.service.requires/control-plane-state-disk.service

if [ -d /opt/boot-sim-bin ]; then
    for f in c8s rke2-role.sh rke2-server rke2-agent boot-sim-check.sh; do
        [ -e "/opt/boot-sim-bin/$f" ] && cp -a "/opt/boot-sim-bin/$f" /usr/local/bin/
    done
fi

exec /sbin/init
