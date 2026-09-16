#!/bin/sh
# Fake /usr/local/bin/rke2-role.sh. The real one reads the joindata disk;
# this one reads the role run.sh bind-mounted into /etc/boot-sim-role (one
# word, "server" or "agent") and writes the same marker file and
# directories the real rke2-role.sh and its tmpfiles rule create, which
# control-plane-state-disk.sh and RKE2 both depend on existing at runtime.
set -eu
role=$(cat /etc/boot-sim-role)
mkdir -p /run/confos /etc/rancher/rke2/config.yaml.d
: > "/run/confos/role-${role}"
echo "rke2-role.sh: wrote /run/confos/role-${role}"
