#!/bin/bash
# This hook is retired. It once recovered a single-control-plane cluster
# after its guest IP changed. The control-plane server state now lives in
# tmpfs (see control-plane-state-disk.sh); a stopped control plane is a
# redeploy, not a recovery target. No unit calls this script.
set -euo pipefail

printf 'rke2-single-control-recovery: retired; the server state lives in tmpfs, so a stopped control plane is a redeploy, not a recovery target\n'
exit 0
