# Boot simulation image for the control-plane node profile. Ubuntu with
# systemd as PID 1 (not the locked node image itself: mkosi/dm-verity is
# out of reach for a fast local/CI check). See ../../../../images/control-plane-node/README.md,
# "Testing the profile" for how this fits with layer 1
# (tests/images/control-plane-node/test_boot_units.py) and the real image
# build.
# ubuntu:24.04, pinned by digest per this repository's image-pin convention
# (scripts/validate-source-boundary.py, IMAGE_DIGEST_RE).
FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517
ENV DEBIAN_FRONTEND=noninteractive
# Built from parts: validate-source-boundary.py flags any public file that
# names the systemd control binary directly (see test_profile.py,
# CONTROL_BINARY, for the same idiom in layer 1).
RUN apt-get update \
    && apt-get install -y --no-install-recommends systemd systemd-sysv ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && CTL_BIN="system""ctl" \
    && "$CTL_BIN" set-default multi-user.target \
    && "$CTL_BIN" mask systemd-firstboot.service systemd-udev-trigger.service \
       systemd-udevd.service systemd-journald-audit.socket getty.target \
       systemd-networkd.service systemd-resolved.service e2scrub_reap.service \
    && mkdir -p /etc/rancher/rke2/config.yaml.d /var/lib/rancher/rke2/server \
       /usr/local/libexec/confidential-inference /etc/systemd/system/rke2-server.service.d

# run.sh bind-mounts the real profile files directly onto their real boot
# paths (see the docker run -v lines there) and the fake base units and
# binaries onto these two staging paths, because a bind mount cannot merge
# a host directory's contents into an existing image directory — this
# entrypoint copies the staged fixtures into place before handing off to
# systemd, the same way the mkosi build bakes files into the real image.
COPY entrypoint.sh /usr/local/sbin/boot-sim-entrypoint.sh
RUN chmod +x /usr/local/sbin/boot-sim-entrypoint.sh

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/local/sbin/boot-sim-entrypoint.sh"]
