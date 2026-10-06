# uat/lite (UAT.8): an Ubuntu 24.04 "machine" for one sprout: systemd as
# PID 1 and sshd, nothing of imas. uat/enroll installs the published
# imas-sprout package over SSH with ansible/site.yml, as on an Azure VM.
#
# Base: the Docker Official Image ubuntu:24.04 (Canonical). Its packages and
# the ones added here carry their own licences (GPL, LGPL, MIT, BSD and
# others; systemd is LGPL-2.1+, OpenSSH BSD-style, Python PSF). The image is
# built and run locally for tests only, never shipped (README.md, Licences).
#
# Run it as up.sh does: --privileged --cgroupns=private --tmpfs /run
# --tmpfs /run/lock (what systemd needs in a container).
ARG BASE_IMAGE=docker.io/library/ubuntu:24.04
FROM ${BASE_IMAGE}

ENV container=docker \
    DEBIAN_FRONTEND=noninteractive

# systemd and sshd; python3 and python3-apt for Ansible's apt modules; sudo
# for become; gnupg and ca-certificates for the role's signed apt
# repository; iproute2 and procps for the checks the tests run.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server \
      python3 python3-apt sudo ca-certificates gnupg curl \
      iproute2 procps \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_*

# Units that need hardware or a console, which a container has neither of.
RUN systemctl mask \
      systemd-udevd.service systemd-udevd-control.socket systemd-udevd-kernel.socket \
      systemd-modules-load.service sys-kernel-config.mount sys-kernel-debug.mount \
      sys-kernel-tracing.mount getty.target console-getty.service \
      systemd-firstboot.service \
 && systemctl set-default multi-user.target

COPY files/10-imas-lite.conf /etc/ssh/sshd_config.d/10-imas-lite.conf
COPY files/imas-lite-hostkeys.service /etc/systemd/system/imas-lite-hostkeys.service

# Ubuntu 24.04 starts sshd from ssh.socket by default; the rig wants the
# plain service, so the port is always open once the container has booted.
RUN systemctl enable imas-lite-hostkeys.service ssh.service \
 && (systemctl disable ssh.socket || true) \
 && mkdir -p /run/sshd

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
