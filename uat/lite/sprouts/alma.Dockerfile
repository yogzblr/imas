# uat/lite (UAT.8): an AlmaLinux 9 "machine" for one sprout (it stands in
# for RHEL 9, as on Azure): systemd as PID 1 and sshd, nothing of imas.
# uat/enroll installs the published imas-sprout package over SSH with
# ansible/site.yml, as on an Azure VM.
#
# Base: the Docker Official Image almalinux:9 (AlmaLinux OS Foundation). Its
# packages and the ones added here carry their own licences (GPL, LGPL, MIT,
# BSD and others; systemd is LGPL-2.1+, OpenSSH BSD-style, Python PSF). The
# image is built and run locally for tests only, never shipped (README.md,
# Licences).
#
# Run it as up.sh does: --privileged --cgroupns=private --tmpfs /run
# --tmpfs /run/lock (what systemd needs in a container).
ARG BASE_IMAGE=docker.io/library/almalinux:9
FROM ${BASE_IMAGE}

ENV container=docker

# systemd and sshd; python3 (dnf's own bindings come with dnf) for Ansible;
# sudo for become; gnupg2 for the role's repo_gpgcheck; iproute and
# procps-ng for the checks the tests run.
RUN dnf -y install \
      systemd openssh-server openssh-clients \
      python3 sudo ca-certificates gnupg2 \
      iproute procps-ng hostname \
 && dnf clean all \
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

RUN systemctl enable imas-lite-hostkeys.service sshd.service

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
