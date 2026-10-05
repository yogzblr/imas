#!/bin/sh
# deb and rpm pre-install: create the farmer system user before the package
# unpacks, because the package ships /etc/imas/pki/farmer and
# /var/cache/imas/farmer owned by farmer:farmer. (The Alpine pre-install
# script uses addgroup/adduser -S, which Debian and RHEL do not have.)
# Idempotent, so upgrades are fine.
if ! getent group farmer >/dev/null 2>&1; then
  groupadd -r farmer
fi
if ! id -u farmer >/dev/null 2>&1; then
  useradd -r -s /usr/sbin/nologin -d /var/cache/imas/farmer -g farmer farmer 2>/dev/null ||
    useradd -r -s /bin/false -d /var/cache/imas/farmer -g farmer farmer
fi
exit 0
