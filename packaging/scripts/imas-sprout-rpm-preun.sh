#!/bin/sh
# imas-sprout %preun. Stop and disable the service on erase, not on upgrade.
# rpm passes the number of package instances left after this one: 0 on
# erase, 1 or more on an upgrade (a self_update's rpm -U must not stop it).
if [ "${1:-1}" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
	systemctl stop imas-sprout.service || true
	systemctl disable imas-sprout.service || true
fi
exit 0
