#!/bin/sh
# imas-sprout prerm. Stop and disable the service when the package is
# removed or purged, but not on an upgrade (a self_update installs the new
# package over the running one and the service must keep running).
# dpkg passes the action as $1: remove | upgrade | deconfigure | failed-upgrade.
set -e
case "$1" in
remove | deconfigure)
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop imas-sprout.service || true
		systemctl disable imas-sprout.service || true
	fi
	;;
esac
exit 0
