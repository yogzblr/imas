#!/bin/sh
# Install -> start -> upgrade -> remove an imas-sprout RPM and print the
# systemd unit state after each step. Run it inside a container that boots
# systemd as PID 1, once per distro, to compare how the shared
# packaging/scripts/imas-sprout-rpm-postinstall.sh behaves under dnf and
# zypper (see "SUSE and the shared RPM scripts" in packaging/README.md):
#
#   docker run -d --name leap --privileged --cgroupns=host \
#     -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v "$PWD/pkgs:/pkg" \
#     dokken/opensuse-leap-15.6 /usr/lib/systemd/systemd
#   docker exec leap /pkg/rpm-service-lifecycle.sh \
#     /pkg/imas-sprout-0.0.1-1.x86_64.rpm /pkg/imas-sprout-0.0.2-1.x86_64.rpm
#
# (dokken/rockylinux-9 likewise for RHEL.) The two RPMs must be the same
# package at two versions; build them with nfpm from the imas-sprout nfpms
# entry in .goreleaser.yaml. No repositories are needed.
set -u

old="${1:?usage: $0 <old.rpm> <new.rpm>}"
new="${2:?usage: $0 <old.rpm> <new.rpm>}"
unit=imas-sprout

state() {
	echo "  [$1] enabled=$(systemctl is-enabled "$unit" 2>&1 | tail -1)" \
		"active=$(systemctl is-active "$unit" 2>&1)" \
		"mainpid=$(systemctl show -p MainPID --value "$unit" 2>/dev/null)"
}

if command -v zypper >/dev/null; then
	inst="zypper --non-interactive --no-refresh install -y --allow-unsigned-rpm"
	rm="zypper --non-interactive --no-refresh remove -y"
else
	inst="dnf install -y --disablerepo=* --nogpgcheck"
	rm="dnf remove -y --disablerepo=*"
fi
log="$(mktemp)"

# shellcheck source=/dev/null
. /etc/os-release
echo "== $PRETTY_NAME, $(rpm -q systemd), installer: ${inst%% *}"

echo "-- install $(basename "$old")"
$inst "$old" >"$log" 2>&1; echo "  rc=$?"; grep -iE "scriptlet failed|error" "$log"
state install

echo "-- systemctl start"
systemctl start "$unit"; sleep 2
state started

echo "-- upgrade to $(basename "$new")"
$inst "$new" >"$log" 2>&1; echo "  rc=$?"; grep -iE "scriptlet failed|error" "$log"
state upgraded

echo "-- remove"
$rm "$unit" >"$log" 2>&1; echo "  rc=$?"; grep -iE "scriptlet failed|error|rpmsave" "$log"
state removed
if ls /etc/systemd/system/*.wants/"$unit".service >/dev/null 2>&1; then
	echo "  leftover: $(ls /etc/systemd/system/*.wants/"$unit".service)"
fi

echo "-- vendor preset default: $(grep -h '^[a-z]' /usr/lib/systemd/system-preset/*.preset 2>/dev/null | grep -E '^(enable|disable) \*$' | head -1)"
rm -f "$log"
