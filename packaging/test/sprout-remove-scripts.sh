#!/bin/sh
# Checks the imas-sprout remove scripts with a stub systemctl: they stop and
# disable the service on remove/erase and do nothing on upgrade.
set -u
here=$(cd "$(dirname "$0")/../scripts" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/systemctl" <<'STUB'
#!/bin/sh
echo "$*" >>"$STUB_LOG"
STUB
chmod +x "$tmp/systemctl"
fail=0
run() { # name script arg expect(stop|none)
	: >"$tmp/log"
	STUB_LOG="$tmp/log" PATH="$tmp:$PATH" sh "$2" "$3"
	rc=$?
	got=none
	grep -q '^stop imas-sprout.service' "$tmp/log" && grep -q '^disable imas-sprout.service' "$tmp/log" && got=stop
	if [ "$rc" -eq 0 ] && [ "$got" = "$4" ]; then echo "ok    $1"; else echo "FAIL  $1 (rc=$rc, got $got, want $4)"; fail=1; fi
}
run "deb prerm remove stops and disables" "$here/imas-sprout-deb-prerm.sh" remove stop
run "deb prerm deconfigure stops and disables" "$here/imas-sprout-deb-prerm.sh" deconfigure stop
run "deb prerm upgrade leaves it running" "$here/imas-sprout-deb-prerm.sh" upgrade none
run "deb prerm failed-upgrade leaves it" "$here/imas-sprout-deb-prerm.sh" failed-upgrade none
run "rpm preun erase (0) stops and disables" "$here/imas-sprout-rpm-preun.sh" 0 stop
run "rpm preun upgrade (1) leaves it running" "$here/imas-sprout-rpm-preun.sh" 1 none
run "rpm preun upgrade (2) leaves it running" "$here/imas-sprout-rpm-preun.sh" 2 none
# no systemctl at all (chroot, container image build): still exit 0
if PATH=/nonexistent /bin/sh "$here/imas-sprout-deb-prerm.sh" remove && PATH=/nonexistent /bin/sh "$here/imas-sprout-rpm-preun.sh" 0; then
	echo "ok    no systemctl: both scripts exit 0"
else echo "FAIL  no systemctl"; fail=1; fi
exit $fail
