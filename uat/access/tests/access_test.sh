#!/usr/bin/env bash
# Tests uat/access/tunnels.sh and vmctl.sh against a stubbed az (tests/stubs):
# tunnels become local listeners, Linux run-commands run locally with a stub
# systemctl, Windows run-commands return canned output. Nothing reaches Azure.
# Needs bash, jq and python3. Run: bash uat/access/tests/access_test.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tunnels="$here/../tunnels.sh"
vmctl="$here/../vmctl.sh"
session="$here/../session.sh"
uat="$here/../testdata/uat.json"
uat_ha="$here/../testdata/uat-ha.json"
stubs="$here/stubs"

pass=0
fail=0
work=$(mktemp -d)
cleanup() {
  # Never leave a listener behind, whatever the tests did.
  for d in "$work"/*/state; do
    [ -d "$d" ] && PATH="$stubs:$PATH" bash "$tunnels" close "$d" >/dev/null 2>&1
  done
  [ -n "${blocker:-}" ] && kill "$blocker" 2>/dev/null
  [ -n "${sleeper:-}" ] && kill "$sleeper" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT
# vmctl.sh's tunnel credentials (the stubs never read them).
echo "stub key" >"$work/id_test"
echo "stub password" >"$work/winrm_password"

ok() { pass=$((pass + 1)); echo "ok   - $1"; }
nok() { fail=$((fail + 1)); echo "FAIL - $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/       /'; }

new_case() {
  STUB_STATE="$work/$1"
  mkdir -p "$STUB_STATE"
  : >"$STUB_STATE/calls.log"
  state="$STUB_STATE/state"
  export STUB_STATE
}
calls() { cat "$STUB_STATE/calls.log"; }

# A random port window per test run, so parallel runs do not collide, below
# the Linux ephemeral range (32768 and up) so outgoing connections of other
# processes do not take the ports.
base=$((20000 + (RANDOM % 120) * 100))

t() { # t <args>: tunnels.sh with the stubs; sets rc, out
  out=$(PATH="$stubs:$PATH" TUNNEL_PORT_BASE="$base" TUNNEL_WAIT_SECONDS=30 bash "$tunnels" "$@" 2>&1)
  rc=$?
}
v() { # v <args>: vmctl.sh with the stubs; sets rc, out (stdout), err (stderr)
  local ef="$STUB_STATE/vmctl.err"
  out=$(PATH="$stubs:$PATH" PYTHONPATH="$stubs/py" VMCTL_ACCESS="${V_ACCESS:-$STUB_STATE/no-access.json}" \
    PYTHONDONTWRITEBYTECODE=1 VMCTL_STATE_DIR="$STUB_STATE/vmctl" VMCTL_SSH_KEY="${V_KEY-$work/id_test}" \
    VMCTL_WINRM_PASSWORD_FILE="${V_PASSWORD-$work/winrm_password}" VMCTL_BACKOFF_SCALE=0 \
    VMCTL_WAIT_SECONDS=5 VMCTL_POWER_WAIT_SECONDS=5 VMCTL_POLL_SECONDS=0 \
    CURL="$stubs/curl" UAT_PROBE_SSH_SECONDS=1 UAT_PROBE_HTTPS_SECONDS=1 CH_REOPEN_WAIT_SECONDS=2 \
    VMCTL_SSH_CONTROL_DIR="$STUB_STATE/cm" VMCTL_WINRM_POOL_IDLE=30 AZ_RELOGIN_DIR="$STUB_STATE/login" bash "$vmctl" "$@" 2>"$ef")
  rc=$?
  err=$(cat "$ef")
}

listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
# running <pid>: alive and not a zombie (an exited tunnel can wait to be
# reaped by whatever adopted it).
running() { kill -0 "$1" 2>/dev/null && [[ "$(ps -o stat= -p "$1" 2>/dev/null)" != Z* ]]; }

# ---------------------------------------------------------------- tunnels.sh

new_case args
t
if [ "$rc" -eq 2 ]; then ok "tunnels: no arguments is a usage error (2)"; else nok "tunnels: no args (rc=$rc)" "$out"; fi
t bogus x
if [ "$rc" -eq 2 ]; then ok "tunnels: unknown command is a usage error"; else nok "tunnels: unknown command (rc=$rc)" "$out"; fi
t open "$uat"
if [ "$rc" -eq 2 ]; then ok "tunnels: open needs a state dir"; else nok "tunnels: open without state dir (rc=$rc)" "$out"; fi
t close
if [ "$rc" -eq 2 ]; then ok "tunnels: close needs a state dir"; else nok "tunnels: close without dir (rc=$rc)" "$out"; fi
t open "$work/missing.json" "$state"
if [ "$rc" -ne 0 ] && [ ! -e "$state/access.json" ]; then ok "tunnels: unreadable uat.json fails"; else nok "tunnels: missing uat.json (rc=$rc)" "$out"; fi
echo '{"resource_group":"rg","bastion":{"name":"b"},"dmz":{}}' >"$work/bad.json"
t open "$work/bad.json" "$state"
if [ "$rc" -ne 0 ] && ! calls | grep -q "bastion tunnel"; then ok "tunnels: a uat.json without the contract shape fails before any tunnel"; else nok "tunnels: bad shape (rc=$rc)" "$out"; fi
t close "$work/nowhere"
if [ "$rc" -eq 0 ]; then ok "tunnels: close of a missing state dir is a no-op"; else nok "tunnels: close missing dir (rc=$rc)" "$out"; fi

new_case open
# Something already listens on the first port: open must skip it.
python3 -I -c 'import socket,sys,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(1); time.sleep(120)' "$base" &
blocker=$!
for _ in $(seq 50); do listening "$base" && break; sleep 0.1; done
t open "$uat" "$state"
if [ "$rc" -eq 0 ]; then ok "tunnels: open succeeds"; else nok "tunnels: open (rc=$rc)" "$out"; fi
a="$state/access.json"
if [ -f "$a" ] && jq -e . "$a" >/dev/null 2>&1; then ok "tunnels: writes access.json"; else nok "tunnels: access.json" "$out"; fi
if [ "$(jq -r 'keys | sort | join(",")' "$a")" = "t1-alma,t1-ubuntu,t1-win,t2-alma,t2-ubuntu,t2-win,uat-core,uat-dmz" ]; then
  ok "tunnels: access.json has every VM by name"
else nok "tunnels: VM names" "$(cat "$a")"; fi
if jq -e 'all(.[]; .host == "127.0.0.1")' "$a" >/dev/null; then ok "tunnels: every host is 127.0.0.1"; else nok "tunnels: hosts" "$(cat "$a")"; fi
if jq -e '[.["uat-dmz"], .["uat-core"]] | all(.ssh_port and .kube_port and (.winrm_port | not))' "$a" >/dev/null; then
  ok "tunnels: hubs get ssh_port and kube_port"
else nok "tunnels: hub ports" "$(cat "$a")"; fi
if jq -e '[.["t1-ubuntu"], .["t1-alma"], .["t2-ubuntu"], .["t2-alma"]] | all(.ssh_port and (.kube_port | not) and (.winrm_port | not))' "$a" >/dev/null; then
  ok "tunnels: Linux sprouts get ssh_port only"
else nok "tunnels: Linux sprout ports" "$(cat "$a")"; fi
if jq -e '[.["t1-win"], .["t2-win"]] | all(.winrm_port and (.ssh_port | not) and (.kube_port | not))' "$a" >/dev/null; then
  ok "tunnels: Windows sprouts get winrm_port only"
else nok "tunnels: Windows ports" "$(cat "$a")"; fi
ports=$(jq -r '[.[] | (.ssh_port, .kube_port, .winrm_port) | select(.)] | .[]' "$a")
if [ "$(printf '%s\n' "$ports" | wc -l)" -eq 10 ] && [ "$(printf '%s\n' "$ports" | sort -u | wc -l)" -eq 10 ]; then
  ok "tunnels: ten tunnels on distinct ports"
else nok "tunnels: distinct ports" "$ports"; fi
if ! printf '%s\n' "$ports" | grep -qx "$base"; then ok "tunnels: a port already in use is skipped"; else nok "tunnels: used port reused" "$ports"; fi
all_listen=1
for p in $ports; do listening "$p" || all_listen=0; done
if [ "$all_listen" = 1 ]; then ok "tunnels: every port accepts connections"; else nok "tunnels: ports not listening" "$ports"; fi
pids=$(jq -r '[.[].pids[]] | .[]' "$a")
alive=1
for p in $pids; do kill -0 "$p" 2>/dev/null || alive=0; done
if [ "$(printf '%s\n' "$pids" | wc -l)" -eq 10 ] && [ "$alive" = 1 ]; then ok "tunnels: access.json lists the ten live process ids"; else nok "tunnels: pids" "$pids"; fi
dmz_id=$(jq -r '.dmz.id' "$uat")
win_id=$(jq -r '.sprouts["t2-win"].id' "$uat")
if calls | grep -q -- "network bastion tunnel --name uat-bastion --resource-group imas-uat-abc123 --target-resource-id $dmz_id --resource-port 6443 --port $(jq '.["uat-dmz"].kube_port' "$a")"; then
  ok "tunnels: az bastion tunnel gets the bastion, group, VM id and ports"
else nok "tunnels: az arguments" "$(calls)"; fi
if calls | grep -q -- "--target-resource-id $win_id --resource-port 5986 "; then ok "tunnels: Windows tunnels target 5986"; else nok "tunnels: 5986" "$(calls)"; fi
if [ "$(calls | grep -c -- '--resource-port 22 ')" -eq 6 ]; then ok "tunnels: six SSH tunnels (two hubs, four Linux sprouts)"; else nok "tunnels: SSH count" "$(calls)"; fi
if [ -d "$state/logs" ] && [ "$(find "$state/logs" -name '*.log' | wc -l)" -eq 10 ]; then ok "tunnels: one log per tunnel"; else nok "tunnels: logs" "$(ls "$state/logs" 2>&1)"; fi

t open "$uat" "$state"
if [ "$rc" -ne 0 ] && [ -f "$a" ]; then ok "tunnels: a second open refuses while tunnels run, and keeps access.json"; else nok "tunnels: second open (rc=$rc)" "$out"; fi

t close "$state"
if [ "$rc" -eq 0 ]; then ok "tunnels: close succeeds"; else nok "tunnels: close (rc=$rc)" "$out"; fi
sleep 0.5
dead=1
for p in $pids; do running "$p" && dead=0; done
if [ "$dead" = 1 ]; then ok "tunnels: close stops every tunnel"; else nok "tunnels: tunnels survive close" "$pids"; fi
still=0
for p in $ports; do listening "$p" && still=1; done
if [ "$still" = 0 ]; then ok "tunnels: close stops the listeners (children) too"; else nok "tunnels: listeners survive close" "$ports"; fi
if [ ! -e "$a" ] && [ ! -e "$state/tunnels.pids" ]; then ok "tunnels: close removes access.json and tunnels.pids"; else nok "tunnels: files after close" "$(ls "$state")"; fi
t close "$state"
if [ "$rc" -eq 0 ]; then ok "tunnels: close is safe to repeat"; else nok "tunnels: second close (rc=$rc)" "$out"; fi
kill "$blocker" 2>/dev/null
blocker=""

new_case unrelated
mkdir -p "$state"
sleep 300 &
sleeper=$!
printf '%s\tt1-ubuntu\tssh\t1\n' "$sleeper" >"$state/tunnels.pids"
t close "$state"
if [ "$rc" -eq 0 ] && kill -0 "$sleeper" 2>/dev/null; then ok "tunnels: close never kills a process that is not a bastion tunnel"; else nok "tunnels: killed an unrelated pid (rc=$rc)" "$out"; fi
kill "$sleeper" 2>/dev/null
sleeper=""

new_case one_fails
jq -r '.sprouts["t2-alma"].id' "$uat" >"$STUB_STATE/fail_ids"
t open "$uat" "$state"
if [ "$rc" -ne 0 ] && [ ! -e "$state/access.json" ]; then ok "tunnels: one failed tunnel fails open, no access.json"; else nok "tunnels: failure (rc=$rc)" "$out"; fi
if printf '%s' "$out" | grep -q "stub tunnel failure"; then ok "tunnels: the failed tunnel's log is shown"; else nok "tunnels: failure log" "$out"; fi
sleep 0.5
if [ ! -e "$state/tunnels.pids" ] && ! pgrep -f "bastion tunnel .*--port $base" >/dev/null 2>&1; then
  ok "tunnels: a failed open stops what it started"
else nok "tunnels: leftovers after failed open" "$(pgrep -af 'bastion tunnel' 2>&1)"; fi

new_case retry
jq -r '.sprouts["t1-alma"].id' "$uat" >"$STUB_STATE/fail_once_ids"
t open "$uat" "$state"
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "t1-alma (ssh) exited; starting it again (attempt 2 of 3)" &&
  [ "$(calls | grep -c -- "--target-resource-id $(jq -r '.sprouts["t1-alma"].id' "$uat") ")" -ge 2 ]; then
  ok "tunnels: a tunnel that exits early is started again on a new port"
else nok "tunnels: retry (rc=$rc)" "$out"; fi
if [ "$rc" -eq 0 ] && [ "$(jq '[.[].pids[]] | length' "$state/access.json")" -eq 10 ] &&
  [ "$(wc -l <"$state/tunnels.pids")" -eq 10 ]; then
  ok "tunnels: after a retry, access.json and tunnels.pids list only the live tunnels"
else nok "tunnels: files after retry" "$(cat "$state/tunnels.pids" 2>&1)"; fi
t close "$state"
out=$(PATH="$stubs:$PATH" TUNNEL_START_ATTEMPTS=zero bash "$tunnels" open "$uat" "$state" 2>&1)
rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q TUNNEL_START_ATTEMPTS; then ok "tunnels: a bad TUNNEL_START_ATTEMPTS is refused"; else nok "tunnels: bad attempts (rc=$rc)" "$out"; fi

new_case no_banner
touch "$STUB_STATE/no_banner"
out=$(PATH="$stubs:$PATH" TUNNEL_PORT_BASE="$base" TUNNEL_WAIT_SECONDS=2 bash "$tunnels" open "$uat" "$state" 2>&1)
rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "not ready" && [ ! -e "$state/access.json" ]; then
  ok "tunnels: an SSH tunnel with no SSH banner times out and fails"
else nok "tunnels: no banner (rc=$rc)" "$out"; fi

new_case docker
jq '.sprouts |= with_entries(.value.connection = "docker")' "$uat" >"$work/docker.json"
t open "$work/docker.json" "$state"
if [ "$rc" -eq 0 ] && [ "$(jq -r 'keys | join(",")' "$state/access.json")" = "uat-core,uat-dmz" ]; then
  ok "tunnels: sprouts with connection docker get no tunnel"
else nok "tunnels: docker sprouts (rc=$rc)" "$out"; fi
t close "$state"

# An HA hub (P24, brief H2): SSH and kube tunnels to every node by its own
# id, and one kube tunnel per hub to its API address by IP.
new_case ha
jq '.sprouts |= with_entries(.value.connection = "docker")' "$uat_ha" >"$work/ha.json"
t open "$work/ha.json" "$state"
a="$state/access.json"
if [ "$rc" -eq 0 ] && [ "$(jq -r 'keys | join(",")' "$a")" = "core-api,dmz-api,uat-core-1,uat-core-2,uat-core-3,uat-dmz-1,uat-dmz-2,uat-dmz-3" ]; then
  ok "tunnels: an HA hub gets every node and its API address"
else nok "tunnels: HA keys (rc=$rc)" "$out $(cat "$a" 2>/dev/null)"; fi
if jq -e '[to_entries[] | select(.key | startswith("uat-")) | .value] | length == 6 and all(.ssh_port and .kube_port)' "$a" >/dev/null; then
  ok "tunnels: every HA node gets ssh_port and kube_port"
else nok "tunnels: HA node ports" "$(cat "$a")"; fi
if jq -e '[.["dmz-api"], .["core-api"]] | all(.kube_port and (.ssh_port | not) and (.pids | length) == 1)' "$a" >/dev/null; then
  ok "tunnels: the API address entries have kube_port only"
else nok "tunnels: API entries" "$(cat "$a")"; fi
if calls | grep -q -- "network bastion tunnel --name uat-bastion --resource-group imas-uat-abc123 --target-ip-address 10.60.1.250 --resource-port 6443 --port $(jq '.["dmz-api"].kube_port' "$a")" &&
  calls | grep -q -- "--target-ip-address 10.60.2.250 --resource-port 6443 --port $(jq '.["core-api"].kube_port' "$a")"; then
  ok "tunnels: the API tunnel targets the hub's api_address by IP"
else nok "tunnels: API tunnel arguments" "$(calls)"; fi
core3_id=$(jq -r '.core.node_ids[2]' "$uat_ha")
if calls | grep -q -- "--target-resource-id $core3_id --resource-port 22 --port $(jq '.["uat-core-3"].ssh_port' "$a")" &&
  calls | grep -q -- "--target-resource-id $core3_id --resource-port 6443 --port $(jq '.["uat-core-3"].kube_port' "$a")"; then
  ok "tunnels: each HA node's tunnels target that node's id"
else nok "tunnels: HA node ids" "$(calls)"; fi
if [ "$(calls | grep -c -- 'network bastion tunnel')" -eq 14 ]; then ok "tunnels: fourteen tunnels for 3 + 3 nodes"; else nok "tunnels: HA tunnel count" "$(calls)"; fi
t close "$state"

new_case ha_bad
jq '.dmz.api_address = "10.60.1.250; id"' "$uat_ha" >"$work/ha-bad.json"
t open "$work/ha-bad.json" "$state"
if [ "$rc" -ne 0 ] && ! calls | grep -q "bastion tunnel"; then ok "tunnels: a bad api_address fails before any tunnel"; else nok "tunnels: bad api_address (rc=$rc)" "$out"; fi
jq 'del(.core.api_address)' "$uat_ha" >"$work/ha-noapi.json"
t open "$work/ha-noapi.json" "$state"
if [ "$rc" -ne 0 ] && ! calls | grep -q "bastion tunnel"; then ok "tunnels: an HA hub without api_address fails before any tunnel"; else nok "tunnels: no api_address (rc=$rc)" "$out"; fi
jq '.dmz.node_ids |= .[:2]' "$uat_ha" >"$work/ha-ids.json"
t open "$work/ha-ids.json" "$state"
if [ "$rc" -ne 0 ] && ! calls | grep -q "bastion tunnel"; then ok "tunnels: node_names and node_ids of different lengths fail"; else nok "tunnels: node list lengths (rc=$rc)" "$out"; fi

# ------------------------------------------------------------------ vmctl.sh

new_case vargs
v
if [ "$rc" -eq 2 ]; then ok "vmctl: no arguments is a usage error (2)"; else nok "vmctl: no args (rc=$rc)" "$err"; fi
v "$uat" reboot t1-ubuntu
if [ "$rc" -eq 2 ]; then ok "vmctl: unknown action is a usage error"; else nok "vmctl: unknown action (rc=$rc)" "$err"; fi
v "$uat" run t1-ubuntu
if [ "$rc" -eq 2 ]; then ok "vmctl: run needs a command"; else nok "vmctl: run without command (rc=$rc)" "$err"; fi
v "$uat" restart t1-ubuntu extra
if [ "$rc" -eq 2 ]; then ok "vmctl: restart takes no command"; else nok "vmctl: restart extra (rc=$rc)" "$err"; fi
v "$uat" run t9-nothing true
if [ "$rc" -eq 2 ] && printf '%s' "$err" | grep -q "no VM named"; then ok "vmctl: unknown VM is refused"; else nok "vmctl: unknown VM (rc=$rc)" "$err"; fi
v "$work/missing.json" run t1-ubuntu true
if [ "$rc" -eq 2 ]; then ok "vmctl: unreadable uat.json is refused"; else nok "vmctl: missing uat.json (rc=$rc)" "$err"; fi
if ! calls | grep -q "^az"; then ok "vmctl: usage errors make no Azure call"; else nok "vmctl: Azure called on usage error" "$(calls)"; fi

new_case vrun
# shellcheck disable=SC2016 # expanded on the VM, not here
v "$uat" run t1-ubuntu 'echo hello "$((1+2))"; echo oops >&2; exit 3'
if [ "$rc" -eq 3 ]; then ok "vmctl: run exits with the command's exit code"; else nok "vmctl: run rc (rc=$rc)" "$err"; fi
if [ "$out" = "hello 3" ]; then ok "vmctl: run prints the command's stdout (marker removed)"; else nok "vmctl: run stdout" "$out"; fi
if printf '%s' "$err" | grep -q "^oops$" && printf '%s' "$err" | grep -q "exit_code=3"; then ok "vmctl: run prints stderr and the exit code"; else nok "vmctl: run stderr" "$err"; fi
t1u_id=$(jq -r '.sprouts["t1-ubuntu"].id' "$uat")
if calls | grep -q -- "^az vm run-command invoke --ids $t1u_id --command-id RunShellScript"; then ok "vmctl: Linux uses RunShellScript on the VM id"; else nok "vmctl: Linux command id" "$(calls)"; fi
v "$uat" run uat-core echo two words
if [ "$rc" -eq 0 ] && [ "$out" = "two words" ]; then ok "vmctl: run joins its arguments with spaces"; else nok "vmctl: run args (rc=$rc)" "$out $err"; fi
v "$uat" run uat-core "printf '%s\n' \"it's\" 'a \$HOME' | tr a-z A-Z"
if [ "$rc" -eq 0 ] && [ "$out" = "IT'S"$'\n'"A \$HOME" ]; then ok "vmctl: quotes, \$ and pipes reach the VM's shell intact"; else nok "vmctl: quoting (rc=$rc)" "$out $err"; fi

new_case vwin
echo 7 >"$STUB_STATE/win_rc"
v "$uat" run t2-win 'Get-Service imas-sprout; exit 7'
if [ "$rc" -eq 7 ] && [ "$out" = "win-out" ] && printf '%s' "$err" | grep -q "win-err"; then
  ok "vmctl: Windows run returns stdout, stderr and the exit code"
else nok "vmctl: Windows run (rc=$rc)" "out=$out err=$err"; fi
t2w_id=$(jq -r '.sprouts["t2-win"].id' "$uat")
if calls | grep -q -- "--ids $t2w_id --command-id RunPowerShellScript" && calls | grep -qxF "decoded: Get-Service imas-sprout; exit 7"; then
  ok "vmctl: Windows uses RunPowerShellScript and carries the command intact"
else nok "vmctl: Windows call" "$(calls)"; fi

new_case vnomarker
touch "$STUB_STATE/win_no_marker"
v "$uat" run t1-win 'hostname'
if [ "$rc" -eq 255 ]; then ok "vmctl: no exit code from Azure gives 255"; else nok "vmctl: missing marker (rc=$rc)" "$err"; fi
touch "$STUB_STATE/linux_no_marker"
v "$uat" run t1-alma 'echo x'
if [ "$rc" -eq 255 ]; then ok "vmctl: no exit code from a Linux run gives 255"; else nok "vmctl: Linux missing marker (rc=$rc)" "$err"; fi
touch "$STUB_STATE/runcmd_fail"
v "$uat" run t1-alma 'echo x'
if [ "$rc" -eq 255 ]; then ok "vmctl: a failed run-command gives 255"; else nok "vmctl: run-command failure (rc=$rc)" "$err"; fi

new_case vservice
v "$uat" stop-sprout t1-alma
if [ "$rc" -eq 0 ] && calls | grep -qx "systemctl stop imas-sprout"; then ok "vmctl: stop-sprout stops the imas-sprout unit"; else nok "vmctl: stop-sprout (rc=$rc)" "$(calls)"; fi
echo 5 >"$STUB_STATE/systemctl_rc"
v "$uat" start-sprout t2-ubuntu
if [ "$rc" -eq 5 ] && calls | grep -qx "systemctl start imas-sprout"; then ok "vmctl: start-sprout runs and returns systemctl's exit code"; else nok "vmctl: start-sprout (rc=$rc)" "$(calls)"; fi
v "$uat" stop-sprout t1-win
if [ "$rc" -eq 0 ] && calls | grep -qxF "decoded: Stop-Service -Name 'imas-sprout' -ErrorAction Stop"; then ok "vmctl: stop-sprout on Windows uses Stop-Service"; else nok "vmctl: Windows stop-sprout (rc=$rc)" "$(calls)"; fi
v "$uat" start-sprout t2-win
if [ "$rc" -eq 0 ] && calls | grep -qxF "decoded: Start-Service -Name 'imas-sprout' -ErrorAction Stop"; then ok "vmctl: start-sprout on Windows uses Start-Service"; else nok "vmctl: Windows start-sprout (rc=$rc)" "$(calls)"; fi
before=$(calls | wc -l)
v "$uat" stop-sprout uat-core
if [ "$rc" -eq 2 ] && [ "$(calls | wc -l)" -eq "$before" ]; then ok "vmctl: stop-sprout refuses a hub"; else nok "vmctl: stop-sprout on a hub (rc=$rc)" "$err"; fi

new_case vrestart
v "$uat" restart t2-alma
t2a_id=$(jq -r '.sprouts["t2-alma"].id' "$uat")
if [ "$rc" -eq 0 ] && calls | grep -q -- "^az vm restart --ids $t2a_id" && calls | grep -q "vm get-instance-view --ids $t2a_id.*PowerState" &&
  calls | grep -q "vm get-instance-view --ids $t2a_id.*vmAgent" && ! calls | grep -q "run-command"; then
  ok "vmctl: restart (no tunnel) waits for the power state, then the guest agent; no run-command"
else nok "vmctl: restart (rc=$rc)" "$(calls) $err"; fi
echo PowerState/stopped >"$STUB_STATE/power"
v "$uat" restart uat-dmz
if [ "$rc" -eq 255 ] && printf '%s' "$err" | grep -q "not running after"; then ok "vmctl: restart that never comes back gives 255"; else nok "vmctl: restart timeout (rc=$rc)" "$err"; fi
rm -f "$STUB_STATE/power"
echo 1 >"$STUB_STATE/restart_rc"
v "$uat" restart uat-dmz
if [ "$rc" -eq 0 ] && calls | grep -qx "reboot requested" && printf '%s' "$err" | grep -q "rebooting it through run-command instead"; then
  ok "vmctl: a failed az vm restart falls back to a reboot through run-command"
else nok "vmctl: restart fallback (rc=$rc)" "$(calls) $err"; fi
touch "$STUB_STATE/runcmd_fail"
v "$uat" restart uat-dmz
if [ "$rc" -eq 255 ] && printf '%s' "$err" | grep -q "the run-command reboot failed"; then ok "vmctl: a restart whose fallback fails too gives 255"; else nok "vmctl: restart failure (rc=$rc)" "$err"; fi
rm -f "$STUB_STATE/runcmd_fail" "$STUB_STATE/restart_rc"

# An HA hub (P24): every node is a VM vmctl knows, by its own id.
new_case vha
core2_id=$(jq -r '.core.node_ids[1]' "$uat_ha")
v "$uat_ha" restart uat-core-2
if [ "$rc" -eq 0 ] && calls | grep -qx -- "az vm restart --ids $core2_id -o none"; then ok "vmctl: restart of an HA node uses that node's id"; else nok "vmctl: HA node restart (rc=$rc)" "$(calls) $err"; fi
dmz3_id=$(jq -r '.dmz.node_ids[2]' "$uat_ha")
v "$uat_ha" run uat-dmz-3 echo on-node-3
if [ "$rc" -eq 0 ] && [ "$out" = "on-node-3" ] && calls | grep -q -- "--ids $dmz3_id --command-id RunShellScript"; then ok "vmctl: run on an HA node"; else nok "vmctl: HA node run (rc=$rc)" "$(calls) $err"; fi
before=$(calls | wc -l)
v "$uat_ha" stop-sprout uat-dmz-2
if [ "$rc" -eq 2 ] && [ "$(calls | wc -l)" -eq "$before" ]; then ok "vmctl: stop-sprout refuses an HA hub node"; else nok "vmctl: stop-sprout on an HA node (rc=$rc)" "$err"; fi
v "$uat_ha" run uat-dmz true
if [ "$rc" -eq 2 ] && printf '%s' "$err" | grep -q "no VM named"; then ok "vmctl: an HA hub has no VM named uat-dmz"; else nok "vmctl: uat-dmz on HA (rc=$rc)" "$err"; fi
v "$uat_ha" run t2-alma echo sprout
if [ "$rc" -eq 0 ] && [ "$out" = "sprout" ]; then ok "vmctl: sprouts still resolve with an HA uat.json"; else nok "vmctl: sprout on HA json (rc=$rc)" "$err"; fi

# stop-vm and start-vm (the ha tier's node stop): hub nodes only.
new_case vstopvm
core3_id=$(jq -r '.core.node_ids[2]' "$uat_ha")
v "$uat_ha" stop-vm uat-core-3
if [ "$rc" -eq 0 ] && calls | grep -qx -- "az vm stop --ids $core3_id -o none" && calls | grep -q "vm get-instance-view --ids $core3_id"; then
  ok "vmctl: stop-vm stops the node by its id and waits for PowerState/stopped"
else nok "vmctl: stop-vm (rc=$rc)" "$(calls) $err"; fi
v "$uat_ha" start-vm uat-core-3
if [ "$rc" -eq 0 ] && calls | grep -qx -- "az vm start --ids $core3_id -o none" && calls | grep -q "vm get-instance-view --ids $core3_id.*vmAgent" && printf '%s' "$err" | grep -q "is back"; then
  ok "vmctl: start-vm starts the node and waits until its guest answers"
else nok "vmctl: start-vm (rc=$rc)" "$(calls) $err"; fi
touch "$STUB_STATE/stop_noeffect"
v "$uat_ha" stop-vm uat-dmz-2
if [ "$rc" -eq 255 ] && printf '%s' "$err" | grep -q "not stopped after"; then ok "vmctl: a VM that does not stop gives 255"; else nok "vmctl: stop-vm timeout (rc=$rc)" "$err"; fi
rm -f "$STUB_STATE/stop_noeffect"
echo 1 >"$STUB_STATE/stop_rc"
v "$uat_ha" stop-vm uat-dmz-2
if [ "$rc" -eq 255 ] && printf '%s' "$err" | grep -q "az vm stop failed"; then ok "vmctl: a failed az vm stop gives 255"; else nok "vmctl: stop-vm failure (rc=$rc)" "$err"; fi
rm -f "$STUB_STATE/stop_rc"
before=$(calls | wc -l)
v "$uat_ha" stop-vm t1-ubuntu
if [ "$rc" -eq 2 ] && [ "$(calls | wc -l)" -eq "$before" ]; then ok "vmctl: stop-vm refuses a sprout VM"; else nok "vmctl: stop-vm on a sprout (rc=$rc)" "$err"; fi
v "$uat_ha" start-vm uat-dmz-1 extra
if [ "$rc" -eq 2 ]; then ok "vmctl: start-vm takes no command"; else nok "vmctl: start-vm usage (rc=$rc)" "$err"; fi

# An expired Azure login: with the relogin hook vmctl logs in again and
# repeats the call; without it the failure stays.
cat >"$work/relogin" <<'RELOGIN'
#!/usr/bin/env bash
echo relogin >>"$STUB_STATE/calls.log"
touch "$STUB_STATE/relogin_done"
RELOGIN
chmod +x "$work/relogin"
new_case vexpired
touch "$STUB_STATE/expired"
UAT_AZ_RELOGIN="$work/relogin" v "$uat" run t1-ubuntu 'echo after-relogin'
if [ "$rc" -eq 0 ] && [ "$out" = "after-relogin" ] && [ "$(calls | grep -c '^relogin$')" -eq 1 ]; then
  ok "vmctl: an expired login is renewed once and the call repeated"
else nok "vmctl: expired login with hook (rc=$rc)" "$(calls) $err"; fi
new_case vexpired2
touch "$STUB_STATE/expired"
v "$uat" run t1-ubuntu 'echo x'
if [ "$rc" -eq 255 ] && printf '%s' "$err" | grep -q AADSTS700024; then
  ok "vmctl: without the hook an expired login fails (255) and says why"
else nok "vmctl: expired login without hook (rc=$rc)" "$err"; fi

# ------------------------------------------- vmctl.sh over the tunnels (W8)
# access.json lists the Linux VMs' SSH ports and the Windows VMs' WinRM
# ports; t2-alma has no entry, so it falls back to run-command.
write_access() {
  jq -n '{"uat-core": {host: "127.0.0.1", ssh_port: 20102, kube_port: 20103},
          "t1-ubuntu": {host: "127.0.0.1", ssh_port: 20105},
          "t1-alma": {host: "127.0.0.1", ssh_port: 20104},
          "t1-win": {host: "127.0.0.1", winrm_port: 20106},
          "t2-win": {host: "127.0.0.1", winrm_port: 20109}}' >"$STUB_STATE/access.json"
  V_ACCESS=$STUB_STATE/access.json
}

new_case vssh
write_access
# shellcheck disable=SC2016 # expanded on the VM, not here
v "$uat" run t1-ubuntu 'echo hello "$((1+2))"; echo oops >&2; exit 3'
if [ "$rc" -eq 3 ] && [ "$out" = "hello 3" ] && printf '%s' "$err" | grep -q "^oops$" && printf '%s' "$err" | grep -q "vmctl.sh: exit_code=3"; then
  ok "vmctl: a Linux run over the SSH tunnel returns stdout, stderr and the exit code"
else nok "vmctl: ssh run (rc=$rc)" "out=$out err=$err"; fi
if calls | grep -q -- "^ssh -p 20105 -i $work/id_test .*HostKeyAlias=t1-ubuntu.* imasuat@127.0.0.1 " && ! calls | grep -q "^az"; then
  ok "vmctl: SSH goes to the tunnel's port as the admin user, by the VM's host key alias, and never to Azure"
else nok "vmctl: ssh arguments" "$(calls)"; fi
if printf '%s' "$err" | grep -q "t1-ubuntu: ran over ssh (127.0.0.1:20105) in"; then ok "vmctl: the channel and its time are logged"; else nok "vmctl: channel log" "$err"; fi
v "$uat" run uat-core "printf '%s\n' \"it's\" 'a \$HOME' | tr a-z A-Z; read -r x; echo \"stdin:\${x:-none}\""
if [ "$rc" -eq 0 ] && [ "$out" = "IT'S"$'\n'"A \$HOME"$'\n'"stdin:none" ] && calls | grep -q -- "^ssh -p 20102 "; then
  ok "vmctl: over SSH (a hub node too) quoting holds and the command's stdin is empty"
else nok "vmctl: ssh quoting (rc=$rc)" "$out $err"; fi
v "$uat" stop-sprout t1-alma
if [ "$rc" -eq 0 ] && calls | grep -qx "systemctl stop imas-sprout" && calls | grep -q -- "^ssh -p 20104 "; then
  ok "vmctl: stop-sprout goes over SSH"
else nok "vmctl: ssh stop-sprout (rc=$rc)" "$(calls) $err"; fi

new_case vfallback
write_access
v "$uat" run t2-alma 'echo via-azure'
if [ "$rc" -eq 0 ] && [ "$out" = "via-azure" ] && calls | grep -q "^az vm run-command invoke" && ! calls | grep -q "^ssh"; then
  ok "vmctl: a VM with no tunnel entry falls back to run-command"
else nok "vmctl: fallback (rc=$rc)" "$(calls) $err"; fi
: >"$STUB_STATE/calls.log"
V_KEY="" v "$uat" run t1-ubuntu 'echo no-key'
if [ "$rc" -eq 0 ] && [ "$out" = "no-key" ] && calls | grep -q "^az vm run-command" && printf '%s' "$err" | grep -q "VMCTL_SSH_KEY is not a readable file; using run-command"; then
  ok "vmctl: a tunnel without its key falls back to run-command, saying so"
else nok "vmctl: no key fallback (rc=$rc)" "$(calls) $err"; fi

new_case vwinrm
write_access
echo 7 >"$STUB_STATE/win_rc"
# Without the pool: a session per call, its shell closed after it.
VMCTL_WINRM_POOL=0 v "$uat" run t1-win 'Get-Service imas-sprout; exit 7'
if [ "$rc" -eq 7 ] && [ "$out" = "win-out" ] && printf '%s' "$err" | grep -q "^win-err" && ! calls | grep -q "^az"; then
  ok "vmctl: a Windows run over the WinRM tunnel returns stdout, stderr (CLIXML decoded) and the exit code"
else nok "vmctl: winrm run (rc=$rc)" "out=$out err=$err $(calls)"; fi
if calls | grep -qx "winrm endpoint=https://127.0.0.1:20106/wsman transport=ntlm user=imasuat password=set cert=ignore" &&
  calls | grep -qxF "winrm decoded: Get-Service imas-sprout; exit 7" && calls | grep -qx "winrm close_shell"; then
  ok "vmctl: WinRM is HTTPS with NTLM to the tunnel's port, carries the command intact and closes its shell"
else nok "vmctl: winrm call" "$(calls)"; fi
rm -f "$STUB_STATE/win_rc"
v "$uat" start-sprout t2-win
if [ "$rc" -eq 0 ] && calls | grep -qxF "winrm decoded: Start-Service -Name 'imas-sprout' -ErrorAction Stop"; then
  ok "vmctl: start-sprout on Windows goes over WinRM"
else nok "vmctl: winrm start-sprout (rc=$rc)" "$(calls) $err"; fi
# The pool (W10): one session and one shell per VM carries every call.
v "$uat" run t2-win 'hostname'
v "$uat" run t2-win 'whoami'
pool="$STUB_STATE/cm/winrm-t2-win.sock"
if [ "$rc" -eq 0 ] && [ "$(calls | grep -c '^winrm open_shell')" -eq 2 ] && calls | grep -qxF "winrm decoded: hostname" &&
  calls | grep -qxF "winrm decoded: whoami" && [ -S "$pool" ] && [ "$(stat -c %a "$STUB_STATE/cm")" = 700 ]; then
  ok "vmctl: Windows calls share one pooled WinRM session and shell per VM, on a private socket"
else nok "vmctl: winrm pool (rc=$rc)" "$(calls) $err"; fi
python3 "$here/../winrm_exec.py" --close-pool "$pool"
for _ in $(seq 50); do [ -S "$pool" ] || break; sleep 0.1; done
if [ ! -S "$pool" ] && [ "$(calls | grep -c '^winrm close_shell')" -eq 2 ]; then
  ok "vmctl: closing the pool (as a tunnel reopen does) closes its shell"
else nok "vmctl: winrm pool close" "$(calls)"; fi
touch "$STUB_STATE/winrm_open_fail"
VMCTL_WINRM_POOL=0 v "$uat" run t1-win 'hostname'
if [ "$rc" -eq 255 ] && [ "$(calls | grep -c '^winrm endpoint')" -eq 4 ] && printf '%s' "$err" | grep -q "retry 1 of 1" &&
  printf '%s' "$err" | grep -q "vmctl.sh: exit_code=255" && printf '%s' "$err" | grep -q "CHANNEL UNAVAILABLE"; then
  ok "vmctl: a WinRM shell that cannot open is retried once (nothing ran), then gives 255, channel unavailable"
else nok "vmctl: winrm open failure (rc=$rc)" "$(calls) $err"; fi
rm -f "$STUB_STATE/winrm_open_fail"
touch "$STUB_STATE/win_no_marker"
before=$(calls | grep -c '^winrm decoded: hostname')
v "$uat" run t2-win 'hostname'
if [ "$rc" -eq 255 ] && [ "$(calls | grep -c '^winrm decoded: hostname')" -eq $((before + 1)) ]; then
  ok "vmctl: a WinRM run with no exit code gives 255 and is not repeated"
else nok "vmctl: winrm no marker (rc=$rc)" "$(calls) $err"; fi

new_case vretry
write_access
echo 1 >"$STUB_STATE/ssh_preexec_fail"
v "$uat" run t1-ubuntu 'echo second-try'
if [ "$rc" -eq 0 ] && [ "$out" = "second-try" ] && [ "$(calls | grep -c '^ssh ')" -eq 2 ]; then
  ok "vmctl: an SSH connection refused before the command started is retried"
else nok "vmctl: ssh retry (rc=$rc)" "$(calls) $err"; fi
touch "$STUB_STATE/ssh_no_marker"
: >"$STUB_STATE/calls.log"
v "$uat" run t1-ubuntu 'echo once'
if [ "$rc" -eq 255 ] && [ "$(calls | grep -c '^ssh ')" -eq 1 ]; then
  ok "vmctl: an SSH run that may have run (no exit code) is not repeated"
else nok "vmctl: ssh no retry (rc=$rc)" "$(calls) $err"; fi
rm -f "$STUB_STATE/ssh_no_marker"
echo 2 >"$STUB_STATE/runcmd_conflict"
: >"$STUB_STATE/calls.log"
v "$uat" run t2-alma 'echo after-conflict'
if [ "$rc" -eq 0 ] && [ "$out" = "after-conflict" ] && [ "$(calls | grep -c '^az vm run-command invoke')" -eq 3 ] &&
  printf '%s' "$err" | grep -q "busy with an earlier command (Conflict); retry 2 of 4"; then
  ok "vmctl: a run-command refused with Conflict is retried with backoff"
else nok "vmctl: conflict retry (rc=$rc)" "$(calls) $err"; fi
echo always >"$STUB_STATE/runcmd_conflict"
: >"$STUB_STATE/calls.log"
VMCTL_CONFLICT_RETRIES=1 v "$uat" run t2-alma 'echo never'
if [ "$rc" -eq 255 ] && [ "$(calls | grep -c '^az vm run-command invoke')" -eq 2 ] && printf '%s' "$err" | grep -q "stayed busy (Conflict)"; then
  ok "vmctl: a run-command still in Conflict after the retries gives 255 and says so"
else nok "vmctl: conflict exhausted (rc=$rc)" "$(calls) $err"; fi

new_case vtimeout
write_access
touch "$STUB_STATE/ssh_hang"
start=$SECONDS
VMCTL_CALL_TIMEOUT=2 v "$uat" run t1-ubuntu 'echo never'
took=$((SECONDS - start))
sleep 0.5
if [ "$rc" -eq 255 ] && [ "$took" -lt 15 ] && printf '%s' "$err" | grep -q "timed out after 2s (VMCTL_CALL_TIMEOUT); killed" &&
  ! running "$(cat "$STUB_STATE/ssh.pid")"; then
  ok "vmctl: a stuck call is killed at VMCTL_CALL_TIMEOUT and gives 255 (took ${took}s)"
else nok "vmctl: call timeout (rc=$rc, ${took}s)" "$err"; fi
rm -f "$STUB_STATE/ssh_hang"
touch "$STUB_STATE/runcmd_hang"
start=$SECONDS
VMCTL_CALL_TIMEOUT=1 v "$uat" run t2-alma 'echo never'
took=$((SECONDS - start))
if [ "$rc" -eq 255 ] && [ "$took" -lt 25 ] && printf '%s' "$err" | grep -q "az vm run-command timed out after 1s"; then
  ok "vmctl: an az that ignores TERM is killed and still reported as a timeout (took ${took}s)"
else nok "vmctl: az killed after TERM (rc=$rc, ${took}s)" "$err"; fi
rm -f "$STUB_STATE/runcmd_hang"

# ------------------------------- vmctl.sh's channel recovery, over stub tunnels (W10)
# The tunnels are tunnels.sh's own (stub az listeners). stale.<port> makes
# one accept and hang, as UAT Run 2 #6's did ~20 minutes after opening;
# heal_on_reopen makes the tunnel tunnels.sh reopen-one starts healthy.
open_real() {
  t open "$uat" "$state"
  [ "$rc" -eq 0 ] || nok "open the stub tunnels (rc=$rc)" "$out"
  V_ACCESS=$state/access.json
}
port_of() { jq -r --arg vm "$1" --arg k "$2_port" '.[$vm][$k]' "$state/access.json"; }
pid_of() { awk -F'\t' -v vm="$1" -v k="$2" '$2 == vm && $3 == k { print $1 }' "$state/tunnels.pids"; }

new_case vrecover
open_real
p=$(port_of t1-ubuntu ssh)
old_pid=$(pid_of t1-ubuntu ssh)
mkdir -p "$STUB_STATE/login" && touch -d "-3 minutes" "$STUB_STATE/login/az-relogin.stamp"
touch "$STUB_STATE/heal_on_reopen" "$STUB_STATE/stale.$p"
VMCTL_DIAG_DIR="$STUB_STATE/diag" v "$uat" run t1-ubuntu 'echo healed'
if [ "$rc" -eq 0 ] && [ "$out" = healed ] && [ ! -e "$STUB_STATE/vmctl/t1-ubuntu.fails" ]; then
  ok "vmctl: a stale SSH tunnel is probed, reopened and the call retried: no strike"
else nok "vmctl: ssh recovery (rc=$rc)" "$err"; fi
if printf '%s' "$err" | grep -Eq "CHANNEL ERROR at [0-9T:-]+Z \(epoch [0-9]+\): vm=t1-ubuntu kind=ssh port=$p login_age=3m[0-9]{2}s tunnel_age=0m[0-9]{2}s probe=fail no SSH banner within 1s: ssh to t1-ubuntu .*banner exchange"; then
  ok "vmctl: the channel error line has the epoch, the VM, the port, both ages and the probe's verdict"
else nok "vmctl: channel error line" "$err"; fi
if [ "$(port_of t1-ubuntu ssh)" = "$p" ] && [ "$(pid_of t1-ubuntu ssh)" != "$old_pid" ] && [ ! -e "$STUB_STATE/stale.$p" ] &&
  printf '%s' "$err" | grep -q "after the reopen: ok SSH banner"; then
  ok "vmctl: the tunnel is reopened on the same port"
else nok "vmctl: reopen on the same port" "$(cat "$state/tunnels.pids") $err"; fi
cf=$(find "$STUB_STATE/diag/channel" -name '*-t1-ubuntu-ssh.txt' 2>/dev/null | head -n 1)
if [ -n "$cf" ] && grep -q "^CHANNEL ERROR" "$cf" && grep -q "== tunnel processes" "$cf" && grep -q "== listening TCP ports" "$cf" &&
  grep -q "^port $p:" "$cf" && grep -q "== the end of the t1-ubuntu ssh tunnel's log" "$cf"; then
  ok "vmctl: the channel's state is captured into diagnostics/channel before the recovery"
else nok "vmctl: channel capture" "$(ls -R "$STUB_STATE/diag" 2>&1)"; fi
for _ in $(seq 50); do
  vf=$(find "$STUB_STATE/diag/channel" -name '*-t1-ubuntu-vm-side.txt' -size +0 2>/dev/null | head -n 1)
  [ -n "$vf" ] && break
  sleep 0.1
done
if [ -n "$vf" ] && grep -q "VM side, through az vm run-command" "$vf" && calls | grep -q "vm run-command invoke --ids $(jq -r '.sprouts["t1-ubuntu"].id' "$uat") --command-id RunShellScript"; then
  ok "vmctl: the VM side of the channel is read through run-command, not the tunnel"
else nok "vmctl: VM side capture" "$(calls)"; fi
p=$(port_of t1-win winrm)
touch "$STUB_STATE/stale.$p"
v "$uat" run t1-win 'hostname'
if [ "$rc" -eq 0 ] && calls | grep -qxF "winrm decoded: hostname" &&
  printf '%s' "$err" | grep -q "vm=t1-win kind=winrm port=$p .*probe=fail no HTTPS answer on /wsman within 1s: WinRM to t1-win .*Read timed out" &&
  [ "$(port_of t1-win winrm)" = "$p" ]; then
  ok "vmctl: a stale WinRM tunnel (shell open read timeout) is reopened on its port and the call retried"
else nok "vmctl: winrm recovery (rc=$rc)" "$(calls) $err"; fi
rm -f "$STUB_STATE/heal_on_reopen"
touch "$STUB_STATE/ssh_no_marker"
: >"$STUB_STATE/calls.log"
v "$uat" run t1-ubuntu 'echo maybe'
if [ "$rc" -eq 255 ] && [ "$(calls | grep -c '^ssh -p')" -eq 1 ] && ! calls | grep -q "bastion tunnel" &&
  printf '%s' "$err" | grep -q "probe=ok SSH banner"; then
  ok "vmctl: a call that may have run is never repeated, and a tunnel that answers is not reopened"
else nok "vmctl: maybe-ran (rc=$rc)" "$(calls) $err"; fi
rm -f "$STUB_STATE/ssh_no_marker" "$STUB_STATE/vmctl/t1-ubuntu.fails"

# The dead mark: strikes, the fast failure, the re-probe and what clears it.
new_case vdead
open_real
p=$(port_of t1-alma ssh)
touch "$STUB_STATE/stale.$p"
for i in 1 2 3; do
  VMCTL_CONNECT_RETRIES=0 v "$uat" run t1-alma "echo try-$i"
done
if [ "$rc" -eq 255 ] && printf '%s' "$err" | grep -q "t1-alma is now marked dead: 3 channel failures in a row"; then
  ok "vmctl: three failures that the reopen did not mend mark the VM dead"
else nok "vmctl: dead mark (rc=$rc)" "$err"; fi
before=$(calls | grep -c '^ssh -p')
start=$SECONDS
v "$uat" run t1-alma 'echo fast'
if [ "$rc" -eq 255 ] && [ "$(calls | grep -c '^ssh -p')" -eq "$before" ] && [ $((SECONDS - start)) -lt 5 ] &&
  printf '%s' "$err" | grep -q "CHANNEL UNAVAILABLE: t1-alma is marked dead after 3 channel failures in a row (last .*banner exchange" &&
  printf '%s' "$err" | grep -q "next re-probe in" && printf '%s' "$err" | grep -q "vmctl.sh: exit_code=255"; then
  ok "vmctl: a dead VM fails at once, channel unavailable, naming the last failure, without touching the channel"
else nok "vmctl: dead fast fail (rc=$rc)" "$(calls) $err"; fi
v "$uat" run t1-ubuntu 'echo other-vm'
if [ "$rc" -eq 0 ] && [ "$out" = other-vm ]; then ok "vmctl: a dead mark is per VM"; else nok "vmctl: dead per VM (rc=$rc)" "$err"; fi
VMCTL_REPROBE_SECONDS=0 v "$uat" run t1-alma 'echo still-dead'
read -r _ _ probed <"$STUB_STATE/vmctl/t1-alma.fails"
if [ "$rc" -eq 255 ] && printf '%s' "$err" | grep -q "re-probing its ssh tunnel" && printf '%s' "$err" | grep -q "CHANNEL UNAVAILABLE" &&
  [ "${probed:-0}" -gt 0 ]; then
  ok "vmctl: a due re-probe that still fails keeps the mark and records when it probed"
else nok "vmctl: re-probe still dead (rc=$rc)" "$err"; fi
touch "$STUB_STATE/heal_on_reopen"
VMCTL_REPROBE_SECONDS=0 v "$uat" run t1-alma 'echo revived'
if [ "$rc" -eq 0 ] && [ "$out" = revived ] && [ ! -e "$STUB_STATE/vmctl/t1-alma.fails" ] && printf '%s' "$err" | grep -q "the dead mark is cleared"; then
  ok "vmctl: a re-probe whose reopened tunnel answers clears the mark, and the call runs"
else nok "vmctl: re-probe heals (rc=$rc)" "$err"; fi
rm -f "$STUB_STATE/heal_on_reopen"
touch "$STUB_STATE/stale.$p"
for i in 1 2 3; do VMCTL_CONNECT_RETRIES=0 v "$uat" run t1-alma "echo x"; done
touch "$STUB_STATE/heal_on_reopen"
v "$uat" restart t1-alma
if [ "$rc" -eq 0 ] && [ ! -e "$STUB_STATE/vmctl/t1-alma.fails" ]; then
  ok "vmctl: a restart that comes back clears a dead mark"
else nok "vmctl: restart clears dead (rc=$rc)" "$err"; fi

# Fresh before each command: a tunnel or login past REFRESH_AFTER.
new_case vfresh
open_real
p=$(port_of t1-ubuntu ssh)
old_pid=$(pid_of t1-ubuntu ssh)
alma_pid=$(pid_of t1-alma ssh)
echo $(($(date +%s) - 11 * 60)) >"$state/opened/t1-ubuntu-ssh"
v "$uat" run t1-ubuntu 'echo fresh'
if [ "$rc" -eq 0 ] && [ "$out" = fresh ] && printf '%s' "$err" | grep -q "its ssh tunnel is 11m0[0-9]s old (REFRESH_AFTER 10m); reopening it first" &&
  [ "$(pid_of t1-ubuntu ssh)" != "$old_pid" ] && [ "$(port_of t1-ubuntu ssh)" = "$p" ] &&
  [ $(($(date +%s) - $(cat "$state/opened/t1-ubuntu-ssh"))) -lt 60 ] && [ "$(pid_of t1-alma ssh)" = "$alma_pid" ]; then
  ok "vmctl: a tunnel past REFRESH_AFTER is reopened on its port before the command, and only that one"
else nok "vmctl: tunnel age (rc=$rc)" "$err"; fi
v "$uat" run t1-ubuntu 'echo young'
if [ "$rc" -eq 0 ] && ! printf '%s' "$err" | grep -q "reopening it first"; then ok "vmctl: a young tunnel is left alone"; else nok "vmctl: young tunnel" "$err"; fi
mkdir -p "$STUB_STATE/login" && touch -d "-11 minutes" "$STUB_STATE/login/az-relogin.stamp"
UAT_AZ_RELOGIN="$work/relogin" v "$uat" run t1-ubuntu 'echo relogged'
if [ "$rc" -eq 0 ] && calls | grep -qx relogin && printf '%s' "$err" | grep -q "the Azure login is 11m0[0-9]s old (REFRESH_AFTER 10m); logging in again first"; then
  ok "vmctl: a login past REFRESH_AFTER is renewed before the command"
else nok "vmctl: login age (rc=$rc)" "$(calls) $err"; fi
UAT_REFRESH_AFTER_MIN=0 v "$uat" run t1-ubuntu 'echo x'
if [ "$rc" -eq 2 ]; then ok "vmctl: a bad UAT_REFRESH_AFTER_MIN is a usage error"; else nok "vmctl: bad refresh knob (rc=$rc)" "$err"; fi

# The slots: a counting semaphore per VM, and the operations that take them all.
new_case vslots
open_real
# shellcheck disable=SC2016 # expanded on the "VM"
body='echo "start $$" >>"$STUB_STATE/order"; sleep 1; echo "end $$" >>"$STUB_STATE/order"'
max_overlap() { awk '$1 == "start" { n++; if (n > m) m = n } $1 == "end" { n-- } END { print m + 0 }' "$STUB_STATE/order"; }
for _ in 1 2 3 4 5; do VMCTL_SLOTS_LINUX=2 v "$uat" run t1-ubuntu "$body" & done
wait
if [ "$(max_overlap)" -eq 2 ] && [ "$(grep -c '^end' "$STUB_STATE/order")" -eq 5 ]; then
  ok "vmctl: calls to one VM run at most VMCTL_SLOTS_LINUX at a time"
else nok "vmctl: semaphore of 2" "$(cat "$STUB_STATE/order")"; fi
: >"$STUB_STATE/order"
for _ in 1 2 3 4 5; do v "$uat" run t1-ubuntu "$body" & done
wait
if [ "$(max_overlap)" -eq 4 ]; then ok "vmctl: a Linux VM has 4 slots by default"; else nok "vmctl: default Linux slots" "$(cat "$STUB_STATE/order")"; fi
# shellcheck disable=SC2016 # expanded on the "VM"
v "$uat" run t1-ubuntu 'sleep 2; echo body-end >>"$STUB_STATE/calls.log"' &
runner=$!
sleep 0.5
v "$uat" restart t1-ubuntu
wait "$runner"
body_at=$(calls | grep -n '^body-end$' | cut -d: -f1)
restart_at=$(calls | grep -n '^az vm restart' | cut -d: -f1)
if [ "$rc" -eq 0 ] && [ -n "$body_at" ] && [ -n "$restart_at" ] && [ "$body_at" -lt "$restart_at" ]; then
  ok "vmctl: a restart waits for the calls in flight (it takes every slot)"
else nok "vmctl: restart exclusive (rc=$rc)" "$(calls)"; fi
( flock 9; sleep 3 ) 9>>"$STUB_STATE/vmctl/t1-ubuntu.slot.0" &
holder=$!
sleep 0.5
start=$SECONDS
v "$uat" run t1-alma 'echo other-vm'
took=$((SECONDS - start))
VMCTL_SLOTS_LINUX=1 VMCTL_LOCK_WAIT_SECONDS=1 v "$uat" run t1-ubuntu 'echo never'
wait "$holder"
if [ "$rc" -eq 255 ] && printf '%s' "$err" | grep -q "held the slots of t1-ubuntu for 1s"; then
  ok "vmctl: slots held past VMCTL_LOCK_WAIT_SECONDS give 255 and say so"
else nok "vmctl: slot wait (rc=$rc)" "$err"; fi
if [ "$took" -lt 3 ]; then ok "vmctl: another VM is not held up by those slots (took ${took}s)"; else nok "vmctl: slots per VM (${took}s)"; fi
if calls | grep -q -- "ControlMaster=auto -o ControlPath=$STUB_STATE/cm/t1-ubuntu -o ControlPersist=300"; then
  ok "vmctl: SSH calls share one persistent master per VM"
else nok "vmctl: ssh master options" "$(calls | grep '^ssh' | head -n 2)"; fi

# The restart's wait: power state, then the probe, recreating the tunnel on
# each failed probe, then a command (UAT Run 2's Windows L1).
new_case vrestart_tunnel
open_real
v "$uat" restart t1-ubuntu
if [ "$rc" -eq 0 ] && calls | grep -q "^az vm restart" && calls | grep -q "PowerState" && calls | grep -q -- "^ssh -p $(port_of t1-ubuntu ssh) " &&
  ! calls | grep -q "run-command" && ! calls | grep -q "vmAgent"; then
  ok "vmctl: restart with a tunnel waits for the power state, then the probe and SSH; no run-command"
else nok "vmctl: restart over ssh (rc=$rc)" "$(calls) $err"; fi
p=$(port_of t2-win winrm)
touch "$STUB_STATE/heal_on_reopen" "$STUB_STATE/stale.$p"
v "$uat" restart t2-win
if [ "$rc" -eq 0 ] && printf '%s' "$err" | grep -q "probe: no HTTPS answer on /wsman within 1s; recreating its tunnel" &&
  calls | grep -qxF "winrm decoded: exit 0" && printf '%s' "$err" | grep -q "t2-win is back" && [ "$(port_of t2-win winrm)" = "$p" ] &&
  ! calls | grep -q "run-command"; then
  ok "vmctl: a Windows restart whose tunnel went stale recreates it on its port and comes back"
else nok "vmctl: restart recreates tunnel (rc=$rc)" "$(calls) $err"; fi
rm -f "$STUB_STATE/heal_on_reopen"
p=$(port_of t1-win winrm)
touch "$STUB_STATE/stale.$p"
VMCTL_RESTART_WAIT_SECONDS=2 v "$uat" restart t1-win
if [ "$rc" -eq 255 ] && printf '%s' "$err" | grep -q "t1-win is running; waiting for its guest" &&
  printf '%s' "$err" | grep -q "not back after 2s: running, but its guest does not answer over winrm (last: probe: no HTTPS answer on /wsman within 1s)"; then
  ok "vmctl: a restart whose guest never answers gives 255, naming the reason and the last probe error"
else nok "vmctl: restart guest timeout (rc=$rc)" "$err"; fi
rm -f "$STUB_STATE/stale.$p"
new_case vrestart_agent
V_ACCESS=""
echo "Ready 2000-01-01T00:00:00+00:00" >"$STUB_STATE/agent"
v "$uat" restart t2-alma
if [ "$rc" -eq 255 ] && printf '%s' "$err" | grep -q "guest agent 'Ready' at '2000-01-01"; then
  ok "vmctl: a guest agent status from before the restart does not count"
else nok "vmctl: stale agent (rc=$rc)" "$err"; fi
new_case vchannel
open_real
VMCTL_CHANNEL=runcommand v "$uat" run t1-ubuntu 'echo via-azure'
if [ "$rc" -eq 0 ] && [ "$out" = via-azure ] && calls | grep -q "^az vm run-command invoke" && ! calls | grep -q "^ssh -p"; then
  ok "vmctl: VMCTL_CHANNEL=runcommand goes past the tunnel"
else nok "vmctl: forced run-command (rc=$rc)" "$(calls) $err"; fi

# tunnels.sh reopen-one on its own.
new_case reopen_one
open_real
p=$(port_of t1-alma ssh)
old_pid=$(pid_of t1-alma ssh)
others=$(grep -v "	t1-alma	ssh	" "$state/tunnels.pids")
t reopen-one "$uat" "$state" t1-alma ssh
if [ "$rc" -eq 0 ] && [ "$(port_of t1-alma ssh)" = "$p" ] && [ "$(pid_of t1-alma ssh)" != "$old_pid" ] && ! running "$old_pid" &&
  [ "$(grep -v "	t1-alma	ssh	" "$state/tunnels.pids")" = "$others" ] &&
  jq -e --argjson pid "$(pid_of t1-alma ssh)" '.["t1-alma"].pids == [$pid]' "$state/access.json" >/dev/null; then
  ok "tunnels: reopen-one replaces one tunnel's process on the same port and leaves the others"
else nok "tunnels: reopen-one (rc=$rc)" "$out"; fi
if grep -q "^--- tunnels.sh reopen-one at .* on port $p (was pid $old_pid)" "$state/logs/t1-alma-ssh.log"; then
  ok "tunnels: reopen-one keeps the tunnel's earlier log lines"
else nok "tunnels: reopen-one log" "$(cat "$state/logs/t1-alma-ssh.log")"; fi
echo $(($(date +%s) - 600)) >"$state/opened/t1-ubuntu-ssh"
t reopen-one "$uat" "$state" t1-alma ssh
if [ "$(cat "$state/opened_at")" = "$(cat "$state/opened/t1-ubuntu-ssh")" ]; then ok "tunnels: opened_at is the oldest tunnel's"; else nok "tunnels: opened_at" "$(cat "$state/opened_at")"; fi
t reopen-one "$uat" "$state" t1-alma winrm
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "no winrm tunnel for t1-alma"; then ok "tunnels: reopen-one refuses a tunnel the VM does not have"; else nok "tunnels: reopen-one unknown (rc=$rc)" "$out"; fi
# Something else takes the port the moment the tunnel stops.
p_pid=$(pid_of t1-alma ssh)
kill -TERM -- "-$p_pid" 2>/dev/null
for _ in $(seq 50); do listening "$p" || break; sleep 0.1; done
python3 -I -c 'import socket,sys,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(16); s.settimeout(30); [s.accept()[0].close() for _ in iter(int, 1)]' "$p" &
blocker=$!
for _ in $(seq 50); do listening "$p" && break; sleep 0.1; done
t reopen-one "$uat" "$state" t1-alma ssh
kill "$blocker" 2>/dev/null
blocker=""
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "port $p is still taken after its tunnel stopped; not moving it" && [ "$(port_of t1-alma ssh)" = "$p" ]; then
  ok "tunnels: reopen-one never moves a tunnel to another port"
else nok "tunnels: reopen-one taken port (rc=$rc)" "$out"; fi
t close "$state"

# ------------------------------------------------------- tunnels.sh reopen

port_map() { jq -r 'to_entries[] | .key as $k | .value | to_entries[] | select(.key | endswith("_port")) | "\($k)/\(.key)=\(.value)"' "$1" | sort; }

new_case reopen
t open "$uat" "$state"
before_ports=$(port_map "$state/access.json")
before_pids=$(jq -r '[.[].pids[]] | sort | .[]' "$state/access.json")
if [ "$rc" -eq 0 ] && [ -s "$state/opened_at" ]; then ok "tunnels: open records opened_at"; else nok "tunnels: opened_at (rc=$rc)" "$(ls "$state")"; fi
t reopen "$uat" "$state"
after_pids=$(jq -r '[.[].pids[]] | sort | .[]' "$state/access.json" 2>/dev/null)
if [ "$rc" -eq 0 ] && [ "$(port_map "$state/access.json")" = "$before_ports" ]; then
  ok "tunnels: reopen keeps every tunnel on its port"
else nok "tunnels: reopen ports (rc=$rc)" "$out"; fi
gone=1
for p in $before_pids; do running "$p" && gone=0; done
if [ "$gone" = 1 ] && [ -n "$after_pids" ] && [ "$after_pids" != "$before_pids" ]; then
  ok "tunnels: reopen stops the old processes and starts new ones"
else nok "tunnels: reopen processes" "before $before_pids after $after_pids"; fi
if [ "$(calls | grep -c 'network bastion tunnel')" -eq 20 ]; then ok "tunnels: reopen starts every tunnel again"; else nok "tunnels: reopen tunnel count" "$(calls)"; fi
# One tunnel's first start fails (as when its old port was taken): it comes
# back on a new port and reopen says so.
core_id=$(jq -r '.core.id' "$uat")
echo "$core_id:6443" >"$STUB_STATE/fail_once_keys"
t reopen "$uat" "$state"
changed=$(diff <(printf '%s\n' "$before_ports") <(port_map "$state/access.json") | grep -c '^>')
if [ "$rc" -eq 0 ] && [ "$changed" -eq 1 ] && printf '%s' "$out" | grep -q "uat-core kube: port changed from" &&
  ! printf '%s' "$out" | grep -q "uat-core ssh: port changed"; then
  ok "tunnels: reopen moves a tunnel whose port is taken and names the change"
else nok "tunnels: reopen with a taken port (rc=$rc, changed=$changed)" "$out"; fi
t close "$state"
if [ ! -e "$state/opened_at" ]; then ok "tunnels: close removes opened_at"; else nok "tunnels: opened_at after close" "$(ls "$state")"; fi

# --------------------------------------------------------------- session.sh

# The login stub: records whether the old tunnels were still open when it
# ran, so the order login, close, open shows in calls.log.
cat >"$work/srelogin" <<'RELOGIN'
#!/usr/bin/env bash
if [ -f "$STUB_STATE/relogin_fail" ]; then echo "stub login failure" >&2; exit 1; fi
if [ -s "$UAT_SESSION_ACCESS/access.json" ]; then echo "relogin tunnels=open" >>"$STUB_STATE/calls.log"
else echo "relogin tunnels=none" >>"$STUB_STATE/calls.log"; fi
RELOGIN
chmod +x "$work/srelogin"

s() { # s <args>: session.sh with the stubs; sets rc, out
  out=$(PATH="$stubs:$PATH" TUNNEL_PORT_BASE="$base" TUNNEL_WAIT_SECONDS=30 \
    AZ_RELOGIN_DIR="$STUB_STATE/login" UAT_SESSION_UAT="${S_UAT:-$uat}" UAT_SESSION_ACCESS="$state" \
    UAT_SESSION_RELOGIN="$work/srelogin" SSH_KEYSCAN="$stubs/ssh-keyscan" CURL="$stubs/curl" \
    bash "$session" "$@" 2>&1)
  rc=$?
}
login_minutes_ago() { mkdir -p "$STUB_STATE/login"; touch -d "-$1 minutes" "$STUB_STATE/login/az-relogin.stamp"; }
tunnels_minutes_ago() { echo $(($(date +%s) - $1 * 60)) >"$state/opened_at"; }

new_case sargs
s
if [ "$rc" -eq 2 ]; then ok "session: no arguments is a usage error (2)"; else nok "session: no args (rc=$rc)" "$out"; fi
s phase x --bogus
if [ "$rc" -eq 2 ]; then ok "session: an unknown option is a usage error"; else nok "session: bad option (rc=$rc)" "$out"; fi
UAT_SESSION_MAX_AGE_MIN=0 s ages x
if [ "$rc" -eq 2 ]; then ok "session: a bad age limit is a usage error"; else nok "session: bad limit (rc=$rc)" "$out"; fi
s mark-login
if [ "$rc" -eq 0 ] && [ -f "$STUB_STATE/login/az-relogin.stamp" ]; then ok "session: mark-login records the login"; else nok "session: mark-login (rc=$rc)" "$out"; fi

new_case srefresh
t open "$uat" "$state"
before_ports=$(port_map "$state/access.json")
login_minutes_ago 50
tunnels_minutes_ago 30
s refresh
if [ "$rc" -eq 0 ] && [ "$(port_map "$state/access.json")" = "$before_ports" ]; then
  ok "session: refresh reopens the tunnels on their ports"
else nok "session: refresh (rc=$rc)" "$out"; fi
first_new=$(calls | grep -n 'network bastion tunnel' | sed -n 11p | cut -d: -f1)
relogin_at=$(calls | grep -n '^relogin' | cut -d: -f1)
if calls | grep -qx 'relogin tunnels=open' && [ -n "$first_new" ] && [ "${relogin_at:-0}" -lt "$first_new" ] &&
  [ "$(calls | grep -c 'network bastion tunnel')" -eq 20 ]; then
  ok "session: refresh logs in first, then closes and opens the tunnels"
else nok "session: refresh order" "$(calls)"; fi
if printf '%s' "$out" | grep -q 'refresh: .*azure login age 50m, tunnels age 30m; logging in again' &&
  printf '%s' "$out" | grep -q 'refresh: done; azure login age 0m, tunnels age 0m'; then
  ok "session: refresh names both ages before and after"
else nok "session: refresh messages" "$out"; fi

# A kube port that changes is carried into the kubeconfigs.
kc="$STUB_STATE/core.kubeconfig"
old_kube=$(jq '.["uat-core"].kube_port' "$state/access.json")
dmz_kube=$(jq '.["uat-dmz"].kube_port' "$state/access.json")
printf 'apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:%s\n  name: core\n- cluster:\n    server: https://127.0.0.1:%s\n  name: dmz\n' "$old_kube" "$dmz_kube" >"$kc"
echo "$core_id:6443" >"$STUB_STATE/fail_once_keys"
rm -f "$STUB_STATE"/failed_once.*
UAT_SESSION_KUBECONFIGS="$STUB_STATE/missing.kubeconfig:$kc" s refresh
new_kube=$(jq '.["uat-core"].kube_port' "$state/access.json")
if [ "$rc" -eq 0 ] && [ "$new_kube" != "$old_kube" ] && grep -qx "    server: https://127.0.0.1:$new_kube" "$kc" &&
  grep -qx "    server: https://127.0.0.1:$dmz_kube" "$kc" && [ "$(stat -c %a "$kc")" = 600 ]; then
  ok "session: a changed kube port is rewritten in the kubeconfigs, the others kept"
else nok "session: kubeconfig remap (rc=$rc, $old_kube -> $new_kube)" "$out $(cat "$kc")"; fi
rm -f "$STUB_STATE/fail_once_keys"

# phase: refreshes when due, then the guard.
: >"$STUB_STATE/calls.log"
login_minutes_ago 5
tunnels_minutes_ago 5
s phase "core hub"
if [ "$rc" -eq 0 ] && ! calls | grep -q relogin && printf '%s' "$out" | grep -q 'core hub: azure login age 5m, tunnels age 5m'; then
  ok "session: phase logs both ages and does not refresh young ones"
else nok "session: phase young (rc=$rc)" "$out $(calls)"; fi
login_minutes_ago 20
s phase "dmz hub"
if [ "$rc" -eq 0 ] && calls | grep -qx 'relogin tunnels=open' && printf '%s' "$out" | grep -q 'dmz hub: azure login age 0m, tunnels age 0m'; then
  ok "session: phase refreshes a login past UAT_SESSION_REFRESH_AFTER_MIN"
else nok "session: phase refresh by login age (rc=$rc)" "$out"; fi
: >"$STUB_STATE/calls.log"
tunnels_minutes_ago 16
s phase "finish"
if [ "$rc" -eq 0 ] && calls | grep -q '^relogin' && [ "$(calls | grep -c 'network bastion tunnel')" -eq 10 ]; then
  ok "session: phase refreshes tunnels past UAT_SESSION_REFRESH_AFTER_MIN"
else nok "session: phase refresh by tunnel age (rc=$rc)" "$out"; fi
: >"$STUB_STATE/calls.log"
s phase "enrolment" --force
if [ "$rc" -eq 0 ] && calls | grep -q '^relogin'; then ok "session: --force refreshes young ones too"; else nok "session: --force (rc=$rc)" "$out"; fi

# The guard: with refresh out of reach (REFRESH_AFTER above the limit), a
# phase at the limit starts and one past it is refused, naming both ages.
login_minutes_ago 39
tunnels_minutes_ago 20
UAT_SESSION_REFRESH_AFTER_MIN=90 s phase "tests"
if [ "$rc" -eq 0 ]; then ok "session: the guard lets a 39m login through (limit 40m)"; else nok "session: guard under limit (rc=$rc)" "$out"; fi
login_minutes_ago 41
UAT_SESSION_REFRESH_AFTER_MIN=90 s phase "tests"
if [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q "tests: refusing to start: azure login age 41m, tunnels age 20m; the limit is 40m"; then
  ok "session: the guard refuses a login past the limit and names both ages"
else nok "session: guard login (rc=$rc)" "$out"; fi
login_minutes_ago 1
tunnels_minutes_ago 45
UAT_SESSION_REFRESH_AFTER_MIN=90 s phase "tests"
if [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q "tests: refusing to start: azure login age 1m, tunnels age 45m"; then
  ok "session: the guard refuses tunnels past the limit"
else nok "session: guard tunnels (rc=$rc)" "$out"; fi
UAT_SESSION_MAX_AGE_MIN=30 UAT_SESSION_REFRESH_AFTER_MIN=90 s phase "tests"
if [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q "the limit is 30m"; then ok "session: UAT_SESSION_MAX_AGE_MIN sets the limit"; else nok "session: limit env (rc=$rc)" "$out"; fi

# A failed login fails the phase before any tunnel is touched.
touch "$STUB_STATE/relogin_fail"
pids_before=$(cat "$state/tunnels.pids")
s phase "tests" --force
if [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q "the Azure login failed" && [ "$(cat "$state/tunnels.pids")" = "$pids_before" ]; then
  ok "session: a failed login fails the phase and leaves the tunnels alone"
else nok "session: failed login (rc=$rc)" "$out"; fi
rm -f "$STUB_STATE/relogin_fail"

# probe
tunnels_minutes_ago 3
login_minutes_ago 3
: >"$STUB_STATE/probes.log"
s phase "enrolment" --probe
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "enrolment: probe: all 10 tunnels answer" &&
  [ "$(grep -c '^ssh-keyscan -T 15 -p [0-9]* 127.0.0.1$' "$STUB_STATE/probes.log")" -eq 6 ] &&
  grep -q -- "-sk -m 20 -o /dev/null -w %{http_code} https://127.0.0.1:$(jq '.["t1-win"].winrm_port' "$state/access.json")/wsman" "$STUB_STATE/probes.log" &&
  grep -q "https://127.0.0.1:$(jq '.["uat-core"].kube_port' "$state/access.json")/version" "$STUB_STATE/probes.log"; then
  ok "session: probe checks every tunnel (ssh-keyscan, /wsman, /version)"
else nok "session: probe (rc=$rc)" "$out $(cat "$STUB_STATE/probes.log")"; fi
win_port=$(jq '.["t1-win"].winrm_port' "$state/access.json")
lin_port=$(jq '.["t2-alma"].ssh_port' "$state/access.json")
printf '%s\n%s\n' "$win_port" "$lin_port" >"$STUB_STATE/dead_ports"
s probe "tests"
if [ "$rc" -eq 1 ] &&
  printf '%s' "$out" | grep -q "tests: probe FAILED: t1-win winrm tunnel (127.0.0.1:$win_port) is stale or dead: no HTTPS answer on /wsman within 20s; tunnel age 3m, azure login age 3m, tunnels age 3m" &&
  printf '%s' "$out" | grep -q "tests: probe FAILED: t2-alma ssh tunnel (127.0.0.1:$lin_port) is stale or dead: no SSH host key within 15s" &&
  printf '%s' "$out" | grep -q "tests: 2 of 10 tunnels did not answer"; then
  ok "session: a dead tunnel fails the probe, naming the tunnel, its port and both ages"
else nok "session: probe failure (rc=$rc)" "$out"; fi
rm -f "$STUB_STATE/dead_ports"
echo 500 >"$STUB_STATE/wsman_code"
s probe "tests"
if [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q "HTTP 500 on /wsman (expected 401 or 405)"; then ok "session: a WinRM answer other than 401 or 405 fails"; else nok "session: wsman 500 (rc=$rc)" "$out"; fi
echo 405 >"$STUB_STATE/wsman_code"
s probe "tests"
if [ "$rc" -eq 0 ]; then ok "session: HTTP 405 on /wsman is alive"; else nok "session: wsman 405 (rc=$rc)" "$out"; fi
rm -f "$STUB_STATE/wsman_code"

# ages: the failure-time diagnostic, never failing.
s ages "failure"
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "failure: azure login age 3m, tunnels age 3m" &&
  printf '%s' "$out" | grep -q "failure: tunnel t1-win winrm on 127.0.0.1:$win_port: process [0-9]* running" &&
  printf '%s' "$out" | grep -q "Opening tunnel on port: $win_port"; then
  ok "session: ages prints both ages, each tunnel's process and its log"
else nok "session: ages (rc=$rc)" "$out"; fi
t close "$state"
s ages "failure"
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "failure: azure login age 3m, tunnels age unknown (not open)"; then
  ok "session: ages after close says the tunnels are not open"
else nok "session: ages after close (rc=$rc)" "$out"; fi
s probe "tests"
if [ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q "the tunnels are not open"; then ok "session: probe without tunnels fails"; else nok "session: probe closed (rc=$rc)" "$out"; fi

# --no-tunnels: the login only, no access directory needed.
: >"$STUB_STATE/calls.log"
login_minutes_ago 200
out=$(PATH="$stubs:$PATH" AZ_RELOGIN_DIR="$STUB_STATE/login" UAT_SESSION_RELOGIN="$work/srelogin" UAT_SESSION_ACCESS="$state" \
  bash "$session" phase destroy --no-tunnels 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && calls | grep -q '^relogin' && ! calls | grep -q 'bastion tunnel' &&
  printf '%s' "$out" | grep -q "destroy: azure login age 0m, tunnels age unknown (not open)"; then
  ok "session: --no-tunnels logs in again and opens no tunnel"
else nok "session: --no-tunnels (rc=$rc)" "$out $(calls)"; fi
out=$(PATH="$stubs:$PATH" AZ_RELOGIN_DIR="$STUB_STATE/login" UAT_SESSION_RELOGIN="$work/srelogin" \
  bash "$session" phase kept --no-tunnels 2>&1)
rc=$?
if [ "$rc" -eq 0 ]; then ok "session: --no-tunnels needs no UAT_SESSION_ACCESS"; else nok "session: --no-tunnels without access (rc=$rc)" "$out"; fi
out=$(PATH="$stubs:$PATH" AZ_RELOGIN_DIR="$STUB_STATE/login" UAT_SESSION_RELOGIN="$work/srelogin" \
  bash "$session" phase k0s 2>&1)
rc=$?
if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -q "UAT_SESSION_ACCESS is not set"; then ok "session: a tunnel phase needs UAT_SESSION_ACCESS"; else nok "session: missing access (rc=$rc)" "$out"; fi

# An HA uat.json: the API tunnels by IP are probed and reopened too.
new_case sha
S_UAT=$uat_ha
t open "$uat_ha" "$state"
before_ports=$(port_map "$state/access.json")
login_minutes_ago 1
S_UAT=$uat_ha s phase "tests" --force --probe
if [ "$rc" -eq 0 ] && [ "$(port_map "$state/access.json")" = "$before_ports" ] &&
  printf '%s' "$out" | grep -q "tests: probe: core-api kube tunnel"; then
  ok "session: an HA run's tunnels (API addresses too) reopen on their ports and are probed"
else nok "session: HA (rc=$rc)" "$out"; fi
t close "$state"
unset S_UAT

# ------------------------------------------------- session.sh supervise (W10)
sv() { # sv <args>: session.sh with the stubs and fast probes; sets rc, out
  out=$(PATH="$stubs:$PATH" TUNNEL_PORT_BASE="$base" TUNNEL_WAIT_SECONDS=30 \
    AZ_RELOGIN_DIR="$STUB_STATE/login" UAT_SESSION_UAT="${S_UAT:-$uat}" UAT_SESSION_ACCESS="$state" \
    UAT_SESSION_RELOGIN="$work/srelogin" SSH_KEYSCAN="$stubs/ssh-keyscan" CURL="$stubs/curl" \
    UAT_PROBE_SSH_SECONDS=1 UAT_PROBE_HTTPS_SECONDS=1 UAT_SUPERVISE_WAIT_SECONDS=1 CH_REOPEN_WAIT_SECONDS=2 \
    VMCTL_SSH_CONTROL_DIR="$STUB_STATE/cm" bash "$session" "$@" 2>&1)
  rc=$?
}
spid_of() { awk -F'\t' -v vm="$1" -v k="$2" '$2 == vm && $3 == k { print $1 }' "$state/tunnels.pids"; }
sport_of() { jq -r --arg vm "$1" --arg k "$2_port" '.[$vm][$k]' "$state/access.json"; }
all_pids() { awk -F'\t' '{ print $2 "/" $3 "=" $1 }' "$state/tunnels.pids" | sort; }

new_case ssup
t open "$uat" "$state"
login_minutes_ago 2
before_ports=$(port_map "$state/access.json")
before=$(all_pids)
sv supervise tick
if [ "$rc" -eq 0 ] && [ "$(all_pids)" = "$before" ] && ! calls | grep -q '^relogin'; then
  ok "supervise: a round leaves a young login and young, answering tunnels alone"
else nok "supervise: quiet round (rc=$rc)" "$out"; fi
# Two tunnels past REFRESH_AFTER: both reopened, one at a time, oldest first,
# on their ports; the others untouched.
echo $(($(date +%s) - 12 * 60)) >"$state/opened/t1-win-winrm"
echo $(($(date +%s) - 14 * 60)) >"$state/opened/uat-core-kube"
u_pid=$(spid_of t1-ubuntu ssh)
sv supervise tick
first=$(printf '%s\n' "$out" | grep -n 'reopening it$' | head -n 1)
if [ "$rc" -eq 0 ] && [ "$(port_map "$state/access.json")" = "$before_ports" ] &&
  [ "$(printf '%s\n' "$out" | grep -c 'reopening it$')" -eq 2 ] && [[ "$first" == *"uat-core kube tunnel"*"age 14m"* ]] &&
  printf '%s' "$out" | grep -q "t1-win winrm tunnel reopened on 127.0.0.1:$(sport_of t1-win winrm): ok HTTP 401 on /wsman" &&
  [ "$(spid_of t1-ubuntu ssh)" = "$u_pid" ]; then
  ok "supervise: tunnels past REFRESH_AFTER are reopened one at a time, oldest first, on their ports"
else nok "supervise: age round (rc=$rc)" "$out"; fi
if printf '%s' "$out" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z session.sh: '; then ok "supervise: its lines carry the UTC time"; else nok "supervise: timestamps" "$out"; fi
# A tunnel that hangs (probe fails) is reopened; heal_on_reopen mends it.
p=$(sport_of t1-alma ssh)
touch "$STUB_STATE/heal_on_reopen" "$STUB_STATE/stale.$p"
a_pid=$(spid_of t1-alma ssh)
sv supervise tick
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "t1-alma ssh tunnel (127.0.0.1:$p): probe: no SSH banner within 1s; reopening it" &&
  [ "$(spid_of t1-alma ssh)" != "$a_pid" ] && [ "$(sport_of t1-alma ssh)" = "$p" ]; then
  ok "supervise: a tunnel whose probe fails is reopened on its port"
else nok "supervise: probe round (rc=$rc)" "$out"; fi
# Never under a running command: a VM whose slots are held is left for the
# next round; a kube tunnel with a connection open is left too.
mkdir -p "$state/vmctl"
echo $(($(date +%s) - 12 * 60)) >"$state/opened/t1-ubuntu-ssh"
( flock 9; sleep 4 ) 9>>"$state/vmctl/t1-ubuntu.slot.2" &
holder=$!
sleep 0.3
u_pid=$(spid_of t1-ubuntu ssh)
sv supervise tick
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q "t1-ubuntu ssh tunnel (127.0.0.1:.*): its VM's slots stayed busy for 1s; leaving it for the next round" &&
  [ "$(spid_of t1-ubuntu ssh)" = "$u_pid" ]; then
  ok "supervise: a tunnel whose VM has a call in flight is not reopened under it"
else nok "supervise: busy slots (rc=$rc)" "$out"; fi
wait "$holder"
sv supervise tick
if [ "$(spid_of t1-ubuntu ssh)" != "$u_pid" ]; then ok "supervise: the next round reopens it once the call is done"; else nok "supervise: later round" "$out"; fi
kp=$(sport_of uat-dmz kube)
echo $(($(date +%s) - 12 * 60)) >"$state/opened/uat-dmz-kube"
python3 -I -c 'import socket,sys,time; c=socket.create_connection(("127.0.0.1", int(sys.argv[1]))); time.sleep(4)' "$kp" &
conn=$!
sleep 0.3
k_pid=$(spid_of uat-dmz kube)
# ss sees the connection only on Linux with iproute2; skip the check without it.
if command -v ss >/dev/null 2>&1; then
  sv supervise tick
  if printf '%s' "$out" | grep -q "uat-dmz kube tunnel (127.0.0.1:$kp): 1 connections still open after 1s; leaving it for the next round" &&
    [ "$(spid_of uat-dmz kube)" = "$k_pid" ]; then
    ok "supervise: a kube tunnel with a connection open (kubectl, a port-forward) is not cut"
  else nok "supervise: kube drain (rc=$rc)" "$out"; fi
fi
kill "$conn" 2>/dev/null
wait "$conn" 2>/dev/null
# Dead marks: re-probed, un-marked when the tunnel answers; refresh clears all.
now=$(date +%s)
printf '3 %s 0\nssh to t1-alma: banner exchange\n' $((now - 300)) >"$state/vmctl/t1-alma.fails"
printf '3 %s 0\nWinRM to t1-win: Read timed out\n' $((now - 30)) >"$state/vmctl/t1-win.fails"
sv supervise tick
if [ ! -e "$state/vmctl/t1-alma.fails" ] && printf '%s' "$out" | grep -q "t1-alma was marked dead (3 channel failures; last: ssh to t1-alma: banner exchange); its ssh tunnel answers (ok SSH banner): un-marked" &&
  [ -e "$state/vmctl/t1-win.fails" ]; then
  ok "supervise: a dead VM is re-probed after VMCTL_REPROBE_SECONDS and un-marked when its tunnel answers; a fresh mark waits"
else nok "supervise: dead re-probe (rc=$rc)" "$out"; fi
rm -f "$STUB_STATE/heal_on_reopen"
p=$(sport_of t2-alma ssh)
touch "$STUB_STATE/stale.$p"
printf '3 %s 0\nssh to t2-alma: banner exchange\n' $((now - 300)) >"$state/vmctl/t2-alma.fails"
UAT_SUPERVISE_PROBE=0 sv supervise tick
read -r _ _ probed <"$state/vmctl/t2-alma.fails"
if printf '%s' "$out" | grep -q "t2-alma is marked dead and its ssh tunnel does not answer" && printf '%s' "$out" | grep -q "t2-alma stays marked dead" &&
  [ "${probed:-0}" -ge "$now" ]; then
  ok "supervise: a dead VM whose reopened tunnel still hangs stays marked, with its re-probe time"
else nok "supervise: still dead (rc=$rc)" "$out"; fi
rm -f "$STUB_STATE/stale.$p"
login_minutes_ago 11
sv supervise tick
if calls | grep -q '^relogin' && printf '%s' "$out" | grep -q "azure login age 11m.* (REFRESH_AFTER 10m); logging in again"; then
  ok "supervise: a login past REFRESH_AFTER is renewed"
else nok "supervise: relogin (rc=$rc)" "$out"; fi
sv refresh
if [ "$rc" -eq 0 ] && ! ls "$state/vmctl/"*.fails >/dev/null 2>&1 && [ ! -e "$state/supervisor.pause" ]; then
  ok "session: a refresh clears every dead mark"
else nok "session: refresh clears marks (rc=$rc)" "$out $(ls "$state/vmctl")"; fi
touch "$state/supervisor.pause"
sv supervise tick
if printf '%s' "$out" | grep -q "a full refresh is running; skipping this round"; then ok "supervise: a round waits out a full refresh"; else nok "supervise: pause" "$out"; fi
rm -f "$state/supervisor.pause"
# ensure kube: the harness's check before kubectl.
echo $(($(date +%s) - 12 * 60)) >"$state/opened/uat-core-kube"
k_pid=$(spid_of uat-core kube)
sv ensure kube
if [ "$rc" -eq 0 ] && [ "$(spid_of uat-core kube)" != "$k_pid" ] && printf '%s' "$out" | grep -q "uat-core kube tunnel: age 12m"; then
  ok "session: ensure kube reopens a kube tunnel past REFRESH_AFTER"
else nok "session: ensure kube (rc=$rc)" "$out"; fi
# start and stop: one supervisor per run, in the background.
UAT_SUPERVISE_INTERVAL=1 sv supervise start
spid=$(cat "$state/supervisor.pid" 2>/dev/null)
UAT_SUPERVISE_INTERVAL=1 sv supervise start
for _ in $(seq 50); do grep -q "supervise: every 1s" "$state/logs/supervisor.log" 2>/dev/null && break; sleep 0.1; done
if [ -n "$spid" ] && running "$spid" && printf '%s' "$out" | grep -q "already running (pid $spid)" && grep -q "supervise: every 1s, REFRESH_AFTER 10m" "$state/logs/supervisor.log"; then
  ok "supervise: start runs one supervisor in the background, and a second start is a no-op"
else nok "supervise: start" "$out $(cat "$state/logs/supervisor.log" 2>&1)"; fi
sv supervise stop
sleep 0.5
if ! running "$spid" && [ ! -e "$state/supervisor.pid" ]; then ok "supervise: stop stops it"; else nok "supervise: stop" "$out"; fi
t close "$state"

echo
echo "access_test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
