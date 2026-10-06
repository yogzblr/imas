#!/usr/bin/env bash
# Tests uat/access/tunnels.sh and vmctl.sh against a stubbed az (tests/stubs):
# tunnels become local listeners, Linux run-commands run locally with a stub
# systemctl, Windows run-commands return canned output. Nothing reaches Azure.
# Needs bash, jq and python3. Run: bash uat/access/tests/access_test.sh
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tunnels="$here/../tunnels.sh"
vmctl="$here/../vmctl.sh"
uat="$here/../testdata/uat.json"
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
  out=$(PATH="$stubs:$PATH" VMCTL_WAIT_SECONDS=5 VMCTL_POLL_SECONDS=0 bash "$vmctl" "$@" 2>"$ef")
  rc=$?
  err=$(cat "$ef")
}

listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

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
for p in $pids; do kill -0 "$p" 2>/dev/null && dead=0; done
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
if [ "$rc" -eq 0 ] && calls | grep -q -- "^az vm restart --ids $t2a_id" && calls | grep -q "vm get-instance-view --ids $t2a_id" && calls | grep -q "vm run-command invoke --ids $t2a_id"; then
  ok "vmctl: restart restarts, checks power state and probes the guest"
else nok "vmctl: restart (rc=$rc)" "$(calls) $err"; fi
echo PowerState/stopped >"$STUB_STATE/power"
v "$uat" restart uat-dmz
if [ "$rc" -eq 255 ] && printf '%s' "$err" | grep -q "not back"; then ok "vmctl: restart that never comes back gives 255"; else nok "vmctl: restart timeout (rc=$rc)" "$err"; fi
rm -f "$STUB_STATE/power"
echo 1 >"$STUB_STATE/restart_rc"
v "$uat" restart uat-dmz
if [ "$rc" -eq 255 ]; then ok "vmctl: a failed az vm restart gives 255"; else nok "vmctl: restart failure (rc=$rc)" "$err"; fi

echo
echo "access_test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
