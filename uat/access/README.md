# UAT access scripts (`uat/access`)

**FLAG FOR SECURITY REVIEW** (part of UAT.1). These two scripts are the whole
interface between the UAT gate and the VMs (Access interface, Shared contract,
section 4h of `docs/claude-code-parallel-build-plan.md`). Every Azure call of
the gate lives here; the hub, enrolment and test briefs call only these, so the
local rig (UAT.8) can supply its own `vmctl.sh` with the same interface.

**Never run against Azure.** Both scripts are tested against a stubbed `az`
only (see [Tests](#tests)).

Requirements: bash, `jq`, coreutils (`timeout`, `base64`), `setsid` (util-linux;
without it the tunnels are started with `nohup`), and the Azure CLI logged in to
the subscription with the `bastion` extension (`az extension add --name
bastion`). The input is the `tofu output -json uat` file from `uat/tofu`.

## tunnels.sh

```sh
uat/access/tunnels.sh open  <uat.json> <state-dir>
uat/access/tunnels.sh close <state-dir>
```

`open` starts one `az network bastion tunnel` in the background per VM and
port:

| VM | Remote port | access.json key |
|---|---|---|
| `uat-dmz`, `uat-core` | 22 | `ssh_port` |
| `uat-dmz`, `uat-core` | 6443 | `kube_port` |
| sprouts with `connection: ssh` (Linux) | 22 | `ssh_port` |
| sprouts with `connection: winrm` (Windows) | 5986 | `winrm_port` |
| sprouts with `connection: docker` (local rig) | none | not listed |

Each tunnel gets its own free port on 127.0.0.1, starting at
`TUNNEL_PORT_BASE` (default 20100, below the ephemeral port ranges of Linux,
macOS and Windows, so outgoing connections do not take them) and skipping any port something already
listens on. `open` then waits, up to `TUNNEL_WAIT_SECONDS` (default 300) per
tunnel, until the port accepts connections; an SSH tunnel must also return
the server's `SSH-` banner, which proves the path to the VM works end to end
(the WinRM and Kubernetes ports speak TLS first, so for those only the local
listener is checked; tools should still retry their first call). Then it
writes `<state-dir>/access.json`:

```json
{
  "uat-dmz":   { "host": "127.0.0.1", "ssh_port": 20100, "kube_port": 20101, "pids": [4101, 4102] },
  "uat-core":  { "host": "127.0.0.1", "ssh_port": 20102, "kube_port": 20103, "pids": [4103, 4104] },
  "t1-ubuntu": { "host": "127.0.0.1", "ssh_port": 20104, "pids": [4105] },
  "t1-win":    { "host": "127.0.0.1", "winrm_port": 20106, "pids": [4107] }
}
```

The top-level keys are exactly the VM names, and a VM has only the ports it
gets. Other files in `<state-dir>`: `tunnels.pids` (one line per tunnel: pid,
VM, kind, local port) and `logs/<vm>-<kind>.log` (each tunnel's output).

A tunnel that exits before it is ready (for example because another process
took its port between the check and the bind) is started again on a new port,
up to `TUNNEL_START_ATTEMPTS` (default 3) starts in all. If a tunnel still
exits, or is not ready in time, `open` prints that tunnel's log, stops every
tunnel it started, writes no `access.json` and exits 1. It refuses
to start while tunnels from an earlier `open` of the same directory still run.
Exit 2 is a usage error.

`close` stops every tunnel in `tunnels.pids` (TERM to the tunnel's process
group, so both the `az` wrapper and its Python child stop; KILL after 10 s),
then removes `tunnels.pids` and `access.json`. It only signals a pid that is
still alive and still an `az ... bastion tunnel` process, so a pid reused by
something else is left alone. It is safe to repeat and exits 0 when there is
nothing to close.

### How a tunnel is closed when a job is cancelled

The tunnels must outlive the step that opens them (later steps use them), so
`open` starts each with `setsid` in its own session and process group. Three
things stop them:

1. **The workflow's close step.** UAT.6 runs `tunnels.sh close <state-dir>` in
   a step with `if: always()`, which runs after a failure and after a
   cancellation too. Within that step, `close` is idempotent, so a second
   close in a later cleanup step is harmless.
2. **The runner's orphan cleanup.** At the end of every job, the GitHub runner
   kills processes the job left running; it finds them by the
   `RUNNER_TRACKING_ID` environment variable they inherited, which `setsid`
   does not clear. This covers a cancellation that interrupts the close step,
   or a step killed before it.
3. **Teardown.** Destroying the Bastion ends every tunnel through it; the local
   `az` processes then exit or are reaped by point 2.

If `open` itself is interrupted (SIGINT or SIGTERM, as GitHub sends on cancel)
or fails, its exit trap stops every tunnel it had started.

## vmctl.sh

```sh
uat/access/vmctl.sh <uat.json> restart      <vm>
uat/access/vmctl.sh <uat.json> stop-sprout  <vm>
uat/access/vmctl.sh <uat.json> start-sprout <vm>
uat/access/vmctl.sh <uat.json> run          <vm> <command...>
```

`<vm>` is `uat-dmz`, `uat-core` or a sprout name. Everything goes through the
Azure control plane (`az vm restart`, `az vm get-instance-view`, `az vm
run-command invoke`); no network path to the VM is needed.

| Action | What it does | Exit status |
|---|---|---|
| `restart` | `az vm restart`, then waits until the power state is running and a trivial run-command succeeds (the guest agent answers), up to `VMCTL_WAIT_SECONDS` (default 600), polling every `VMCTL_POLL_SECONDS` (default 10) | 0 when back, 255 otherwise |
| `stop-sprout`, `start-sprout` | `systemctl stop|start imas-sprout` on Linux, `Stop-Service`/`Start-Service imas-sprout` on Windows (`VMCTL_SPROUT_SERVICE` overrides the name). Sprouts only; a hub is refused | the command's |
| `run` | Runs `<command...>`, joined with spaces, as root with bash on Linux or as SYSTEM with PowerShell on Windows. Prints its stdout on stdout and its stderr on stderr, then `vmctl.sh: exit_code=N` on stderr | the command's (`N`) |

The command is sent base64 encoded and decoded on the VM, so quotes, `$` and
pipes arrive intact. Its exit code comes back through a marker line the wrapper
prints and `vmctl.sh` removes. On Windows, `N` is `$LASTEXITCODE` of the last
native command if it is not 0, else 1 when the script raised an error, else 0.
Azure keeps only the last 4096 bytes of each stream, and a run-command takes
tens of seconds. Exit 2 is a usage error or an unknown VM (no Azure call is
made); 255 means Azure could not run the command or returned no exit code.

## Tests

`tests/access_test.sh` runs both scripts against `tests/stubs/az`: a tunnel
becomes a local Python listener (with an SSH banner for port 22), a Linux
run-command runs the generated script locally with a stub `systemctl`, and a
Windows run-command checks the PowerShell wrapper and returns canned output.
It covers argument handling, the access.json content (names, hosts, ports by
OS, distinct ports, skipping a busy port, live pids, the exact `az` arguments),
refusal of a second open, a tunnel restarted on a new port after an early
exit, close stopping the tunnels and their children and
removing the files, close being repeatable and never killing an unrelated pid,
a failed tunnel, a tunnel without an SSH banner, docker sprouts, and for
`vmctl.sh` the exit codes, stdout and stderr, quoting, the service commands on
both OSes, the hub refusal, restart and its failures. Sample input:
`testdata/uat.json` (the `tofu test` in `uat/tofu` keeps it in the shape of the
real output). shellcheck runs on every script.

```sh
bash uat/access/tests/access_test.sh
go test ./uat/access/   # the same, plus shellcheck, when the tools are on PATH
```
