# UAT access scripts (`uat/access`)

**FLAG FOR SECURITY REVIEW** (part of UAT.1). These scripts are the whole
interface between the UAT gate and the VMs (Access interface, Shared contract,
section 4h of `docs/claude-code-parallel-build-plan.md`). Every Azure call of
the gate lives here; the hub, enrolment and test briefs call only these, so the
local rig (UAT.8) can supply its own `vmctl.sh` with the same interface.

**Ran once on Azure** (UAT run 38107290465, 2026-10-11: the tunnels of a
single-node run). The HA run's API tunnels by IP and `vmctl.sh stop-vm` and
`start-vm` run first in Run 3 of `uat/RUNBOOK.md`; offline both scripts are
tested against a stubbed `az` (see [Tests](#tests)).

Requirements: bash, `jq`, coreutils (`timeout`, `base64`), `setsid` (util-linux;
without it the tunnels are started with `nohup`), and the Azure CLI logged in to
the subscription with the `bastion` extension (`az extension add --name
bastion`). The input is the `tofu output -json uat` file from `uat/tofu`.
`session.sh` also needs `curl`, `flock` and `ssh-keyscan` (OpenSSH), all on
the hosted runner.

## tunnels.sh

```sh
uat/access/tunnels.sh open   <uat.json> <state-dir>
uat/access/tunnels.sh reopen <uat.json> <state-dir>
uat/access/tunnels.sh close  <state-dir>
```

`open` starts one `az network bastion tunnel` in the background per VM and
port:

| VM | Remote port | access.json key |
|---|---|---|
| every hub node (`uat-dmz`, `uat-core`; on an HA hub `uat-dmz-1` to `uat-dmz-N`, `uat-core-1` to `uat-core-N`) | 22 | `ssh_port` |
| every hub node | 6443 | `kube_port` |
| an HA hub's API address (`uat.json` `<hub>.api_address`, the internal load balancer), by IP | 6443 | `kube_port` of `dmz-api`, `core-api` |
| sprouts with `connection: ssh` (Linux) | 22 | `ssh_port` |
| sprouts with `connection: winrm` (Windows) | 5986 | `winrm_port` |
| sprouts with `connection: docker` (local rig) | none | not listed |

A hub's nodes are its `node_names` and `node_ids` in `uat.json` (P24;
`uat/tofu`, "HA topology"), each tunnelled by its own id, or the hub's `name`
and `id` where the file has no node lists: the only node of a single-node
hub. Every node gets its own SSH tunnel (k0sctl installs each one,
`uat/k0s`) and kube tunnel (that node's API server, for the VM-stop tests).
An HA hub (more than one node) also gets one kube tunnel to its
`api_address`, through the Bastion's IP-based connection
(`--target-ip-address`; `uat/tofu` turns `ip_connect_enabled` on for an HA
run). That tunnel reaches whichever node's API server is up, so it keeps
working while a node is stopped; `uat/k0s` writes it into the hub's
kubeconfig. A single-node hub gets no such entry: its API address is the
node's own.

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

On an HA run each hub node has its own entry (`uat-dmz-1` and so on, with
`ssh_port` and `kube_port`), and each hub one more:

```json
  "dmz-api":   { "host": "127.0.0.1", "kube_port": 20120, "pids": [4120] },
  "core-api":  { "host": "127.0.0.1", "kube_port": 20121, "pids": [4121] }
```

The top-level keys are exactly the VM names, plus `dmz-api` and `core-api`
(`host`, `kube_port`, `pids`) for an HA hub, and a VM has only the ports it
gets. Other files in `<state-dir>`: `tunnels.pids` (one line per tunnel: pid,
VM, kind, local port) and `logs/<vm>-<kind>.log` (each tunnel's output).

A tunnel that exits before it is ready (for example because another process
took its port between the check and the bind) is started again on a new port,
up to `TUNNEL_START_ATTEMPTS` (default 3) starts in all. If a tunnel still
exits, or is not ready in time, `open` prints that tunnel's log, stops every
tunnel it started, writes no `access.json` and exits 1. It refuses
to start while tunnels from an earlier `open` of the same directory still run.
Exit 2 is a usage error.

`open` also writes `<state-dir>/opened_at`, the time the tunnels were ready
(seconds since the epoch): the tunnels' age `session.sh` reports.

`reopen` (W6) closes the tunnels of `<state-dir>` and opens them again,
each on the local port it had when that port is free, so `access.json` and
what was made from it (the hubs' kubeconfigs, the enrolment inventory) stay
valid. A tunnel whose port is taken, or whose first start fails, gets a new
port, and `reopen` says so (`<vm> <kind>: port changed from A to B`). The
new `az` processes carry the az login as it is at that moment, which is the
point: see [session.sh](#sessionsh). Without `tunnels.pids` it is `open`.

`close` stops every tunnel in `tunnels.pids` (TERM to the tunnel's process
group, so both the `az` wrapper and its Python child stop; KILL after 10 s;
a process that has exited but is not yet reaped counts as stopped),
then removes `tunnels.pids`, `access.json` and `opened_at`. It only signals a pid that is
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

## session.sh

```sh
uat/access/session.sh mark-login
uat/access/session.sh phase <name> [--force] [--probe] [--no-tunnels]
uat/access/session.sh refresh [--no-tunnels]
uat/access/session.sh probe <name>
uat/access/session.sh ages <name>
```

**Why (W6).** The workflow's az session is a GitHub OIDC login. It cannot
renew itself once its access token expires (about an hour), and an `az
network bastion tunnel` started on it then stops opening new connections:
UAT Run 2 hung 55 to 60 minutes after its login, every host at once, while a
fresh tunnel from a laptop worked (`uat/RUNBOOK.md`, "All tunnels hang or go
UNREACHABLE after about an hour"). The cause is inferred from that timing,
so every message names both ages, to confirm or refute it on the next run.

| Command | What it does |
|---|---|
| `mark-login` | Records that az has just logged in (after the `azure/login` action, which cannot) |
| `phase <name>` | Refreshes when `--force` is given or the login or the tunnels are `UAT_SESSION_REFRESH_AFTER_MIN` (15) minutes old or more (or unknown); then the **age guard**: exits 1 with `<name>: refusing to start: azure login age Xm, tunnels age Ym; the limit is 40m` when either is older than `UAT_SESSION_MAX_AGE_MIN` (40); then logs `<name>: azure login age Xm, tunnels age Ym`. `--probe` then probes. `--no-tunnels`: the login only (no access directory needed) |
| `refresh` | Logs az in again (`az-relogin.sh`, with no minimum age), **then** closes and reopens the tunnels (`tunnels.sh reopen`), then rewrites every kubeconfig in `UAT_SESSION_KUBECONFIGS` whose `server: https://127.0.0.1:<port>` is a kube port that changed. A failed login leaves the tunnels as they were; a failed reopen leaves them closed. Both exit 1 naming the ages |
| `probe <name>` | Every tunnel in `access.json`, at once: SSH by `ssh-keyscan -T 15` (a host key line is alive), WinRM by `curl -sk -m 20 https://127.0.0.1:<port>/wsman` (HTTP 401 or 405 is alive), the Kubernetes API by `/version` (any HTTP answer is alive). Each failure is logged as `<name>: probe FAILED: <vm> <kind> tunnel (127.0.0.1:<port>) is stale or dead: <why>; tunnel age Ym, azure login age Xm, tunnels age Ym`, and the command exits 1 |
| `ages <name>` | Both ages, each tunnel's process (running or exited) and the last 5 lines of its log. Never fails: the workflow's failure-time diagnostic |

Never refresh while something uses a tunnel: the workflow refreshes only at
phase starts, `uat/enroll/enroll.sh` between its Ansible runs and
`uat/tests/run.sh` between top-level tests (both through `UAT_SESSION_HOOK`).

The login's time is the modification time of `az-relogin.sh`'s stamp,
`$AZ_RELOGIN_DIR/az-relogin.stamp`, so a relogin by `vmctl.sh` during the
tests counts too; the tunnels' time is `<access dir>/opened_at`.

Environment: `UAT_SESSION_UAT` (the `uat.json`), `UAT_SESSION_ACCESS`
(`tunnels.sh`'s state directory), `UAT_SESSION_KUBECONFIGS` (colon
separated), `UAT_SESSION_REFRESH_AFTER_MIN`, `UAT_SESSION_MAX_AGE_MIN`,
`AZ_RELOGIN_DIR`, and for the tests `UAT_SESSION_RELOGIN`,
`UAT_SESSION_TUNNELS`, `SSH_KEYSCAN` and `CURL`. The login needs what
`az-relogin.sh` needs: a job with `id-token: write` (each call fetches a new
OIDC token, so any number of logins in one job work) and `AZURE_CLIENT_ID`,
`AZURE_TENANT_ID` and `AZURE_SUBSCRIPTION_ID`.

## vmctl.sh

```sh
uat/access/vmctl.sh <uat.json> restart      <vm>
uat/access/vmctl.sh <uat.json> stop-sprout  <vm>
uat/access/vmctl.sh <uat.json> start-sprout <vm>
uat/access/vmctl.sh <uat.json> stop-vm      <vm>
uat/access/vmctl.sh <uat.json> start-vm     <vm>
uat/access/vmctl.sh <uat.json> run          <vm> <command...>
```

`<vm>` is a hub node or a sprout name. The hub nodes are each hub's
`node_names` in `uat.json` (`uat-dmz` and `uat-core` in the single-node run,
`uat-dmz-1` to `uat-dmz-N` and `uat-core-1` to `uat-core-N` on an HA hub,
each by its own entry of `node_ids`), or the hub's `name` where the file has
no node lists. Everything goes through the
Azure control plane (`az vm restart`, `az vm stop`, `az vm start`, `az vm
get-instance-view`, `az vm run-command invoke`); no network path to the VM is
needed.

| Action | What it does | Exit status |
|---|---|---|
| `restart` | `az vm restart`, then waits until the power state is running and a trivial run-command succeeds (the guest agent answers), up to `VMCTL_WAIT_SECONDS` (default 600), polling every `VMCTL_POLL_SECONDS` (default 10) | 0 when back, 255 otherwise |
| `stop-vm` | `az vm stop` (powered off, still allocated, so it starts again quickly) on a hub node, then waits until the power state is stopped, up to `VMCTL_WAIT_SECONDS`: the `ha` tier's node stop (`uat/tests`, HA2). Hub nodes only; a sprout is refused | 0 when stopped, 255 otherwise |
| `start-vm` | `az vm start` on a hub node, then waits as `restart` does. Hub nodes only. The workflow also runs it on every HA hub node after the tests, so a node stop that failed half way leaves no VM stopped | 0 when back, 255 otherwise |
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

`tests/access_test.sh` runs the scripts against `tests/stubs/az` (and `session.sh`'s probes against `tests/stubs/ssh-keyscan` and `tests/stubs/curl`): a tunnel
becomes a local Python listener (with an SSH banner for port 22), a Linux
run-command runs the generated script locally with a stub `systemctl`, and a
Windows run-command checks the PowerShell wrapper and returns canned output.
It covers argument handling, the access.json content (names, hosts, ports by
OS, distinct ports, skipping a busy port, live pids, the exact `az` arguments),
an HA uat.json (SSH and kube tunnels to every node by its own id, one tunnel
per hub to its `api_address` by IP, and refusal of a bad or missing
`api_address` or of node lists of different lengths),
refusal of a second open, a tunnel restarted on a new port after an early
exit, close stopping the tunnels and their children and
removing the files, close being repeatable and never killing an unrelated pid,
a failed tunnel, a tunnel without an SSH banner, docker sprouts, `reopen`
(every tunnel back on its port with new processes, `opened_at`, a tunnel
whose port is taken moved and named), `session.sh` (the order login, close,
open; both ages before and after; a changed kube port rewritten in a
kubeconfig and the others kept; refresh by login age, by tunnel age and by
`--force`; the guard letting 39 minutes through and refusing 41, for the
login and for the tunnels, with both ages in the message; a failed login
leaving the tunnels alone; the probe's tools and arguments, a dead SSH and
a dead WinRM tunnel named with their ports and ages, a WinRM answer other
than 401 or 405; `ages` with and without tunnels; `--no-tunnels`; an HA
uat.json), and for
`vmctl.sh` the exit codes, stdout and stderr, quoting, the service commands on
both OSes, the hub refusal, restart and its failures, `stop-vm` and `start-vm`
(waiting for the power state and the guest, a VM that never stops, a failed
`az vm stop`, the refusal of a sprout), and every node of an HA hub resolved
by its own id. Sample input: `testdata/uat.json` (single-node) and
`testdata/uat-ha.json` (3 + 3 nodes); the `tofu test` in `uat/tofu` keeps
both in the shape of the real output. shellcheck runs on every script.

```sh
bash uat/access/tests/access_test.sh
go test ./uat/access/   # the same, plus shellcheck, when the tools are on PATH
```
