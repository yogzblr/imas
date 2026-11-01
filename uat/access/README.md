# UAT access scripts (`uat/access`)

**FLAG FOR SECURITY REVIEW** (part of UAT.1). These scripts are the whole
interface between the UAT gate and the VMs (Access interface, Shared contract,
section 4h of `docs/claude-code-parallel-build-plan.md`). Every Azure call of
the gate lives here; the hub, enrolment and test briefs call only these, so the
local rig (UAT.8) can supply its own `vmctl.sh` with the same interface.

**Ran once on Azure** (UAT run 38107290465, 2026-10-11: the tunnels of a
single-node run). Run 3 (the HA run, rc.22) failed in the tunnel phase on
the API tunnels by IP, which Azure Bastion refuses on 6443 (W12, below);
the HA failover between the nodes' own kube tunnels and `vmctl.sh stop-vm`
and `start-vm` run first in its retry (`uat/RUNBOOK.md`); offline both scripts are
tested against a stubbed `az` (see [Tests](#tests)).

Requirements: bash, `jq`, coreutils (`timeout`, `base64`), `flock` and `setsid` (util-linux;
without it the tunnels are started with `nohup`), and the Azure CLI logged in to
the subscription with the `bastion` extension (`az extension add --name
bastion`). The input is the `tofu output -json uat` file from `uat/tofu`.
`vmctl.sh`'s tunnel channel also needs OpenSSH's `ssh` and, for Windows,
`python3` with `pywinrm` (MIT; the workflow installs it for Ansible).
`session.sh` also needs `curl`, `flock` and `ssh-keyscan` (OpenSSH), all on
the hosted runner.

## tunnels.sh

```sh
uat/access/tunnels.sh open       <uat.json> <state-dir>
uat/access/tunnels.sh reopen     <uat.json> <state-dir>
uat/access/tunnels.sh reopen-one <uat.json> <state-dir> <vm> <kind>
uat/access/tunnels.sh close      <state-dir>
uat/access/tunnels.sh plan       <uat.json>
```

`open` starts one `az network bastion tunnel` in the background per VM and
port:

| VM | Remote port | access.json key |
|---|---|---|
| every hub node (`uat-dmz`, `uat-core`; on an HA hub `uat-dmz-1` to `uat-dmz-N`, `uat-core-1` to `uat-core-N`) | 22 | `ssh_port` |
| every hub node | 6443 | `kube_port` |
| sprouts with `connection: ssh` (Linux) | 22 | `ssh_port` |
| sprouts with `connection: winrm` (Windows) | 5986 | `winrm_port` |
| sprouts with `connection: docker` (local rig) | none | not listed |

A hub's nodes are its `node_names` and `node_ids` in `uat.json` (P24;
`uat/tofu`, "HA topology"), each tunnelled by its own id, or the hub's `name`
and `id` where the file has no node lists: the only node of a single-node
hub. Every node gets its own SSH tunnel (k0sctl installs each one,
`uat/k0s`) and kube tunnel (that node's API server, for the VM-stop tests).
Every tunnel goes to a VM by its resource id (`--target-resource-id`).

**No tunnel goes to an HA hub's internal load balancer (W12).** Azure
Bastion's IP-based connection (`--target-ip-address`) tunnels to ports 22
and 3389 only: Azure UAT Run 3 (tier `ha`, `hub_nodes` 3) failed in setup
with `ERROR: Custom ports are not allowed. Allowed ports for Tunnel with IP
connect is 22, 3389.`, three times, opening a 6443 tunnel to each hub's
`api_address`. An HA hub's k0s API is reached through its nodes' own kube
tunnels instead, with failover between them ("HA hubs: the API through the
nodes" below). `start_tunnel` refuses a tunnel by IP to any other port
before `az` runs; `tunnels.sh plan <uat.json>` lists the tunnels `open` would
start (name, kind, remote port, `id:` or `ip:` target) and fails on such a
one; `check-bastion-ports.sh` runs `plan` on the test uat.json files and
fails when any script or workflow but `tunnels.sh` passes
`--target-ip-address` (the access tests run it).

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
`ssh_port` and `kube_port`) and nothing else: there is no `dmz-api` or
`core-api` entry any more (W12).

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

`open` also writes `<state-dir>/opened_at`, the time the tunnels were ready
(seconds since the epoch): the tunnels' age `session.sh` reports; and
`<state-dir>/opened/<vm>-<kind>`, the same per tunnel (W10).

`reopen-one` (W10) closes one tunnel (`<kind>` is `ssh`, `winrm` or
`kube`) and opens it again on **the same local port**, waits until it is
ready as `open` does, and updates `tunnels.pids`, `access.json`, its
`opened/` stamp and `opened_at` (then the oldest tunnel's). It never moves
the port: if the port is still taken after the old process stopped, it
fails and the caller tries again later. The tunnel's log keeps its earlier
lines, with a `--- tunnels.sh reopen-one at ...` line between. It is what
`session.sh`'s supervisor and `vmctl.sh`'s recovery use, one tunnel at a
time, each holding the VM's slots. `open`, `reopen`, `reopen-one` and
`close` hold `<state-dir>/tunnels.lock`, so two never rewrite the state at
once, and a tunnel inherits no file descriptor but its log (a lock must not
live on in it).

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
then removes `tunnels.pids`, `access.json`, `opened_at` and `opened/`. It only signals a pid that is
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

### HA hubs: the API through the nodes (W12)

An HA hub's kubeconfig (`uat/k0s` writes `core.kubeconfig` and
`dmz.kubeconfig`) points its server at one node's kube tunnel,
`https://127.0.0.1:<that node's kube_port>`: the first node's at first.
Every node's k0s API certificate names `127.0.0.1` (`uat/k0s`, the SANs), and
all nodes share the cluster CA and admin credential, so the same kubeconfig
works through any node's tunnel; only the port changes.

`session.sh kube-select [<kubeconfig>...]` (default every file in
`UAT_SESSION_KUBECONFIGS`) keeps it on a node that answers, through
`channel.sh ch_kube_select`:

1. the node it points at, if the ha tier has not stopped it and its kube
   tunnel answers the probe (HTTPS `/version`; k0s answers 401 without
   credentials, any HTTP answer counts as the API, `000` as no answer);
2. else the hub's nodes in order (`uat.json` `node_names`), skipping one
   that is stopped or has no kube tunnel, the first that answers; the
   server line is rewritten in place (temporary file, `mv`, mode 0600) and
   the move is logged;
3. else exit 1, the kubeconfig left as it was, every node's verdict named.

It does not move back to node 1 when that one answers again: it stays where
it is while that node answers. A single-node hub's kubeconfig is never
touched or probed. Who calls it:

- every `session.sh phase` (after its refresh; with `--probe` a hub with
  no answering node fails the phase);
- the supervisor, every round (it logs a move or a hub with no answering
  node as `kube-select: ...` in `logs/supervisor.log`, not a kubeconfig that
  stays);
- `vmctl.sh stop-vm`, before `az vm stop`: it writes
  `<access dir>/stopped/<vm>` and moves every kubeconfig on that node;
  `start-vm` removes the mark once `az vm start` returns;
- the harness: `Kube.Run` when kubectl says `Unable to connect to the
  server` or the local tunnel refused (the request never reached the API),
  then runs the call again on the new node, at most twice per call; before
  `helm upgrade` (HA3), `check.sh` (HA3) and `acceptance.sh` on an HA core
  hub, which it never retries;
- `uat/tests/run.sh`, before a failed test's diagnostics.

A node marked stopped is left alone: the supervisor, `ensure kube` and
`probe` skip its tunnels, saying so, rather than reopening them every round
while the VM is off. Which node HA2 stops is not fixed (core: a node with a
farmer pod and a replica of PXC, OpenBao and Valkey but not Valkey's primary
or Keycloak; DMZ: the last node with a bus and an Envoy pod), so no node is
"safe": `stop-vm` moves the kubeconfig first, whichever it is.

The kube lock (W11) works as before: the harness holds the shared lock of
the port its kubeconfig points at, and a reopen holds that port's lock
exclusively. A move between nodes changes which port's lock the next call
takes.

## session.sh

```sh
uat/access/session.sh mark-login
uat/access/session.sh phase <name> [--force] [--probe] [--no-tunnels]
uat/access/session.sh refresh [--no-tunnels]
uat/access/session.sh probe <name>
uat/access/session.sh ages <name>
uat/access/session.sh supervise start|stop|run|tick
uat/access/session.sh ensure kube
uat/access/session.sh kube-select [<kubeconfig>...]
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
| `phase <name>` | Refreshes when `--force` is given or the login or the tunnels are `UAT_SESSION_REFRESH_AFTER_MIN` (default `UAT_REFRESH_AFTER_MIN`, 10) minutes old or more (or unknown); then the **age guard**: exits 1 with `<name>: refusing to start: azure login age Xm, tunnels age Ym; the limit is 40m` when either is older than `UAT_SESSION_MAX_AGE_MIN` (40); then logs `<name>: azure login age Xm, tunnels age Ym`. `--probe` then probes. Then `kube-select` on `UAT_SESSION_KUBECONFIGS` (W12; with `--probe` a hub with no answering node fails the phase). `--no-tunnels`: the login only (no access directory needed) |
| `refresh` | Logs az in again (`az-relogin.sh`, with no minimum age), **then** closes and reopens the tunnels (`tunnels.sh reopen`), then rewrites every kubeconfig in `UAT_SESSION_KUBECONFIGS` whose `server: https://127.0.0.1:<port>` is a kube port that changed. A failed login leaves the tunnels as they were; a failed reopen leaves them closed. Both exit 1 naming the ages |
| `probe <name>` | Every tunnel in `access.json`, at once: SSH by `ssh-keyscan -T 15` (a host key line is alive), WinRM by `curl -sk -m 20 https://127.0.0.1:<port>/wsman` (HTTP 401 or 405 is alive), the Kubernetes API by `/version` (any HTTP answer is alive). Each failure is logged as `<name>: probe FAILED: <vm> <kind> tunnel (127.0.0.1:<port>) is stale or dead: <why>; tunnel age Ym, azure login age Xm, tunnels age Ym`, and the command exits 1. A VM the ha tier stopped (`<access dir>/stopped/<vm>`) is skipped, saying so |
| `ages <name>` | Both ages, each tunnel's process (running or exited, and "VM stopped by the ha tier"), the last 5 lines of its log, and where each kubeconfig in `UAT_SESSION_KUBECONFIGS` points (port and node). Never fails: the workflow's failure-time diagnostic |
| `kube-select [<kubeconfig>...]` | Points each HA hub's kubeconfig at a node that answers and is not stopped (W12, "HA hubs: the API through the nodes" above); exits 1 when a hub has none. A single-node hub's is left as it is |
| `supervise start`, `stop` | One background supervisor per run (W10; pid in `<access dir>/supervisor.pid`, log `<access dir>/logs/supervisor.log`, every line stamped with the UTC time). A second `start` is a no-op while it runs. The workflow starts it at the top of the Tests step and stops it before the tunnels close |
| `supervise tick` (and `run`, the loop of ticks every `UAT_SUPERVISE_INTERVAL`, 60 s) | One round: (1) the login, renewed when `REFRESH_AFTER` old; (2) the tunnels **one at a time, oldest first**: a tunnel `REFRESH_AFTER` old, or whose protocol probe fails, is reopened on **the same port** (`tunnels.sh reopen-one`) and probed again. An SSH or WinRM tunnel only while holding every `vmctl.sh` slot of its VM, a kube tunnel only once no connection is open on its port (kubectl, a port-forward), waiting up to `UAT_SUPERVISE_WAIT_SECONDS` (30) and otherwise leaving it for the next round: never under a running command; (3) every VM `vmctl.sh` marked dead, at most every `VMCTL_REPROBE_SECONDS` (120): its tunnel probed, reopened when it does not answer, and the mark cleared when it answers; (4) `kube-select` on every kubeconfig, logging only a move or a hub with no answering node (W12). A VM the ha tier stopped is skipped in (2). A round skips while a full `refresh` runs (`supervisor.pause`) |
| `ensure kube` | The login and every kube tunnel, renewed as a round does when `REFRESH_AFTER` old: the Go harness runs it before a kubectl call that would go out on an old one |

**REFRESH_AFTER** is `UAT_REFRESH_AFTER_MIN` (10 minutes, W10): the
supervisor's, `vmctl.sh`'s and the harness's limit. UAT Run 2 #6 (rc.20)
showed the tunnels going stale about 20 minutes after they opened, in the
middle of one 15-minute top-level test, so refreshing only at boundaries is
kept as the backstop, not the mechanism.

A full `refresh` (all tunnels at once) is made only at phase starts,
`uat/enroll/enroll.sh` between its Ansible runs and `uat/tests/run.sh`
between top-level tests (both through `UAT_SESSION_HOOK`), never while
something uses a tunnel; it also clears every dead mark of `vmctl.sh`.

The login's time is the modification time of `az-relogin.sh`'s stamp,
`$AZ_RELOGIN_DIR/az-relogin.stamp`, so a relogin by `vmctl.sh` during the
tests counts too; the tunnels' time is `<access dir>/opened_at` (the oldest
tunnel's) and each tunnel's own is `<access dir>/opened/<vm>-<kind>`.

Environment: `UAT_SESSION_UAT` (the `uat.json`), `UAT_SESSION_ACCESS`
(`tunnels.sh`'s state directory), `UAT_SESSION_KUBECONFIGS` (colon
separated), `UAT_SESSION_REFRESH_AFTER_MIN`, `UAT_SESSION_MAX_AGE_MIN`,
`UAT_REFRESH_AFTER_MIN`, `UAT_SUPERVISE_INTERVAL`,
`UAT_SUPERVISE_WAIT_SECONDS`, `UAT_SUPERVISE_PROBE` (0: by age only),
`VMCTL_STATE_DIR`, `VMCTL_REPROBE_SECONDS`, `VMCTL_DEAD_AFTER`,
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
no node lists.

### The channel (W8)

UAT Run 2 (run 39709416839, rc.16) ran every command through `az vm
run-command invoke`: 30 to 60 s a call, one execution at a time per VM, a
call killed on the runner left the VM's extension busy ("(Conflict) Run
command extension execution is in progress") for the calls after it, and
about 85 of its 101 failures came from that channel, not the product. So
`run`, `stop-sprout` and `start-sprout` now go through the VM's **Bastion
tunnel** when `access.json` (`tunnels.sh`) has one:

| VM | Channel | As |
|---|---|---|
| Linux (hub nodes, `connection: ssh` sprouts) with an `ssh_port` | `ssh -p <ssh_port> <admin_user>@127.0.0.1` with `VMCTL_SSH_KEY`; the command goes on stdin into a temporary file and runs with `sudo -n -H bash` (stdin `/dev/null`) | root |
| Windows (`connection: winrm` sprouts) with a `winrm_port` | `winrm_exec.py`: pywinrm (MIT, the runner's Ansible stack) to `https://127.0.0.1:<winrm_port>/wsman`, NTLM, certificate not validated (as `uat/enroll`'s inventory: the certificate is self-signed and names the VM); the command goes to `powershell.exe` on stdin, so its length is not bound by the command line | the admin user (an elevated token, as for enrolment), **not SYSTEM** |
| a VM with no tunnel entry | `az vm run-command invoke` (`RunShellScript`, `RunPowerShellScript`), as before | root, SYSTEM |

A tunnel entry without its credential (`VMCTL_SSH_KEY`,
`VMCTL_WINRM_PASSWORD_FILE` unset or unreadable) also falls back to
run-command, and says so on stderr. Over SSH the host key is accepted on
first use into `<state>/known_hosts` under the VM's name
(`HostKeyAlias`), so a tunnel that moves to another local port keeps its
key. Every successful call logs `<vm>: ran over <channel> (127.0.0.1:<port>)
in Ns`: the measured per-call time.

**Slots per VM (W10).** Calls to one VM share a counting semaphore,
`VMCTL_SLOTS_LINUX` (4) or `VMCTL_SLOTS_WINDOWS` (2) slots (`flock` on
`<state>/<vm>.slot.<i>`), across processes too, well inside sshd's
`MaxStartups` (10) and `MaxSessions` (10) and WinRM's `MaxShellsPerUser`
(30). `restart`, `stop-vm`, `start-vm`, a run-command call (Azure runs one
at a time per VM) and every tunnel reopen take **all** of them, so nothing
else runs on the VM meanwhile. A call that waits more than 5 s says so; one
that cannot get its slots within `VMCTL_LOCK_WAIT_SECONDS` (900) exits 255.
Nothing long-lived started here (an SSH master, a tunnel, a background
capture) keeps a slot's file open: `channel.sh`'s `ch_closefds`.

**One SSH master per Linux VM.** SSH calls share a persistent master
(`ControlMaster=auto`, `ControlPath=/tmp/imas-cm-<uid>/<vm>`,
`ControlPersist` `VMCTL_SSH_PERSIST` 300 s, `ServerAliveInterval` 15 and
`ServerAliveCountMax` 4), so a call opens no new connection through the
tunnel; a tunnel reopen closes the master first.

**One pooled WinRM session per Windows VM.** `winrm_exec.py --pool`: the
first call starts a server process holding the NTLM session and one shell,
on a Unix socket in the same private directory
(`/tmp/imas-cm-<uid>/winrm-<vm>.sock`); later calls hand it their script
and get the output back, so no call opens a new connection or shell through
the tunnel. It runs one script at a time, exits after
`VMCTL_WINRM_POOL_IDLE` (300 s) without a call, exits on any failure (the
next call starts a fresh one), and a watchdog ends it when a script outlives
its call's timeout, so a hung command never blocks the next one. A tunnel
reopen closes it first. `VMCTL_WINRM_POOL=0` goes back to a session per
call.

**Fresh before each command.** When the login (`UAT_AZ_RELOGIN` set) or the
VM's tunnel is `REFRESH_AFTER` (`UAT_REFRESH_AFTER_MIN`, 10 minutes) old,
`vmctl.sh` renews it first, under the VM's slots (a call that waited for
them checks the age again).

**Timeouts.** Each channel call has its own timeout, `VMCTL_CALL_TIMEOUT`
(120 s), and is killed (TERM, then KILL 5 s later) when it runs over; each
`az` power operation has `VMCTL_AZ_TIMEOUT` (600 s). The harness's own
per-call limit (`IMAS_UAT_VMCTL_TIMEOUT`, 25 minutes: a restart's own bounds are 20) kills `vmctl.sh`'s
whole process group, so no `az`, `ssh` or `python3` child survives it.

**A channel failure: probe, mend, then retry (W10).** When a call over the
tunnel comes back with no exit code, `vmctl.sh`, at that moment:

1. prints one line, `vmctl.sh: CHANNEL ERROR at <UTC time> (epoch <n>):
   vm=<vm> kind=<ssh|winrm> port=<port> login_age=<XmYYs>
   tunnel_age=<XmYYs> probe=<ok|fail ...>: <the failure>` (stamped here:
   the Go tests print a subtest's output only when it ends);
2. captures the channel's state, before touching it, into
   `$VMCTL_DIAG_DIR/channel/<epoch>-<vm>-<kind>.txt` (`channel.sh`'s
   `ch_capture`, below);
3. probes the tunnel by its protocol (`channel.sh`: the SSH banner within
   `UAT_PROBE_SSH_SECONDS` 5, an HTTPS answer 401 or 405 on `/wsman` within
   `UAT_PROBE_HTTPS_SECONDS` 10) and, when the probe fails, reopens the
   tunnel on its port under every slot of the VM and probes it again;
4. tries the call once more (`VMCTL_CONNECT_RETRIES`, 1) **only if it
   certainly never started** (SSH refused, closed, reset or timed out
   before or during the banner, the master's session never opened,
   `kex_exchange_identification`; a WinRM shell that never opened). A call
   that may have run (it timed out, or gave no exit code) is never
   repeated, but its tunnel is still mended for the next one.

A run-command refused with Conflict is retried `VMCTL_CONFLICT_RETRIES` (4)
times, 15, 30, 60 and 120 s apart.

**The dead mark: a strike only after the recovery, and a re-probe.** A
failure that remains after the above is a strike; a success clears them.
After `VMCTL_DEAD_AFTER` (3) strikes in a row the VM is marked dead
(`<state>/<vm>.fails`: count, last failure and last re-probe, and the
failure), and a call to it fails at once with `vmctl.sh: CHANNEL
UNAVAILABLE: <vm> is marked dead after ... next re-probe in Ns` (the harness
reports such a case as channel unavailable, not as a product failure).
There is no fixed hold: a call made `VMCTL_REPROBE_SECONDS` (120) after the
last failure or re-probe re-probes the tunnel (reopening it when the probe
fails) and, when it answers, clears the mark and runs; `session.sh`'s
supervisor does the same every round, and every full refresh, a reopen that
answers, and a `restart` or `start-vm` that comes back clear it. The state
is in `VMCTL_STATE_DIR` (default `<access.json's directory>/vmctl`, else
`${TMPDIR:-/tmp}/imas-vmctl-<uid>`).

**What a capture holds** (`diagnostics/channel/<epoch>-<vm>-<kind>.txt`,
redacted): the CHANNEL ERROR line; `tunnels.pids` and every `bastion
tunnel` process (pid, process group, elapsed time, state); the listening
TCP ports; per tunnel port, its connections by state (`ss`); the end of the
tunnel's own log (its az process's stderr). Then, at most once per VM per
`UAT_VM_LIMITS_EVERY_SECONDS` (600) and in the background, through `az vm
run-command` and never the tunnel, `<epoch>-<vm>-vm-side.txt`: on Linux
`sshd -T`'s `MaxStartups`, `MaxSessions`, `MaxAuthTries`, `LoginGraceTime`
and `ClientAlive*`, the connections on port 22 and the end of sshd's
journal; on Windows `winrm get winrm/config/winrs` (`MaxShellsPerUser`,
`MaxConcurrentUsers`, `MaxMemoryPerShellMB`), `winrm/config/service`
(`MaxConnections`), the WinRM service, the connections on 5986 and the last
WinRM operational events.

`VMCTL_CHANNEL=runcommand` sends a call through `az vm run-command` even
where there is a tunnel: the harness's way past a dead tunnel to a failed
cook's job record, and `diagnostics.sh vm`'s.

### Actions

| Action | What it does | Exit status |
|---|---|---|
| `restart` | `az vm restart` (when that fails, a reboot through `az vm run-command` a few seconds out), then waits, up to `VMCTL_RESTART_WAIT_SECONDS` (default `VMCTL_WAIT_SECONDS`, else 600) in all and polling every `VMCTL_POLL_SECONDS` (10), until the power state is running and the guest answers: the tunnel's protocol probe and then a command over it that must print `IMAS_VMCTL_GUEST_OK` (`VMCTL_PROBE_TIMEOUT` 30 s). **Every failed probe recreates the tunnel on its port** (W10: UAT Run 2 #6's Windows restarts waited out the 600 s on a tunnel that no longer served, and passed minutes later on a reopened one). The VM's SSH master and pooled WinRM session are closed before and after the power operation and after every failed check (W11: a reboot kills a pooled shell; and the old check, `exit 0`, ended the Windows wrapper's `powershell.exe` before its exit code marker, so it never passed); a failed check names the last attempt's raw output. With no tunnel, the guest agent reporting `Ready` with a time after the restart began. It never depends on the channel it restarts | 0 when back, 255 otherwise (naming the reason and the last probe's error) |
| `stop-vm` | `az vm stop` (powered off, still allocated, so it starts again quickly) on a hub node, then waits until the power state is stopped, up to `VMCTL_POWER_WAIT_SECONDS`: the `ha` tier's node stop (`uat/tests`, HA2). Hub nodes only; a sprout is refused | 0 when stopped, 255 otherwise |
| `start-vm` | `az vm start` on a hub node, then waits as `restart` does. Hub nodes only. The workflow also runs it on every HA hub node after the tests, so a node stop that failed half way leaves no VM stopped | 0 when back, 255 otherwise |
| `stop-sprout`, `start-sprout` | `systemctl stop` or `start imas-sprout` on Linux, `Stop-Service`/`Start-Service imas-sprout` on Windows (`VMCTL_SPROUT_SERVICE` overrides the name), over the channel above. Sprouts only; a hub is refused | the command's |
| `run` | Runs `<command...>`, joined with spaces, over the channel above. Prints its stdout on stdout and its stderr on stderr, then `vmctl.sh: exit_code=N` on stderr | the command's (`N`) |

The command is sent base64 encoded (or on stdin) and decoded on the VM, so
quotes, `$` and pipes arrive intact. Its exit code comes back through a
marker line the wrapper prints and `vmctl.sh` removes. On Windows, `N` is
`$LASTEXITCODE` of the last native command if it is not 0, else 1 when the
script raised an error, else 0 (the same wrapper on WinRM and run-command).
Through run-command Azure keeps only the last 4096 bytes of each stream.
Exit 2 is a usage error or an unknown VM (no Azure call is made); 255 means
the command could not be run or returned no exit code.

Environment: `VMCTL_ACCESS` (default `$UAT_SESSION_ACCESS/access.json`,
else `<uat.json's directory>/access/access.json`), `VMCTL_SSH_KEY`,
`VMCTL_SSH_USER` and `VMCTL_WINRM_USER` (default the VM's `admin_user`),
`VMCTL_WINRM_PASSWORD_FILE`, `VMCTL_STATE_DIR`, `VMCTL_DIAG_DIR`,
`VMCTL_CHANNEL`, `VMCTL_SLOTS_LINUX`, `VMCTL_SLOTS_WINDOWS`,
`VMCTL_SSH_PERSIST`, `VMCTL_SSH_CONTROL_DIR`, `VMCTL_WINRM_POOL`,
`VMCTL_WINRM_POOL_IDLE`, `UAT_REFRESH_AFTER_MIN`,
`UAT_PROBE_SSH_SECONDS`, `UAT_PROBE_HTTPS_SECONDS`, the timeouts, retries
and waits above, `VMCTL_BACKOFF_SCALE` (1; the tests set 0), `AZ` and
`UAT_AZ_RELOGIN` (an expired az login is renewed once and the call
repeated; a login `REFRESH_AFTER` old is renewed before a command). The UAT workflow sets `VMCTL_SSH_KEY` and
`VMCTL_WINRM_PASSWORD_FILE` to the run's own credentials (never uploaded).

## Tests

`tests/access_test.sh` runs the scripts against `tests/stubs/az` (and `session.sh`'s probes against `tests/stubs/ssh-keyscan` and `tests/stubs/curl`): a tunnel
becomes a local Python listener (with an SSH banner for port 22), a Linux
run-command runs the generated script locally with a stub `systemctl`, and a
Windows run-command checks the PowerShell wrapper and returns canned output.
It covers argument handling, the access.json content (names, hosts, ports by
OS, distinct ports, skipping a busy port, live pids, the exact `az` arguments),
an HA uat.json (SSH and kube tunnels to every node by its own id, no
tunnel by IP and none to `api_address`, refusal of node lists of different
lengths), the Bastion port limit (`plan`, `check_target` refusing a tunnel
by IP to 6443, the stub `az` refusing it with Azure's message, and
`check-bastion-ports.sh` on the repository and on a planted offender), the
HA failover (`session.sh kube-select`: a kubeconfig on an answering node
stays; one on a node that does not answer moves to the next; a node the ha
tier stopped is skipped; no answering node fails and leaves the kubeconfig;
a single-node hub's is never touched; a phase, the supervisor and
`vmctl.sh stop-vm` move it; the supervisor leaves a stopped node's tunnels
alone; `start-vm` clears the mark; `ages` says where each kubeconfig
points),
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
by its own id; and the W8 channel: SSH (`tests/stubs/ssh` runs the command
locally, with `tests/stubs/sudo`) with its port, user, host key alias, quoting
and empty stdin, WinRM (`winrm_exec.py` against a stub pywinrm in
`tests/stubs/py`: NTLM over HTTPS to the tunnel's port, the command intact,
CLIXML stderr decoded, the shell closed), the run-command fallback for a VM
with no tunnel entry or no credential, the per-VM lock (two calls never
overlap, another VM is not held up, a lock held too long gives 255), the
Conflict retry with backoff and its limit, the connection retry and no retry
of a call that may have run, a stuck call killed at `VMCTL_CALL_TIMEOUT`, a
VM marked dead after 3 failures failing at once without touching the
channel, per VM, expiring and cleared by a success or a restart, and a
restart that waits over SSH, over WinRM or for a guest agent status newer
than the restart, never through run-command. Sample input: `testdata/uat.json` (single-node) and
`testdata/uat-ha.json` (3 + 3 nodes); the `tofu test` in `uat/tofu` keeps
both in the shape of the real output. shellcheck runs on every script.

```sh
bash uat/access/tests/access_test.sh
go test ./uat/access/   # the same, plus shellcheck, when the tools are on PATH
```
