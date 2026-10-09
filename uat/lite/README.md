# uat/lite: the local UAT rig (UAT.8)

A rig that runs the UAT gate's hub scripts and the smoke and core tiers of
its test suite on one machine with Docker, for free, so the tests can be
debugged before any Azure run (plan section 4h, "How the runner reaches the
VMs, and how the suite is validated").

It reuses the other briefs' scripts **unchanged**: `uat/hub/core/install.sh`
(UAT.3b), `uat/hub/dmz/install.sh` and `check.sh` (UAT.3a), `uat/enroll/enroll.sh`
(UAT.4) and `uat/tests/run.sh` (UAT.5). What it adds is what Azure, k0s and
the Bastion tunnels give the gate: two clusters, four sprout machines, the
UAT CA, name resolution, a `vmctl.sh`, and the files in the Shared contract's
shapes.

**Status: the rig has never been run.** The agent that wrote it had no
access to a Docker registry, so no image was pulled or built, no cluster was
created and nothing was installed. What was checked is listed under
[Tests](#tests). Expect fix rounds on the first real run.

## What the rig proves, and what it cannot

| Proves (once it runs green) | Cannot prove |
|---|---|
| The hub scripts install the **published** charts of a `release_tag` on upstream Kubernetes, core first, then the DMZ | **Windows**: there are no Windows sprouts. Every scenario that ran on a Linux sprout gets a SKIP line for Windows (see [run.sh](#runsh)) |
| One UAT CA on both clusters, the certificates' SANs for the public and private names, sprouts pinning the CA | **Network separation**: the hubs and the sprouts share one Docker network. A sprout can reach core, so X3 is skipped by default, and the NSG rules of UAT.1 are not exercised |
| The Keycloak issuer, saasapi's JWKS URL and the token `iss` as one string on the core FQDN, resolved from the host, from pods in both clusters and from the sprouts | **One machine**: no real latency or separate kernels; a reboot is a container restart (systemd stops and starts, the kernel does not) |
| The real `imas-sprout` deb and rpm installed by `ansible/site.yml` over SSH, enrolment through Envoy, the same sproutid in both tenants (S2) | **Azure Bastion**, `uat/access/tunnels.sh` and the Azure `vmctl.sh`, the Private DNS zone, public IPs and FQDNs, a LoadBalancer |
| The smoke and core scenarios on Ubuntu 24.04 and AlmaLinux 9 in two tenants; the harness, `uatreport`, the no silent green rule, the `vmctl.sh` interface | **k0s** itself: kind is not k0s (kindnet, not kube-router; kubeadm, not k0s's CoreDNS patch) |
| The charts' NetworkPolicies in each cluster (kind v0.24 and later enforce them), with cross-cluster traffic arriving from the other node's address, as on Azure | RHEL (AlmaLinux stands in, as on Azure), sizing, load, HA |

## Files

| File | What it is |
|---|---|
| `up.sh` | Brings the rig up: network, clusters, add-ons, CA, names, sprouts, the material files, the hub installs, enrolment. Every step is safe to repeat |
| `down.sh` | Removes everything `up.sh` made, and nothing else |
| `run.sh` | Brings the rig up if needed, runs `uat/tests/run.sh` for `smoke`, `core` or `all`, and reports, adding the Windows and X3 skips |
| `vmctl.sh` | The Access interface's `vmctl.sh`, on Docker |
| `write-material.sh` | Writes `uat.json`, `access.json`, `endpoints.json` and `harness.json` |
| `lib.sh`, `config.env`, `versions.env` | Shared helpers, settings, version pins |
| `sprouts/*.Dockerfile`, `sprouts/files/` | The sprout machines: systemd and sshd on the official Ubuntu 24.04 and AlmaLinux 9 images |
| `tests/` | `test_lite.sh` with stubbed `docker`, `kind`, `kubectl` and the rest; `lite_test.go` runs it under `go test` |

## Why kind

The clusters are [kind](https://kind.sigs.k8s.io) (Apache-2.0,
kubernetes-sigs). k3d (MIT) was the alternative. kind was chosen because:

- it runs upstream Kubernetes with kubeadm, stock CoreDNS and kube-proxy,
  which is closer to k0s's upstream components than k3s;
- k3s, under k3d, ships Traefik and ServiceLB, which claim 80 and 443 on the
  node unless turned off, and core's edge needs 443 as a hostPort;
- k3s's add-on controller rewrites the CoreDNS manifest, as k0s does, while
  kind leaves the CoreDNS ConfigMap alone, so the hosts block stays;
- kind ships a default StorageClass (local-path) and the `portmap` CNI
  plugin that hostPorts need, and its kindnet enforces NetworkPolicy (v0.24
  and later).

Its one drawback here: a kind cluster joins a chosen Docker network only
through the `KIND_EXPERIMENTAL_DOCKER_NETWORK` environment variable, which
kind documents as experimental (k3d has a `--network` flag).

## Prerequisites

| Tool | Why | Notes |
|---|---|---|
| Docker (Engine on Linux, or Docker Desktop) | everything | cgroup v2 for the systemd containers |
| kind v0.30 or later | the two clusters | `versions.env` pins the node image |
| kubectl | `up.sh`, the hub scripts | within one minor version of the kind node image (Kubernetes 1.34) |
| helm 3.8 or later (or 4) | the hub scripts | `helm pull oci://` needs 3.8 |
| jq, curl, openssl, awk, sha256sum, base64, tar | the scripts | |
| ssh, ssh-keygen | enrolment over SSH | |
| Go | `uat/tests/run.sh` builds the tests; `uat/hub/core` builds `nk` | the repository's Go version |
| python3, ansible-core 2.15 or later | `uat/enroll` | `ansible-galaxy collection install -r uat/enroll/requirements.yml` |
| sudo | the hub names in `/etc/hosts` | or `--hosts-file none` and add the lines yourself |

Outbound internet from the host and the containers: the release's charts
(GHCR, as OCI charts, pulled anonymously: the owner makes each chart package
public once), images (GHCR, quay.io, Docker Hub), the `imas` CLI
(GitHub releases), the sprout packages (Buildkite `imasdeb`, `imasrpm`), and
the Ubuntu and AlmaLinux mirrors.

Two kind clusters need more inotify instances than many distributions give
(`up.sh` warns):

```sh
sudo sysctl fs.inotify.max_user_instances=512 fs.inotify.max_user_watches=524288
```

**Rough size, a guess, not measured:** 8 CPUs, 16 GiB of memory for Docker,
40 GB of free disk. The core cluster dominates: PXC, Keycloak (Java), MinIO,
OpenBao, Valkey, farmer and saasapi, plus cert-manager and a control plane in
each cluster. The four sprouts add a few hundred MiB in all.

One rig per machine: the network, the cluster names, the host ports 443 and
8443 (in published mode) and the private names are per machine.

## Running it on Linux

```sh
uat/lite/up.sh --release-tag v0.1.0-rc.4        # a guess: 20 to 40 minutes the first time
uat/lite/run.sh smoke
uat/lite/run.sh core
uat/lite/run.sh core C2 X4                       # some scenarios
uat/lite/down.sh
```

`run.sh` brings the rig up itself when it is not up for the release:
`uat/lite/run.sh --release-tag v0.1.0-rc.4 smoke` on a clean machine does
everything. The state (kubeconfigs, keys, the hub scripts' outputs, reports)
goes to `~/.local/state/imas-uat-lite/<run_id>/` (`--state` to change it),
outside the repository because it holds secrets. Reports are under
`<state>/report/`.

On Docker Engine the host reaches the containers' addresses, so the hub
names resolve to the kind nodes' addresses on the host as well (host access
`direct`).

## Running it on WSL2

The owner runs WSL2 with systemd enabled. There are two ways.

**Docker Desktop with the WSL2 backend (recommended).** Turn on WSL
integration for the distribution. The containers then run in Docker
Desktop's own VM, not in your distribution, so the distribution's systemd
setting does not matter to the sprout containers; what they need is
Docker Desktop's cgroup v2 and privileged containers, which it gives.

- Container addresses are not reachable from the distribution, so `up.sh`
  detects Docker Desktop and switches to host access `published`: kind
  publishes core's 443 and the DMZ's 8443 on `127.0.0.1`, and the hub names
  resolve to `127.0.0.1` on the host. Inside the clusters and the sprouts
  they still resolve to the nodes. Ports 443 and 8443 must be free on
  Windows (IIS and some VPN clients take 443).
- Give the WSL2 VM the memory: in `%UserProfile%\.wslconfig`, under
  `[wsl2]`, set `memory=16GB` and `processors=8`, then `wsl --shutdown`.
- WSL rewrites `/etc/hosts` at start when `generateHosts` is on (the
  default). After a `wsl --shutdown`, run `up.sh` again (it puts the names
  back), or set `[network] generateHosts = false` in `/etc/wsl.conf`.

**Docker Engine inside the distribution.** With `[boot] systemd=true` in
`/etc/wsl.conf` you can run Docker Engine in the distribution, which is
then a Linux host (host access `direct`). The systemd containers need cgroup
v2: `stat -fc %T /sys/fs/cgroup` must print `cgroup2fs`. If it prints
`tmpfs` (the hybrid layout), add `kernelCommandLine = cgroup_no_v1=all`
under `[wsl2]` in `.wslconfig` and `wsl --shutdown`.

**Fallback: the distribution as one Ubuntu sprout.** If the sprout
containers never boot (`up.sh` stops at "systemd boot"), an Ubuntu 24.04
distribution with systemd can stand in for one sprout:

1. Install `openssh-server`, listening on a port Windows does not use (for
   example 2222), and run `uat/lite/up.sh --release-tag <tag> --skip-hubs`
   once with the settings below, so it makes the rig's key
   `<state>/ssh/id_ed25519`.
2. Add `<state>/ssh/id_ed25519.pub` to `~root/.ssh/authorized_keys` (or to a
   user with passwordless sudo, named in `LITE_HOST_SPROUT_USER`).
3. Run with the distribution as `t1-ubuntu`:

   ```sh
   export LITE_SPROUTS=t1-ubuntu LITE_HOST_SPROUT=t1-ubuntu LITE_HOST_SPROUT_PORT=2222
   uat/lite/up.sh --release-tag v0.1.0-rc.4
   uat/lite/run.sh smoke
   ```

   Other sprouts can stay containers if some of them do boot
   (`LITE_SPROUTS="t1-ubuntu t2-ubuntu"`).

What it costs: tenant 2 has no Ubuntu sprout, so S2 has no pair; the
distribution cannot be rebooted by `vmctl.sh restart` (it exits 255, so L1
cannot run); and the distribution keeps the `imas-sprout` package and the
repository the role added (`ansible/roles/imas_sprout/tasks/repo_apt.yml`)
until you remove them (`sudo apt-get purge imas-sprout`, then the
`imas-*` files under `/etc/apt/sources.list.d` and `/etc/apt/keyrings`).

## What up.sh builds

1. **The network.** One Docker bridge network, `imas-uat-lite`,
   `172.29.88.0/24`, labelled `imas.io/purpose=imas-uat-lite`. The sprouts
   have fixed addresses `.21` to `.24`; Docker gives the kind nodes addresses
   from `.128/25`.
2. **The clusters.** kind clusters `dmz` and `core` (nodes
   `dmz-control-plane`, `core-control-plane`) on that network, with their own
   pod and Service ranges. The DMZ's API server gets the NodePort range
   `8442-8443` (UAT.2's `config.env`), through a kubeadm patch written for
   both kubeadm API versions; `up.sh` checks the API server took it. Core
   keeps `30000-32767`.
3. **Add-ons.** kind's default StorageClass (`standard`, local-path) is
   checked, and cert-manager is applied from UAT.2's pinned, checksummed
   manifest (`uat/k0s/versions.env`).
4. **The UAT CA.** One self-signed root (ECDSA P-256, as UAT.2's), valid
   `LITE_CA_DAYS` (30) days because a local rig lives longer than an Azure
   run. It goes into `cert-manager/imas-uat-ca` on both clusters, with the
   ClusterIssuer `imas-uat-ca` from UAT.2's template. Its key stays in
   `<state>/sensitive/ca` (mode 600) so a re-run keeps the CA the sprouts pin;
   `up.sh` refuses a CA that expires within a day.
5. **Names**, so the issuer and the certificates work everywhere:

   | Name | Host | Pods (both clusters) | Sprouts |
   |---|---|---|---|
   | `uat<run_id>-core.imas-lite.test` (the issuer's host), `core.uat.imas.internal` | hosts file block: the core node (direct) or `127.0.0.1` (published) | CoreDNS `hosts` block: the core node | `--add-host`: the core node |
   | `uat<run_id>-dmz.imas-lite.test`, `dmz.uat.imas.internal` (sprouts' `farmerinterface`) | the DMZ node, or `127.0.0.1` | the DMZ node | the DMZ node |

   The hosts file block is between `# BEGIN imas-uat-lite <run_id>` and
   `# END imas-uat-lite <run_id>`; every other line is kept, and the file is
   rewritten in place (with `sudo` when it is not writable). `.test` is
   reserved for testing (RFC 2606). Keycloak's issuer is
   `https://uat<run_id>-core.imas-lite.test/realms/imas-uat` from everywhere,
   and that is the token's `iss`.
6. **Sprouts.** Images `imas-uat-lite/sprout-ubuntu` and `sprout-alma` built
   from `sprouts/`; containers `imas-lite-<vm>` with hostname `<vm>`, started
   with what systemd needs (`--privileged --cgroupns=private --tmpfs /run
   --tmpfs /run/lock`, `STOPSIGNAL SIGRTMIN+3`), sshd on
   `127.0.0.1:22221` to `22224`, and the rig's per-run SSH key authorised
   for root. Each makes its own SSH host keys on first boot. Nothing of imas
   is in the images: `uat/enroll` installs the published package over SSH
   (owner decision: no docker connection plugin).
7. **The material** (`write-material.sh`), in the state directory:

   | File | Shape | Notes |
   |---|---|---|
   | `uat.json` | the tofu output `uat` | `connection: ssh` for every sprout; `id` is the container (the hubs' is the kind node); `admin_user` root; `private_dns_zone`; no `public_ip`, since nothing has one and X3 must not probe a made-up address |
   | `access.json` | the Access interface's | each sprout's `host` `127.0.0.1` and `ssh_port`; each hub's `kube_port` (kind's API server port) |
   | `endpoints.json` | what `uat/hub/core` and `uat/hub/dmz` read | both readers' key names: `cluster_issuer` and `ca.cluster_issuer`, `private_dns_zone` and `*.private_fqdn`; `core.exposure: hostPort` |
   | `harness.json` | `uat/tests/harness` Settings | `envoy_url` and `sprout_envoy_address` on 8443, the rig's `vmctl.sh`, `bind_tenant` |
   | `uat-ca.pem`, `kube/*.kubeconfig`, `rig.json` | | `rig.json` records the settings and what was made, for `down.sh` |

8. **The hubs**, from the release named by `--release-tag`:
   `uat/hub/core/install.sh <kube/core.kubeconfig> <endpoints.json> <state> <tag>`,
   then `uat/hub/dmz/install.sh --seeds-from-kubeconfig <kube/core.kubeconfig> ...`,
   then `uat/hub/core/finish.sh` (same arguments as core's install.sh; farmer
   and saasapi need the DMZ bus), then `uat/hub/dmz/check.sh --connect <the DMZ node or 127.0.0.1>`. A
   release already installed is not installed again (`--reinstall`).
9. **Enrolment**: first each sprout's package index is refreshed
   (`apt-get update`, or `dnf clean all` and `dnf makecache`), so a release
   published since the sprout last looked is found (a failure only warns).
   Then `uat/enroll/enroll.sh --core-state <state> ...` with the
   rig's `uat.json`, `access.json` and SSH key; `tenants.json` and
   `sprouts.json` are linked into the state directory, which is the tests'
   material directory (`IMAS_UAT_DIR`).

## vmctl.sh

Same interface as `uat/access/vmctl.sh`:

```sh
uat/lite/vmctl.sh <uat.json> restart|stop-sprout|start-sprout <vm>
uat/lite/vmctl.sh <uat.json> run <vm> <command...>
```

`run` is `docker exec <container> bash -c` as root (on a hub, with
`KUBECONFIG=/etc/kubernetes/admin.conf`, so the harness's default farmer,
bus and Envoy restarts work on the kind node); it prints the streams, then
`vmctl.sh: exit_code=N` on stderr, and exits N. `restart` is `docker
restart`, then a wait until systemd reports running (and, on a hub, the API
server answers); a hub that comes back at another address fails with 255,
because the names no longer match (run `up.sh` again). Exit 2 for a usage
error, an unknown VM or a Windows VM; 255 when Docker cannot run the
command. The host sprout of the WSL2 fallback is reached over SSH and cannot
be restarted.

## run.sh

```sh
uat/lite/run.sh [--state DIR] [--release-tag TAG] [--no-up] [--with-x3] smoke|core|all [ids...]
```

It runs `uat/tests/run.sh` unchanged, with `IMAS_UAT_DIR` the state
directory, `IMAS_UAT_VMCTL` this `vmctl.sh`, `IMAS_UAT_RELEASE_TAG`, and the
core kubeconfig and endpoints for `bind-tenant.sh`. Then, under each run's
summary (and in `<report>/lite-summary.txt`), it adds lines that are never
counted as passed:

- **Windows.** For every scenario that has a line on a Linux sprout and none
  on Windows, one `SKIP <id> windows <tenant>` line with the reason. The
  harness leaves Windows out silently when `uat.json` has no Windows sprout
  (finding 2), so the rig says it.
- **X3.** Without ids, `core` and `all` pass every id of the tier except X3
  to `uat/tests/run.sh` and add `SKIP X3` with the reason: the rig has no
  network separation, so a sprout can always reach core. `--with-x3` runs it
  anyway (it will fail).

`all` is two runs, because ingredient ids cannot share a run with the
others: the static scenarios of every tier, then `ingredients`. The
lifecycle and ingredients tiers need UAT.7. The exit status is
`uat/tests/run.sh`'s; the last line says `RIG RESULT: PASS on the Linux
sprouts only` or `RIG RESULT: FAIL`.

## Settings

Environment variables, with defaults in `config.env` and `versions.env`. The
ones you may want: `LITE_RUN_ID` (lite01), `LITE_STATE`, `LITE_HOST_ACCESS`
(auto, direct, published), `LITE_PUBLISH_ADDRESS` (127.0.0.1),
`LITE_HOSTS_FILE` (/etc/hosts, or none), `LITE_SUDO` (sudo), `LITE_SUBNET`,
`LITE_SPROUTS`, `LITE_HOST_SPROUT` and its port and user, `LITE_CA_DAYS`,
`LITE_WAIT_TIMEOUT`. `up.sh` saves them in `rig.json`; later runs of
`up.sh`, `run.sh` and `down.sh` on that state use the saved ones, and `up.sh`
refuses to switch host access on a built rig. `LITE_CORE_INSTALL`, `LITE_CORE_FINISH`,
`LITE_DMZ_INSTALL`, `LITE_DMZ_CHECK`, `LITE_ENROLL`, `LITE_TESTS_RUN` and
`LITE_UP` exist for the tests.

## Cleaning up

```sh
uat/lite/down.sh                 # containers, clusters, network, hosts block, state
uat/lite/down.sh --keep-state    # keep <state> (reports, keys) for a look
uat/lite/down.sh --images        # also the sprout images
```

`down.sh` removes only what is the rig's: containers with its labels, kind
clusters whose node is on its network, the network with its label, its
block in the hosts file, and a state directory holding `rig.json`. It is
safe to repeat. By hand, if it cannot run:

```sh
docker rm -f $(docker ps -aq --filter label=imas.io/purpose=imas-uat-lite)
kind delete cluster --name dmz; kind delete cluster --name core
docker network rm imas-uat-lite
sudo sed -i '/^# BEGIN imas-uat-lite/,/^# END imas-uat-lite/d' /etc/hosts
rm -rf ~/.local/state/imas-uat-lite
```

Images pulled by kind and Docker (the node image, the base images, the
charts' images inside the nodes go with the clusters) stay until `docker
image prune`.

## Licences

Nothing here is linked into imas, shipped or a dependency of a released
artifact; all of it runs locally for tests only. Flagged, as CLAUDE.md asks:

| Piece | Licence | Note |
|---|---|---|
| kind | Apache-2.0 | a host tool |
| kind node image `kindest/node` | Apache-2.0 (Kubernetes, containerd, runc, kindnet) on a Debian base | **Flagged**: the Debian base carries GPL and other licences; pulled and run unmodified |
| kind's local-path provisioner and its helper image | Apache-2.0 provisioner; the helper image's base carries its own licences | **Flagged**, like UAT.2's busybox: run unmodified, UAT only |
| `ubuntu:24.04` (Docker Official Image, Canonical) | packages under GPL, LGPL, MIT, BSD and others; Ubuntu trademark policy | **Flagged**: base of the Ubuntu sprout image, built and run locally |
| `almalinux:9` (Docker Official Image, AlmaLinux OS Foundation) | packages under GPL, LGPL, MIT, BSD and others; AlmaLinux trademark | **Flagged**: base of the AlmaLinux sprout image, built and run locally |
| systemd, OpenSSH, Python, sudo (installed into the sprout images) | LGPL-2.1+, BSD-style, PSF, ISC-style | part of the base OS flag |
| cert-manager | Apache-2.0 | already in the Shared contract (UAT.2's pin) |

No Go dependency is added (`lite_test.go` uses the standard library and
`uat/tests/harness`).

## Tests

```sh
bash uat/lite/tests/test_lite.sh     # 293 checks, stubbed docker/kind/kubectl/helm
go test ./uat/lite/                  # the same, plus shellcheck, yamllint, harness parsing
```

`tests/test_lite.sh` runs every script against stubs (`tests/stubs`) that
keep containers, networks and clusters as JSON files, and stand-ins for the
hub scripts, enrolment and the test runner (`tests/fake`). It covers
argument handling and refusals; the network, the kind configs (NodePort
range for both kubeadm API versions, pod ranges, published ports), the
add-ons, the CA and ClusterIssuer, the CoreDNS block, the hosts file block
(kept lines, one block, removal); the sprout containers' `docker run`
arguments and builds; the four material files field by field; the order and
arguments of the hub installs, the check and enrolment; re-runs, failures
and the stop points; direct and published host access; the host sprout
fallback; `vmctl.sh` (exit codes, streams, quoting, hub kubeconfig, service
commands, restart waits, timeouts, a hub that moved, a stopped container,
the SSH path); `down.sh` (only the rig's things, repeatable, a network
still in use); `run.sh` (the ids passed for each tier, X3 and Windows skip
lines, exit status, bringing the rig up). It also feeds the generated files
to the **real readers, unchanged**: `uat/hub/dmz/lib.sh`'s
`dmz_load_endpoints`, `uat/hub/core/lib/common.sh`'s `load_endpoints`, and
`uat/enroll/gen-inventory.py` (same sprout IDs in both tenants, the SSH
ports, root login, Envoy's private name). `lite_test.go` also parses
`uat.json` with `harness.ParseUAT` and decodes `harness.json` strictly into
`harness.Settings`, as the harness does.

**Not run:** Docker, kind, a cluster, an image build (no registry access;
hadolint was not available either), the hub installs, enrolment, the test
suite against the rig. The kubeadm patch shape, kind's node image tag (the
digest is for the owner to add), the systemd containers on Docker Desktop
and on WSL2, and the published-port path are all unverified.

## Findings for the other briefs (nothing outside uat/lite was changed)

1. **`core.exposure` (UAT.2 and UAT.3b).** `uat/k0s/bootstrap.sh` writes
   `core.exposure: "hostPorts on the uat/hub/core edge, no node ports"` into
   its `endpoints.json`, and `uat/hub/core/lib/common.sh` refuses any
   `core.exposure` other than `hostPort`. If UAT.6 hands UAT.2's
   `endpoints.json` to `uat/hub/core/install.sh`, the install stops at its
   first line. The rig writes `hostPort`. One of the two should change.
2. **Windows silently absent (UAT.5, UAT.7).** When `uat.json` has no
   Windows sprout, the per-OS loops in `uat/tests` skip it without a line
   (`runByFamily`, S2, R3 and others `continue`), so C1 ("all three OS")
   passes with no Windows line. The rig adds the SKIP lines itself; the
   harness could record a written skip per missing OS instead.
3. **Envoy's port in the harness (UAT.5, UAT.6).** The harness's default
   `envoy_url` is `https://<dmz fqdn>` (port 443) and X3's control defaults
   to it, but Envoy is on 8443 (owner decision). The rig sets `envoy_url`
   and `sprout_envoy_address` in `harness.json`; the Azure workflow must do
   the same, or the default should use `dmz.ports.envoy`.
4. **Two key names for one thing (UAT.3a, UAT.3b).** `uat/hub/dmz` reads
   `cluster_issuer` and `private_dns_zone`; `uat/hub/core` reads
   `ca.cluster_issuer`, `dmz.private_fqdn` and `core.private_fqdn`. Today
   both default to the same values, so a file with either set works; a
   changed issuer or zone in only one key would split the hubs. The rig
   writes both.
5. **Windows-only ingredient cases (UAT.7, not merged).** With no Windows
   sprout, `Fleet.EachSprout` fails a scenario ("no sprouts match") rather
   than skipping it. So a Windows-only case would show as FAIL on the rig,
   never as passed, but not as the SKIP with a reason the brief asks for.
   UAT.7's runner should skip a case that has no sprout of its OS, with that
   reason; the rig's run.sh then needs no change.

## Open questions

1. **X3 on the rig.** Skipped by default, with the reason. The rig could
   model separation with a second Docker network for the sprouts and the
   DMZ node only (Docker isolates bridge networks from each other), at the
   cost of the DMZ node having two addresses. Worth it?
2. **The kind node image digest** in `versions.env`: for the owner to pin on
   the first run.
3. **Privileged sprout containers.** systemd in Docker needs them here (as
   Molecule's containers in `ansible/molecule`). The sprouts then run as
   root with the host's devices; run the rig only on a machine a test job
   may have that on.
4. **One rig per machine** is assumed (fixed network, cluster names and host
   ports). Enough?
