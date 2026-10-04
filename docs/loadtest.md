# Load and latency harness (`tools/loadtest`)

`tools/loadtest` opens N simulated sprout connections to a bus and measures
what requirements 1, 7 and 10 (`docs/design/requirements.md`) need a number
for:

| | What it reports | For |
|---|---|---|
| (a) | Connect rate, peak connects per second, failed attempts by reason, sprouts that never connected, connections dropped while holding | Requirement 1 (1M endpoints), 7 (horizontal scale) |
| (b) | `test.ping` round trip: p50, p95, p99, max, timeouts, compared with 300 ms | Requirement 10 |
| (c) | A bus node restarted mid-run (the whole bus when there is one node): time to full reconnect, peak reconnects per second, peak reconnect attempts per second | Phase 2 exit criterion of `docs/design/imas-1m-scale-plan.md` |
| (d) | Bus memory, CPU, connections, subscriptions and slow consumers per node; CPU and RSS of local processes (the generator, the local bus, core if you name its PID) | Sizing; whether the generator or the bus was the bottleneck |

It is a Go program in the main module (no CGO, no dependency the module
did not already have). It has never been run at 1M, and a run on a laptop
or a CI runner says nothing about production capacity: see
[What a result proves](#what-a-result-proves-and-what-it-does-not).

## Quick start

```sh
go build -o loadtest ./tools/loadtest

# The CI smoke run: 200 sprouts, local bus, one restart, about 40 s.
./loadtest -smoke

# 1000 sprouts against a local bus, 60 s hold, one restart, JSON result.
./loadtest -json result.json
```

The exit status is 0 when every check passed, 1 when a check failed or the
run was cut short, and 2 for a usage error. The text report goes to stdout,
progress to stderr.

## How the simulated sprouts authenticate: the fixture path

Real enrollment (`POST /v1/enroll`) costs a join-token check, a PXC write,
an Account re-sign and push, and a gateway JWT from OpenBao transit per
sprout. That is the enrollment path's load, not the bus's, and it is heavy
above about 10,000 sprouts. So the harness **mints the credentials itself**,
from the same seeds the bus and core hold, in the shape `internal/pki`
gives them:

- a **load-test tenant Account**, signed by the operator signing key, with
  its own delegated signing key (as `ensureTenantAccountMaterial` builds a
  tenant Account);
- one **User JWT per sprout**, signed by that signing key, naming the
  Account as issuer, with the sprout's own grants (a copy of
  `sproutPermissions`: publish its announce, facts, cook events, box key
  submission and logs; subscribe to `imas.sprouts.<id>.>`);
- one **core User** in the same Account with core's per-tenant grants (a
  copy of `allowAllPermissions`), used by the requesters that play core;
- the Account is pushed to the bus as core pushes it: a request on
  `$SYS.REQ.CLAIMS.UPDATE` from a SYS account user. The harness's SYS
  connection pushes it again whenever it reconnects, as core's
  `PushAllAccounts` does.

Each simulated sprout then connects the way `cmd/sprout` does: TLS pinned to
the bus CA, the User JWT plus a signature over the server nonce, discovered
servers ignored, unlimited reconnects with the sprout's full-jitter backoff
(`internal/natsretry`, same `busreconnectbase` and `busreconnectcap`
defaults). On connect it does what `natsInit` does on the bus: publishes its
announce and facts (this host's facts, collected once) and subscribes to the
same seven subjects. It answers `test.ping` with the sprout's own handler
(`test.SPing`) and `facts.request` with the facts; the other five
subscriptions only carry the bus-side interest.

So per connection the bus does the same work as for an enrolled sprout: TLS
handshake, JWT and nonce verification against the Account's signing key,
permission load, seven subscriptions.

The harness checks the copied grants against `internal/pki`'s exported
helpers in its tests, and a test checks the bus refuses a simulated sprout
that subscribes to another sprout's subject. A grant added to
`sproutPermissions` still has to be added to `tools/loadtest/fixture.go`
by hand: the function is unexported.

### What the fixture path does not test

- **Enrollment and refresh**: `POST /v1/enroll`, `/v1/refresh`, the join
  token, PXC, OpenBao transit. A fleet-wide re-enrollment is not simulated.
- **Envoy and the websocket path**: sprouts here dial the bus's TLS listener
  directly. Envoy's `jwt_authn` check of the gateway JWT on each websocket
  handshake, and Envoy's own CPU and connection limits, are not exercised.
  (`-servers` accepts `wss://` URLs, but no gateway JWT is sent, so Envoy
  would refuse them.)
- **Core**: no farmer process is in the loop. The requesters are a stand-in
  with core's User shape; core's API, RBAC, PXC reads and its queue group
  are not measured, and neither is core's handling of thousands of announce,
  CONNECT and DISCONNECT events (internal/heartbeat, Valkey).
- **A realistic tenant Account**: a real tenant's Account JWT carries a
  revocation entry per denied or rejected sprout; the load-test Account
  carries none, so it is smaller.
- **Many tenants**: every simulated sprout is in one Account (one per
  generator). Requirement 1's tenant mix is not modelled.
- **Real sprout work**: no cook, `cmd.run`, shell, log shipping or
  self-update traffic. Only the startup publishes and `test.ping`.
- **Real hosts and networks**: one generator process holds thousands of
  connections from a handful of IP addresses, without the latency, loss or
  NAT and proxy behaviour of a real fleet.

## Running against a local bus

Without `-servers` the harness generates a throwaway trust chain and starts
a one-node bus as its own child process, built the way `cmd/farmerbus`
builds a single node (`pki.ConfigureBusNats`, the same logger with NATS
debug and trace on). The child is a separate process so that restarting it
disconnects every sprout and so that varz reports the bus's memory and CPU,
not the generator's. Its log is `bus.log` in `-workdir`.

The restart (`-restart local`, the default here) sends SIGTERM (graceful,
like a pod delete) or, with `-restart-signal kill`, SIGKILL; `-restart-downtime`
keeps the bus down for a while before starting it again. A node's resolver
directory survives the restart, as a bus pod's volume does.

The local bus does not have the clustered bus's routes or fence
(`cmd/farmerbus/cluster.go`, `fence.go`); for those, run against deployed
nodes.

`-bus-trace=false` starts the local bus with NATS debug and trace off, to
measure what they cost: `cmd/farmerbus` always turns them on, and although
the internal logger drops them at the default level, nats-server still
builds a trace line for every message before handing it over.

## Running against a deployed bus

```sh
./loadtest \
  -servers tls://bus-0.example:5406,tls://bus-1.example:5406,tls://bus-2.example:5406 \
  -ca bus-ca.pem \
  -operator-signing-seed-file operator-signing.nk \
  -sys-account-seed-file sys-account.nk \
  -sprouts 10000 -connect-rate 500 -hold 5m -ping-rate 200 \
  -restart cmd -restart-cmd 'kubectl -n imas delete pod <bus-statefulset>-0' \
  -max-full-reconnect 10m -json gen1.json
```

- The two seeds are keys `operator-signing.nk` and `sys-account.nk` of the
  Secret the nats chart mounts (`natsSeeds.secretName`, by default
  `imas-farmer-nats-seeds`). **They let the holder sign any tenant
  Account.** Run the harness only against a bus you are allowed to load,
  from a host you would trust with those keys, and never against
  production. Nothing is written to disk from them.
- `-servers` is the bus client port (the chart's `bus.ports.client`, 5406),
  one URL per node so that sprouts spread and the restart has somewhere to
  go. Through a single load-balanced address a sprout comes back through
  the balancer.
- At the end the harness pushes a locked-out copy of its Account (every
  User revoked, no connections), as a tenant deprovision does, so the
  load-test tenant does not stay live. `-lockout=false` skips that.
- A bus whose nodes are fenced (`/readyz` 503) refuses clients: wait for
  the cluster to be ready before starting.
- With `-restart cmd`, the command runs through `sh -c`; the restart
  window starts when it is run and the first disconnect must follow within
  `-restart-wait`. For a one-node bus, deleting its pod restarts the whole
  bus. For a cluster, deleting one pod restarts one node: only that node's
  sprouts reconnect, to the other nodes or to it once it is back and
  unfenced.

### Core metrics

Neither `cmd/farmer` nor `cmd/farmerbus` exposes a metrics endpoint (no
NATS HTTP monitor port, no Prometheus). The harness reads each bus node's
varz over the SYS account (`$SYS.REQ.SERVER.PING.VARZ`, which every node
answers), and `/proc` for processes on its own host: name core with `-proc
core=<pid>` when core runs beside the generator. In Kubernetes, watch core
with what the cluster has (`kubectl top pod`, the metrics server, or the
node's own monitoring) for the length of the run.

## Running at 10,000 sprouts

One generator is enough.

```sh
ulimit -n 20000
./loadtest -sprouts 10000 -connect-rate 1000 -hold 5m -ping-rate 200 -after 2m -json 10k.json
```

Against a local bus, give the host 4 or more cores and 4 GiB or more:
generator and bus share it, which the generator's and the bus's CPU rows
show. Against a deployed bus, run the generator on its own host in the same
network as the bus.

## Running at 100,000 sprouts

This needs several generators and a bus that can hold the connections.

**The bus.** Each node accepts at most `bus.maxConnections` clients
(`busmaxconnections`; 65,536 by default, nats-server's own default), and
the default 512Mi memory limit is OOM-killed far sooner, at a few
thousand connections. Size `bus.resources` and `bus.maxConnections`
together, as the nats chart README's "Connection limit" section
describes. With one node of a cluster restarted, the remaining nodes must
hold its sprouts too, so give each node room for
`sprouts / (replicaCount - 1)`. The harness reports a refusal at the
limit as "refused during TLS (a bus at its connection limit does this)":
on the TLS-only listener a client never sees nats-server's
`maximum connections exceeded` message. Against the local bus,
`-bus-max-connections` sets the same limit. Also check the nodes' file
descriptor limit.

**The generators.** One generator process holds about 20,000 to 25,000
connections comfortably. Size them from your own smaller run: the report
prints the generator's RSS growth per connection held. (As an order of
magnitude only: a 5,000-sprout run on a 4-core development VM showed about
50 KiB per connection on the generator and 80 to 90 KiB per connection in
the bus's varz memory.) For each generator:

| Resource | For 25,000 sprouts |
|---|---|
| CPU | 4 cores (TLS handshakes during ramp and reconnect) |
| Memory | 4 to 8 GiB |
| File descriptors | `ulimit -n 30000` or more |
| Local ports | about 28,000 per source IP and bus address with the default `ip_local_port_range`; widen it (`sysctl net.ipv4.ip_local_port_range="1024 65000"`), list several bus nodes in `-servers`, or give the host several addresses and pass them with `-source-ips` |
| Clock | NTP-synchronised: merged per-second series assume it |

**Running them together.** Give each generator its own `-id-prefix` and
`-tenant` (the defaults are random, which is enough), the same `-servers`,
the same `-hold`, and its own `-json`. Exactly one generator triggers the
restart (`-restart cmd`); the others watch for it (`-restart observe`) and
measure their own sprouts' way back:

```sh
# Generators 2 to 4, started first:
./loadtest -servers ... -sprouts 25000 -connect-rate 500 -hold 10m \
  -restart observe -restart-wait 20m -json gen2.json

# Generator 1, started last, once the others have connected:
./loadtest -servers ... -sprouts 25000 -connect-rate 500 -hold 10m \
  -restart cmd -restart-cmd 'kubectl -n imas delete pod <bus-statefulset>-0' \
  -json gen1.json

# Then, anywhere:
./loadtest merge -max-full-reconnect 10m -json all.json gen1.json gen2.json gen3.json gen4.json
```

An observer's latency window must end before the leader restarts, so start
the leader last and with the same `-hold`. `merge` adds the counts, merges
the latency histograms exactly, and takes the restart window from the
earliest first disconnect to the latest full reconnect across generators.

## Reading the result

- **(a)** "connected N of N" and no failure reasons is the pass. A
  connect rate well below `-connect-rate`, or the generator's CPU at its
  core count during "connect", means the generator, not the bus, set the
  pace.
- **(b)** The round trip is requester to bus to sprout and back. Requests
  go at a fixed rate; when `-ping-concurrency` requests are already in
  flight, a tick is skipped and counted rather than queued. Skips mean the
  bus (or the generator) was not keeping up.
- **(c)** Time to full reconnect runs from the first disconnect to the
  moment every sprout that was connected before the restart is connected
  again, held for `-settle`. It is **dominated by the sprout's backoff**,
  not by the bus: every failed attempt doubles the ceiling of the next
  random wait (2 s, 4 s, 8 s, up to 5 minutes), so a bus that is down for a
  few seconds can leave the last sprouts waiting tens of seconds after it
  is back. That is the jitter doing its job (spreading the herd); the
  number to watch for a storm is the peak attempts per second against the
  bus's CPU during "restart". `-reconnect-base` and `-reconnect-cap` set the
  same knobs the sprout config has.
- **(d)** Varz CPU is nats-server's own reading; the `/proc` CPU is the
  average over each sample interval, in percent of one core. Peaks are
  shown per phase (idle, connect, hold, restart, after).

## The smoke run in CI

`.github/workflows/loadtest-smoke.yml` runs `loadtest -smoke` on every pull
request that touches `tools/loadtest/` and uploads the JSON result and the
bus log. `-smoke` means 200 sprouts on a local bus, a 20 s latency window
at 50 pings per second, a SIGTERM restart with the bus down for 2 s, a 10 s
window after it, and a 170 s deadline. Its thresholds are deliberately
generous, because a shared runner's numbers mean little:

| Check | Smoke limit | Default limit |
|---|---|---|
| Sprouts never connected | 0 | 0 |
| `test.ping` p99, each window | 1 s | 300 ms (requirement 10) |
| `test.ping` without a reply, each window | 1% | 0.1% |
| Sprouts not reconnected after the restart | 0 | 0 |
| Time to full reconnect | 60 s | not checked |

A failing smoke run means the harness or the reconnect path broke, not
that the bus got slow.

## What a result proves, and what it does not

A run proves, for the bus it ran against, the hardware it ran on and the
fixture path: that this many sprout-shaped connections could be opened at
this rate and held; that `test.ping` round trips had this distribution at
this request rate while they were held; and that after this restart they
all came back within this time, with this peak reconnect rate.

It does not prove:

- **Requirement 1 (1M)**: nothing has run at 1M, and per-node and
  per-generator figures do not extrapolate linearly (resolver sync, route
  fan-out of subscription interest, and Envoy all grow with the cluster).
- **Requirement 10 as the user sees it**: the 300 ms there is a response to
  a sprout; this measures the bus leg only. A CLI or SaaS API request adds
  core's API, RBAC and PXC time, and Envoy's hop for a websocket sprout.
- **Requirement 7 (core scales out)**: core is not in the loop.
- **Production capacity**: the bus here runs on whatever host or cluster
  the run used, under a single synthetic tenant.
- **The scale plan's Phase 2 exit criterion**, unless the run had hundreds
  of thousands of sprouts on a clustered bus on production-shaped
  infrastructure.

A smoke run or a laptop run proves only that the harness works. Do not
quote their numbers as scale or latency results.
