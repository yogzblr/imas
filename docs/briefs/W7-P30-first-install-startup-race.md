# W7 + P30 - clean first install of the core hub takes ~10 min and misses the rollout deadline

Source: the owner's brief in the Claude Project "SaaS based machine manager"
(`briefs/W7-P30-first-install-startup-race.md`), pasted unchanged below down
to "Brief corrections"; read `docs/briefs/ORCHESTRATOR.md` first (zero open
items, repo-wide search, brief errors decided by its rule 6). W7 and P30 are
separate units: W7 (UAT only) first, P30 (product) after it.

Evidence: UAT Run 2 #5 (2026-10-21, env imas-uat-tnbx7rqt). W6 worked (login/tunnel age 1m at "core hub, second half"). The step then failed: "deployment imas-core-farmer exceeded its progress deadline" (0 of 2 available). Farmer pods became Ready at 05:19:34Z, seconds AFTER the workflow gave up.

Measured on the live environment:
- farmer Deployment: progressDeadlineSeconds 600; startupProbe GET /health (HTTPS, port api), periodSeconds 5, failureThreshold 60 (= 300 s budget), timeout 1 s.
- First container (started ~05:14:28Z): 05:14:30 wrote 2 Account JWTs to the accounts bucket ("wrote 2 Account JWTs that were missing or older"); 05:14:31 "announcing 2 reconciled Accounts: connecting to the bus: nats: no servers available for connection; the bus loaders will apply it"; pushes to bus resolver logged as errors then "Pushed all 2 Account JWTs"; then NO log lines until 05:16:39, when the SYS listener connected and handlers registered ("SYS listener connected: pushed all 1 Account JWTs to the bus"). DMZ bus loader: "accountloader: initial load complete, 2 accounts" at 05:16:29. /health answered 503 from start until the container was killed at 05:19:28 (60 consecutive failures), i.e. it stayed 503 for ~3 min AFTER farmer connected to the bus.
- Second container (started 05:19:29): Ready at 05:19:34, 5 s, bus and accounts already in place.
- DMZ side is healthy: imas-dmz-nats-bus-0 2/2, envoy running. Envoy JWKS fetch of https://10.60.2.4:5405/v1/.well-known/jwks.json failed until ~05:19:33 (farmer API not up) then recovered. The bus's "TLS handshake error: EOF" every 20 s from 10.244.0.1 is a TCP probe on the TLS port: noise.

Interpretation (to be verified in code, not assumed):
1. Chicken-and-egg: the bus is readiness-gated until it holds all accounts; farmer writes the accounts then tells the bus via a plain broadcast event; with no ready endpoint the event is lost and the loader only learns of the accounts on its timer (~2 min here).
2. farmer /health stays 503 after the bus is reachable. Suspect: the startup announce of reconciled Accounts is one-shot (not retried) and health depends on it, so only a restart clears it.
3. Install-time budgets (rollout wait, progressDeadlineSeconds 600, startup 300 s) are shorter than a clean first install.

## W7 (UAT only, small, goes first)
Make the UAT install tolerate a slow first start without touching product code:
- uat/hub/core install script (and DMZ if it has the same pattern): the `kubectl rollout status` / wait timeout for farmer and saasapi to 20 min; find every wait with a short timeout in uat/hub/* and align them (repo-wide search, list them).
- UAT chart values (uat/hub/core values, NOT the chart defaults): progressDeadlineSeconds 1200, farmer startupProbe failureThreshold 120 (10 min at 5 s) so the first container is not killed while the bus is still loading accounts.
- On a timeout, print before failing: pod status, `kubectl describe` events, last 40 farmer log lines, and the DMZ bus/loader tail, so the next failure is diagnosed from the log.
- Tests/stubs updated; docs/RUNBOOK entry "first core install takes up to ~10 min until P30 lands".
- Status fragment zz-W7.md, ORCHESTRATOR row, commit prefix "W7: ". Expect Run 2 to proceed past the core hub with this alone.

## P30 (product fix, separate unit, after reading the code)
1. Find what /health (farmer) checks and why it stayed 503 after the bus connection at 05:16:39. Fix so farmer reports ready within seconds of reaching the bus. If the startup account announce is one-shot, make it retry with backoff until it succeeds, and do not let a failed announce keep /health at 503 once the bus is reachable (the loaders reconcile on their own).
2. bus loader (cmd/farmerbus-loader): while it holds fewer accounts than accounts/index lists (initial load), poll quickly (e.g. every 5-10 s, with jitter) instead of waiting for the normal timer; keep the normal interval once complete. Keep newest-iat-wins and the readiness gating.
3. Tests: unit tests for a farmer started before the bus (health goes ready after the bus appears, without restart) and for the loader's fast initial poll; add a lite-rig or fakestack case if there is a natural place (start order farmer before bus).
4. Docs: P21 slice 2 brief corrections, plan/rig docs. Status fragment zz-P30.md, ORCHESTRATOR row, commit prefix "P30: ", brief corrections list.
Do not change signing, enrolment, or the account-loader trust model. rc.15 stays under test for Run 2; P30 would ship in a later rc.

## Brief corrections (W7, 2026-10-21)

Decided by the order of `docs/briefs/ORCHESTRATOR.md` rule 6 and built that
way. No product code or chart default changed; rc.15 stays under test.

- **Where the farmer and saasapi waits are.** `uat/hub/core/install.sh` does
  not wait for farmer or saasapi (both need the DMZ bus, which is installed
  after it); `uat/hub/core/finish.sh` does, and it already waited 900 s for
  each. So the 600 s that failed Run 2 was not a script timeout but the
  Deployment's progress deadline: `kubectl rollout status` exits at once on
  `ProgressDeadlineExceeded`, whatever its `--timeout`. The 20-minute waits
  are in `finish.sh` (both rollouts, and saasapi's after the registration,
  which was 300 s) and in `acceptance.sh restart` (600 s), all through one
  helper, `first_start_rollout` in `uat/hub/core/lib/common.sh`
  (`FIRST_START_SECONDS=1200`). There is no `uat/lib`: the shared shell
  libraries are `uat/hub/core/lib/common.sh` and `uat/hub/dmz/lib.sh`, both
  searched.
- **`progressDeadlineSeconds 1200` "in the UAT chart values".** The farmer
  chart has no value for it (its Deployment templates render none, so the
  API default of 600 s applies), and adding one is a chart change, outside
  W7. Instead `install.sh` patches farmer's and saasapi's live Deployments
  as soon as helm creates them (`raise_progress_deadlines_as_created`,
  run alongside the farmer install, as the Deployments exist minutes before
  helm returns), and `first_start_rollout` patches again before each wait.
  Helm's three-way merge keeps a field neither manifest sets, so
  `finish.sh`'s `helm upgrade --reuse-values` leaves it. The value is 3600,
  not the brief's 1200 (review of PR 305): the deadline runs from when
  helm creates the Deployment, early in `install.sh`, and farmer cannot
  turn Ready before the rest of `install.sh` and the DMZ install (up to 20
  minutes a wait) have brought up the bus, so 1200 could run out before
  `finish.sh` starts its own 1200 s wait. With 3600
  (`PROGRESS_DEADLINE_SECONDS`), `finish.sh`'s wait is the bound.
  `TestFarmerChartRender` fails if the chart ever renders the field, so the
  patch is revisited then.
- **saasapi's progress deadline too.** The brief names farmer only;
  saasapi's Deployment has the same 600 s default and also waits on the bus
  (it exits at startup without it), so it gets the same deadline and wait,
  and the timeout diagnostics include its containers' logs too.
- **The startup probe at 120 failures and the 20 minutes.** If P30's
  suspicion 2 holds (`/health` clears only on a restart), 10 minutes of
  probe delays that restart rather than avoiding it. Built as the brief
  says, and the budget checked against that worst case: in Run 2 the
  ReplicaSet was created about five minutes before the first container
  started (inferred: the 600 s deadline ran out at about 05:19:30, the
  container started at 05:14:28), so a first container killed after 10
  minutes and a successor Ready in seconds (as at 05:19:34) is Ready about
  15 minutes after the ReplicaSet, inside the deadline and, with the DMZ
  up by then, inside `finish.sh`'s 1200 s wait. Only `failureThreshold` is set in `values/farmer-uat.yaml`; helm
  merges it into the chart's probe (`/health`, HTTPS, every 5 s).
- **The DMZ bus and loader tail.** `finish.sh` had only the core
  kubeconfig. It now reads `DMZ_KUBECONFIG`, by default `dmz.kubeconfig`
  next to the core kubeconfig (the workflow's `$STATE/k0s/` and uat/lite's
  `kube/` layouts), and the workflow passes it explicitly. The tails are the
  bus pods' two containers, `farmerbus` and `loader`, 40 lines each, one
  pod per DMZ node. Without a DMZ kubeconfig the core diagnostics still
  print and the line says why the DMZ tail is missing. Farmer's tail includes
  each container's previous run when it restarted, as the killed first
  container is the one that shows the race.
- **"DMZ if it has the same pattern".** `uat/hub/dmz/install.sh` waits with
  one `--timeout` (helm `--wait`, the bus StatefulSet's and Envoy's
  rollouts, the certificates, the load balancer address). StatefulSets have
  no progress deadline, but the bus turns Ready only once its loader holds
  the Accounts a first core install writes, so its default goes from 10m to
  20m, the same budget. Envoy's chart is the nats chart; its defaults are
  unchanged.
- **The search, and what stays.** Every wait in `uat/hub/*`, the two
  libraries, uat/lite (which runs the same scripts) and `uat.yml`:
  - changed: `finish.sh` farmer and saasapi rollouts 900 s -> 1200 s,
    saasapi after the registration 300 s -> 1200 s; `acceptance.sh restart`
    600 s -> 1200 s; `uat/hub/dmz/install.sh --timeout` default 10m -> 20m;
    farmer's and saasapi's progress deadline 600 s -> 3600 s; farmer's
    startup probe 60 -> 120 failures.
  - kept, not on the bus path: `install.sh` the UAT-only chart's `helm
    --wait` (already 20m), its three certificate waits (300 s; cert-manager
    and the UAT CA issue in seconds), OpenBao 600 s, PXC 900 s, the PXC and
    HAProxy StatefulSets 300 s each (after PXC is ready), Valkey 600 s, and
    the `rollout` default of 600 s for Versity Gateway, RustFS, Keycloak and
    the edge (their Deployments keep the API's 600 s progress deadline, so a
    longer wait could not help, and none needs the bus); `HELM_TIMEOUT` 45m
    (install and finish); `openbao-bootstrap.sh` (1200, 1200, 900, 300, 300,
    1200 and 120 s, all OpenBao); `finish.sh` `REGISTER_WAIT` 600 s (the Job
    runs once saasapi is Ready); `acceptance.sh`'s log retention Job 600 s
    (a CronJob run); the 30 s port-forward waits (`acceptance.sh`,
    `operator-release.sh`); `uat/hub/dmz/check.sh` (the 30 s `openssl`
    timeout and the 65 s enrol bucket refill are protocol checks); uat/lite's
    cluster bring-up waits (`LITE_WAIT_TIMEOUT`, kind, CoreDNS, the
    ClusterIssuer); the workflow's job (350 min) and test step (180 min)
    limits and the 60 s tofu retry pause.
  - the budget: the longer waits add at most 25 minutes to "Core hub,
    second half" and 10 per wait to the DMZ hub, and only on a failing run;
    a slow but successful first start keeps "Core hub, second half" at about
    12 minutes, inside W6's 40-minute phase limit and the job's 350.
