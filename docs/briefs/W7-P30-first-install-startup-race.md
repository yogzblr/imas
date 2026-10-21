# W7 + P30 - clean first install of the core hub takes ~10 min and misses the rollout deadline

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
