# W6 - Azure login and Bastion tunnels go stale mid-run: refresh at phase boundaries

Source: the owner's brief in the Claude Project "SaaS based machine manager"
(`briefs/W6-azure-auth-age-and-tunnels.md`), pasted unchanged above
"Brief corrections"; read `docs/briefs/ORCHESTRATOR.md` first (zero open
items, repo-wide search, brief errors decided by its rule 6).

Status: ready to dispatch. Product code (rc.15) is NOT affected; UAT workflow/scripts/Ansible only.

## 1. Evidence (UAT Run 2 #4, 2026-10-20; the run's resource group is imas-uat-<its own suffix>, not the earlier run's imas-uat-oy8tj79l)

Job steps (UTC): Azure login (OIDC) 17:23:54 -> tofu apply 17:24:02 (20 min) -> Bastion tunnels opened 17:44:24 -> k0s on hubs 17:44:46 -> Tenants and enrolment (uat/enroll) 18:13:58, failed at ~18:24 -> tests skipped. The workflow already has "Azure login again (before the tests)" and "(before the destroy)" but NOTHING before enrolment.

Symptoms at ~18:19 (login age ~55 min, tunnels ~35 min): Linux hosts had completed 26 tasks (changed=7) over the tunnels; then (a) Windows "Download the imas-sprout installer" read-timed-out after 300 s on both Windows hosts, (b) the next Linux SSH task (imas_verify "Read the sprout's config file", no_log) went UNREACHABLE on all four Linux hosts. Same pattern in the earlier failed run: everything worked for a long while, then all hosts failed together.

Ruled out by direct checks on the live environment (do not re-investigate):
- VM health/CPU: t1/t2-win idle (CPU 0-5 %, burstable credits never depleted, 111 -> 157), WinRM and imas-sprout running, Defender on with current signatures, no stuck process.
- Network/NSG/firewall: from the VM, TCP 443 and a full HTTPS fetch to github.com 0.7 s; the exact NuGet package (imas.sprout.windows.msi 0.1.0-rc.15, 16.7 MB) downloads in 1.0 s via curl.exe.
- The feed has the rc.15 package; windows.yml unchanged since the last green run (2fe395c, 11 Oct); Terraform diff for tenants/Windows VMs: none for a single-node run.
- A FRESH Bastion tunnel from a laptop with a normal az login runs, against the same VM and with the same connection variables (ntlm, https, read timeout 900 s / operation 600 s): win_ping 6.6 s, a 30 s sleep 35 s, win_get_url (the very task that hung in CI) 6.2 s.
- The 11 Oct "green" run (38107290465) per uat/access/README.md exercised only the tunnels of a single-node run, not Windows enrolment.

Inference (strongly supported, mechanism not proven): the runner's Azure CLI session is an OIDC federated login, which cannot silently renew once its token expires (~1 h); `az network bastion tunnel` processes started earlier then fail to open new websocket connections (hang, no refusal), while already-open connections keep working. Failure arrives ~55-60 min after the login in both failed runs.

## 2. Scope

1. New script `uat/scripts/refresh-azure-session.sh` (name may differ) used at every phase boundary: re-run the OIDC login the same way the existing "Azure login again (before the tests)" step does (look at it and reuse its mechanism), then CLOSE and REOPEN the Bastion tunnels through uat/access (so the tunnel processes carry fresh credentials and the inventory ports stay valid; check that tunnels.sh reopens on the same ports when all are free, otherwise regenerate the inventory ports after reopen).
2. Workflow: call it before "Tenants and enrolment" (new step "Azure login again (before enrolment)"), keep the existing re-login before the tests but make it reopen the tunnels too if it does not already, and before the destroy. Check the OIDC token/`permissions: id-token: write` works for repeated logins in the same job.
3. Age guard: each phase start logs "azure login age Xm, tunnels age Ym" (record login/tunnel start times in the state dir). Fail early with a clear message if either exceeds a threshold (default 40 min) at a phase start; also print both ages in the failure-time diagnostic step from W5.
4. Phases that can exceed the token life (enrol with HA, tests) : split at natural boundaries and refresh between; document the maximum safe phase length. Do NOT reopen tunnels mid-Ansible-run.
5. Tunnel health probe at the start of enrol and tests: `ssh-keyscan -T 15` through one Linux tunnel and a TLS/HTTP probe (`curl -sk -m 20 https://127.0.0.1:<port>/wsman`, 401/405 = alive) through one Windows tunnel; fail fast naming the tunnel and its age.
6. `ansible/roles/imas_verify/tasks/main.yml:21` ("Read the sprout's config file", no_log): add an unmasked connectivity task before it (e.g. wait_for_connection with a short timeout and its own error message) so UNREACHABLE shows the reason; keep no_log only around the task that reads the token.
7. Docs: soften the W5 text in uat/tofu/variables.tf and uat/tofu/README.md that states the runner-egress-address cause as fact (the allowlist change stands; the Run 2 hang cause was not the allowlist); add a uat/RUNBOOK.md troubleshooting entry: "all tunnels hang/UNREACHABLE after ~1 h = stale Azure login/tunnels", with the evidence timeline above and the two laptop checks (fresh tunnel + ssh-keyscan / curl /wsman).
8. Keep the W4 timeouts and W5 ingress change as they are. Do NOT change Windows install tasks or VM sizes.

## 3. Out of scope
No product changes (cmd/, internal/), no tags/releases, rc.15 stays under test. X3 untouched.

## 4. Acceptance
- actionlint/yamllint/shellcheck green; uat/scripts and uat/access stub tests extended (refresh script: login then close then open order, ports preserved or inventory regenerated, age guard refuses at threshold, probe failure message).
- Brief corrections section; status fragment docs/status/days/2026-10-21/zz-W6.md; ORCHESTRATOR.md W6 row; rollup --check passes.
- Real proof: Azure Run 2 re-dispatch. Expect enrolment to pass on Linux and Windows and tests to start; if it still fails, the new age/probe lines in the log say whether the tunnel was stale.

## 5. Owner follow-ups
Delete the failed run's resource group (list with: az group list --query "[?starts_with(name,'imas-uat-') && name!='imas-uat-state'].name" -o tsv; never delete imas-uat-state), then re-dispatch Run 2 after merge.

## Brief corrections (W6, 2026-10-21)

Decided by the order of `docs/briefs/ORCHESTRATOR.md` rule 6 and built that
way:

- **The script's place and name.** Not `uat/scripts/refresh-azure-session.sh`
  but `uat/access/session.sh` (the brief allowed another name): every Azure
  call and tunnel operation of the gate lives in `uat/access`
  (`uat/access/README.md`), and the script sits next to `tunnels.sh` and
  `az-relogin.sh`, which it drives. Its tests extend
  `uat/access/tests/access_test.sh`; `uat/scripts` gets the workflow wiring
  test (`workflow_test.go`) and the janitor's hook test.
- **"Reuse the mechanism of the re-login before the tests".** That step was
  the `azure/login` action, which a script cannot call. `az-relogin.sh`
  (already in the repo for `vmctl.sh`) does the same OIDC exchange
  (an ID token for `api://AzureADTokenExchange`, then `az login
  --service-principal --federated-token`), so the refresh uses it. The steps
  "before enrolment" and "before the tests" now run `session.sh phase ...
  --force --probe` instead of the action; the first login and the one before
  the destroy stay the action (the destroy must not depend on `uat/access`,
  and the age guard never stops it), followed by `session.sh mark-login`.
  Repeated logins in one job work: each fetches a new token from the job's
  `ACTIONS_ID_TOKEN_REQUEST_URL` (`id-token: write`, already set); the
  `AZURE_*` variables move to the job's env so every step has them.
- **Same ports.** `tunnels.sh open` gave each run new ports from
  `TUNNEL_PORT_BASE` up but had no way to reuse a tunnel's port. It gets
  `reopen`, which closes and reopens each tunnel on its old port where free
  and names any change. A changed kube port is rewritten in the hubs'
  kubeconfigs (`UAT_SESSION_KUBECONFIGS`); the enrolment inventory is
  regenerated from `access.json` after every boundary (`enroll.sh`).
- **Age guard and refresh threshold.** The brief gives one number (40
  minutes, fail at a phase start). A phase start also refreshes when either
  age reaches 15 minutes (`UAT_SESSION_REFRESH_AFTER_MIN`), so the 40-minute
  guard (`UAT_SESSION_MAX_AGE_MIN`) only fires if a refresh did not happen.
  Every phase from the tunnels on starts this way, not only enrolment, the
  tests and the destroy: the hub steps use the tunnels too, and k0s through
  the DMZ check took 29 minutes in Run 2.
- **The tunnels were opened on a 20-minute-old login.** tofu apply runs
  between the first login and the tunnels; the tunnels step now logs in
  again first.
- **Splitting the tests.** `run.sh` ran one test process per package. With
  `UAT_SESSION_HOOK` it now runs each top-level test in its own process and
  refreshes between them when due (the sprout IDs come from `sprouts.json`,
  so a new process costs only the harness's start). `IMAS_UAT_TIMEOUT` is
  then the budget of all of them. One effect: X1's "expired" case waits out
  the realm's token lifespan, as its token is minted when its own process
  starts.
- **Probe.** The brief asks for one Linux and one Windows tunnel; the probe
  checks every tunnel in `access.json`, in parallel (the Kubernetes API
  ones by `/version`, any HTTP answer alive), so the failing one is named.
- **"The failure-time diagnostic step from W5".** There was none in the
  workflow (W5 changed only the network rules and the input). W6 adds it:
  "Azure login and tunnel ages (on failure)", before the tunnels close.
- **More places stated W5's cause as fact.** Besides
  `uat/tofu/variables.tf` and `uat/tofu/README.md`: `uat/README.md`,
  `docs/security-review-pack.md` 3.7 and the plan
  (`docs/claude-code-parallel-build-plan.md`, section 4h). All softened the
  same way; the allowlist change stands.
- **Another long-lived Azure session.** The repo-wide search found the
  janitor (`uat-janitor.yml`, `uat/scripts/janitor.sh`): each `az group
  delete` waits for the deletion, so several groups outlive its login.
  `janitor.sh` now runs the same hook (login only) before each group.
  Searched and unchanged: `vmctl.sh` (already logs in again on
  AADSTS700024, and its logins now count in the login age),
  `collect-artifacts.sh` (no Azure call), `verify-teardown.sh` and
  `destroy.sh` (right after a fresh login), `azure-owner-setup.sh` (an
  owner's interactive login), the local rig `uat/lite` (no Azure; the hooks
  are unset there).
- **`no_log`.** Only "Read the sprout's config file" in `imas_verify` is
  `no_log`; it stays so. The new unmasked task before it is a
  `wait_for_connection` (`imas_verify_connection_timeout`, default 300 s,
  the role's own wait) in a block whose rescue fails with the host, address
  and connection error.

