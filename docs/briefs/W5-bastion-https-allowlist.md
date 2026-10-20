# W5: the Bastion 443 allowlist must follow the caller

Read `docs/briefs/ORCHESTRATOR.md` first: its session prompt (zero open items,
repo-wide search, brief errors decided by a fixed order) applies to this unit.

**Source of this file.** The owner's brief for W5 is kept in the Claude
Project "SaaS based machine manager"
(`briefs/W5-bastion-https-allowlist.md`). The building session could not
read that Project, so this file was rebuilt from the unit's prompt
(2026-10-20) and from the repo. The owner decisions below are quoted from
that prompt. If the Project copy says something different, the Project copy
wins: replace this file with it and reopen the unit for the difference.

## What happened

Azure UAT Run 2 (`hub_nodes` 1, `v0.1.0-rc.15`) failed at "Tenants and
enrolment": the Windows sprouts hit WinRM read timeouts, and the Linux
sprouts were UNREACHABLE, with `no_log` hiding the reason. The root cause was
proven on the live environment: `uat-bastion-nsg` rule `AllowHttpsInbound`
allowed TCP 443 from a single `/32` only (`runner_cidr`, the address an echo
service reported at the start of the run). A caller whose egress address is
different is dropped by the NSG without an answer, so its Bastion tunnel
hangs silently.

Already correct, and **not changed** by W5: WinRM (listener, timeouts after
W4), the Windows firewall, the tenants NSG, the Bastion's outbound rules.
No product code changes; `v0.1.0-rc.15` stays the build under test.

## Owner decisions (2026-10-20, final)

- The default for the UAT gate is an Internet-open Bastion 443.
- An explicit-CIDR hardened mode stays supported, behind a variable.
- Every consumer of the runner-IP value is found by a repo-wide search and
  fixed: the Bastion NSG and any other allowlist fed by the same value.
- Scenario X3 (a sprout cannot open a connection to core) stays untouched.
- The UAT-only relaxation is recorded in the P3 security-review record.

## Scope

1. **The variable.** `uat/tofu` gets `public_ingress` (`internet`, the
   default, or `cidrs`) and `public_ingress_cidrs` (1 to 50 public IPv4
   ranges with `cidrs`, empty with `internet`; each `a.b.c.d/N`, N from 8
   to 32, no host bits, none repeated). `AllowHttpsInbound` in
   `uat-bastion-nsg` takes its source from them: the service tag `Internet`,
   or the ranges.
2. **Every other consumer.** Every allowlist fed by `runner_cidr` takes the
   same source, so all of them follow the caller together; `runner_cidr`
   goes away.
3. **The workflow.** `.github/workflows/uat.yml` gets the input
   `ingress_cidrs` (empty: Internet). `uat/scripts/check-inputs.sh`
   validates it with the same rule as `uat/tofu` and outputs
   `public_ingress` and `public_ingress_cidrs` for the apply and destroy
   steps and for `run.json`. The runner-address lookup goes.
4. **Tests.** `tofu test` covers the default (all three rules from
   `Internet`, and no other rule open to it), the hardened mode (all three
   rules take the ranges; one range uses the singular field) and every
   refused value. `uat/scripts/tests/scripts_test.sh` covers the input.
5. **Docs.** `uat/tofu/README.md` (inputs, network rules, the Bastion
   section with the reason), `uat/README.md` (inputs, run steps, reaching a
   kept environment), `uat/RUNBOOK.md` (Run 2 inputs), the DMZ hub's notes
   and the plan's Shared contract.
6. **Records.** `docs/security-review-pack.md` 3.7 records the relaxation;
   status fragment `docs/status/days/2026-10-20/zz-W5.md` (P1 and P3); the
   W5 row in `docs/briefs/ORCHESTRATOR.md`; this file.

Done when: `go test ./...`, `tofu fmt -check` and `tofu test` (uat/tofu),
`bash uat/scripts/tests/scripts_test.sh` and `scripts/status/rollup.py
--check` pass.

Needs: none.

## Brief corrections (W5, 2026-10-20)

Decided by the order of `docs/briefs/ORCHESTRATOR.md` rule 6 and built that
way:

- **The brief file.** The Project copy could not be read from the building
  session; this file was rebuilt (see the top).
- **Three allowlists, not one.** The repo-wide search found `runner_cidr`
  feeding three rules, not only the Bastion's: `AllowHttpsInbound`
  (Bastion 443), `AllowRunnerHttpsIn` (core 443, saasapi and Keycloak) and
  `AllowRunnerEnvoyIn` (DMZ Envoy). The same runner calls all three, so the
  two others fail the same way when its egress changes. All three take
  `public_ingress`. Their names stay `AllowRunner*` so the rule names in
  the README, the tests and the live NSGs keep matching.
- **`runner_cidr` removed, not kept beside the new variable.** One source
  for the three rules. With it went `uat/scripts/runner-cidr.sh`, its tests
  and the `curl` stub only they used; `run.json` records `public_ingress`
  and `public_ingress_cidrs` instead. `uat/tofu/destroy.sh` no longer sets a
  placeholder (the new variables have defaults).
- **The hardened mode is not "the runner's /32".** A list of ranges the
  owner names (for example a self-hosted runner's NAT ranges plus their own
  address), since one looked-up address is what failed.
- **`no_log`.** It hid the reason in Run 2 but did not cause the failure;
  the roles and playbooks are unchanged (out of scope: no change outside
  the network rules and the workflow).
- **Unit table.** `docs/briefs/ORCHESTRATOR.md` had no W4 row (W4 merged as
  PR #300 without one) and no W5 row; W5's is added, W4's left as it is.
