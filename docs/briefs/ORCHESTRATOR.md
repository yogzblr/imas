# Build orchestrator

How the P22 and P21 briefs are built by several hosted Claude Code sessions.
The owner pastes the prompt under "Orchestrator prompt" into one Claude Code
session in the repo. That session launches the build sessions, watches them,
and launches the next ones as PRs merge. It writes no product code itself.

## Build units and dependencies

Each unit is one PR and one hosted session. "Spec" is the section of the brief the
session must implement; it reads the whole brief but builds only that section.
A unit may start only when every unit in "Needs" is merged to main.

| ID | Spec | Needs |
|---|---|---|
| A1 | `P22-gpg-fleet-trust.md` Slice 1 | none |
| A2 | `P22-gpg-fleet-trust.md` Slice 2 | A1 |
| B1 | `P21-slice1-transit-signer.md` section 7, PR1 | none |
| B2 | same, PR2 | B1 |
| B3 | same, PR3 | B2, A2 |
| B4 | same, PR4a | B3 |
| B5 | same, PR4b | B4 |
| B6 | same, PR5 | B5 |
| B7 | same, PR6 | B6 |
| B8 | same, PR7 | B7 |
| C1 | `P21-slice2-bus-loader.md` section 15, PR 1 | none |
| C2 | same, PR 2 | C1, B5 |
| C3 | same, PR 3 | C1 |
| C4 | same, PR 4 | C3, B6 |
| C5 | same, PR 5 | C3, C4 |
| C6 | same, PR 6 | C5, B7 |
| C7 | same, PR 7 | C6 |
| D1 | `P21-slice3-farmer-saasapi-state.md` section 7, PR 1 | none |
| D2 | same, PR 2 | none |
| D3 | same, PR 3 | A1 |
| D4 | same, PR 4 | D3, B7 |
| D5 | same, PR 5 | D1, D2, B5, C3 |
| D6 | same, PR 6 | D5 |
| D7 | same, PR 7 | D6 |
| D8 | same, PR 8 | D7 |
| D9 | same, PR 9 | D8, C6, B7 |
| E1 | `E-followups.md` E1 | none |
| E2 | `E-followups.md` E2 | none |
| E3 | `E-followups.md` E3 | E2, E6 |
| E6 | `E-followups.md` E6 | none |
| E4 | `E-followups.md` E4 | none |
| E5 | `E-followups.md` E5 | E1 |
| Z | `E-followups.md` Z | every other unit |

First wave of the original build (no needs): A1, B1, C1, D1, D2. Units A to D are all merged (C2 last, as PR 229; its leftovers are E6); the follow-up units E1 to E5 and Z are launched in the same way, E6 first by rule 10 (E3 waits for it). Why the order: P22 first (design D13);
A2 and the P21 slice 1 chart work both edit the farmer bootstrap Job and policies, so
A2 lands before B3 and B7; P22 slice 2 owns saas migration 00007 and slice 3's saas
migration is 00008; B5 and C2 both edit `internal/pki`, so C2 waits for B5.

## Rules the orchestrator follows

1. At most 5 sessions run at once. Never run two units at once if the briefs'
   file scopes overlap; when unsure, run them one after the other (but see rule 10).
2. Sessions are launched from main as it is when the unit becomes ready, on branch
   `build/<ID>` (for example `build/A1`).
3. The orchestrator never merges, never approves, never pushes to a unit's branch,
   never edits a brief. The owner reviews and merges. Every unit carries
   FLAG FOR SECURITY REVIEW; there is no auto-merge.
4. A unit is done when its PR is merged. The orchestrator checks with
   `gh api repos/yogzblr/imas/pulls?state=all&head=yogzblr:build/<ID>` (REST only;
   GraphQL is blocked in these sessions).
5. Zero open items. A unit's PR may not defer, skip or note anything for later. If a
   merged-ready PR (or the session's final message) says something was left out,
   not verified, or needs a follow-up, the orchestrator does not report it to the
   owner. It relaunches the same unit on the same branch with the instruction
   "Finish the items you listed as left out, then rerun every check", up to 2 times.
   Only after the third attempt does it tell the owner, with the unit, the item and
   the reason the session gave.
6. A wrong brief is not an open item. If a brief and the code disagree, the session
   decides by this order: (1) the numbered owner decisions D1 to D22 and the
   "Owner decisions" section of its brief; (2) the code on main; (3) the smallest
   change that keeps main building, deployable and tested. It records the call under
   "Brief corrections" in the PR and commits the fix to the brief file in the same PR.
   The only reason to stop is a conflict with a numbered owner decision; then the
   orchestrator tells the owner in one message.
7. Progress lives in one GitHub issue titled `Build orchestration P22 and P21`,
   created through `gh api repos/yogzblr/imas/issues`, with the table above as a
   checklist and the PR number next to each unit. The orchestrator edits that
   issue as units change state. It does not edit `docs/BUILD-STATUS.md`.
8. If it cannot launch hosted sessions, it prints each session prompt for the owner
   to paste, one block per ready unit, and waits.
9. It reports to the owner only: units launched, PRs opened (number and one line),
   and the next units waiting on a merge. A report never contains a list of open
   points. The only other message is a conflict with a numbered owner decision, or
   a unit that is still incomplete after rule 5's third attempt.
10. Critical path first. When more units are ready than the cap allows, launch the one
    that most others wait on (the longest chain behind it) before the rest. A unit
    that is ready is never held back more than once because of a file overlap with a
    unit that started later; the later one waits instead.
11. Main stays deployable. Every unit must leave `helm template` for every chart
    with the repo's ci/ and uat/ values, the UAT render, and `go test ./...` passing on
    its own branch. A unit that needs chart or values changes to keep that true makes
    them in the same PR, even if the brief put them in a later unit.

## Orchestrator prompt

Paste this into a Claude Code session started in the yogzblr/imas repo on main.

    You are the build orchestrator for yogzblr/imas. Read CLAUDE.md and
    docs/briefs/ORCHESTRATOR.md completely first; that file is your whole
    instruction set: the unit table, the dependency rules and the reporting rules.

    Do this:
    1. Run git pull on main. Create the tracking issue described in rule 7 if it does
       not exist (search first), with one checklist line per unit in the table.
    2. Work out which units are ready: every unit in Needs is merged to main and
       the unit has no open or merged PR from branch build/<ID>.
    3. Launch one hosted Claude Code session per ready unit, up to 5 running at
       once, each with the session prompt below, with the unit values filled in
       from the table. Use claude --cloud with the prompt. Record the PR number in
       the tracking issue when the session opens it.
    4. Then loop: every 20 minutes, list build/* PRs; update the issue; for each
       newly merged unit, run git pull on main and launch the units that became ready.
       Stop when every unit is merged, or when rule 5 or 6 applies and nothing else can
       run.
    5. Do not write product code, do not merge, do not answer a session's
       questions with new decisions. If a session raises a question, point it to the
       section of the brief that settles it; if none does, tell the owner.

    Session prompt, per unit (fill in ID, title, brief file, section):

    Implement unit ID (title) in yogzblr/imas. Read CLAUDE.md first, then the whole
    of docs/briefs/BRIEF-FILE, then build SECTION completely. The brief and its
    Owner decisions section are final: do not reopen a decision and do not ask
    questions in the PR. On the first attempt, create build/ID from main. On a retry,
    check out the existing build/ID branch and continue from its tip.

    The files the section names are the minimum, not the limit. You own the unit end to
    end: when you add, rename, remove or change a name, path, key, env var, value,
    flag, route, table or file, run a repo-wide search for the old and the new name
    across code, charts, uat/, deploy/, docs/, scripts and .github/workflows, and
    update every hit so that nothing is left stale. Where the brief is silent or wrong,
    decide in this order: the numbered owner decisions D1 to D22 and the brief's
    Owner decisions section; the code on main; the smallest change that keeps main
    building, deployable and tested. Fix a wrong brief in the same PR.

    Do not leave anything for later. No deferred items, no follow-ups, no TODO, no
    skipped test, no note that something was not verified. If a check cannot run in your
    session, find another way to check it (a fake, a rendered chart, a container) and say
    what you ran. Before you open the PR: go build, go vet and go test pass for ./... ;
    CGO_ENABLED=0 go build ./... passes; helm template passes for every chart with
    its ci and uat values; scripts/status/rollup.py --check passes; the search in the
    previous paragraph is clean. Do not edit docs/BUILD-STATUS.md; add the status
    fragment docs/status/days/YYYY-MM-DD/zz-ID.md (zz- sorts after the day's
    z- fragments, which may add the items it updates). Commit messages start
    with ID: .

    Open the PR with FLAG FOR SECURITY REVIEW at the very top, then the sections
    Built, Verified (each command and its result), Consumers updated (the names you
    searched for and the files you changed) and Brief corrections. Say ready for
    review, never done or safe to merge. After the PR is open, read the CodeRabbit
    comments once: fix the valid ones, reply to the others with a reason, resolve each
    thread.

## Session values, copy per unit

| ID | Title | Brief file | Section |
|---|---|---|---|
| A1 | P22 slice 1: GPG verify library, sprout, packaging | P22-gpg-fleet-trust.md | Slice 1 |
| A2 | P22 slice 2: server side, release stamping, retire fleetreleaser | P22-gpg-fleet-trust.md | Slice 2 |
| B1 | P21 slice 1 PR1: natskeys package | P21-slice1-transit-signer.md | section 7, PR1 |
| B2 | P21 slice 1 PR2: trust model | P21-slice1-transit-signer.md | section 7, PR2 |
| B3 | P21 slice 1 PR3: natsbootstrap subcommand | P21-slice1-transit-signer.md | section 7, PR3 |
| B4 | P21 slice 1 PR4a: pki seam | P21-slice1-transit-signer.md | section 7, PR4a |
| B5 | P21 slice 1 PR4b: Transit cut-over | P21-slice1-transit-signer.md | section 7, PR4b |
| B6 | P21 slice 1 PR5: bus side | P21-slice1-transit-signer.md | section 7, PR5 |
| B7 | P21 slice 1 PR6: charts | P21-slice1-transit-signer.md | section 7, PR6 |
| B8 | P21 slice 1 PR7: UAT scripts and docs | P21-slice1-transit-signer.md | section 7, PR7 |
| C1 | P21 slice 2 PR1: accountrank extraction | P21-slice2-bus-loader.md | section 15, PR 1 |
| C2 | P21 slice 2 PR2: farmer account publisher | P21-slice2-bus-loader.md | section 15, PR 2 |
| C3 | P21 slice 2 PR3: account loader and binary | P21-slice2-bus-loader.md | section 15, PR 3 |
| C4 | P21 slice 2 PR4: fence size and SYS user files | P21-slice2-bus-loader.md | section 15, PR 4 |
| C5 | P21 slice 2 PR5: loader integration tests | P21-slice2-bus-loader.md | section 15, PR 5 |
| C6 | P21 slice 2 PR6: bus chart | P21-slice2-bus-loader.md | section 15, PR 6 |
| C7 | P21 slice 2 PR7: cleanup | P21-slice2-bus-loader.md | section 15, PR 7 |
| D1 | P21 slice 3 PR1: inventory guard and lease package | P21-slice3-farmer-saasapi-state.md | section 7, PR 1 |
| D2 | P21 slice 3 PR2: migrations | P21-slice3-farmer-saasapi-state.md | section 7, PR 2 |
| D3 | P21 slice 3 PR3: config, logging, audit | P21-slice3-farmer-saasapi-state.md | section 7, PR 3 |
| D4 | P21 slice 3 PR4: seeds from Secrets | P21-slice3-farmer-saasapi-state.md | section 7, PR 4 |
| D5 | P21 slice 3 PR5: sprout JWT store and lease | P21-slice3-farmer-saasapi-state.md | section 7, PR 5 |
| D6 | P21 slice 3 PR6: SaaS API credential state | P21-slice3-farmer-saasapi-state.md | section 7, PR 6 |
| D7 | P21 slice 3 PR7: job leases, recipe writes, merged cook call | P21-slice3-farmer-saasapi-state.md | section 7, PR 7 |
| D8 | P21 slice 3 PR8: tenant bus connections | P21-slice3-farmer-saasapi-state.md | section 7, PR 8 |
| D9 | P21 slice 3 PR9: farmer chart, replicas and PDB | P21-slice3-farmer-saasapi-state.md | section 7, PR 9 |
| E1 | P26: make the UAT work after the stateless build | E-followups.md | E1 |
| E2 | P27: every package gets tenant connections from the registry | E-followups.md | E2 |
| E3 | P27: no local JWT or key files in farmer | E-followups.md | E3 |
| E4 | P27: loadtest without trust seeds; sprout honours Retry-After | E-followups.md | E4 |
| E5 | P28: docs, CI, flake and earlier reports | E-followups.md | E5 |
| Z | Final gate: nothing left open | E-followups.md | Z |
| E6 | P21: finish C2, the farmer account publisher | E-followups.md | E6 |
