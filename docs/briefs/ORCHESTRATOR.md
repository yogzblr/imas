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

First wave (no needs): A1, B1, C1, D1, D2. Why the order: P22 first (design D13);
A2 and the P21 slice 1 chart work both edit the farmer bootstrap Job and policies, so
A2 lands before B3 and B7; P22 slice 2 owns saas migration 00007 and slice 3's saas
migration is 00008; B5 and C2 both edit `internal/pki`, so C2 waits for B5.

## Rules the orchestrator follows

1. At most 5 sessions run at once. Never run two units at once if the briefs'
   file scopes overlap; when unsure, run them one after the other.
2. Sessions are launched from main as it is when the unit becomes ready, on branch
   `build/<ID>` (for example `build/A1`).
3. The orchestrator never merges, never approves, never pushes to a unit's branch,
   never edits a brief. The owner reviews and merges. Every unit carries
   FLAG FOR SECURITY REVIEW; there is no auto-merge.
4. A unit is done when its PR is merged. The orchestrator checks with
   `gh api repos/yogzblr/imas/pulls?state=all&head=yogzblr:build/<ID>` (REST only;
   GraphQL is blocked in these sessions).
5. If a session reports it is blocked, or its PR says it left something out that a later
   unit needs, the orchestrator stops launching units that depend on it and tells the
   owner in one message: unit, reason, what it needs. It does not guess a fix.
6. If a brief and the code disagree (a file or function the brief names does not
   exist), that is a brief error. The orchestrator tells the owner; it does not let
   the session improvise across units.
7. Progress lives in one GitHub issue titled `Build orchestration P22 and P21`,
   created through `gh api repos/yogzblr/imas/issues`, with the table above as a
   checklist and the PR number next to each unit. The orchestrator edits that
   issue as units change state. It does not edit `docs/BUILD-STATUS.md`.
8. If it cannot launch hosted sessions, it prints each session prompt for the owner
   to paste, one block per ready unit, and waits.
9. It reports to the owner only: units launched, PRs opened (number and one line),
   units blocked, and the next units waiting on a merge. No narration between.

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
    of docs/briefs/BRIEF-FILE, then build only SECTION. The brief and its Owner
    decisions section are final: do not reopen a decision and do not ask questions
    in the PR. Where the brief is silent, choose the smallest option that matches the
    surrounding code and list it under Choices I made. Work on a new branch named
    build/ID from main. Touch only the files the section names; if you need another
    file, stop and say why in the PR instead of editing it. Before you open the PR:
    go build, go vet and go test must pass for ./..., CGO_ENABLED=0 go build ./...
    must pass, and any chart tests the section lists must pass. Do not edit
    docs/BUILD-STATUS.md; add the status fragment docs/status/days/YYYY-MM-DD/z-ID.md
    (format in docs/status/README.md, check with scripts/status/rollup.py --check).
    Commit messages start with ID: . Open the PR with FLAG FOR SECURITY REVIEW at
    the very top, then the sections Built, Deliberately not done, Choices I made and
    Files outside scope. Say ready for review, never done or safe to merge. After the
    PR is open, read the CodeRabbit comments once: fix the valid ones, reply to the
    others with a reason, and resolve each thread.

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
