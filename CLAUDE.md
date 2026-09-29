# imas — Infrastructure Management At Scale — repo conventions

imas began as a fork of gogrlx/grlx (github.com/gogrlx/grlx) and has since
diverged into its own project. See docs/design/ for the full architecture —
read imas-master-plan.md and imas-fork-roadmap.md first, then the specific
design doc named in your task.

## Constraints (non-negotiable)
- Licensing: Apache-2.0 / MIT dependencies by default. Recorded
  exceptions: Percona XtraDB Cluster (GPLv2, commercial arrangement) and
  MPL-2.0 dependencies generally, including OpenBao and its Go client,
  used unmodified or with changes shared (docs/design/requirements.md
  item 21). Flag any other license before adding it as a dependency,
  don't just add it.
- Sprout updates install from the repository configured in the sprout,
  like the Ansible role `imas_sprout`; an update command never carries an
  artifact URL (docs/design/requirements.md item 20, API design §1.8).
- Go, existing module layout. Don't introduce a second language/runtime
  without flagging it first.
- No CGO (blocks a CGO-free build target elsewhere in the plan).
- Follow the existing self-registering ingredient plugin pattern
  (see internal/ingredients/*) for any new ingredient.
- `sprout_id` is unique per tenant only, never globally: always key
  tables, indexes, caches and maps on `(tenant_id, sprout_id)` — keying on
  `sprout_id` alone is a cross-tenant collision bug. See §4 "Tenant
  safety" in docs/design/cloudxp-machine-manager-api-design.md.

## Workflow
- Work only within the file scope stated in your task brief. If you need
  to touch a file outside that scope, stop and say why instead of doing it.
- Write unit tests for new logic. `go test ./...` must pass before you
  consider the task done.
- Commit messages: `<workstream-id>: <what>` (e.g. `B: mint sprout JWT
  via nats-io/jwt/v2`).
- Open a PR when done. In the PR description, state what you built,
  what you deliberately left out or deferred, and any open question.

## Security review flag
If your task brief includes the line "FLAG FOR SECURITY REVIEW", say so
explicitly at the top of the PR description, and do not describe the
work as "done" or "safe to merge" — only as "ready for review."