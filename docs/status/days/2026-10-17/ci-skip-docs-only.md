change: Pull requests that change only briefs, status fragments, design docs or the security reviews no longer run the Go test, lint, build, CodeQL and govulncheck workflows. Pushes to main still run all of them.
item: P10
action: update
next-append: **CI (2026-10-17):** `ci.yml`, `build.yml`, `codeql.yml`, `codeql-analysis.yml` and `govulncheck.yml` skip a pull request whose changes are all under `docs/briefs/`, `docs/status/`, `docs/design/` or `docs/security-review*.md`. the docs site build still runs, and gitleaks (`gitleak.yml`) is unchanged by the path filter and now also runs when a commit is pushed to an open pull request (`synchronize` was missing). Other `docs/` files (for example `docs/api/`) still run everything, because tests read them.
