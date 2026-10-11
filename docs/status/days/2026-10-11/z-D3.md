change: D3 (P21 slice 3 PR 3): farmer audit records go to stdout as JSON lines (`"kind":"audit"`, `ts`), never to a file; `IMAS_LOG_FORMAT=json` switches the terminal logger to JSON; `LoadConfig("farmer")` never creates or rewrites the config file and `auditlogdir` is gone; farmer fails fast on a missing config root instead of creating it. Owner decision 1 applied: the `audit.dates`/`audit.query` API, its HTTP routes, client and the `imas audit` CLI are removed; audit is queried in the log platform. Flagged for security review.
item: P21
action: update
next-append: Slice 3 PR 3 (D3) built: audit to stdout JSON, JSON log format, no farmer config writes, audit query API and CLI removed (owner decision 1).
