change: P21 slice 2 PR 2 (C2): farmer publishes every Account JWT it pushes to the accounts bucket (`accounts/<pub>.jwt`, never replacing a newer one, under an `account:<pub>` row lease), bumps `accounts/index`, pushes to every bus node (server ping gather, replies per node, 3 retry rounds; missing nodes are logged, not fatal) and announces `imas.bus.accounts.changed`; `ReconcileAll` repairs the bucket at start-up and in every `PushAllAccounts`; every re-sign gets a strictly newer iat; config `IMAS_ACCOUNTS_S3_*`, `IMAS_ACCOUNTS_EVENT_SUBJECT`, `IMAS_BUS_EXPECTED_NODES`; farmer chart `accountStore.*` and `bus.expectedNodes`. Flagged for security review.
pr: 229
item: P21
action: update
next-append: **Slice 2 PR 2 (C2), ready for review:** farmer side of the accounts bucket (publisher, all-node push, ReconcileAll, chart values).
