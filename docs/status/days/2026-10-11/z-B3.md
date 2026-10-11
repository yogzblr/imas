change: P21 slice 1 PR3 (unit B3): `farmer bootstrap-nats-trust` (`internal/natsbootstrap`), the bootstrap Job's nats-trust step: creates the three platform Transit keys, mints the trust chain with `pki.BootstrapNATSTrust`, writes the `imas-nats-trust` ConfigMap through a minimal in-cluster client, and revokes its handoff token. Flagged for security review.
item: P21
action: update
next-append: **Slice 1 PR3 (B3), ready for review:** bootstrap subcommand built and registered; the chart Job that runs it is PR6.
