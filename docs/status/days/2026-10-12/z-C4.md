change: P21 slice 2 PR 4 (C4): the bus fence's cluster size follows IMAS_BUS_CLUSTER_SIZE_FILE (never below the route count, never lowered by a bad file), and the NATS trust bootstrap mints the account loader's SYS user JWT (`bus-loader-user.jwt`, exactly the §5.2 grant plus CLAIMS.LOOKUP). Flagged for security review.
pr: 214
item: P21
action: update
next-append: **Slice 2 PR 4 (C4), ready for review:** fence size source and the loader SYS user minted by `bootstrap-nats-trust` (IMAS_NATSBOOT_BUS_LOADER_USER_PUB); chart wiring is PR 6.
