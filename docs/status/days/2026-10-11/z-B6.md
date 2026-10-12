change: P21 slice 1 PR5 (unit B6): the DMZ bus (`cmd/farmerbus`, `pki.ConfigureBusNats`) configures itself from the public NATS trust directory only: no operator, operator-signing or SYS account seed, no Transit access, no self-signed SYS bootstrap. A clustered bus needs the fence user (seed from `IMAS_NATS_BUS_FENCE_USER_SEED_FILE`, JWT `bus-fence-user.jwt` from the trust) and refuses to start without it. Cluster test and loadtest local bus moved to the trust directory. Flagged for security review.
pr: 211
item: P21
action: update
next-append: **Slice 1 PR5 (B6), ready for review:** bus reads only the trust directory; the charts (PR6) still mount seeds until their PR.
