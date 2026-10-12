change: D6 follow-up (P21 slice 3 PR 6): saasapi records its NATS key in `saas.saasapi_credential_state` at boot, after the bus accepts the credential and before serving, so farmer revokes the rotated-out key at its next boot. A replica on a rotated-out seed fails to start. Flagged for security review.
pr: 216
item: P21
action: update
next-append: D6 follow-up, ready for review: saasapi records its NATS key at boot. Still open: rotation history beyond `prev_pub` needs a later migration.
