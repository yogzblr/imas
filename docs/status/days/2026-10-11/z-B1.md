change: P21 slice 1 PR1 (unit B1): `internal/pki/natskeys`, the Transit-backed NATS key store and signer, with its fake Transit, `openbao.Client.ResetToken`, and real-OpenBao tests in a new workflow. Flagged for security review.
item: P21
action: update
next-append: **Slice 1 PR1 (B1), ready for review:** `internal/pki/natskeys` built; nothing uses it yet. Real OpenBao 2.7.1 answered: slashes in key names are refused (flat names stay); creating a Transit key needs `update`, not `create`, and `update` on a `nats-tsign-*` glob also grants `rotate` and `config`, so the §3.2 policies need fixing in PR6.
