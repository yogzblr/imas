change: D6 (P21 slice 3 PR 6): SaaS API credential rotation state moves to PXC `saas.saasapi_credential_state`. saasapi's writer (`pki.SaaSAPICredentialRecorder.Record`) rotates under the row lease with an UPDATE conditional on the version it read, so of two replicas one wins; farmer's `EnsureSaaSAPICredential` reads `prev_pub` from that row to revoke the old key on the SYS Account and no longer writes or reads a SaaS API User JWT file. Flagged for security review.
item: P21
action: update
next-append: Slice 3 PR 6 (D6), ready for review: SaaS API credential state in PXC. Still open: call `Record` from saasapi's boot (cmd/saasapi) with its credential's key.
