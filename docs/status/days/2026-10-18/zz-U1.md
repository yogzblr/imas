change: U1 (P3, P4): L9, L15, L22, L23 and I6 fixed with tests. L9: farmer sends `internal.sprout.action`'s `cmd.run` with `no_output`, the sprout leaves stdout and stderr out of its sealed reply, and `controlplane.CmdRunResult` carries the exit code and duration only, so output size no longer matters on that subject. L15: the bus fence counts only routed peers whose server name is one of its own routes' first labels (route hosts must be DNS names; farmerbus refuses IP routes), and fences while any routed peer reports a different route count (`VARZ`); a resize changes every node in one rollout (`deploy/helm/nats` README, "Resizing the cluster"). L22: the sever boundary is in the current tenant-key version's data (`sever_floor`) and the secret's KV `custom_metadata` (`imas_sever_floor`; farmer's `imas-farmer-tenantbox` policy gains `update` on `<kvPath>/tenants/+` metadata), and a gap in the version chain stops the continuity walk. L23: a continuity proof must be inside the ±5 minute window and pass the sprout's persisted replay guard. I6: farmer migration 00007 (`pki_cli_admin_keys`) records the CLI admin keys granted on the Account; one removed from the config (`users.admin` or `pubkeys.admin`) and no user at all is put on the tenant's revoked list, its CLI box keys retired, and the Account re-signed. Ready for security review.
pr: 280
item: P4
action: update
next-append: **U1 built (2026-10-18):** L9, L15, L22, L23 and I6 fixed with tests (`internal/natsapi/sprout_action.go`, `cmd/farmerbus/fence.go`, `internal/pki/tenantbox.go`, `sproutbox.go`, `cliadminkeys.go`); their rows in "Review findings re-checked" below are superseded. Open after U1: L24 (brief U2).
---
pr: 280
item: P17
action: update
next-append: **U1 (2026-10-18):** the L9 and L22 tests that pinned the old behaviour changed with the fixes (`TestSproutAction_CmdRunThroughRealHandler` now requires no output in the reply; `TestTenantKeyContinuity_SkipsDeletedVersions` became `TestTenantKeyContinuity_GapStopsTheWalk`), and L15, L23 and I6 have tests.
---
pr: 280
item: P3
action: update
next-append: **U1 adds to the review scope (2026-10-18):** the fence's member and cluster-size rules and the resize procedure (`cmd/farmerbus/fence.go`, `cluster.go`); the sever boundary in `custom_metadata` and farmer's new `update` on tenant key metadata (it also lets farmer change a tenant secret's `max_versions` and `delete_version_after`, never create metadata for a tenant with no keypair); continuity proof freshness and replay; CLI admin key revocation (farmer migration 00007, `internal/pki/cliadminkeys.go`).
