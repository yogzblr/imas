change: T3 (P12): a sprout's presence key holds the ID of the bus connection that set it (`heartbeat.ConnID`: bus node server ID and client ID); DISCONNECT deletes it only when it holds its own connection's ID, in one Lua compare-and-delete, so a reconnect whose CONNECT is processed before the old connection's DISCONNECT stays online (owner decision T3); a heartbeat extends the key and keeps its owner, and writes a missing one with the connection ID it carries. Tested in both orders against miniredis, a real Valkey and a real 3-shard Valkey Cluster from CI service containers (`IMAS_TEST_VALKEY_CLUSTER_ADDR`, `IMAS_REQUIRE_VALKEY=1`). The load test mints from `pki.SproutPermissions` (no copy) and its sprouts heartbeat (`-heartbeat-interval`); a sprout reconnects with a User JWT a refresh changed at its next heartbeat, and the startup refresh (UAT.13) checks the full grant. Ready for security review.
item: P12
action: close
---
item: P3
action: update
next-append: **T3 adds to the review scope (2026-10-17):** the sprout reconnects with a refreshed User JWT at its next heartbeat without a restart (`cmd/sprout` `heartbeatGate`, `pki.SproutBus.ReloadUserJWT`); the heartbeat body now carries the sending connection's ID, used only as the owner of a presence key farmer creates.
