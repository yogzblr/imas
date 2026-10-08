package main

import (
	"context"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/heartbeat"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
)

// heartbeatPermitted reports whether this sprout may publish its heartbeat
// subject. An empty userJWT is a bus connection without a per-sprout User
// JWT, which has no per-subject permissions to check.
func heartbeatPermitted(userJWT, id string) bool {
	return userJWT == "" || userJWTGrantsPub(userJWT, pki.SproutHeartbeatSubject(id))
}

// startHeartbeat starts the periodic liveness heartbeat on nc, tied to ctx
// like the sprout's other loops: it publishes once now and then every
// heartbeat.Interval, so farmer keeps the sprout's "connected" key fresh
// for as long as the connection is up. Farmer takes the sprout ID from the
// subject only; the message is empty.
//
// A User JWT minted before the heartbeat grant existed can't publish it;
// nats-server would drop every message with a permissions violation, so
// the loop isn't started. The sprout still shows as connected from its
// CONNECT event until the key's TTL lapses; farmer re-mints the JWT, and
// it takes effect after the next refresh and restart.
func startHeartbeat(ctx context.Context, nc *nats.Conn, userJWT string) {
	if !heartbeatPermitted(userJWT, sproutID) {
		log.Warnf("not sending heartbeats: this sprout's User JWT has no publish grant for %s, so farmer will show it as disconnected %s after it connects; farmer re-mints the JWT, and it takes effect after the next refresh and restart", pki.SproutHeartbeatSubject(sproutID), heartbeat.TTL)
		return
	}
	go heartbeat.RunSprout(ctx, nc, sproutID, heartbeat.Interval)
}
