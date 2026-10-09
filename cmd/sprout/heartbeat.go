package main

import (
	"context"
	"time"

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

// staleJWTRefreshTimeout bounds the one refresh refreshStaleUserJWT makes
// before the sprout connects.
const staleJWTRefreshTimeout = 20 * time.Second

// refreshStaleUserJWT asks farmer for a fresh User JWT when the persisted
// one lacks the heartbeat grant, so a sprout whose package was upgraded
// connects with the re-minted JWT on that very start. Without it the
// refresher, which sleeps until the gateway JWT is due, fetches the
// re-minted JWT hours or days later and the sprout needs another restart
// to use it, meanwhile showing as disconnected 5 minutes after each
// connect. Only a sprout with a stale JWT refreshes early, so a fleet-wide
// restart does not turn into a refresh stampede. Best effort: any failure
// is logged and the sprout connects with the JWT it has; the refresher
// still handles everything else, fatal pin errors included. It reports
// whether a refresh was made and succeeded.
func refreshStaleUserJWT(ctx context.Context, id string, load func() (string, error), refresh func(context.Context) (string, error)) bool {
	userJWT, err := load()
	if err != nil || heartbeatPermitted(userJWT, id) {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, staleJWTRefreshTimeout)
	defer cancel()
	if _, err := refresh(ctx); err != nil {
		log.Warnf("refreshing the User JWT before connecting failed, connecting with the one on disk: %v", err)
		return false
	}
	log.Infof("this sprout's User JWT predates the heartbeat grant; refreshed it from farmer before connecting")
	return true
}
