package main

import (
	"context"
	"sync"
	"time"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/heartbeat"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/shell"
)

// heartbeatPermitted reports whether this sprout may publish its heartbeat
// subject. An empty userJWT is a bus connection without a per-sprout User
// JWT, which has no per-subject permissions to check.
func heartbeatPermitted(userJWT, id string) bool {
	return userJWT == "" || userJWTGrantsPub(userJWT, pki.SproutHeartbeatSubject(id))
}

// sproutBus is the part of *pki.SproutBus the heartbeat gate uses.
type sproutBus interface {
	UserJWT() string
	ReloadUserJWT() (bool, error)
}

// reconnecter is the part of *nats.Conn the heartbeat gate uses.
type reconnecter interface {
	ForceReconnect() error
}

// heartbeatGate is the heartbeat loop's before hook (heartbeat.RunSprout).
// On every tick it reads the persisted User JWT; when a refresh has
// changed it, the bus connection is reopened with the new one
// (ForceReconnect, and the bus applies the new grant at once) and
// onSwitch re-applies what depends on the grant (log shipping, the
// warnings of applyGrants), so the sprout uses a re-minted JWT without a
// restart. That tick does not publish: the reconnect's CONNECT event sets
// farmer's presence key, and the next tick publishes on the new
// connection. Otherwise the tick publishes only if the JWT in use grants
// the heartbeat subject; a JWT minted before that grant is warned about
// once, not on every tick.
func heartbeatGate(bus sproutBus, nc reconnecter, id string, onSwitch func(userJWT string)) func() bool {
	var once sync.Once
	return func() bool {
		changed, err := bus.ReloadUserJWT()
		if err != nil {
			log.Debugf("heartbeat: not checking for a refreshed User JWT: %v", err)
		}
		if changed {
			log.Infof("this sprout's User JWT was refreshed; reconnecting to the bus with it")
			if err := nc.ForceReconnect(); err != nil {
				log.Warnf("reconnecting to the bus with the refreshed User JWT: %v; it is used on the next reconnect", err)
			}
			if onSwitch != nil {
				onSwitch(bus.UserJWT())
			}
			return false
		}
		if !heartbeatPermitted(bus.UserJWT(), id) {
			once.Do(func() {
				log.Warnf("not sending heartbeats: this sprout's User JWT has no publish grant for %s, so farmer will show it as disconnected %s after it connects; farmer re-mints the JWT, and the sprout reconnects with it at the first heartbeat after the next refresh", pki.SproutHeartbeatSubject(id), heartbeat.TTL)
			})
			return false
		}
		return true
	}
}

// startHeartbeat starts the periodic liveness heartbeat on nc, tied to ctx
// like the sprout's other loops: it publishes once now and then every
// heartbeat.Interval, so farmer keeps the sprout's "connected" key fresh
// for as long as the connection is up. Farmer takes the sprout ID from the
// subject; the message is the connection's ID (heartbeat.ConnID). Each
// tick first runs heartbeatGate, which also picks up a User JWT a refresh
// has changed.
func startHeartbeat(ctx context.Context, nc *nats.Conn, bus *pki.SproutBus) {
	gate := heartbeatGate(bus, nc, sproutID, func(userJWT string) { applyGrants(nc, userJWT) })
	go heartbeat.RunSprout(ctx, nc, sproutID, heartbeat.Interval, gate)
}

// applyGrants sets up what depends on the User JWT's grants, for the JWT
// the connection presents: log shipping over the bus connection when the
// JWT grants it, and a warning for each feature the JWT cannot serve yet.
// ConnectSprout calls it once connected, and heartbeatGate again after it
// reconnects with a refreshed JWT; attaching log shipping twice to the
// same connection is harmless (log.UseNATSConn).
func applyGrants(nc *nats.Conn, userJWT string) {
	// Ship logs over this same authenticated connection: a separate dial to
	// FarmerBusURL has neither the User JWT nor the enrolled addresses.
	if !pki.SproutUserJWTGrantsLogs(userJWT, sproutID) {
		log.Warnf("not shipping logs to the bus: this sprout's User JWT has no grant for %s.>; farmer re-mints it, and the sprout reconnects with it at the first heartbeat after the next refresh", pki.SproutLogSubjectPrefix(sproutID))
	} else if err := log.UseNATSConn(nc, pki.SproutLogSubjectPrefix(sproutID)); err != nil {
		log.Errorf("Failed to attach log-nats backend to the bus connection: %v", err)
	}
	// A User JWT minted before SproutPermissions carried the grant: until
	// then nats-server drops the submission, and a rotation farmer
	// triggers never completes (harmlessly; see boxkey.go).
	if submit := pki.SproutBoxKeySubmitSubject(sproutID); userJWT != "" && !userJWTGrantsPub(userJWT, submit) {
		log.Warnf("farmer-triggered payload-encryption key rotation can't complete: this sprout's User JWT has no publish grant for %s; farmer re-mints it, and the sprout reconnects with it at the first heartbeat after the next refresh", submit)
	}
	// Sealed shell's s2f frames need this grant (J.5); a JWT minted
	// before it can't publish them until the sprout reconnects with a
	// refreshed one.
	if grant := shell.SproutOutSubjectPrefix(sproutID) + ".>"; userJWT != "" && !userJWTGrantsPub(userJWT, grant) {
		log.Warnf("shell sessions to this sprout can't work yet: its User JWT has no publish grant for %s.>; farmer re-mints it, and the sprout reconnects with it at the first heartbeat after the next refresh", shell.SproutOutSubjectPrefix(sproutID))
	}
}

// staleJWTRefreshTimeout bounds the one refresh refreshStaleUserJWT makes
// before the sprout connects.
const staleJWTRefreshTimeout = 20 * time.Second

// refreshStaleUserJWT asks farmer for a fresh User JWT when the persisted
// one does not carry the sprout's full grant (pki.SproutUserJWTHasFullGrant:
// every subject of pki.SproutPermissions, heartbeat, logs, box key, shell
// and any later one, and nothing else), so a sprout whose package was
// upgraded connects with the re-minted JWT on that very start. Without it
// the refresher, which sleeps until the gateway JWT is due, fetches the
// re-minted JWT hours or days later (the heartbeat gate then reconnects
// with it), meanwhile showing as disconnected 5 minutes after each connect
// when the heartbeat grant is the one missing. Only a sprout with a stale
// JWT refreshes early, so a fleet-wide restart does not turn into a
// refresh stampede. Best effort: any failure is logged and the sprout
// connects with the JWT it has; the refresher still handles everything
// else, fatal pin errors included. It reports whether a refresh was made
// and succeeded.
func refreshStaleUserJWT(ctx context.Context, id string, load func() (string, error), refresh func(context.Context) (string, error)) bool {
	userJWT, err := load()
	if err != nil || pki.SproutUserJWTHasFullGrant(userJWT, id) {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, staleJWTRefreshTimeout)
	defer cancel()
	if _, err := refresh(ctx); err != nil {
		log.Warnf("refreshing the User JWT before connecting failed, connecting with the one on disk: %v", err)
		return false
	}
	log.Infof("this sprout's User JWT does not carry its current grant; refreshed it from farmer before connecting")
	return true
}
