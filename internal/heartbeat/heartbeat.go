// Package heartbeat answers "is this sprout online" for GetSprout and
// ListSprouts with a single Valkey read (key imas:heartbeat:<tenant>:
// <sprout_id>) instead of a live round trip to the sprout, which is what
// the old app-level heartbeat (internal/natsapi's probeSprout, a
// synchronous request/reply ping with a 3s worst-case timeout — see
// docs/design/imas-master-plan.md Phase 1) did.
//
// Three things write that key, and TTL is only the last resort:
//
//  1. CONNECT sets it. Farmer subscribes to $SYS.ACCOUNT.*.CONNECT/
//     DISCONNECT on its bus (as the SYS account — see
//     internal/pki.ConnectSystemAccount) and sets the key, with TTL, when a
//     sprout's connection is authenticated. This is also all an older
//     sprout that sends no heartbeat gets.
//  2. The sprout's own periodic heartbeat refreshes it. A CONNECT event
//     fires once, so on its own the key would expire TTL after the
//     connection was made while the sprout stays connected (UAT.12: four
//     sprouts connected for 38 minutes had no key at all). RunSprout
//     publishes pki.SproutHeartbeatSubject(id) at connect and then every
//     Interval; RegisterTenant, on each per-tenant farmer connection,
//     refreshes the key from it.
//  3. DISCONNECT deletes it immediately.
//
// TTL is therefore a safety net behind the heartbeat, not the thing that
// normally ends or sustains the key: it takes a sprout offline within TTL
// when neither a DISCONNECT nor a heartbeat arrives (the sprout or its host
// dying without the bus noticing, the bus dying before it can publish a
// DISCONNECT, a DISCONNECT lost to a farmer restart). Interval is TTL/5, so
// several heartbeats can be lost before the key lapses.
//
// Trust: a heartbeat is only the subject it arrived on. Farmer ignores the
// body, takes the sprout ID from the subject's last token, validates it
// (pki.IsValidSproutID) and refreshes the key only if
// pki.VerifySproutInTenant says that sprout is accepted in the tenant of
// the connection it arrived on (a positive answer is cached for
// DefaultAcceptCacheTTL; acceptcache.go). A sprout's User JWT can publish only its
// own subject (pki.sproutPermissions), so one sprout cannot keep another
// looking online. A heartbeat from an unaccepted, unknown or other
// tenant's sprout is dropped silently.
//
// Correlating a CONNECT/DISCONNECT event to a sprout: nats-server's
// ConnectEventMsg/DisconnectEventMsg carry ClientInfo.User, which for a
// JWT-authenticated connection is the User JWT's subject — i.e. the
// sprout's NKey public key (see internal/pki/jwtusers.go's
// mintOrReuseUserJWT, which mints each sprout's User JWT with Subject =
// its NKey pubkey). This package reverse-looks that up via
// pki.SproutIDForNKey, which also acts as the filter for events that
// aren't a sprout at all (farmer's own connection, a imas CLI admin, or
// the SYS push user itself) — those simply fail the lookup and are
// ignored.
//
// Known race, not addressed here: a DISCONNECT for an old connection that
// is processed after the CONNECT of its replacement deletes the key. The
// next heartbeat (at most Interval later) sets it again.
package heartbeat

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/valkey-io/valkey-go"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
)

// TTL is how long a heartbeat key survives without being refreshed. It is
// a safety net behind the sprout's periodic heartbeat (see Interval and the
// package comment), not the mechanism that keeps a connected sprout online:
// a sprout that is connected and healthy refreshes the key long before it
// lapses.
const TTL = 5 * time.Minute

// Interval is how often a sprout publishes its heartbeat. Derived from TTL
// so the two cannot drift: the key is refreshed five times per TTL, so a
// few lost heartbeats do not flap a sprout offline.
const Interval = TTL / 5

// ttl is the TTL actually written to Valkey; tests shorten it. Production
// code never assigns it.
var ttl = TTL

const keyPrefix = "imas:heartbeat:"

// client is the shared Valkey client. Nil until SetClient is called.
var client valkey.Client

// SetClient installs the Valkey client this package reads and writes
// through. Call once at startup.
func SetClient(c valkey.Client) { client = c }

func keyFor(tenant, sproutID string) string {
	return keyPrefix + tenant + ":" + sproutID
}

// IsOnline reports whether sproutID, within tenantID, currently holds a
// live heartbeat key.
func IsOnline(ctx context.Context, tenantID, sproutID string) bool {
	if client == nil {
		return false
	}
	n, err := client.Do(ctx, client.B().Exists().Key(keyFor(tenantID, sproutID)).Build()).ToInt64()
	return err == nil && n > 0
}

// clientInfo mirrors the fields this package needs from nats-server's
// server.ClientInfo (events.go): User (the authenticated pubkey) and
// Account (the connecting NATS Account's own public key, JSON-tagged
// "acc") — the SYS account sees this field for every tenant's
// connections, not just one, which is what makes CONNECT/DISCONNECT the
// one call site in this package that can derive a real per-event tenant
// today (see docs/design/imas-tenant-context-threading.md).
type clientInfo struct {
	User    string `json:"user"`
	Account string `json:"acc"`
}

type connectOrDisconnectEvent struct {
	Client clientInfo `json:"client"`
}

// RegisterListener subscribes nc — a connection authenticated as the SYS
// account (see pki.ConnectSystemAccount) — to
// $SYS.ACCOUNT.*.CONNECT/DISCONNECT and maintains Valkey heartbeat keys
// from them. nc should be a long-lived, dedicated connection: this
// function returns once both subscriptions are registered, not when the
// listener stops.
func RegisterListener(nc *nats.Conn) error {
	if _, err := nc.Subscribe("$SYS.ACCOUNT.*.CONNECT", func(msg *nats.Msg) {
		handleConnect(msg.Data)
	}); err != nil {
		return err
	}
	if _, err := nc.Subscribe("$SYS.ACCOUNT.*.DISCONNECT", func(msg *nats.Msg) {
		handleDisconnect(msg.Data)
	}); err != nil {
		return err
	}
	return nil
}

func handleConnect(data []byte) {
	tenant, sproutID, ok := sproutIDFromEvent(data, "CONNECT")
	if !ok || client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := client.B().Set().Key(keyFor(tenant, sproutID)).Value("1").Ex(ttl).Build()
	if err := client.Do(ctx, cmd).Error(); err != nil {
		log.Errorf("heartbeat: setting key for sprout %s (tenant %s): %v", sproutID, tenant, err)
	}
}

func handleDisconnect(data []byte) {
	tenant, sproutID, ok := sproutIDFromEvent(data, "DISCONNECT")
	if !ok || client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := client.B().Del().Key(keyFor(tenant, sproutID)).Build()
	if err := client.Do(ctx, cmd).Error(); err != nil {
		log.Errorf("heartbeat: deleting key for sprout %s (tenant %s): %v", sproutID, tenant, err)
	}
}

// sproutIDFromEvent decodes a CONNECT/DISCONNECT event, resolves its
// connecting Account pubkey (ev.Client.Account) to a real tenant ID via
// pki.TenantIDForAccountPub, and then resolves its authenticated user
// pubkey to an accepted sprout ID *within that tenant*. ok is false for a
// malformed event, an Account that isn't a provisioned tenant (the SYS
// account's own connections, e.g.), or a connection that isn't a
// currently-accepted sprout of that tenant (farmer's own connection, a CLI
// admin, or a sprout that was denied/deleted between connecting and this
// lookup) — none of those are errors worth logging, just events this
// package has nothing to do with.
func sproutIDFromEvent(data []byte, kind string) (tenant, sproutID string, ok bool) {
	var ev connectOrDisconnectEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		log.Errorf("heartbeat: decoding %s event: %v", kind, err)
		return "", "", false
	}
	tenant, err := pki.TenantIDForAccountPub(ev.Client.Account)
	if err != nil {
		return "", "", false
	}
	sproutID, err = pki.SproutIDForNKey(tenant, ev.Client.User)
	if err != nil {
		return "", "", false
	}
	return tenant, sproutID, true
}

// natsCoreQueueGroup is the queue group farmer's other per-tenant
// subscriptions share (internal/facts, internal/jobs, internal/natsapi),
// so with several farmer replicas each heartbeat is handled by one of
// them: one PXC lookup and one Valkey write, not one per replica.
const natsCoreQueueGroup = "imas-core"

// RegisterTenant subscribes nc — farmer's connection into tenantID's own
// Account — to every sprout's heartbeat subject and refreshes the
// matching Valkey key for each valid heartbeat from an accepted sprout of
// tenantID. Call it once per tenant connection (cmd/farmer's
// registerTenantHandlers).
func RegisterTenant(nc *nats.Conn, tenantID string) error {
	_, err := nc.QueueSubscribe(pki.SproutHeartbeatSubjectPattern, natsCoreQueueGroup, func(msg *nats.Msg) {
		handleHeartbeat(tenantID, msg.Subject)
	})
	return err
}

// sproutIDFromHeartbeatSubject extracts the sprout ID from a heartbeat
// subject: whatever follows pki.SproutHeartbeatSubjectPrefix, which must
// be a single valid sprout ID token. The message body plays no part.
func sproutIDFromHeartbeatSubject(subject string) (string, bool) {
	id, ok := strings.CutPrefix(subject, pki.SproutHeartbeatSubjectPrefix)
	if !ok || !pki.IsValidSproutID(id) {
		return "", false
	}
	return id, true
}

// handleHeartbeat refreshes the key for the sprout named by subject, if it
// is an accepted sprout of tenantID, through acceptedSprouts (a bounded
// cache of positive results; see acceptcache.go for what staleness that
// accepts). tenantID comes from the connection
// the message arrived on (a tenant's Account), never from the message.
// Anything else is dropped without logging: it is not an error, just a
// message this package has nothing to do with.
func handleHeartbeat(tenantID, subject string) {
	if client == nil {
		return
	}
	sproutID, ok := sproutIDFromHeartbeatSubject(subject)
	if !ok {
		return
	}
	if err := acceptedSprouts.check(tenantID, sproutID); err != nil {
		if !errors.Is(err, pki.ErrSproutIDNotFound) && !errors.Is(err, pki.ErrSproutIDInvalid) &&
			!errors.Is(err, pki.ErrTenantNotFound) && !errors.Is(err, pki.ErrTenantIDInvalid) {
			log.Warnf("heartbeat: checking sprout %s (tenant %s): %v", sproutID, tenantID, err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := client.B().Set().Key(keyFor(tenantID, sproutID)).Value("1").Ex(ttl).Build()
	if err := client.Do(ctx, cmd).Error(); err != nil {
		log.Errorf("heartbeat: refreshing key for sprout %s (tenant %s): %v", sproutID, tenantID, err)
	}
}

// busConn is the part of *nats.Conn RunSprout uses.
type busConn interface {
	Publish(subject string, data []byte) error
	IsConnected() bool
}

// RunSprout publishes sproutID's heartbeat on nc once immediately and then
// every interval (Interval when interval <= 0), until ctx is done. Run it
// in its own goroutine once the sprout is connected to the bus. The
// message is empty: it carries nothing farmer trusts, and farmer takes the
// sprout ID from the subject. While nc is disconnected or reconnecting the
// tick is skipped rather than buffered; the reconnect itself produces a
// CONNECT event that sets the key, and the next tick follows.
func RunSprout(ctx context.Context, nc busConn, sproutID string, interval time.Duration) {
	if interval <= 0 {
		interval = Interval
	}
	subject := pki.SproutHeartbeatSubject(sproutID)
	beat := func() {
		if !nc.IsConnected() {
			return
		}
		if err := nc.Publish(subject, nil); err != nil {
			log.Debugf("heartbeat: publishing on %s: %v", subject, err)
		}
	}
	beat()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			beat()
		}
	}
}
