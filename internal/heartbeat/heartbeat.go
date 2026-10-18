// Package heartbeat answers "is this sprout online" for GetSprout and
// ListSprouts with a single Valkey read (key imas:heartbeat:{<tenant>:
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
//     sprout's connection is authenticated. The value is that
//     connection's ID (ConnID: the bus node's server ID and the client ID
//     it gave the connection). This is also all an older sprout that sends
//     no heartbeat gets.
//  2. The sprout's own periodic heartbeat refreshes it. A CONNECT event
//     fires once, so on its own the key would expire TTL after the
//     connection was made while the sprout stays connected (UAT.12: four
//     sprouts connected for 38 minutes had no key at all). RunSprout
//     publishes pki.SproutHeartbeatSubject(id) at connect and then every
//     Interval; RegisterTenant, on each per-tenant farmer connection,
//     refreshes the key from it. A refresh extends the key and keeps the
//     connection ID it holds; only when there is no key does it write
//     one, with the connection ID the heartbeat names (see
//     handleHeartbeat).
//  3. DISCONNECT deletes it immediately, but only if it still holds the
//     ID of the connection that ended (disconnectScript, one atomic
//     compare-and-delete). A sprout that reconnects gets a CONNECT for its
//     new connection and a DISCONNECT for its old one, on two different
//     subscriptions, in either order; the DISCONNECT that arrives after
//     the new CONNECT finds the new connection's ID and leaves the key
//     alone (owner decision T3: a DISCONNECT only removes the presence of
//     the connection it belongs to).
//
// TTL is therefore a safety net behind the heartbeat, not the thing that
// normally ends or sustains the key: it takes a sprout offline within TTL
// when neither a DISCONNECT nor a heartbeat arrives (the sprout or its host
// dying without the bus noticing, the bus dying before it can publish a
// DISCONNECT, a DISCONNECT lost to a farmer restart). Interval is TTL/5, so
// several heartbeats can be lost before the key lapses.
//
// Trust: which sprout a heartbeat is for is only the subject it arrived on.
// Farmer takes the sprout ID from the subject's last token (the body, the
// sending connection's ID, only names the owner of a presence key the
// heartbeat has to create; see handleHeartbeat), validates it
// (pki.IsValidSproutID) and refreshes the key only if
// pki.VerifySproutInTenant says that sprout is accepted in the tenant of
// the connection it arrived on. The answer is remembered in Valkey as an
// acceptance marker (AcceptedTTL), so most heartbeats cost no database read.
// A sprout's User JWT can publish only its own subject
// (pki.SproutPermissions), so one sprout cannot keep another looking
// online. A heartbeat from an unaccepted, unknown or other
// tenant's sprout is dropped silently.
//
// Correlating a CONNECT/DISCONNECT event to a sprout: nats-server's
// ConnectEventMsg/DisconnectEventMsg carry ClientInfo.User, which for a
// JWT-authenticated connection is the User JWT's subject — i.e. the
// sprout's NKey public key (see internal/pki/jwtusers.go's
// MintOrReuseUserJWT, which mints each sprout's User JWT with Subject =
// its NKey pubkey). This package reverse-looks that up via
// pki.SproutIDForNKey, which also acts as the filter for events that
// aren't a sprout at all (farmer's own connection, a imas CLI admin, or
// the SYS push user itself) — those simply fail the lookup and are
// ignored.
//
// Valkey Cluster: every script here names only keys that share the hash
// tag {<tenant>:<sprout>} (slotTag), so each runs on one shard. The tests
// prove it against a real standalone Valkey and a real 3-shard Valkey
// Cluster (valkey_real_test.go).
package heartbeat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/valkey-io/valkey-go"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/tenantpurge"
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

// keyPrefix names the presence keys. internal/tenantpurge's inventory
// owns the name, so a purge deletes exactly these keys.
const keyPrefix = tenantpurge.ValkeyHeartbeatPrefix

// acceptedPrefix names the acceptance markers.
const acceptedPrefix = tenantpurge.ValkeyAcceptedPrefix

// acceptedKeyFor is the acceptance marker for sproutID within tenant:
// "farmer has verified, against the database, that this sprout is accepted
// in this tenant". Keyed on both, like the presence key, because a sprout
// ID is unique per tenant only. The presence key (keyFor) keeps its name
// and meaning and its TTL; the marker is separate and long-lived.
func acceptedKeyFor(tenant, sproutID string) string {
	return acceptedPrefix + slotTag(tenant, sproutID)
}

// client is the shared Valkey client. Nil until SetClient is called.
var client valkey.Client

// SetClient installs the Valkey client this package reads and writes
// through. Call once at startup.
func SetClient(c valkey.Client) { client = c }

// slotTag is the part of both keys inside the braces: Valkey hashes only
// that part, so a sprout's presence key and acceptance marker share a slot
// (needed by refreshScript) and still differ per (tenant, sprout).
func slotTag(tenant, sproutID string) string {
	return "{" + tenant + ":" + sproutID + "}"
}

func keyFor(tenant, sproutID string) string {
	return keyPrefix + slotTag(tenant, sproutID)
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
	ID      uint64 `json:"id"`
	User    string `json:"user"`
	Account string `json:"acc"`
}

// serverInfo mirrors the field this package needs from nats-server's
// server.ServerInfo: the ID of the bus node that published the event,
// the node the connection is on.
type serverInfo struct {
	ID string `json:"id"`
}

type connectOrDisconnectEvent struct {
	Server serverInfo `json:"server"`
	Client clientInfo `json:"client"`
}

// ConnID names one bus connection: the server ID of the bus node it is
// on and the client ID that node gave it, "<server_id>/<client_id>". A
// client ID is unique on one node only, and a node gets a new server ID
// each time it starts, so the pair names one connection across a bus
// cluster and its restarts. A CONNECT/DISCONNECT event carries both
// (server.id, client.id); a sprout learns them from its own connection
// (nats.Conn's ConnectedServerId and GetClientID). It returns "" when
// either is missing: such a connection cannot be told apart from another.
func ConnID(serverID string, clientID uint64) string {
	if serverID == "" || clientID == 0 || strings.ContainsAny(serverID, "/ \t\r\n") {
		return ""
	}
	return serverID + "/" + strconv.FormatUint(clientID, 10)
}

// maxConnIDLen bounds a connection ID taken from a heartbeat body: a
// server ID is a 56-character NKey and a client ID at most 20 digits.
const maxConnIDLen = 96

// connIDFromBody returns the connection ID a heartbeat names, or "" when
// the body is empty (a sprout from before this field) or not a
// well-formed ID.
func connIDFromBody(body []byte) string {
	if len(body) == 0 || len(body) > maxConnIDLen {
		return ""
	}
	serverID, client, ok := strings.Cut(string(body), "/")
	if !ok {
		return ""
	}
	n, err := strconv.ParseUint(client, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != client {
		return ""
	}
	return ConnID(serverID, n)
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

// handleConnect writes the presence key of the sprout that connected,
// holding the new connection's ID: a plain write, so the newest
// connection always owns the key, whatever the key held before.
func handleConnect(data []byte) {
	tenant, sproutID, connID, ok := sproutIDFromEvent(data, "CONNECT")
	if !ok || client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := setPresence(ctx, tenant, sproutID, connID); err != nil {
		log.Errorf("heartbeat: setting key for sprout %s (tenant %s): %v", sproutID, tenant, err)
	}
}

// handleDisconnect deletes the presence key of the sprout whose
// connection ended, if the key still holds that connection's ID. An event
// without a connection ID deletes nothing: it cannot show that the key is
// its connection's.
func handleDisconnect(data []byte) {
	tenant, sproutID, connID, ok := sproutIDFromEvent(data, "DISCONNECT")
	if !ok || client == nil || connID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := deletePresenceIfOwner(ctx, tenant, sproutID, connID); err != nil {
		log.Errorf("heartbeat: deleting key for sprout %s (tenant %s): %v", sproutID, tenant, err)
	}
}

// setPresence is CONNECT's write: the presence key holds connID, with
// the presence TTL.
func setPresence(ctx context.Context, tenant, sproutID, connID string) error {
	return client.Do(ctx, client.B().Set().Key(keyFor(tenant, sproutID)).Value(connID).Ex(ttl).Build()).Error()
}

// disconnectScript deletes the presence key KEYS[1] if, and only if, it
// holds the connection ID ARGV[1], in one step, so no CONNECT can land
// between the compare and the delete. It returns 1 if it deleted the key
// and 0 if the key was absent or held another connection's ID.
var disconnectScript = valkey.NewLuaScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0`)

// deletePresenceIfOwner is DISCONNECT's compare-and-delete. It reports
// whether it deleted the key.
func deletePresenceIfOwner(ctx context.Context, tenant, sproutID, connID string) (bool, error) {
	n, err := disconnectScript.Exec(ctx, client, []string{keyFor(tenant, sproutID)}, []string{connID}).ToInt64()
	return n == 1, err
}

// presenceOwner returns the connection ID the presence key holds, and
// whether the key exists.
func presenceOwner(ctx context.Context, tenant, sproutID string) (string, bool, error) {
	v, err := client.Do(ctx, client.B().Get().Key(keyFor(tenant, sproutID)).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return "", false, nil
	}
	return v, err == nil, err
}

// sproutIDFromEvent decodes a CONNECT/DISCONNECT event, takes its
// connection ID (ConnID of server.id and client.id, "" if either is
// missing), resolves its
// connecting Account pubkey (ev.Client.Account) to a real tenant ID via
// pki.TenantIDForAccountPub, and then resolves its authenticated user
// pubkey to an accepted sprout ID *within that tenant*. ok is false for a
// malformed event, an Account that isn't a provisioned tenant (the SYS
// account's own connections, e.g.), or a connection that isn't a
// currently-accepted sprout of that tenant (farmer's own connection, a CLI
// admin, or a sprout that was denied/deleted between connecting and this
// lookup) — none of those are errors worth logging, just events this
// package has nothing to do with.
func sproutIDFromEvent(data []byte, kind string) (tenant, sproutID, connID string, ok bool) {
	var ev connectOrDisconnectEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		log.Errorf("heartbeat: decoding %s event: %v", kind, err)
		return "", "", "", false
	}
	tenant, err := pki.TenantIDForAccountPub(ev.Client.Account)
	if err != nil {
		return "", "", "", false
	}
	sproutID, err = pki.SproutIDForNKey(tenant, ev.Client.User)
	if err != nil {
		return "", "", "", false
	}
	return tenant, sproutID, ConnID(ev.Server.ID, ev.Client.ID), true
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
		handleHeartbeat(tenantID, msg.Subject, msg.Data)
	})
	return err
}

// sproutIDFromHeartbeatSubject extracts the sprout ID from a heartbeat
// subject: whatever follows pki.SproutHeartbeatSubjectPrefix, which must
// be a single valid sprout ID token. The message body plays no part in
// which sprout it is.
func sproutIDFromHeartbeatSubject(subject string) (string, bool) {
	id, ok := strings.CutPrefix(subject, pki.SproutHeartbeatSubjectPrefix)
	if !ok || !pki.IsValidSproutID(id) {
		return "", false
	}
	return id, true
}

// AcceptedTTL is how long an acceptance marker lives. It is a fixed
// lifetime set when the marker is written, never extended by heartbeats, so
// every sprout is re-verified against the database about every AcceptedTTL
// (plus up to 10% jitter) no matter how steadily it heartbeats. That bounds
// how long a missed invalidation can matter; see acceptedKeyFor.
const AcceptedTTL = 4 * time.Hour

// acceptedTTL and acceptedJitter are the values actually used; tests change
// them. Production code never assigns them.
var (
	acceptedTTL    = AcceptedTTL
	acceptedJitter = 0.10
)

// verifySprout is the database check a missing marker falls back to; tests
// replace it to count calls.
var verifySprout = pki.VerifySproutInTenant

// refreshScript atomically refreshes the presence key if, and only if, the
// acceptance marker exists. KEYS[1] is the marker, KEYS[2] the presence
// key, ARGV[1] the presence TTL in seconds, ARGV[2] the connection ID the
// heartbeat names ("" if none). A presence key that exists is extended and
// keeps the connection ID it holds, so a heartbeat never takes the key
// from the connection a CONNECT gave it to (a heartbeat of an old
// connection can arrive after the CONNECT of the new one); one that does
// not exist is written with ARGV[2]. It returns 1 if it refreshed and 0
// (touching nothing) if the marker is absent. Both keys are passed as
// KEYS, so they must hash to one slot: valkey-go rejects a multi-key command
// over different slots client-side, even against a standalone server (it
// panics). keyFor and acceptedKeyFor therefore share the hash tag
// "{tenant:sprout}" (see slotTag).
var refreshScript = valkey.NewLuaScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then
  if redis.call('EXPIRE', KEYS[2], ARGV[1]) == 0 then
    redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[1])
  end
  return 1
end
return 0`)

// refreshPresence runs refreshScript for (tenant, sproutID). It reports
// whether the marker was there (and so the presence key refreshed).
func refreshPresence(ctx context.Context, tenant, sproutID, connID string) (bool, error) {
	n, err := refreshScript.Exec(ctx, client,
		[]string{acceptedKeyFor(tenant, sproutID), keyFor(tenant, sproutID)},
		[]string{strconv.FormatInt(int64(ttl/time.Second), 10), connID}).ToInt64()
	return n == 1, err
}

// markerLifetime is a new marker's lifetime: acceptedTTL plus a random 0 to
// acceptedJitter of it, so markers written together do not expire together.
func markerLifetime() time.Duration {
	d := time.Duration(float64(acceptedTTL) * (1 + acceptedJitter*rand.Float64()))
	return d.Truncate(time.Second)
}

// handleHeartbeat refreshes the presence key of the sprout named by
// subject, if it is an accepted sprout of tenantID. tenantID comes from the
// connection the message arrived on (a tenant's Account), never from the
// message. The body is the sending connection's ID (ConnID), used only as
// the value of a presence key the heartbeat has to create: it can only
// name which of this sprout's own connections a DISCONNECT may end the
// presence of, since the subject is the sprout's own (its JWT grants no
// other), and an empty or malformed body writes "", which no DISCONNECT
// matches, so the key then lapses by TTL. Anything that is not an accepted sprout is dropped without
// logging: it is not an error, just a message this package has nothing to
// do with.
//
// Farmer keeps no state for this; the shared state is in Valkey:
//
//  1. refreshScript: marker present, so refresh the presence key (one
//     round trip, no database).
//  2. Marker absent (first heartbeat after accept, marker lapsed or
//     evicted by Valkey), or Valkey errored (treated as a miss): the live
//     pki.VerifySproutInTenant check. If it passes, write the marker with
//     its fixed lifetime and then refresh the presence key the way
//     refreshScript does, so it keeps the connection ID it holds. If it fails,
//     write nothing: a newly accepted sprout works at once.
//
// Staleness: a sprout moved out of the accepted state loses both keys at
// once through pki.OnSproutLeftAccepted (Invalidate). If that is ever
// missed (a farmer failing between the database write and the delete, a
// Valkey outage at that moment) the sprout can keep refreshing its
// presence flag until its marker lapses, at most acceptedTTL plus jitter.
// A deprovisioned tenant needs no sweep: farmer closes that tenant's bus
// connection, so no handler runs for it, and its keys lapse. None of this
// is authority: commands are authorised by the NATS User JWT permissions,
// and CONNECT/DISCONNECT does not use the marker.
func handleHeartbeat(tenantID, subject string, body []byte) {
	if client == nil {
		return
	}
	sproutID, ok := sproutIDFromHeartbeatSubject(subject)
	if !ok {
		return
	}
	connID := connIDFromBody(body)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	refreshed, err := refreshPresence(ctx, tenantID, sproutID, connID)
	if err == nil && refreshed {
		return
	}
	if err != nil {
		logLimited(fmt.Sprintf("heartbeat: refreshing sprout %s (tenant %s) in Valkey, falling back to the database: %v", sproutID, tenantID, err))
	}

	if err := verifySprout(tenantID, sproutID); err != nil {
		if !errors.Is(err, pki.ErrSproutIDNotFound) && !errors.Is(err, pki.ErrSproutIDInvalid) &&
			!errors.Is(err, pki.ErrTenantNotFound) && !errors.Is(err, pki.ErrTenantIDInvalid) {
			logLimited(fmt.Sprintf("heartbeat: checking sprout %s (tenant %s): %v", sproutID, tenantID, err))
		}
		return
	}
	// The presence write is refreshScript's without the marker check, as
	// plain commands so it works when the script is what failed: create the
	// key with connID only if there is none (NX), then extend whichever
	// key is there. A DISCONNECT between the two leaves the key deleted,
	// which is right: that connection ended.
	marker := client.B().Set().Key(acceptedKeyFor(tenantID, sproutID)).Value("1").Ex(markerLifetime()).Build()
	create := client.B().Set().Key(keyFor(tenantID, sproutID)).Value(connID).Nx().Ex(ttl).Build()
	extend := client.B().Expire().Key(keyFor(tenantID, sproutID)).Seconds(int64(ttl / time.Second)).Build()
	for _, r := range client.DoMulti(ctx, marker, create, extend) {
		if err := r.Error(); err != nil && !valkey.IsValkeyNil(err) {
			logLimited(fmt.Sprintf("heartbeat: writing keys for sprout %s (tenant %s): %v", sproutID, tenantID, err))
			break
		}
	}
}

// Invalidate deletes both the acceptance marker and the presence key of
// (tenantID, sproutID). Register it with pki.OnSproutLeftAccepted so a
// sprout that is denied, rejected, unaccepted or deleted stops being
// refreshed and stops looking online at once, on every farmer replica
// (the keys are shared).
func Invalidate(tenantID, sproutID string) {
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, r := range client.DoMulti(ctx,
		client.B().Del().Key(acceptedKeyFor(tenantID, sproutID)).Build(),
		client.B().Del().Key(keyFor(tenantID, sproutID)).Build()) {
		if err := r.Error(); err != nil {
			log.Errorf("heartbeat: dropping keys of sprout %s (tenant %s) that left the accepted state; its marker lapses within %s: %v", sproutID, tenantID, acceptedTTL, err)
			return
		}
	}
}

// lastLogged rate-limits logLimited. It is a log throttle only; it holds
// no state the heartbeat result depends on.
var lastLogged atomic.Int64

// logLimited logs msg at most once every 30 seconds, at warning level. The
// heartbeat handler runs per sprout per Interval, so a Valkey or database
// outage must not log once per heartbeat.
func logLimited(msg string) {
	now := time.Now().UnixNano()
	last := lastLogged.Load()
	if now-last < int64(30*time.Second) || !lastLogged.CompareAndSwap(last, now) {
		log.Debugf("%s", msg)
		return
	}
	log.Warnf("%s", msg)
}

// busConn is the part of *nats.Conn RunSprout uses.
type busConn interface {
	Publish(subject string, data []byte) error
	IsConnected() bool
	ConnectedServerId() string
	GetClientID() (uint64, error)
}

// connIDOf is the ID of nc's current connection (ConnID), "" when nc
// cannot tell it.
func connIDOf(nc busConn) string {
	cid, err := nc.GetClientID()
	if err != nil {
		return ""
	}
	return ConnID(nc.ConnectedServerId(), cid)
}

// RunSprout publishes sproutID's heartbeat on nc once immediately and then
// every interval (Interval when interval <= 0), until ctx is done. Run it
// in its own goroutine once the sprout is connected to the bus. The
// message is the connection's own ID (ConnID): farmer takes the sprout ID
// from the subject and uses the ID only to name the connection a presence
// key it has to create belongs to. While nc is disconnected or
// reconnecting the tick is skipped rather than buffered; the reconnect
// itself produces a CONNECT event that sets the key, and the next tick
// follows.
//
// before, if not nil, runs at the start of every tick, connected or not,
// and the tick publishes only if it returns true. cmd/sprout uses it to
// pick up a User JWT a refresh has changed (reconnecting with it) and to
// skip the publish while the JWT in use has no heartbeat grant.
func RunSprout(ctx context.Context, nc busConn, sproutID string, interval time.Duration, before func() bool) {
	if interval <= 0 {
		interval = Interval
	}
	subject := pki.SproutHeartbeatSubject(sproutID)
	beat := func() {
		if before != nil && !before() {
			return
		}
		if !nc.IsConnected() {
			return
		}
		if err := nc.Publish(subject, []byte(connIDOf(nc))); err != nil {
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

// PurgeTenant deletes every presence key, acceptance marker and upgrade
// marker (upgrade.go) of tenantID's sprouts (S6: a purged tenant's live
// cache), on every Valkey node, and returns how many keys of each kind it
// deleted ("valkey.heartbeat", "valkey.accepted", "valkey.upgrade"). The keys are found by the
// tenant part of their hash tag, {<tenant_id>:, which ends at a ':' no
// tenant ID contains, so no other tenant's key, even one for a sprout of
// the same ID, matches.
func PurgeTenant(ctx context.Context, tenantID string, batch int) (map[string]int64, error) {
	counts := map[string]int64{}
	if !tenantpurge.ValidTenantID(tenantID) {
		return counts, tenantpurge.ErrInvalidTenantID
	}
	if client == nil {
		return counts, errors.New("heartbeat: no Valkey client")
	}
	for _, prefix := range tenantpurge.PurgeValkeyPrefixes {
		n, err := tenantpurge.DeleteValkeyKeys(ctx, client, tenantpurge.ValkeyPattern(prefix, tenantID), batch)
		counts[tenantpurge.ValkeyCategory(prefix)] = n
		if err != nil {
			return counts, err
		}
	}
	return counts, nil
}
