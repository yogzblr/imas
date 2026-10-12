package pki

// The push-to-resolver mechanism from
// docs/design/imas-nats-jwt-auth-design.md: replaces pki.ReloadNKeys()'s old
// in-process NatsServer.ReloadOptions() call with an ordinary NATS
// connection, authenticated as the SYS account, that publishes the updated
// tenant Account JWT to the bus's "full" resolver. Unlike ReloadOptions(),
// this works identically whether the bus is embedded in this process, a
// separate DMZ node, or a cluster member — it only needs network
// reachability to the bus, not a shared Go process handle.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"

	nats_server "github.com/nats-io/nats-server/v2/server"

	"github.com/yogzblr/imas/internal/config"
	log "github.com/yogzblr/imas/internal/log"
)

const (
	claimsUpdateSubject = "$SYS.REQ.CLAIMS.UPDATE"
	serverPingSubject   = "$SYS.REQ.SERVER.PING"
	pushTimeout         = 10 * time.Second
)

// pushAccountUpdate publishes accountJWT (a signed Account JWT — the
// legacy single-tenant seam's mat.tenantJWT, or any dynamically-provisioned
// tenant's own Account JWT, see tenant.go) to the bus. Every push goes
// through here. With an AccountPublisher installed (cmd/farmer) that is
// its Publish: the accounts bucket first, then every bus node, then the
// accounts-changed event (docs/briefs/P21-slice2-bus-loader.md §7.3), so
// a newer JWT is always in the bucket before an older push can land.
// An older JWT than the bucket's is neither written nor pushed, and is not
// an error unless it is a lock-out (ErrAccountJWTSuperseded).
// Without one it is a push to every bus node over a fresh connection
// authenticated as the SYS account, failing if no node accepted it: the
// in-process test bus (ConfigureNats) only, as cmd/farmer refuses to
// start without the accounts bucket.
//
// This is the only publish point, and there is no write hook on signing
// (brief §7.2): no code sends an Account JWT to $SYS.REQ.CLAIMS.UPDATE
// but through here (TestNoAccountJWTReachesBusWithoutPublisher). A
// minimal Account JWT that farmer mints at boot (ensureNatsAuth's
// tenantMinted, ensureTenantAccountMaterial's minted) is deliberately not
// published when it is minted: it carries none of the tenant's
// revocations yet, and with its new iat it would outrank the revoked JWT
// in the bucket, so a bus node that restarts would admit revoked users.
// It reaches the bucket only through here, after syncNatsAuth or
// syncTenantSprouts has applied the revocations.
func pushAccountUpdate(mat *natsAuthMaterial, accountJWT string) error {
	if p := currentAccountPublisher(); p != nil {
		ac, err := jwt.DecodeAccountClaims(accountJWT)
		if err != nil {
			return fmt.Errorf("decoding the Account JWT to push: %w", err)
		}
		err = p.Publish(context.Background(), ac.Subject, accountJWT)
		if errors.Is(err, ErrAccountJWTSuperseded) && !errors.Is(err, errLockoutSuperseded) {
			return nil // the replica that signed the newer one pushed it
		}
		return err
	}
	nc, err := connectSystemAccount(mat)
	if err != nil {
		return fmt.Errorf("connecting as the SYS account: %w", err)
	}
	defer nc.Close()
	res, err := pushToAllNodes(nc, accountJWT, config.BusExpectedNodes)
	if err == nil && res.missing > 0 {
		log.Warnf("Account JWT push: %d bus nodes did not answer (%s=%d)", res.missing, logFieldPushMissingNodes, res.missing)
	}
	return err
}

// ConnectSystemAccount dials the configured bus authenticated as the
// farmer's SYS account, bootstrapping the same trust material ReloadNKeys
// uses for claims-update pushes. It's exported for internal/heartbeat,
// which needs a SYS-account connection to subscribe to
// $SYS.ACCOUNT.*.CONNECT/DISCONNECT — only the SYS account (or a Account
// with SDK-level system-event permissions) receives those advisories —
// and cmd/farmer/main.go also registers internal/natsapi's
// internal.tenant.provision/deprovision handlers on that same connection
// (docs/design/imas-internal-api-account.md). The caller owns the returned
// connection and should keep it open for the life of the listener rather
// than reconnecting per call; extra opts (e.g. nats.MaxReconnects(-1),
// nats.RetryOnFailedConnect(true) for a connection that must outlive a
// bus outage) are applied after the defaults below.
func ConnectSystemAccount(opts ...nats.Option) (*nats.Conn, error) {
	mat, err := ensureNatsAuth()
	if err != nil {
		return nil, fmt.Errorf("bootstrapping NATS auth material: %w", err)
	}
	return connectSystemAccount(mat, opts...)
}

// pushResult is how many bus nodes accepted a push and how many of
// those expected did not answer.
type pushResult struct {
	acked, missing int
}

// Timing of pushToAllNodes; tests shorten them.
var (
	// discoverWait bounds the server ping gather; discoverQuiet ends it
	// early once that long passes with no new node (with no expected
	// count to wait for).
	discoverWait  = time.Second
	discoverQuiet = 100 * time.Millisecond
	// pushRoundWait is how long one round waits for the nodes' replies.
	pushRoundWait = 3 * time.Second
	// pushRetries are the rounds after the first for nodes still
	// missing, with backoff from pushBackoffMin, tripled, to pushBackoffMax.
	pushRetries    = 3
	pushBackoffMin = 200 * time.Millisecond
	pushBackoffMax = 2 * time.Second
)

// pushToAllNodes pushes accountJWT to every bus node and waits for each
// (docs/briefs/P21-slice2-bus-loader.md §7.4): it finds the nodes with a
// $SYS.REQ.SERVER.PING gather, publishes the claims update once with
// its own reply inbox (every node handles it, and each reply names the
// node), and publishes it again for nodes that have not answered, up to
// pushRetries more rounds. It waits for expected nodes if expected is
// more than the number found. Nodes still missing are counted, not an
// error: the accounts bucket has the JWT and their loaders apply it. It
// fails if a node rejects the JWT or no node accepts it.
func pushToAllNodes(nc *nats.Conn, accountJWT string, expected int) (pushResult, error) {
	nodes := discoverBusNodes(nc, expected)
	want := max(expected, len(nodes), 1)

	inbox := nc.NewRespInbox()
	sub, err := nc.SubscribeSync(inbox)
	if err != nil {
		return pushResult{missing: want}, fmt.Errorf("claims update: %w", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	acked := map[string]bool{}
	done := func() bool {
		if len(acked) < want {
			return false
		}
		for id := range nodes {
			if !acked[id] {
				return false
			}
		}
		return true
	}
	var rejected error
	backoff := pushBackoffMin
	for round := 0; round <= pushRetries && !done() && rejected == nil; round++ {
		if round > 0 {
			time.Sleep(backoff)
			backoff = min(backoff*3, pushBackoffMax)
		}
		if err := nc.PublishRequest(claimsUpdateSubject, inbox, []byte(accountJWT)); err != nil {
			return pushResult{acked: len(acked), missing: want - len(acked)}, fmt.Errorf("claims update request: %w", err)
		}
		deadline := time.Now().Add(pushRoundWait)
		for !done() {
			wait := time.Until(deadline)
			if wait <= 0 {
				break
			}
			msg, err := sub.NextMsg(wait)
			if err != nil {
				break
			}
			var resp nats_server.ServerAPIClaimUpdateResponse
			if err := json.Unmarshal(msg.Data, &resp); err != nil || resp.Server == nil || resp.Server.ID == "" {
				continue
			}
			if resp.Error != nil {
				rejected = fmt.Errorf("bus node %s rejected the claims update: %s", resp.Server.ID, resp.Error.Description)
				continue
			}
			acked[resp.Server.ID] = true
		}
	}
	unacked := 0
	for id := range nodes {
		if !acked[id] {
			unacked++
		}
	}
	res := pushResult{acked: len(acked), missing: max(want-len(acked), unacked)}
	switch {
	case rejected != nil:
		return res, rejected
	case len(acked) == 0:
		return res, errors.New("claims update request: no bus node answered")
	}
	return res, nil
}

// discoverBusNodes gathers the server IDs that answer $SYS.REQ.SERVER.PING
// within discoverWait, stopping early once expected (if set) have
// answered or, without one, once discoverQuiet passes with no new answer.
func discoverBusNodes(nc *nats.Conn, expected int) map[string]bool {
	nodes := map[string]bool{}
	inbox := nc.NewRespInbox()
	sub, err := nc.SubscribeSync(inbox)
	if err != nil {
		return nodes
	}
	defer func() { _ = sub.Unsubscribe() }()
	if err := nc.PublishRequest(serverPingSubject, inbox, nil); err != nil {
		return nodes
	}
	deadline := time.Now().Add(discoverWait)
	for expected <= 0 || len(nodes) < expected {
		wait := time.Until(deadline)
		if expected <= 0 && len(nodes) > 0 {
			wait = min(wait, discoverQuiet)
		}
		if wait <= 0 {
			break
		}
		msg, err := sub.NextMsg(wait)
		if err != nil {
			break
		}
		var reply struct {
			Server struct {
				ID string `json:"id"`
			} `json:"server"`
		}
		if json.Unmarshal(msg.Data, &reply) == nil && reply.Server.ID != "" {
			nodes[reply.Server.ID] = true
		}
	}
	return nodes
}

// natsAccountBus is the accountBus over a SYS-account connection.
type natsAccountBus struct{ nc *nats.Conn }

func (b natsAccountBus) pushAll(accountJWT string) (pushResult, error) {
	return pushToAllNodes(b.nc, accountJWT, config.BusExpectedNodes)
}

func (b natsAccountBus) publish(subject string, payload []byte) error {
	if err := b.nc.Publish(subject, payload); err != nil {
		return err
	}
	return b.nc.FlushTimeout(pushTimeout)
}

func (b natsAccountBus) close() { b.nc.Close() }

// dialAccountBus opens the publisher's SYS-account connection.
func dialAccountBus() (accountBus, error) {
	nc, err := ConnectSystemAccount()
	if err != nil {
		return nil, err
	}
	return natsAccountBus{nc}, nil
}

// connectSystemAccount dials the configured bus as the farmer's SYS push
// user. It reuses the same root-CA trust the farmer's own NATS connection
// (cmd/farmer/main.go's ConnectFarmer) already relies on.
func connectSystemAccount(mat *natsAuthMaterial, opts ...nats.Option) (*nats.Conn, error) {
	busURL := config.FarmerBusURL
	rootPEM, err := os.ReadFile(config.RootCA)
	if err != nil || rootPEM == nil {
		return nil, fmt.Errorf("loading root CA %s: %w", config.RootCA, err)
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(rootPEM); !ok {
		return nil, ErrCannotParseRootCA
	}
	tlsCfg := &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}
	return nats.Connect(busURL, append([]nats.Option{
		nats.Secure(tlsCfg),
		nats.UserJWTAndSeed(mat.sysUserJWT, string(mat.sysUserSeed)),
		nats.Timeout(pushTimeout),
	}, opts...)...)
}
