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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"time"

	nats "github.com/nats-io/nats.go"

	nats_server "github.com/nats-io/nats-server/v2/server"

	"github.com/yogzblr/imas/internal/config"
)

const (
	claimsUpdateSubject = "$SYS.REQ.CLAIMS.UPDATE"
	pushTimeout         = 10 * time.Second
)

// pushAccountUpdate publishes accountJWT (a signed Account JWT — the
// legacy single-tenant seam's mat.tenantJWT, or any dynamically-provisioned
// tenant's own Account JWT, see tenant.go) to the bus's resolver, over a
// fresh connection authenticated as the SYS account.
func pushAccountUpdate(mat *natsAuthMaterial, accountJWT string) error {
	nc, err := connectSystemAccount(mat)
	if err != nil {
		return fmt.Errorf("connecting as the SYS account: %w", err)
	}
	defer nc.Close()
	return publishClaimsUpdate(nc, accountJWT)
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

func publishClaimsUpdate(nc *nats.Conn, accountJWT string) error {
	resp, err := nc.Request(claimsUpdateSubject, []byte(accountJWT), pushTimeout)
	if err != nil {
		return fmt.Errorf("claims update request: %w", err)
	}
	var status nats_server.ServerAPIClaimUpdateResponse
	if err := json.Unmarshal(resp.Data, &status); err != nil {
		return fmt.Errorf("decoding claims update response: %w", err)
	}
	if status.Error != nil {
		return fmt.Errorf("bus rejected claims update: %s", status.Error.Description)
	}
	return nil
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
