package harness

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	nats "github.com/nats-io/nats.go"
)

// ErrBusRefused means the bus node refused the sprout's credentials: its
// account is unknown to the node or locked out, or the sprout's NKey is
// revoked on it.
var ErrBusRefused = errors.New("the bus node refused the sprout's credentials")

// BusConnect opens a NATS connection to one bus node at addr (host:port,
// in the ha tier a kubectl port-forward to the node's client port) as the
// enrolled sprout e, and closes it again. nil means the node accepted the
// sprout's User JWT and NKey signature; ErrBusRefused (wrapped) that it
// refused them; any other error that the connection failed for another
// reason (TLS, a fenced node, the network).
//
// The node's certificate is verified against pool, the run's CA, for
// serverName: the address is a local forward, so the name is the one the
// node's own loader uses to dial it on 127.0.0.1 (BusServerName).
func BusConnect(ctx context.Context, addr, serverName string, pool *x509.CertPool, e *Enrolment) error {
	if serverName == "" {
		return errors.New("no TLS server name for the bus node")
	}
	seed, err := e.Seed()
	if err != nil {
		return err
	}
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: serverName}
	timeout := 20 * time.Second
	if d, ok := ctx.Deadline(); ok && time.Until(d) < timeout {
		timeout = time.Until(d)
	}
	nc, err := nats.Connect("tls://"+addr,
		nats.Secure(tcfg),
		nats.UserJWTAndSeed(e.UserJWT(), string(seed)),
		nats.Name("imas-uat-ha"),
		nats.Timeout(timeout),
		nats.NoReconnect(),
	)
	if err != nil {
		if refused(err) {
			return fmt.Errorf("%w: %v", ErrBusRefused, err)
		}
		return fmt.Errorf("connecting to the bus node at %s: %w", addr, err)
	}
	defer nc.Close()
	// A round trip: the server has processed CONNECT and kept us.
	if err := nc.FlushTimeout(timeout); err != nil {
		if refused(err) {
			return fmt.Errorf("%w: %v", ErrBusRefused, err)
		}
		return fmt.Errorf("flushing the connection to %s: %w", addr, err)
	}
	return nil
}

// refused reports whether a connection error is the server refusing the
// credentials: an authorization violation (a revoked user, or an account
// the node does not hold), or a locked-out account's connection limit of 0
// (internal/pki lockOutAccount).
func refused(err error) bool {
	if errors.Is(err, nats.ErrAuthorization) || errors.Is(err, nats.ErrAuthExpired) || errors.Is(err, nats.ErrAuthRevoked) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "authorization violation") || strings.Contains(s, "maximum account active connections")
}
