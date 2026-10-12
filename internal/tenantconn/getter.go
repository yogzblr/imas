package tenantconn

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// ConnGetter is the one source of a tenant's NATS connection in farmer:
// *Registry, whose Get dials lazily. Packages that send to a tenant's bus
// (natsapi, cook, the test and cmd ingredients) are handed one and call
// Get on every use; none keeps a connection of its own, by tenant or
// otherwise, so a connection the idle sweeper closed is simply dialled
// again by the next Get.
type ConnGetter interface {
	Get(ctx context.Context, tenantID string) (*nats.Conn, error)
}

// GetterFunc adapts a function to ConnGetter.
type GetterFunc func(ctx context.Context, tenantID string) (*nats.Conn, error)

// Get calls f.
func (f GetterFunc) Get(ctx context.Context, tenantID string) (*nats.Conn, error) {
	return f(ctx, tenantID)
}

// DialTimeout bounds how long Source.Conn waits for a tenant's connection
// when the caller has no deadline of its own: a dial to a bus that is
// away retries until its context ends.
const DialTimeout = 30 * time.Second

// ErrNoGetter means no ConnGetter was installed in a Source: the process
// holds no tenant connections (sprout), or a test installed none.
var ErrNoGetter = errors.New("tenantconn: no tenant connection getter installed")

// Source is the ConnGetter a package's functions get tenant connections
// from, installed once by cmd/farmer (Set). It holds the getter, never a
// connection. The zero value has none installed. Safe for concurrent use.
type Source struct {
	mu sync.RWMutex
	g  ConnGetter
}

// Set installs g (nil uninstalls).
func (s *Source) Set(g ConnGetter) {
	s.mu.Lock()
	s.g = g
	s.mu.Unlock()
}

// Conn is ConnCtx with a DialTimeout deadline.
func (s *Source) Conn(tenantID string) (*nats.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DialTimeout)
	defer cancel()
	return s.ConnCtx(ctx, tenantID)
}

// ConnCtx returns tenantID's connection from the installed getter, dialing
// it if the tenant has none. A failed dial is returned wrapped as "not
// connected"; that is the only way this reports a tenant as not connected.
func (s *Source) ConnCtx(ctx context.Context, tenantID string) (*nats.Conn, error) {
	s.mu.RLock()
	g := s.g
	s.mu.RUnlock()
	if g == nil {
		return nil, ErrNoGetter
	}
	nc, err := g.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant %s: not connected to the NATS bus: %w", tenantID, err)
	}
	if nc == nil {
		return nil, fmt.Errorf("tenantconn: getter returned no connection for tenant %s", tenantID)
	}
	return nc, nil
}

var _ ConnGetter = (*Registry)(nil)
