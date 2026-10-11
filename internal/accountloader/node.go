package accountloader

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// SYS subjects the loader uses (brief §5.2). Its SYS user may publish
// only the first two and subscribe only to _INBOX.> and the event subject.
const (
	claimsUpdateSubj = "$SYS.REQ.CLAIMS.UPDATE"
	claimsListSubj   = "$SYS.REQ.CLAIMS.LIST"
	claimsLookupSubj = "$SYS.REQ.ACCOUNT.%s.CLAIMS.LOOKUP"
)

// ErrNotConnected is returned by a NodeClient while it has no connection
// to its node.
var ErrNotConnected = errors.New("accountloader: not connected to the bus node")

// NodeClient is the loader's connection to its own bus node.
type NodeClient interface {
	// Push sends one Account JWT to $SYS.REQ.CLAIMS.UPDATE and waits for
	// the own node's answer.
	Push(ctx context.Context, accountPub string, jwt []byte) error
	// ListIDs returns the account IDs in the own node's resolver
	// ($SYS.REQ.CLAIMS.LIST, the reply carrying the own server's ID).
	ListIDs(ctx context.Context) (serverID string, accounts []string, err error)
	// Lookup returns every answer to the account's CLAIMS.LOOKUP that
	// arrives before ctx ends; an empty answer is a node that does not
	// hold the account. Answers carry no server ID, so they come from
	// this node and any node it is routed to.
	Lookup(ctx context.Context, accountPub string) ([][]byte, error)
	// ConnectedServerID is the own node's server ID, empty while
	// disconnected.
	ConnectedServerID() string
	// Subscribe delivers every message on subject to fn, with a plain
	// (non-queue) subscription so every node's loader gets each event.
	Subscribe(subject string, fn func(data []byte)) error
}

// NATSConfig is how the loader reaches its own node.
type NATSConfig struct {
	// URL is the own node over localhost, never the bus Service.
	URL string
	// TLS verifies the node's certificate; nil connects without TLS
	// (tests only).
	TLS *tls.Config
	// UserJWTFile and UserSeedFile hold the loader's SYS user. Both are
	// read on every (re)connect, so a rotated Secret is picked up.
	UserJWTFile, UserSeedFile string
	// OnReconnect runs after the connection comes back.
	OnReconnect func()
	// RequestTimeout bounds one SYS request; 10s when zero.
	RequestTimeout time.Duration
}

// NATSNode is the NodeClient over a NATS connection.
type NATSNode struct {
	nc      *nats.Conn
	timeout time.Duration
}

// DialNode connects to the node, retrying forever in the background with
// exponential backoff from 500ms to 10s with jitter (brief §5.2): it
// returns at once, and ConnectedServerID stays empty until connected.
func DialNode(cfg NATSConfig) (*NATSNode, error) {
	if cfg.URL == "" || cfg.UserJWTFile == "" || cfg.UserSeedFile == "" {
		return nil, errors.New("accountloader: node URL and SYS user files are required")
	}
	opts := []nats.Option{
		nats.Name("farmerbus-loader"),
		nats.UserJWT(
			func() (string, error) { return readTrimmed(cfg.UserJWTFile) },
			func(nonce []byte) ([]byte, error) {
				seed, err := readTrimmed(cfg.UserSeedFile)
				if err != nil {
					return nil, err
				}
				kp, err := nkeys.FromSeed([]byte(seed))
				if err != nil {
					return nil, fmt.Errorf("accountloader: SYS user seed: %w", err)
				}
				defer kp.Wipe()
				return kp.Sign(nonce)
			}),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.CustomReconnectDelay(func(attempts int) time.Duration {
			return Backoff{Min: 500 * time.Millisecond, Max: 10 * time.Second}.Jittered(attempts)
		}),
	}
	if cfg.TLS != nil {
		opts = append(opts, nats.Secure(cfg.TLS))
	}
	if cfg.OnReconnect != nil {
		opts = append(opts, nats.ReconnectHandler(func(*nats.Conn) { cfg.OnReconnect() }))
	}
	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("accountloader: connecting to %s: %w", cfg.URL, err)
	}
	t := cfg.RequestTimeout
	if t <= 0 {
		t = 10 * time.Second
	}
	return &NATSNode{nc: nc, timeout: t}, nil
}

func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Close closes the connection.
func (n *NATSNode) Close() { n.nc.Close() }

// ConnectedServerID implements NodeClient.
func (n *NATSNode) ConnectedServerID() string {
	if !n.nc.IsConnected() {
		return ""
	}
	return n.nc.ConnectedServerId()
}

// Subscribe implements NodeClient.
func (n *NATSNode) Subscribe(subject string, fn func([]byte)) error {
	_, err := n.nc.Subscribe(subject, func(m *nats.Msg) { fn(m.Data) })
	return err
}

type serverReply struct {
	Server struct {
		ID string `json:"id"`
	} `json:"server"`
}

type updateReply struct {
	serverReply
	Error *struct {
		Description string `json:"description"`
	} `json:"error"`
}

type listReply struct {
	serverReply
	Data []string `json:"data"`
}

// ownReply sends one request on subj and returns the first reply whose
// server ID is the own node's. Other nodes answer too (the request fans
// out over routes); their replies are skipped.
func (n *NATSNode) ownReply(ctx context.Context, subj string, data []byte) ([]byte, string, error) {
	own := n.ConnectedServerID()
	if own == "" {
		return nil, "", ErrNotConnected
	}
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	inbox := n.nc.NewRespInbox()
	sub, err := n.nc.SubscribeSync(inbox)
	if err != nil {
		return nil, "", err
	}
	defer sub.Unsubscribe()
	if err := n.nc.PublishRequest(subj, inbox, data); err != nil {
		return nil, "", err
	}
	for {
		m, err := sub.NextMsgWithContext(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("accountloader: no answer from own node %s to %s: %w", own, subj, err)
		}
		var r serverReply
		if json.Unmarshal(m.Data, &r) == nil && r.Server.ID == own {
			return m.Data, own, nil
		}
	}
}

// Push implements NodeClient.
func (n *NATSNode) Push(ctx context.Context, accountPub string, jwt []byte) error {
	b, _, err := n.ownReply(ctx, claimsUpdateSubj, jwt)
	if err != nil {
		return err
	}
	var r updateReply
	if err := json.Unmarshal(b, &r); err != nil {
		return fmt.Errorf("accountloader: decoding the claims update answer for %s: %w", accountPub, err)
	}
	if r.Error != nil {
		return fmt.Errorf("accountloader: node rejected %s: %s", accountPub, r.Error.Description)
	}
	return nil
}

// ListIDs implements NodeClient.
func (n *NATSNode) ListIDs(ctx context.Context) (string, []string, error) {
	b, own, err := n.ownReply(ctx, claimsListSubj, nil)
	if err != nil {
		return "", nil, err
	}
	var r listReply
	if err := json.Unmarshal(b, &r); err != nil {
		return "", nil, fmt.Errorf("accountloader: decoding the claims list: %w", err)
	}
	return own, r.Data, nil
}

// Lookup implements NodeClient.
func (n *NATSNode) Lookup(ctx context.Context, accountPub string) ([][]byte, error) {
	if !nkeys.IsValidPublicAccountKey(accountPub) {
		return nil, fmt.Errorf("accountloader: %q is not an account key", accountPub)
	}
	if n.ConnectedServerID() == "" {
		return nil, ErrNotConnected
	}
	inbox := n.nc.NewRespInbox()
	sub, err := n.nc.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer sub.Unsubscribe()
	if err := n.nc.PublishRequest(fmt.Sprintf(claimsLookupSubj, accountPub), inbox, nil); err != nil {
		return nil, err
	}
	var out [][]byte
	for {
		m, err := sub.NextMsgWithContext(ctx)
		if err != nil {
			return out, nil
		}
		out = append(out, m.Data)
	}
}

// Backoff is exponential backoff from Min, doubling to Max.
type Backoff struct {
	Min, Max time.Duration
}

// Delay is the un-jittered wait after the given failed attempt (1-based).
func (b Backoff) Delay(attempt int) time.Duration {
	d := b.Min
	for i := 1; i < attempt && d < b.Max; i++ {
		d *= 2
	}
	return min(d, b.Max)
}

// Jittered is Delay with full jitter: uniform over [0, Delay].
func (b Backoff) Jittered(attempt int) time.Duration {
	d := b.Delay(attempt)
	if d <= 0 {
		return 0
	}
	return rand.N(d + 1)
}
