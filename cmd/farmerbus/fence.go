package main

// The fence makes a clustered bus node fail closed on stale account
// claims. FLAG FOR SECURITY REVIEW.
//
// How an Account JWT reaches the nodes (nats-server v2.14 "full"
// resolver, see docs/design/imas-1m-scale-plan.md, Phase 2 status):
//
//   - core pushes it to $SYS.REQ.CLAIMS.UPDATE on whichever node its SYS
//     connection landed on. Every node holds a plain (non-queue) SYS
//     subscription on that subject, so the push is delivered to that node
//     and to every node it has a DIRECT route to. Routes do not forward
//     messages a second hop.
//   - a node that missed it (down, or not directly routed to the entry
//     node) only catches up through the resolver's own pull sync (a hash
//     exchange every minute) or, for an account it has never seen, a
//     lookup at connect time.
//
// Until that catch-up, a node that missed a lock-out would keep the
// tenant's connections alive and accept new ones. The fence closes that
// window: a node serves clients only while
//
//  1. it has direct routes to a strict majority of the configured cluster
//     (counting itself), and
//  2. no peer it is routed to reports a route to a server it is not itself
//     routed to (a non-transitive partition: it could miss pushes that
//     land on that server), sustained for longer than fenceGrace, and
//  3. after it was last fenced, it has pulled every Account JWT from every
//     directly-routed peer and merged the newer ones into its resolver.
//
// While fenced the node refuses every TLS handshake on the client and
// websocket ports (so core's SYS push cannot land on it either, and
// fails over to a healthy node or fails loudly) and disconnects every
// client it still holds. Routes stay up so it can resynchronise.
//
// Two healthy nodes are always directly routed to each other: they share
// a member of their majorities, and condition 2 forbids that member seeing
// a server either of them doesn't. So a push accepted by a healthy node
// reaches every other healthy node directly. What remains is the
// detection window: a partition that forms within one tick plus the grace
// before a push can let one push slip past a node, until the next pull
// (fence re-entry, a peer rejoining, or the resolver's own sync).

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
)

const (
	routezPingSubj   = "$SYS.REQ.SERVER.PING.ROUTEZ"
	claimsListSubj   = "$SYS.REQ.CLAIMS.LIST"
	claimsLookupSubj = "$SYS.REQ.ACCOUNT.%s.CLAIMS.LOOKUP"
)

var errFenced = errors.New("farmerbus: node is fenced (no quorum, partial mesh, or resolver not yet synced); try another node")

// fenceTiming is overridable by tests.
type fenceTiming struct {
	Interval   time.Duration // how often health is evaluated
	Grace      time.Duration // how long a partial mesh is tolerated
	ReqTimeout time.Duration // per SYS request round
}

var defaultFenceTiming = fenceTiming{Interval: time.Second, Grace: 3 * time.Second, ReqTimeout: 2 * time.Second}

type fence struct {
	size     int
	timing   fenceTiming
	fenced   atomic.Bool
	srv      *nats_server.Server
	resolver *nats_server.DirAccResolver
	// trusted issuers for pulled Account JWTs: the operator and its
	// signing keys.
	issuers map[string]bool

	mu       sync.Mutex
	nc       *nats.Conn
	ownCID   uint64
	synced   map[string]bool // peer set at the last successful pull
	suspect  time.Time       // when a partial mesh was first seen
	lastWhy  string
	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// newFence returns a fence for a cluster of size nodes. It starts fenced.
func newFence(size int, timing fenceTiming) *fence {
	f := &fence{size: size, timing: timing, stopCh: make(chan struct{}), doneCh: make(chan struct{})}
	f.fenced.Store(true)
	return f
}

// Fenced reports whether this node currently refuses clients.
func (f *fence) Fenced() bool { return f.fenced.Load() }

// install wires the TLS gate into the client and websocket listeners.
// Call before nats_server.NewServer. VerifyConnection runs inside every
// server-side handshake (TLS 1.2 and 1.3), and for the websocket listener
// it is the hook nats-server's own GetConfigForClient indirection leaves
// in place.
func (f *fence) install(opts *nats_server.Options) error {
	if opts.TLSConfig == nil {
		return errors.New("fence: the client port has no TLS config")
	}
	opts.TLSConfig.VerifyConnection = f.gate(opts.TLSConfig.VerifyConnection)
	if opts.Websocket.TLSConfig != nil {
		opts.Websocket.TLSConfig.VerifyConnection = f.gate(opts.Websocket.TLSConfig.VerifyConnection)
	}
	dr, ok := opts.AccountResolver.(*nats_server.DirAccResolver)
	if !ok {
		return fmt.Errorf("fence: account resolver is %T, want the full (*DirAccResolver)", opts.AccountResolver)
	}
	f.resolver = dr
	f.issuers = map[string]bool{}
	for _, op := range opts.TrustedOperators {
		f.issuers[op.Subject] = true
		for _, k := range op.SigningKeys {
			f.issuers[k] = true
		}
	}
	return nil
}

func (f *fence) gate(next func(tls.ConnectionState) error) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if f.fenced.Load() {
			return errFenced
		}
		if next != nil {
			return next(cs)
		}
		return nil
	}
}

// start connects the fence's own in-process SYS client and runs the
// health loop until stop. The in-process connection never touches a
// listener, so the TLS gate does not apply to it.
func (f *fence) start(srv *nats_server.Server) error {
	f.srv = srv
	nc, err := pki.ConnectSystemAccount(
		nats.InProcessServer(srv),
		nats.Name("farmerbus-fence"),
		// pki adds nats.Secure for the network push path; an in-process
		// pipe has no network to protect, and nats-server does not offer
		// TLS on it as required.
		func(o *nats.Options) error { o.Secure = false; o.TLSConfig = nil; return nil },
		nats.MaxReconnects(-1),
	)
	if err != nil {
		return fmt.Errorf("fence: in-process SYS connection: %w", err)
	}
	cid, err := nc.GetClientID()
	if err != nil {
		nc.Close()
		return fmt.Errorf("fence: reading own client ID: %w", err)
	}
	f.mu.Lock()
	f.nc, f.ownCID = nc, cid
	f.mu.Unlock()
	go f.loop()
	return nil
}

func (f *fence) stop() {
	f.stopOnce.Do(func() {
		close(f.stopCh)
		<-f.doneCh
		f.mu.Lock()
		if f.nc != nil {
			f.nc.Close()
		}
		f.mu.Unlock()
	})
}

func (f *fence) loop() {
	defer close(f.doneCh)
	t := time.NewTicker(f.timing.Interval)
	defer t.Stop()
	for {
		f.evaluate()
		select {
		case <-f.stopCh:
			return
		case <-t.C:
		}
	}
}

// directPeers is the set of server IDs this node has a live route to.
func (f *fence) directPeers() (map[string]bool, error) {
	rz, err := f.srv.Routez(&nats_server.RoutezOptions{})
	if err != nil {
		return nil, err
	}
	peers := map[string]bool{}
	for _, r := range rz.Routes {
		if r.RemoteID != "" && r.RemoteID != f.srv.ID() {
			peers[r.RemoteID] = true
		}
	}
	return peers, nil
}

func (f *fence) evaluate() {
	if f.srv == nil || !f.srv.Running() {
		return
	}
	peers, err := f.directPeers()
	if err != nil {
		f.fence("cannot read routes: " + err.Error())
		return
	}
	if (len(peers)+1)*2 <= f.size {
		f.fence(fmt.Sprintf("routed to %d of %d nodes (incl. itself), no majority", len(peers)+1, f.size))
		return
	}
	views, complete := f.peerViews(peers)
	var foreign []string
	for p := range peers {
		for id := range views[p] {
			if id != f.srv.ID() && !peers[id] {
				foreign = append(foreign, id)
			}
		}
	}
	f.mu.Lock()
	if len(foreign) > 0 {
		if f.suspect.IsZero() {
			f.suspect = time.Now()
		}
		since := time.Since(f.suspect)
		f.mu.Unlock()
		if since >= f.timing.Grace {
			slices.Sort(foreign)
			f.fence(fmt.Sprintf("peers are routed to %v, this node is not (partial mesh)", slices.Compact(foreign)))
		}
		return
	}
	f.suspect = time.Time{}
	newMember := false
	for p := range peers {
		if !f.synced[p] {
			newMember = true
		}
	}
	f.mu.Unlock()

	if !f.fenced.Load() {
		if newMember {
			// A peer (re)joined: pull anything it accepted that we lack.
			if err := f.pull(peers); err != nil {
				log.Warnf("farmerbus fence: resync after a peer joined failed, retrying: %v", err)
				return
			}
			f.setSynced(peers)
		}
		return
	}
	if !complete {
		return // a peer didn't answer; neither evidence to fence nor to unfence
	}
	f.kickAll() // anything that slipped in between ticks
	if err := f.pull(peers); err != nil {
		log.Warnf("farmerbus fence: resolver pull before unfencing failed, staying fenced: %v", err)
		return
	}
	after, err := f.directPeers()
	if err != nil || !maps.Equal(after, peers) {
		return // mesh changed during the pull; re-evaluate next tick
	}
	f.setSynced(peers)
	f.mu.Lock()
	f.lastWhy = ""
	f.mu.Unlock()
	f.fenced.Store(false)
	log.Infof("farmerbus fence: lifted; routed to %d of %d nodes and resolver synced from every peer", len(peers)+1, f.size)
}

func (f *fence) setSynced(peers map[string]bool) {
	f.mu.Lock()
	f.synced = maps.Clone(peers)
	f.mu.Unlock()
}

// fence closes the gate and disconnects every client.
func (f *fence) fence(why string) {
	was := f.fenced.Swap(true)
	f.mu.Lock()
	if !was || f.lastWhy != why {
		log.Warnf("farmerbus fence: refusing clients: %s", why)
	}
	f.lastWhy = why
	// Force a full pull before the fence lifts again.
	f.synced = nil
	f.mu.Unlock()
	f.kickAll()
}

func (f *fence) kickAll() {
	n := f.srv.NumClients()
	if n <= 1 { // only the fence's own connection
		return
	}
	cz, err := f.srv.Connz(&nats_server.ConnzOptions{Limit: n + 64})
	if err != nil {
		log.Errorf("farmerbus fence: listing clients to disconnect: %v", err)
		return
	}
	f.mu.Lock()
	own := f.ownCID
	f.mu.Unlock()
	for _, c := range cz.Conns {
		if c.Cid == own {
			continue
		}
		_ = f.srv.DisconnectClientByID(c.Cid)
	}
}

// gather sends one SYS request and collects up to want replies.
func (f *fence) gather(subj string, want int) ([][]byte, error) {
	f.mu.Lock()
	nc := f.nc
	f.mu.Unlock()
	inbox := nats.NewInbox()
	sub, err := nc.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer sub.Unsubscribe()
	if err := nc.PublishRequest(subj, inbox, nil); err != nil {
		return nil, err
	}
	var out [][]byte
	deadline := time.Now().Add(f.timing.ReqTimeout)
	for len(out) < want {
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		m, err := sub.NextMsg(left)
		if err != nil {
			break
		}
		out = append(out, m.Data)
	}
	return out, nil
}

type routezReply struct {
	Server struct {
		ID string `json:"id"`
	} `json:"server"`
	Data struct {
		Routes []struct {
			RemoteID string `json:"remote_id"`
		} `json:"routes"`
	} `json:"data"`
}

// peerViews asks this node and its peers for their routes. complete is
// true when every direct peer answered.
func (f *fence) peerViews(peers map[string]bool) (map[string]map[string]bool, bool) {
	views := map[string]map[string]bool{}
	replies, err := f.gather(routezPingSubj, len(peers)+1)
	if err != nil {
		return views, false
	}
	for _, b := range replies {
		var r routezReply
		if json.Unmarshal(b, &r) != nil || r.Server.ID == "" {
			continue
		}
		v := map[string]bool{}
		for _, rt := range r.Data.Routes {
			if rt.RemoteID != "" {
				v[rt.RemoteID] = true
			}
		}
		views[r.Server.ID] = v
	}
	for p := range peers {
		if _, ok := views[p]; !ok {
			return views, false
		}
	}
	return views, true
}

type listReply struct {
	Server struct {
		ID string `json:"id"`
	} `json:"server"`
	Data []string `json:"data"`
}

// pull fetches every Account JWT every direct peer holds and merges each
// into the local resolver, newest issued-at winning (the same rule as the
// resolver's own sync). Merging a newer JWT for a loaded account applies
// it at once: a lock-out closes the account's connections here.
func (f *fence) pull(peers map[string]bool) error {
	want := len(peers) + 1
	replies, err := f.gather(claimsListSubj, want)
	if err != nil {
		return err
	}
	answered := map[string]bool{}
	ids := map[string]bool{}
	for _, b := range replies {
		var r listReply
		if json.Unmarshal(b, &r) != nil {
			continue
		}
		answered[r.Server.ID] = true
		for _, id := range r.Data {
			if nkeys.IsValidPublicAccountKey(id) {
				ids[id] = true
			}
		}
	}
	for p := range peers {
		if !answered[p] {
			return fmt.Errorf("peer %s did not answer the account list", p)
		}
	}
	for id := range ids {
		jwts, err := f.gather(fmt.Sprintf(claimsLookupSubj, id), want)
		if err != nil {
			return err
		}
		if len(jwts) < want {
			return fmt.Errorf("account %s: %d of %d nodes answered the lookup", id, len(jwts), want)
		}
		cands := make([]string, 0, len(jwts))
		for _, b := range jwts {
			if len(b) > 0 {
				cands = append(cands, string(b))
			}
		}
		if err := f.merge(id, cands); err != nil {
			log.Warnf("farmerbus fence: account %s: %v", id, err)
		}
	}
	return nil
}

// claimRank orders Account JWTs for one account: newest issued-at first;
// at the same issued-at a locked-out JWT (connection limit 0) beats a live
// one, so a tie never re-opens a tenant; the JWT text breaks any remaining
// tie so every node picks the same winner.
type claimRank struct {
	iat    int64
	locked bool
	raw    string
}

func (a claimRank) beats(b claimRank) bool {
	if a.iat != b.iat {
		return a.iat > b.iat
	}
	if a.locked != b.locked {
		return a.locked
	}
	return a.raw > b.raw
}

func (f *fence) rank(id, theJWT string) (claimRank, error) {
	ac, err := jwt.DecodeAccountClaims(theJWT)
	if err != nil {
		return claimRank{}, err
	}
	if ac.Subject != id {
		return claimRank{}, fmt.Errorf("subject %s does not match", ac.Subject)
	}
	if !f.issuers[ac.Issuer] {
		return claimRank{}, fmt.Errorf("issuer %s is not the trusted operator", ac.Issuer)
	}
	return claimRank{iat: ac.IssuedAt, locked: ac.Limits.Conn == 0, raw: theJWT}, nil
}

// merge stores the best of cands (the peers' JWTs for id, possibly
// including this node's own answer) if it beats what this node holds.
func (f *fence) merge(id string, cands []string) error {
	var best *claimRank
	for _, c := range cands {
		r, err := f.rank(id, c)
		if err != nil {
			log.Warnf("farmerbus fence: ignoring a peer's JWT for account %s: %v", id, err)
			continue
		}
		if best == nil || r.beats(*best) {
			best = &r
		}
	}
	if best == nil {
		return nil
	}
	if local, err := f.resolver.LoadAcc(id); err == nil && local != "" {
		if lr, err := f.rank(id, local); err == nil && (lr.raw == best.raw || !best.beats(lr)) {
			return nil
		}
	}
	// SaveAcc, not Store: Store is the resolver's saveIfNewer, which also
	// treats two JWTs with the same jti as the same JWT. The jti hashes
	// only the generic claims (subject, issuer, name, issued-at), not
	// limits or revocations, so a lock-out signed in the same second as
	// the live JWT it replaces would be silently dropped. beats() has
	// already decided this one wins. Saving fires the resolver's change
	// callback, which applies the claims to a loaded account at once.
	return f.resolver.SaveAcc(id, best.raw)
}

// serveHealth runs the probe listener: /healthz is liveness, /readyz is
// 200 only while the node accepts clients. It exposes nothing else.
func serveHealth(ctx context.Context, addr string, ready func() bool) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	hs := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = hs.Close()
	}()
	go func() { _ = hs.Serve(ln) }()
	return nil
}
