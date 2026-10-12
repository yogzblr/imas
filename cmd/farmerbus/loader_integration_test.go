package main

// The five loader scenarios of P21 slice 2 (docs/briefs/
// P21-slice2-bus-loader.md §12 "Integration"): real bus nodes, built as
// cluster_integration_test.go builds them, each with a real account
// loader (internal/accountloader over the fake S3 server, connected to
// its own node as the loader's SYS user that the NATS trust bootstrap
// mints). The test plays farmer: it writes Account JWT objects, bumps
// accounts/index and publishes the accounts-changed event, in that order
// (brief §7.3).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/accountloader"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/pki"
)

// ---- the accounts bucket --------------------------------------------------

// accountsBucket is the fake S3 accounts bucket and farmer's writer
// client. The fake checks no credential, so the reader/writer split is a
// Deny policy: PUT and DELETE are refused unless the test is writing as
// farmer, which is what the loader's read-only self-check probes.
type accountsBucket struct {
	srv     *objectstoretest.Server
	w       *objectstore.Store
	mu      sync.Mutex
	writing atomic.Bool
	n       int // index bumps so far
}

// newAccountsBucket starts the fake S3 server with the reader policy and
// opens farmer's writer client on it.
func newAccountsBucket(t *testing.T) *accountsBucket {
	t.Helper()
	b := &accountsBucket{srv: objectstoretest.NewServer(t)}
	var err error
	if b.w, err = objectstore.Open(b.srv.Config()); err != nil {
		t.Fatal(err)
	}
	b.srv.Deny(func(op, _ string) bool {
		return (op == "PUT" || op == "DELETE") && !b.writing.Load()
	})
	return b
}

// put writes key as farmer, the one writer the policy lets through.
func (b *accountsBucket) put(t *testing.T, key, body string) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.writing.Store(true)
	defer b.writing.Store(false)
	if err := b.w.Put(context.Background(), key, []byte(body)); err != nil {
		t.Fatalf("farmer writing %s: %v", key, err)
	}
}

// putAccount writes accounts/<pub>.jwt.
func (b *accountsBucket) putAccount(t *testing.T, pub, accountJWT string) {
	t.Helper()
	b.put(t, accountloader.AccountKey(pub), accountJWT)
}

// bumpIndex writes accounts/index with a fresh token and returns it.
func (b *accountsBucket) bumpIndex(t *testing.T) string {
	t.Helper()
	b.mu.Lock()
	b.n++
	token := fmt.Sprintf("TOKEN%021d", b.n)
	b.mu.Unlock()
	b.put(t, accountloader.IndexKey, fmt.Sprintf(`{"v":1,"token":%q,"written":%q}`, token, time.Now().UTC().Format(time.RFC3339)))
	return token
}

// ---- loader fixture -------------------------------------------------------

// loaderEnv is the trust, bucket and loader credentials shared by every
// node's loader.
type loaderEnv struct {
	tr      *trust
	bucket  *accountsBucket
	trusted []string
	sysPub  string
	sysJWT  string // the SYS Account JWT farmer keeps in the bucket
	// userJWTFile and userSeedFile are the loader's SYS user, as the
	// chart mounts bus-loader-user.jwt and its seed.
	userJWTFile, userSeedFile string
	reconcile                 time.Duration
}

// newLoaderEnv builds the trust (newTrust) with the loader's SYS user
// added to the trust directory, minted as pki.BootstrapNATSTrust mints it
// (signed by the SYS account, exactly pki.BusLoaderUserPermissions), and a
// bucket holding the SYS Account JWT.
func newLoaderEnv(t *testing.T, reconcile time.Duration) *loaderEnv {
	t.Helper()
	tr := newTrust(t)
	e := &loaderEnv{tr: tr, bucket: newAccountsBucket(t), reconcile: reconcile}
	trustDir := filepath.Join(tr.dir, "nats-trust")
	for _, name := range []string{pki.TrustOperatorPub, pki.TrustOperatorSigningPub} {
		e.trusted = append(e.trusted, readTrimmedFile(t, filepath.Join(trustDir, name)))
	}
	e.sysPub = readTrimmedFile(t, filepath.Join(trustDir, pki.TrustSysAccountPub))

	kp, _ := nkeys.CreateUser()
	pub, _ := kp.PublicKey()
	uc := jwt.NewUserClaims(pub)
	uc.Name = "imas-bus-loader"
	uc.Permissions = pki.BusLoaderUserPermissions()
	userJWT, err := uc.Encode(tr.sysAccount)
	if err != nil {
		t.Fatal(err)
	}
	e.userJWTFile = filepath.Join(trustDir, pki.TrustBusLoaderUserJWT)
	if err := os.WriteFile(e.userJWTFile, []byte(userJWT), 0o644); err != nil {
		t.Fatal(err)
	}
	e.userSeedFile = filepath.Join(tr.dir, "bus-loader-user.nk")
	if err := os.WriteFile(e.userSeedFile, []byte(mustSeed(kp)), 0o600); err != nil {
		t.Fatal(err)
	}

	sac := jwt.NewAccountClaims(e.sysPub)
	sac.Name = "SYS"
	if e.sysJWT, err = sac.Encode(tr.operatorSigning); err != nil {
		t.Fatal(err)
	}
	e.bucket.putAccount(t, e.sysPub, e.sysJWT)
	e.bucket.bumpIndex(t)
	return e
}

// readTrimmedFile returns a file's content without surrounding space.
func readTrimmedFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// runningLoader is one node's loader sidecar: the loader, its connection
// to the node and its /readyz endpoint.
type runningLoader struct {
	l      *accountloader.Loader
	node   *accountloader.NATSNode
	readyz string
	stop   func()
}

// startLoader runs a loader against the node at url, as farmerbus-loader
// wires it (cmd/farmerbus-loader/main.go), with short waits. It is
// stopped at the end of the test, or by stop.
func (e *loaderEnv) startLoader(t *testing.T, nodeURL string) *runningLoader {
	t.Helper()
	var lp atomic.Pointer[accountloader.Loader]
	node, err := accountloader.DialNode(accountloader.NATSConfig{
		URL:          nodeURL,
		TLS:          e.tr.tlsConfig(),
		UserJWTFile:  e.userJWTFile,
		UserSeedFile: e.userSeedFile,
		OnReconnect: func() {
			if l := lp.Load(); l != nil {
				l.NodeReconnected()
			}
		},
		RequestTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := e.bucket.srv.Config()
	l, err := accountloader.New(accountloader.Config{
		Source:            accountloader.NewStoreSource(func() (*objectstore.Store, error) { return objectstore.Open(cfg) }),
		Node:              node,
		Trusted:           e.trusted,
		SysAccount:        e.sysPub,
		ReconcileInterval: e.reconcile,
		Backoff:           accountloader.Backoff{Min: 20 * time.Millisecond, Max: 200 * time.Millisecond},
		PushBackoff:       accountloader.Backoff{Min: 10 * time.Millisecond, Max: 100 * time.Millisecond},
		RequestTimeout:    5 * time.Second,
		EventWindow:       time.Second,
		LookupWindow:      200 * time.Millisecond,
	})
	if err != nil {
		node.Close()
		t.Fatal(err)
	}
	lp.Store(l)
	// /readyz as farmerbus-loader's health listener serves it.
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/readyz" && l.Ready() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	var once sync.Once
	rl := &runningLoader{l: l, node: node, readyz: hs.URL + "/readyz"}
	rl.stop = func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("loader Run: %v", err)
			}
			node.Close()
			hs.Close()
		})
	}
	t.Cleanup(rl.stop)
	return rl
}

// waitLoaded waits for each loader's initial load.
func waitLoaded(t *testing.T, loaders ...*runningLoader) {
	t.Helper()
	for i, rl := range loaders {
		waitFor(t, fmt.Sprintf("loader %d to finish its initial load", i), 20*time.Second, rl.l.Ready)
	}
}

// ---- farmer and operator helpers -------------------------------------------

// signAccountAt signs ac with its issued-at set to iat (jwt/v2's Encode
// stamps the current time, so the payload is re-signed).
func signAccountAt(t *testing.T, signer nkeys.KeyPair, ac *jwt.AccountClaims, iat int64) string {
	t.Helper()
	enc, err := ac.Encode(signer)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(enc, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["iat"] = iat
	m["jti"] = fmt.Sprintf("JTI%d%s", iat, ac.Subject)
	raw, _ = json.Marshal(m)
	toSign := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw)
	sig, err := signer.Sign([]byte(toSign))
	if err != nil {
		t.Fatal(err)
	}
	return toSign + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// iatOf is an Account JWT's issued-at.
func iatOf(t *testing.T, accountJWT string) int64 {
	t.Helper()
	ac, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil {
		t.Fatal(err)
	}
	return ac.IssuedAt
}

// sysConn is an operator's SYS connection (the test's unrestricted SYS
// user), for publishing farmer's event and asking a node what it holds.
func (e *loaderEnv) sysConn(t *testing.T, nodeURL string) *nats.Conn {
	t.Helper()
	var nc *nats.Conn
	waitFor(t, "a SYS connection to "+nodeURL, 10*time.Second, func() bool {
		var err error
		nc, err = nats.Connect(nodeURL, nats.Secure(e.tr.tlsConfig()), nats.UserJWTAndSeed(e.tr.sysUserJWT, mustSeed(e.tr.sysUser)),
			nats.Timeout(2*time.Second), nats.NoReconnect())
		return err == nil
	})
	t.Cleanup(nc.Close)
	return nc
}

// publishEvent publishes farmer's accounts-changed event (brief §4.3).
func publishEvent(t *testing.T, nc *nats.Conn, token string, accounts map[string]int64) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"v": 1, "token": token, "accounts": accounts})
	if err := nc.Publish(accountloader.DefaultEventSubject, b); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
}

// claimsList is the account IDs in the reply of the node nc is connected
// to ($SYS.REQ.CLAIMS.LIST; other nodes' replies are skipped).
func claimsList(t *testing.T, nc *nats.Conn) []string {
	t.Helper()
	inbox := nc.NewRespInbox()
	sub, err := nc.SubscribeSync(inbox)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := nc.PublishRequest("$SYS.REQ.CLAIMS.LIST", inbox, nil); err != nil {
		t.Fatal(err)
	}
	own := nc.ConnectedServerId()
	for {
		m, err := sub.NextMsg(2 * time.Second)
		if err != nil {
			t.Fatalf("no CLAIMS.LIST reply from the own node: %v", err)
		}
		var r struct {
			Server struct {
				ID string `json:"id"`
			} `json:"server"`
			Data []string `json:"data"`
		}
		if json.Unmarshal(m.Data, &r) == nil && r.Server.ID == own {
			return r.Data
		}
	}
}

// lookupIATs is the issued-at of every answer to the account's
// CLAIMS.LOOKUP (0 for a node that does not hold it).
func lookupIATs(t *testing.T, nc *nats.Conn, pub string) []int64 {
	t.Helper()
	inbox := nc.NewRespInbox()
	sub, err := nc.SubscribeSync(inbox)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := nc.PublishRequest(fmt.Sprintf("$SYS.REQ.ACCOUNT.%s.CLAIMS.LOOKUP", pub), inbox, nil); err != nil {
		t.Fatal(err)
	}
	var out []int64
	for {
		m, err := sub.NextMsg(500 * time.Millisecond)
		if err != nil {
			return out
		}
		if len(m.Data) == 0 {
			out = append(out, 0)
			continue
		}
		out = append(out, iatOf(t, string(m.Data)))
	}
}

// waitAllBy polls every cond until each has held once, and fails at
// deadline naming the ones that never did. A cond is only counted when it
// held before deadline, and each is checked at least once.
func waitAllBy(t *testing.T, what string, deadline time.Time, conds ...func() bool) {
	t.Helper()
	held := make([]bool, len(conds))
	for {
		before := time.Now().Before(deadline)
		all := true
		for i, cond := range conds {
			if !held[i] {
				held[i] = cond() && time.Now().Before(deadline)
			}
			all = all && held[i]
		}
		if all {
			return
		}
		if !before || !time.Now().Before(deadline) {
			var missing []int
			for i, h := range held {
				if !h {
					missing = append(missing, i)
				}
			}
			t.Fatalf("deadline passed waiting for %s: conditions %v never held", what, missing)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// hostOf is the host:port of a node's client URL.
func hostOf(t *testing.T, u string) string {
	t.Helper()
	pu, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return pu.Host
}

// readyzOK reports whether a /readyz endpoint answers 200.
func readyzOK(endpoint string) bool {
	resp, err := http.Get(endpoint)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// admitted reports whether the tenant's sprout can connect to the node.
func (tr *trust) admitted(tn *tenant, nodeURL string) bool {
	nc, err := tr.dialSprout(tn, []string{nodeURL}, nats.NoReconnect())
	if err == nil {
		nc.Close()
	}
	return err == nil
}

// ---- the five scenarios ---------------------------------------------------

// TestLoaderEmptyNodeReadyOnlyAfterLoadingEverything (scenario 1): a node
// starting on an empty resolver directory, with a bucket of 25 tenants and
// the SYS account. /readyz, sampled every 10ms, is never 200 before the
// node's CLAIMS.LIST holds all 26 accounts, and is 200 afterwards; a
// sprout of every tenant can then connect.
func TestLoaderEmptyNodeReadyOnlyAfterLoadingEverything(t *testing.T) {
	e := newLoaderEnv(t, time.Hour)
	tenants := make([]*tenant, 25)
	want := []string{e.sysPub}
	for i := range tenants {
		tenants[i] = e.tr.newTenant(t, fmt.Sprintf("web-%02d", i))
		e.bucket.putAccount(t, tenants[i].pub, e.tr.accountJWT(t, tenants[i], false))
		want = append(want, tenants[i].pub)
	}
	e.bucket.bumpIndex(t)

	c := newTestCluster(t, e.tr, 1)
	c.waitReady(0)
	sys := e.sysConn(t, c.url(0))
	holdsAll := func() bool {
		have := claimsList(t, sys)
		for _, p := range want {
			if !slices.Contains(have, p) {
				return false
			}
		}
		return true
	}
	if holdsAll() {
		t.Fatal("the node holds the tenants before any loader ran")
	}

	rl := e.startLoader(t, c.url(0))
	notReady, early := 0, false
	deadline := time.Now().Add(20 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("/readyz never became 200")
		}
		if readyzOK(rl.readyz) {
			// Accounts are never removed from a node, so a node that holds
			// them all now held them all when /readyz answered.
			early = !holdsAll()
			break
		}
		notReady++
		time.Sleep(10 * time.Millisecond)
	}
	if early {
		t.Fatal("/readyz answered 200 before the node's CLAIMS.LIST held all 26 accounts")
	}
	if notReady == 0 {
		t.Fatal("/readyz was never sampled not-ready: the test did not see the load")
	}
	for range 20 {
		if !readyzOK(rl.readyz) {
			t.Fatal("/readyz fell back to not-ready after the load")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := rl.l.Status(); st.Target != 26 || st.Applied != 26 {
		t.Fatalf("loader status target %d applied %d, want 26 and 26", st.Target, st.Applied)
	}
	for _, tn := range tenants {
		if !e.tr.admitted(tn, c.url(0)) {
			t.Fatalf("a sprout of tenant %s was refused after the load", tn.sproutID)
		}
	}
}

// TestLoaderMissedEventRepairedByTimer (scenario 2): three nodes with
// loaders; farmer writes a new tenant and bumps the index but no event is
// published. Every node accepts the tenant's sprout within five reconcile
// intervals.
func TestLoaderMissedEventRepairedByTimer(t *testing.T) {
	const reconcile = 200 * time.Millisecond
	e := newLoaderEnv(t, reconcile)
	c := newTestCluster(t, e.tr, 3)
	c.waitReady(0, 1, 2)
	var loaders []*runningLoader
	for i := range 3 {
		loaders = append(loaders, e.startLoader(t, c.url(i)))
	}
	waitLoaded(t, loaders...)

	// Anything published on the event subject would show up here.
	sys := e.sysConn(t, c.url(0))
	events, err := sys.SubscribeSync(accountloader.DefaultEventSubject)
	if err != nil {
		t.Fatal(err)
	}
	sys.Flush()

	tn := e.tr.newTenant(t, "web-01")
	e.bucket.putAccount(t, tn.pub, e.tr.accountJWT(t, tn, false))
	e.bucket.bumpIndex(t)
	admitted := make([]func() bool, 3)
	for i := range admitted {
		admitted[i] = func() bool { return e.tr.admitted(tn, c.url(i)) }
	}
	waitAllBy(t, "every node to accept the new tenant's sprout", time.Now().Add(5*reconcile), admitted...)
	if m, err := events.NextMsg(10 * time.Millisecond); err == nil {
		t.Fatalf("an accounts-changed event was published (%q); the test needs none", m.Data)
	}
}

// TestLoaderOlderJWTNotApplied (scenario 3): the bucket object goes from
// issued-at 200 back to 100 and the index is bumped; the node keeps 200
// and the loader counts a stale skip.
func TestLoaderOlderJWTNotApplied(t *testing.T) {
	e := newLoaderEnv(t, 200*time.Millisecond)
	tn := e.tr.newTenant(t, "web-01")
	ac := jwt.NewAccountClaims(tn.pub)
	ac.Name = "acme"
	newer := signAccountAt(t, e.tr.operatorSigning, ac, 200)
	ac.Name = "acme-old"
	older := signAccountAt(t, e.tr.operatorSigning, ac, 100)
	e.bucket.putAccount(t, tn.pub, newer)
	e.bucket.bumpIndex(t)

	c := newTestCluster(t, e.tr, 1)
	c.waitReady(0)
	rl := e.startLoader(t, c.url(0))
	waitLoaded(t, rl)
	sys := e.sysConn(t, c.url(0))
	if got := lookupIATs(t, sys, tn.pub); !slices.Equal(got, []int64{200}) {
		t.Fatalf("node holds issued-at %v after the load, want [200]", got)
	}

	e.bucket.putAccount(t, tn.pub, older)
	token := e.bucket.bumpIndex(t)
	waitFor(t, "the loader to reconcile the bumped index", 10*time.Second, func() bool {
		return rl.l.Status().LastIndexToken == token
	})
	if n := rl.l.Status().Counters[accountloader.CounterStaleSkipped]; n != 1 {
		t.Fatalf("%s = %d, want 1", accountloader.CounterStaleSkipped, n)
	}
	if got := lookupIATs(t, sys, tn.pub); !slices.Equal(got, []int64{200}) {
		t.Fatalf("node holds issued-at %v after the stale object, want [200]", got)
	}
	if !e.tr.admitted(tn, c.url(0)) {
		t.Fatal("the tenant's sprout was refused")
	}
}

// TestLoaderRevokedSproutRefusedOnEveryNode (scenario 4): three nodes, a
// sprout of one tenant on each. Farmer writes an Account JWT revoking that
// sprout (newer issued-at), bumps the index and publishes the event while
// the link between node 2 and its loader is down, so that loader misses
// it. Nodes 0 and 1 drop the sprout before any timer could fire; node 2
// drops it too, its loader catches up by the timer, and a new connection
// is refused on all three.
func TestLoaderRevokedSproutRefusedOnEveryNode(t *testing.T) {
	const reconcile = 3 * time.Second
	e := newLoaderEnv(t, reconcile)
	tn := e.tr.newTenant(t, "web-01")
	now := time.Now().Unix()
	ac := jwt.NewAccountClaims(tn.pub)
	ac.Name = "acme"
	e.bucket.putAccount(t, tn.pub, signAccountAt(t, e.tr.operatorSigning, ac, now-10))
	e.bucket.bumpIndex(t)

	c := newTestCluster(t, e.tr, 3)
	c.waitReady(0, 1, 2)
	// Node 2's loader reaches its node through a proxy the test can cut.
	link := newProxy(t)
	link.setTarget(hostOf(t, c.url(2)))
	linkURL := "tls://" + link.addr()
	loaders := []*runningLoader{e.startLoader(t, c.url(0)), e.startLoader(t, c.url(1)), e.startLoader(t, linkURL)}
	waitLoaded(t, loaders...)

	sprouts := make([]*nats.Conn, 3)
	for i := range sprouts {
		waitFor(t, fmt.Sprintf("the sprout to connect to node %d", i), 5*time.Second, func() bool {
			var err error
			sprouts[i], err = e.tr.dialSprout(tn, []string{c.url(i)}, nats.NoReconnect())
			return err == nil
		})
		t.Cleanup(sprouts[i].Close)
	}

	uc, err := jwt.DecodeUserClaims(tn.sproutJWT)
	if err != nil {
		t.Fatal(err)
	}
	ac.Revoke(uc.Subject)
	revoking := signAccountAt(t, e.tr.operatorSigning, ac, now)

	link.setCut(true)
	waitFor(t, "node 2's loader to lose its node", 5*time.Second, func() bool {
		return loaders[2].node.ConnectedServerID() == ""
	})
	sys := e.sysConn(t, c.url(0))
	e.bucket.putAccount(t, tn.pub, revoking)
	token := e.bucket.bumpIndex(t)
	published := time.Now()
	publishEvent(t, sys, token, map[string]int64{tn.pub: now})
	// Before node 2's loader is back, so the event is gone for it.
	time.Sleep(100 * time.Millisecond)
	link.setCut(false)

	// No index timer can fire before 0.8 of an interval: dropping the
	// sprout before then is the event's work.
	waitAllBy(t, "nodes 0 and 1 to drop the revoked sprout before any timer", published.Add(reconcile*4/5),
		sprouts[0].IsClosed, sprouts[1].IsClosed)
	waitFor(t, "node 2 to drop the revoked sprout", 5*reconcile, sprouts[2].IsClosed)
	waitFor(t, "node 2's loader to apply the revocation by its timer", 5*reconcile, func() bool {
		return loaders[2].l.Status().LastIndexToken == token
	})
	for i := range 3 {
		if e.tr.admitted(tn, c.url(i)) {
			t.Fatalf("node %d admitted the revoked sprout", i)
		}
	}
}

// TestLoaderAllNodesRestartWithFarmerDown (scenario 5): every node stops
// and comes back on an empty resolver directory with no farmer running.
// Each node's loader loads it from the bucket alone, the fence forms the
// mesh, and the sprouts reconnect.
func TestLoaderAllNodesRestartWithFarmerDown(t *testing.T) {
	e := newLoaderEnv(t, 200*time.Millisecond)
	tenants := make([]*tenant, 3)
	for i := range tenants {
		tenants[i] = e.tr.newTenant(t, fmt.Sprintf("web-%02d", i))
		e.bucket.putAccount(t, tenants[i].pub, e.tr.accountJWT(t, tenants[i], false))
	}
	e.bucket.bumpIndex(t)

	c := newTestCluster(t, e.tr, 3)
	c.waitReady(0, 1, 2)
	// Sprouts reach node i through a front proxy, as through the bus
	// Service: a restarted node listens on a new port.
	fronts := make([]*proxy, 3)
	var frontURLs []string
	for i := range fronts {
		fronts[i] = newProxy(t)
		fronts[i].setTarget(hostOf(t, c.url(i)))
		frontURLs = append(frontURLs, "tls://"+fronts[i].addr())
	}
	var loaders []*runningLoader
	for i := range 3 {
		loaders = append(loaders, e.startLoader(t, c.url(i)))
	}
	waitLoaded(t, loaders...)

	var reconnects atomic.Int32
	sprouts := make([]*nats.Conn, 3)
	for i, tn := range tenants {
		urls := append([]string{frontURLs[i]}, slices.Delete(slices.Clone(frontURLs), i, i+1)...)
		waitFor(t, fmt.Sprintf("sprout %d to connect", i), 5*time.Second, func() bool {
			var err error
			sprouts[i], err = e.tr.dialSprout(tn, urls,
				nats.MaxReconnects(-1), nats.ReconnectWait(50*time.Millisecond),
				nats.ReconnectHandler(func(*nats.Conn) { reconnects.Add(1) }))
			return err == nil
		})
		t.Cleanup(sprouts[i].Close)
	}

	// Everything stops; the resolver directories (emptyDirs) go with it.
	for _, rl := range loaders {
		rl.stop()
	}
	for i := range 3 {
		c.stop(i)
		if err := os.RemoveAll(c.pkiDirs[i]); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "every sprout to lose the bus", 5*time.Second, func() bool {
		for _, nc := range sprouts {
			if nc.IsConnected() {
				return false
			}
		}
		return true
	})

	for i := range 3 {
		c.start(i)
	}
	c.waitReady(0, 1, 2)
	loaders = loaders[:0]
	for i := range 3 {
		loaders = append(loaders, e.startLoader(t, c.url(i)))
	}
	waitLoaded(t, loaders...)
	// The Service sends traffic to a pod only once it is Ready: fence
	// lifted and loader loaded (brief §3).
	for i := range 3 {
		fronts[i].setTarget(hostOf(t, c.url(i)))
	}
	for i := range 3 {
		sys := e.sysConn(t, c.url(i))
		have := claimsList(t, sys)
		for _, p := range append([]string{e.sysPub}, tenants[0].pub, tenants[1].pub, tenants[2].pub) {
			if !slices.Contains(have, p) {
				t.Fatalf("node %d does not hold %s after loading from the bucket", i, p)
			}
		}
	}
	waitFor(t, "every sprout to reconnect", 15*time.Second, func() bool {
		for _, nc := range sprouts {
			if !nc.IsConnected() {
				return false
			}
		}
		return reconnects.Load() >= 3
	})
	for i, tn := range tenants {
		for n := range 3 {
			if !e.tr.admitted(tn, c.url(n)) {
				t.Fatalf("node %d refused tenant %d's sprout after the restart", n, i)
			}
		}
	}
}
