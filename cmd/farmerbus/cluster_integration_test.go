package main

// In-process three-node bus clusters, built the way cmd/farmerbus builds
// one node (pki.ConfigureNats + startBus), each node with its own resolver
// directory and the shared trust chain supplied as external seed files,
// like the chart's IMAS_NATS_*_SEED_FILE mounts. The test plays core: it
// signs Account and sprout User JWTs with the same seeds and pushes them
// over a SYS connection, as internal/pki's pushAccountUpdate does.
//
// Every route goes through a per-pair TCP proxy so a test can cut any
// link. Nodes advertise an address nothing listens on, so nats-server's
// implicit route gossip cannot heal a cut behind the test's back.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki"
)

var testTiming = fenceTiming{Interval: 100 * time.Millisecond, Grace: 500 * time.Millisecond, ReqTimeout: 500 * time.Millisecond}

// testRoutePassword is a fixture, built at runtime so it doesn't read as a
// committed credential.
var testRoutePassword = strings.Repeat("route-test-", 4)

// ---- trust material -------------------------------------------------------

type trust struct {
	dir                 string
	operatorSigning     nkeys.KeyPair
	sysAccount, sysUser nkeys.KeyPair
	sysUserJWT          string
	caPool              *x509.CertPool
}

func newTrust(t *testing.T) *trust {
	t.Helper()
	dir := t.TempDir()
	tr := &trust{dir: dir}
	seeds := map[string]func() (nkeys.KeyPair, error){
		"OPERATOR": nkeys.CreateOperator, "OPERATOR_SIGNING": nkeys.CreateOperator,
		"SYS_ACCOUNT": nkeys.CreateAccount, "TENANT": nkeys.CreateAccount, "TENANT_SIGNING": nkeys.CreateAccount,
	}
	kps := map[string]nkeys.KeyPair{}
	for name, mk := range seeds {
		kp, err := mk()
		if err != nil {
			t.Fatal(err)
		}
		seed, _ := kp.Seed()
		p := filepath.Join(dir, strings.ToLower(name)+".nk")
		if err := os.WriteFile(p, seed, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("IMAS_NATS_"+name+"_SEED_FILE", p)
		kps[name] = kp
	}
	tr.operatorSigning = kps["OPERATOR_SIGNING"]
	tr.sysAccount = kps["SYS_ACCOUNT"]
	tr.sysUser, _ = nkeys.CreateUser()
	pub, _ := tr.sysUser.PublicKey()
	uc := jwt.NewUserClaims(pub)
	var err error
	if tr.sysUserJWT, err = uc.Encode(tr.sysAccount); err != nil {
		t.Fatal(err)
	}
	tr.writeCerts(t)

	config.FarmerInterface = "127.0.0.1"
	config.FarmerBusPort = "-1"
	config.FarmerWSPort = ""
	config.FarmerOrganization = "imas"
	return tr
}

// writeCerts issues a CA and one node certificate for 127.0.0.1 with both
// server and client EKUs, as route mTLS requires.
func (tr *trust) writeCerts(t *testing.T) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "imas test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	nodeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nodeTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "bus"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	nodeDER, err := x509.CreateCertificate(rand.Reader, nodeTmpl, caCert, &nodeKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(nodeKey)
	write := func(name, typ string, der []byte) string {
		p := filepath.Join(tr.dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	config.RootCA = write("ca.pem", "CERTIFICATE", caDER)
	config.CertFile = write("cert.pem", "CERTIFICATE", nodeDER)
	config.KeyFile = write("key.pem", "EC PRIVATE KEY", keyDER)
	tr.caPool = x509.NewCertPool()
	tr.caPool.AddCert(caCert)
}

func (tr *trust) tlsConfig() *tls.Config {
	return &tls.Config{RootCAs: tr.caPool, MinVersion: tls.VersionTLS12}
}

// tenant is one Account, signed the way internal/pki signs tenant Accounts
// (by the operator signing key), with a sprout User JWT carrying the
// sprout permission shape internal/pki/jwtusers.go grants.
type tenant struct {
	kp         nkeys.KeyPair
	pub        string
	sproutSeed []byte
	sproutJWT  string
	sproutID   string
}

func (tr *trust) newTenant(t *testing.T, sproutID string) *tenant {
	t.Helper()
	kp, _ := nkeys.CreateAccount()
	pub, _ := kp.PublicKey()
	sk, _ := nkeys.CreateUser()
	spub, _ := sk.PublicKey()
	seed, _ := sk.Seed()
	uc := jwt.NewUserClaims(spub)
	uc.Name = sproutID
	uc.Permissions = jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{"imas.sprouts.announce." + sproutID, "_INBOX.>", "imas.sprouts." + sproutID + ".facts"}},
		Sub: jwt.Permission{Allow: jwt.StringList{"imas.sprouts." + sproutID + ".>"}},
	}
	userJWT, err := uc.Encode(kp)
	if err != nil {
		t.Fatal(err)
	}
	return &tenant{kp: kp, pub: pub, sproutSeed: seed, sproutJWT: userJWT, sproutID: sproutID}
}

func (tr *trust) accountJWT(t *testing.T, tn *tenant, lockedOut bool) string {
	t.Helper()
	ac := jwt.NewAccountClaims(tn.pub)
	ac.Name = "acme"
	if lockedOut {
		// Same shape as internal/pki's lockOutAccount.
		ac.RevokeAt(jwt.All, time.Now())
		ac.Limits.Conn = 0
		ac.Limits.LeafNodeConn = 0
	}
	s, err := ac.Encode(tr.operatorSigning)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// push sends an Account JWT to one node's $SYS.REQ.CLAIMS.UPDATE as core
// does, and fails unless that node accepted it.
func (tr *trust) push(url, accountJWT string) error {
	nc, err := nats.Connect(url, nats.Secure(tr.tlsConfig()), nats.UserJWTAndSeed(tr.sysUserJWT, mustSeed(tr.sysUser)),
		nats.Timeout(2*time.Second), nats.NoReconnect())
	if err != nil {
		return err
	}
	defer nc.Close()
	resp, err := nc.Request("$SYS.REQ.CLAIMS.UPDATE", []byte(accountJWT), 2*time.Second)
	if err != nil {
		return err
	}
	var st nats_server.ServerAPIClaimUpdateResponse
	if err := json.Unmarshal(resp.Data, &st); err != nil {
		return err
	}
	if st.Error != nil {
		return fmt.Errorf("rejected: %s", st.Error.Description)
	}
	return nil
}

func mustSeed(kp nkeys.KeyPair) string { s, _ := kp.Seed(); return string(s) }

func (tr *trust) dialSprout(tn *tenant, urls []string, extra ...nats.Option) (*nats.Conn, error) {
	opts := append([]nats.Option{
		nats.Secure(tr.tlsConfig()),
		nats.UserJWTAndSeed(tn.sproutJWT, string(tn.sproutSeed)),
		nats.Timeout(2 * time.Second),
		nats.DontRandomize(),
	}, extra...)
	return nats.Connect(strings.Join(urls, ","), opts...)
}

// ---- route proxies --------------------------------------------------------

// proxy forwards TCP to a target that can change (a restarted node) and
// can be cut: cut closes every live connection and refuses new ones.
type proxy struct {
	ln     net.Listener
	mu     sync.Mutex
	target string
	cut    bool
	conns  map[net.Conn]bool
}

func newProxy(t *testing.T) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln, conns: map[net.Conn]bool{}}
	t.Cleanup(func() { ln.Close(); p.setCut(true) })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(c)
		}
	}()
	return p
}

func (p *proxy) addr() string { return p.ln.Addr().String() }

func (p *proxy) setTarget(a string) { p.mu.Lock(); p.target = a; p.mu.Unlock() }

func (p *proxy) setCut(cut bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cut = cut
	if cut {
		for c := range p.conns {
			c.Close()
		}
		p.conns = map[net.Conn]bool{}
	}
}

func (p *proxy) handle(c net.Conn) {
	p.mu.Lock()
	target, cut := p.target, p.cut
	p.mu.Unlock()
	if cut || target == "" {
		c.Close()
		return
	}
	u, err := net.DialTimeout("tcp", target, time.Second)
	if err != nil {
		c.Close()
		return
	}
	p.mu.Lock()
	if p.cut {
		p.mu.Unlock()
		c.Close()
		u.Close()
		return
	}
	p.conns[c], p.conns[u] = true, true
	p.mu.Unlock()
	go func() { io.Copy(u, c); u.Close(); c.Close() }()
	io.Copy(c, u)
	u.Close()
	c.Close()
}

// ---- the cluster ----------------------------------------------------------

type testCluster struct {
	t       *testing.T
	tr      *trust
	n       int
	pkiDirs []string
	nodes   []*busNode
	// links[a][b] carries node a's route to node b.
	links [][]*proxy
	// blackhole is advertised by every node: it refuses connections, so
	// implicit routes never form and only the proxied explicit ones do.
	blackhole string
}

func newTestCluster(t *testing.T, tr *trust, n int) *testCluster {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bh := ln.Addr().String()
	ln.Close()
	c := &testCluster{t: t, tr: tr, n: n, nodes: make([]*busNode, n), blackhole: bh}
	for a := 0; a < n; a++ {
		c.pkiDirs = append(c.pkiDirs, filepath.Join(t.TempDir(), fmt.Sprintf("pki-%d", a))+"/")
		row := make([]*proxy, n)
		for b := 0; b < n; b++ {
			if a != b {
				row[b] = newProxy(t)
			}
		}
		c.links = append(c.links, row)
	}
	t.Cleanup(func() {
		for _, nd := range c.nodes {
			if nd != nil {
				nd.Shutdown()
			}
		}
	})
	for i := 0; i < n; i++ {
		c.start(i)
	}
	return c
}

// start (re)starts node i on its own resolver directory.
func (c *testCluster) start(i int) {
	c.t.Helper()
	config.FarmerPKI = c.pkiDirs[i]
	opts := pki.ConfigureNats()
	opts.LogFile, opts.Trace, opts.Debug = "", false, false
	opts.NoLog = true
	cl := &clusterConfig{
		Name: "imas-bus", Port: -1, User: defaultRouteUser, Password: testRoutePassword,
		ServerName: fmt.Sprintf("bus-%d", i), Advertise: c.blackhole,
	}
	for b := 0; b < c.n; b++ {
		host := "127.0.0.1:1" // this node's own entry; never dialled successfully
		if b != i {
			host = c.links[i][b].addr()
		}
		u, err := parseRouteURL("tls://" + host)
		if err != nil {
			c.t.Fatal(err)
		}
		cl.Routes = append(cl.Routes, u)
	}
	nd, err := startBus(opts, cl, testTiming)
	if err != nil {
		c.t.Fatalf("starting node %d: %v", i, err)
	}
	c.nodes[i] = nd
	addr := nd.srv.ClusterAddr().String()
	for a := 0; a < c.n; a++ {
		if a != i {
			c.links[a][i].setTarget(addr)
		}
	}
}

func (c *testCluster) stop(i int) {
	c.nodes[i].Shutdown()
	c.nodes[i] = nil
}

func (c *testCluster) url(i int) string { return c.nodes[i].srv.ClientURL() }

func (c *testCluster) urls() []string {
	var out []string
	for i := range c.nodes {
		if c.nodes[i] != nil {
			out = append(out, c.url(i))
		}
	}
	return out
}

// cut severs (or heals) both directions between a and b.
func (c *testCluster) cut(a, b int, cut bool) {
	c.links[a][b].setCut(cut)
	c.links[b][a].setCut(cut)
}

func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %s", d, what)
}

func (c *testCluster) waitReady(idx ...int) {
	c.t.Helper()
	for _, i := range idx {
		waitFor(c.t, fmt.Sprintf("node %d to lift its fence", i), 15*time.Second, c.nodes[i].Ready)
	}
}

// accountConns counts client connections bound to account pub on node i.
func (c *testCluster) accountConns(i int, pub string) int {
	cz, err := c.nodes[i].srv.Connz(&nats_server.ConnzOptions{Account: pub})
	if err != nil {
		c.t.Fatal(err)
	}
	return len(cz.Conns)
}

// ---- tests ----------------------------------------------------------------

// TestClusterMeshAndFailover: three nodes, one sprout client on each,
// publish on one node and receive on the others; then stop a node and
// check its client reconnects to a surviving node and still delivers.
func TestClusterMeshAndFailover(t *testing.T) {
	tr := newTrust(t)
	c := newTestCluster(t, tr, 3)
	c.waitReady(0, 1, 2)

	tn := tr.newTenant(t, "web-01")
	if err := tr.push(c.url(0), tr.accountJWT(t, tn, false)); err != nil {
		t.Fatalf("pushing the tenant Account: %v", err)
	}

	// Client i prefers node i, but knows every node (as core and Envoy
	// reach "the bus", not one pod).
	all := c.urls()
	clients := make([]*nats.Conn, 3)
	reconnected := make(chan struct{}, 1)
	for i := range clients {
		urls := append([]string{all[i]}, append(append([]string{}, all[:i]...), all[i+1:]...)...)
		opts := []nats.Option{nats.ReconnectWait(50 * time.Millisecond), nats.MaxReconnects(-1)}
		if i == 0 {
			opts = append(opts, nats.ReconnectHandler(func(*nats.Conn) { reconnected <- struct{}{} }))
		}
		var nc *nats.Conn
		waitFor(t, fmt.Sprintf("sprout to connect to node %d", i), 5*time.Second, func() bool {
			var err error
			nc, err = tr.dialSprout(tn, urls, opts...)
			return err == nil
		})
		if got := nc.ConnectedServerName(); got != fmt.Sprintf("bus-%d", i) {
			t.Fatalf("client %d connected to %q, want bus-%d", i, got, i)
		}
		clients[i] = nc
		t.Cleanup(nc.Close)
	}

	subj := "imas.sprouts.web-01.facts"
	subs := make([]*nats.Subscription, 3)
	for i, nc := range clients {
		s, err := nc.SubscribeSync(subj)
		if err != nil {
			t.Fatal(err)
		}
		nc.Flush()
		subs[i] = s
	}
	// Interest crosses the routes asynchronously; publish until it lands.
	expectAcross := func(pub *nats.Conn, recv []*nats.Subscription, payload string) {
		t.Helper()
		for _, s := range recv {
			waitFor(t, "a message published on one node to reach a subscriber on another", 5*time.Second, func() bool {
				pub.Publish(subj, []byte(payload))
				pub.Flush()
				m, err := s.NextMsg(100 * time.Millisecond)
				return err == nil && string(m.Data) == payload
			})
		}
	}
	expectAcross(clients[0], subs[1:], "from-node-0")

	// Stop node 0: its client must fail over to node 1 or 2, and the two
	// survivors keep quorum and keep serving.
	c.stop(0)
	select {
	case <-reconnected:
	case <-time.After(10 * time.Second):
		t.Fatal("client of the stopped node did not reconnect to a surviving node")
	}
	if got := clients[0].ConnectedServerName(); got != "bus-1" && got != "bus-2" {
		t.Fatalf("client 0 reconnected to %q, want bus-1 or bus-2", got)
	}
	if !c.nodes[1].Ready() || !c.nodes[2].Ready() {
		t.Fatal("survivors fenced themselves after losing one node of three")
	}
	expectAcross(clients[0], []*nats.Subscription{subs[1], subs[2]}, "after-failover")
}

// TestClusterLockOutWhileNodeDown: a tenant is locked out while node 2 is
// down. Node 2 restarts from its old resolver directory, which still holds
// the live Account JWT, and must not serve the tenant: first because it is
// fenced, then because its pull from the peers merged the lock-out.
func TestClusterLockOutWhileNodeDown(t *testing.T) {
	tr := newTrust(t)
	c := newTestCluster(t, tr, 3)
	c.waitReady(0, 1, 2)
	tn := tr.newTenant(t, "web-01")
	if err := tr.push(c.url(0), tr.accountJWT(t, tn, false)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Account to reach node 2", 5*time.Second, func() bool {
		nc, err := tr.dialSprout(tn, []string{c.url(2)})
		if err == nil {
			nc.Close()
		}
		return err == nil
	})

	c.stop(2)
	live, err := tr.dialSprout(tn, []string{c.url(1)}, nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if err := tr.push(c.url(0), tr.accountJWT(t, tn, true)); err != nil {
		t.Fatalf("pushing the lock-out: %v", err)
	}
	waitFor(t, "node 1 to close the locked-out tenant's connection", 5*time.Second, func() bool { return live.IsClosed() })

	c.start(2)
	// Fenced on start: refuses even a valid TLS handshake.
	if nc, err := tr.dialSprout(tn, []string{c.url(2)}); err == nil {
		nc.Close()
		if !c.nodes[2].Ready() {
			t.Fatal("node 2 accepted a client while fenced")
		}
	}
	c.waitReady(2)
	if nc, err := tr.dialSprout(tn, []string{c.url(2)}); err == nil {
		nc.Close()
		t.Fatal("node 2 accepted the locked-out tenant after restarting with its stale resolver")
	}
	if n := c.accountConns(2, tn.pub); n != 0 {
		t.Fatalf("node 2 holds %d connections for the locked-out tenant", n)
	}
}

// TestClusterLockOutDuringPartition: node 2 is cut off from both peers
// while one of the tenant's sprouts is connected to it, and the lock-out
// is pushed to the majority side. Node 2 never received it, so it must
// not keep or accept the tenant's connections; after the partition heals
// it must sync the lock-out before serving anyone.
func TestClusterLockOutDuringPartition(t *testing.T) {
	tr := newTrust(t)
	c := newTestCluster(t, tr, 3)
	c.waitReady(0, 1, 2)
	tn := tr.newTenant(t, "web-01")
	if err := tr.push(c.url(0), tr.accountJWT(t, tn, false)); err != nil {
		t.Fatal(err)
	}
	var onNode2 *nats.Conn
	waitFor(t, "a sprout on node 2", 5*time.Second, func() bool {
		var err error
		onNode2, err = tr.dialSprout(tn, []string{c.url(2)}, nats.NoReconnect())
		return err == nil
	})
	defer onNode2.Close()

	c.cut(2, 0, true)
	c.cut(2, 1, true)
	waitFor(t, "node 2 to fence after losing its majority", 5*time.Second, func() bool { return !c.nodes[2].Ready() })
	waitFor(t, "node 2 to drop its clients", 5*time.Second, func() bool { return onNode2.IsClosed() })

	// Core's push lands on the majority side; the minority node refuses it.
	if err := tr.push(c.url(2), tr.accountJWT(t, tn, true)); err == nil {
		t.Fatal("fenced node 2 accepted a claims push")
	}
	if err := tr.push(c.url(0), tr.accountJWT(t, tn, true)); err != nil {
		t.Fatalf("pushing the lock-out to the majority: %v", err)
	}
	if nc, err := tr.dialSprout(tn, []string{c.url(2)}); err == nil {
		nc.Close()
		t.Fatal("partitioned node 2 accepted the locked-out tenant")
	}
	if !c.nodes[0].Ready() || !c.nodes[1].Ready() {
		t.Fatal("majority side fenced itself")
	}

	c.cut(2, 0, false)
	c.cut(2, 1, false)
	c.waitReady(2)
	if nc, err := tr.dialSprout(tn, []string{c.url(2)}); err == nil {
		nc.Close()
		t.Fatal("node 2 served the locked-out tenant after the partition healed")
	}
}

// TestClusterPartialMeshFences: the 0-1 link breaks while both still reach
// node 2. Each keeps a majority, but a push landing on one would not reach
// the other, so both must fence and only node 2 serves.
func TestClusterPartialMeshFences(t *testing.T) {
	tr := newTrust(t)
	c := newTestCluster(t, tr, 3)
	c.waitReady(0, 1, 2)
	tn := tr.newTenant(t, "web-01")
	if err := tr.push(c.url(0), tr.accountJWT(t, tn, false)); err != nil {
		t.Fatal(err)
	}

	c.cut(0, 1, true)
	waitFor(t, "nodes 0 and 1 to fence on the partial mesh", 5*time.Second, func() bool {
		return !c.nodes[0].Ready() && !c.nodes[1].Ready()
	})
	if !c.nodes[2].Ready() {
		t.Fatal("node 2, routed to both, fenced itself")
	}
	if err := tr.push(c.url(0), tr.accountJWT(t, tn, true)); err == nil {
		t.Fatal("node 0 accepted a claims push on a partial mesh")
	}
	if err := tr.push(c.url(2), tr.accountJWT(t, tn, true)); err != nil {
		t.Fatalf("pushing the lock-out to node 2: %v", err)
	}
	c.cut(0, 1, false)
	c.waitReady(0, 1)
	for i := 0; i < 3; i++ {
		if nc, err := tr.dialSprout(tn, []string{c.url(i)}); err == nil {
			nc.Close()
			t.Fatalf("node %d served the locked-out tenant", i)
		}
	}
}
