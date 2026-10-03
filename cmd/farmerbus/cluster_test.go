package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	nats_server "github.com/nats-io/nats-server/v2/server"

	"github.com/yogzblr/imas/internal/config"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func pwFile(content string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if p != "/pw" {
			return nil, errors.New("no such file")
		}
		return []byte(content + "\n"), nil
	}
}

func TestClusterConfigFromEnv(t *testing.T) {
	good := map[string]string{
		envClusterName:         "imas-bus",
		envClusterPort:         "6222",
		envClusterRoutes:       "tls://b-0.h.ns.svc.cluster.local:6222, tls://b-1.h.ns.svc.cluster.local:6222,tls://b-2.h.ns.svc.cluster.local:6222",
		envClusterPasswordFile: "/pw",
		envClusterAdvertise:    "b-0.h.ns.svc.cluster.local:6222",
		envServerName:          "b-0",
	}
	c, err := clusterConfigFromEnv(envOf(good), pwFile(testRoutePassword))
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "imas-bus" || c.Port != 6222 || c.Size() != 3 || c.User != defaultRouteUser ||
		c.Password != testRoutePassword || c.ServerName != "b-0" || c.Advertise != good[envClusterAdvertise] {
		t.Fatalf("parsed %+v", c)
	}
	if c.Routes[1].Host != "b-1.h.ns.svc.cluster.local:6222" || c.Routes[1].User != nil {
		t.Fatalf("route 1 = %v", c.Routes[1])
	}

	if c, err := clusterConfigFromEnv(envOf(nil), pwFile("")); c != nil || err != nil {
		t.Fatalf("unset env: got %v, %v; want single-node (nil, nil)", c, err)
	}

	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range good {
			m[a] = b
		}
		m[k] = v
		return m
	}
	for name, tc := range map[string]struct {
		env  map[string]string
		pw   string
		want string
	}{
		"name without routes":   {map[string]string{envClusterName: "x"}, testRoutePassword, "is empty"},
		"no name":               {with(envClusterName, ""), testRoutePassword, envClusterName + " is required"},
		"bad port":              {with(envClusterPort, "http"), testRoutePassword, "must be a TCP port"},
		"no password file":      {with(envClusterPasswordFile, ""), testRoutePassword, "never runs without credentials"},
		"unreadable password":   {with(envClusterPasswordFile, "/nope"), testRoutePassword, "reading the route password"},
		"short password":        {good, "hunter2", "shorter than"},
		"password with colon":   {good, strings.Repeat("a", 40) + ":b", "must not contain"},
		"credentials in route":  {with(envClusterRoutes, "tls://u:p@b-0:6222"), testRoutePassword, "carries credentials"},
		"bad scheme":            {with(envClusterRoutes, "http://b-0:6222"), testRoutePassword, "must use tls://"},
		"no port in route":      {with(envClusterRoutes, "tls://b-0"), testRoutePassword, "scheme://host:port"},
		"duplicate route":       {with(envClusterRoutes, "tls://b-0:6222,tls://b-0:6222"), testRoutePassword, "twice"},
		"bad advertise":         {with(envClusterAdvertise, "b-0"), testRoutePassword, "host:port"},
		"routes only separator": {with(envClusterRoutes, " , "), testRoutePassword, "no routes"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := clusterConfigFromEnv(envOf(tc.env), pwFile(tc.pw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// fakeRoute implements nats_server.ClientAuthentication for routeAuth.
type fakeRoute struct {
	opts *nats_server.ClientOpts
	cs   *tls.ConnectionState
}

func (f fakeRoute) GetOpts() *nats_server.ClientOpts            { return f.opts }
func (f fakeRoute) GetTLSConnectionState() *tls.ConnectionState { return f.cs }
func (f fakeRoute) RegisterUser(*nats_server.User)              {}
func (f fakeRoute) RemoteAddress() net.Addr                     { return nil }
func (f fakeRoute) GetNonce() []byte                            { return nil }
func (f fakeRoute) Kind() int                                   { return nats_server.ROUTER }
func (f fakeRoute) GetID() uint64                               { return 1 }

func TestRouteAuth(t *testing.T) {
	a := &routeAuth{user: "u", password: testRoutePassword, hosts: []string{"b-0.h.ns.svc.cluster.local", "10.0.0.7"}}
	podCert := &x509.Certificate{DNSNames: []string{"b-0.h.ns.svc.cluster.local", "b-1.h.ns.svc.cluster.local"}}
	ipCert := &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("10.0.0.7")}}
	otherCert := &x509.Certificate{DNSNames: []string{"envoy.dmz.example.com"}}
	verified := func(c *x509.Certificate) *tls.ConnectionState {
		return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c}}}
	}
	creds := &nats_server.ClientOpts{Username: "u", Password: testRoutePassword}
	for name, tc := range map[string]struct {
		r    fakeRoute
		want bool
	}{
		"creds + pod cert":         {fakeRoute{creds, verified(podCert)}, true},
		"creds + IP SAN":           {fakeRoute{creds, verified(ipCert)}, true},
		"wrong password":           {fakeRoute{&nats_server.ClientOpts{Username: "u", Password: "nope"}, verified(podCert)}, false},
		"wrong user":               {fakeRoute{&nats_server.ClientOpts{Username: "x", Password: testRoutePassword}, verified(podCert)}, false},
		"no TLS":                   {fakeRoute{creds, nil}, false},
		"unverified client cert":   {fakeRoute{creds, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{podCert}}}, false},
		"CA-signed but not a node": {fakeRoute{creds, verified(otherCert)}, false},
		"no CONNECT options":       {fakeRoute{nil, verified(podCert)}, false},
	} {
		if got := a.Check(tc.r); got != tc.want {
			t.Errorf("%s: Check = %v, want %v", name, got, tc.want)
		}
	}
}

func TestCheckRouteCertUsage(t *testing.T) {
	for name, tc := range map[string]struct {
		eku  []x509.ExtKeyUsage
		want bool
	}{
		"no EKU":      {nil, true},
		"both":        {[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, true},
		"any":         {[]x509.ExtKeyUsage{x509.ExtKeyUsageAny}, true},
		"server only": {[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false},
		"client only": {[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false},
	} {
		err := checkRouteCertUsage(tls.Certificate{Certificate: [][]byte{{0}}, Leaf: &x509.Certificate{ExtKeyUsage: tc.eku}})
		if (err == nil) != tc.want {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.want)
		}
	}
}

func TestClaimRank(t *testing.T) {
	live := claimRank{iat: 10, raw: "a"}
	locked := claimRank{iat: 10, locked: true, raw: "b"}
	newer := claimRank{iat: 11, raw: "c"}
	if !locked.beats(live) || live.beats(locked) {
		t.Error("at the same issued-at a lock-out must win over a live JWT")
	}
	if !newer.beats(locked) {
		t.Error("a newer JWT (e.g. re-provisioning) must win over an older lock-out")
	}
	x, y := claimRank{iat: 10, raw: "x"}, claimRank{iat: 10, raw: "y"}
	if x.beats(y) == y.beats(x) {
		t.Error("ties must have exactly one winner so every node converges")
	}
}

// TestRouteListenerRejectsUnauthenticated points rogue servers at a real
// node's route port: one with the right password but no client
// certificate, one with a valid certificate but the wrong password. Neither
// may become a route.
func TestRouteListenerRejectsUnauthenticated(t *testing.T) {
	tr := newTrust(t)
	c := newTestCluster(t, tr, 3)
	c.waitReady(0, 1, 2)
	target := c.nodes[0].srv.ClusterAddr().String()
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	before := len(routeIDs(t, c.nodes[0].srv))

	rogue := func(name, password string, withCert bool) *nats_server.Server {
		u, _ := parseRouteURL("tls://" + target)
		u.User = url.UserPassword(defaultRouteUser, password)
		tc := &tls.Config{RootCAs: tr.caPool, MinVersion: tls.VersionTLS12}
		if withCert {
			tc.Certificates = []tls.Certificate{cert}
		}
		s, err := nats_server.NewServer(&nats_server.Options{
			ServerName: name, Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
			Cluster: nats_server.ClusterOpts{Name: "imas-bus", Host: "127.0.0.1", Port: -1, TLSConfig: tc},
			Routes:  []*url.URL{u},
		})
		if err != nil {
			t.Fatal(err)
		}
		go s.Start()
		t.Cleanup(s.Shutdown)
		return s
	}
	r1 := rogue("rogue-nocert", testRoutePassword, false)
	r2 := rogue("rogue-badpass", "wrong-password-wrong-password-wrong", true)
	time.Sleep(2 * time.Second) // several route connect attempts
	ids := routeIDs(t, c.nodes[0].srv)
	if ids[r1.ID()] || ids[r2.ID()] || len(ids) != before {
		t.Fatalf("an unauthenticated server became a route: %v", ids)
	}
	if r1.NumRoutes() != 0 || r2.NumRoutes() != 0 {
		t.Fatal("rogue server reports a route")
	}
}

func routeIDs(t *testing.T, s *nats_server.Server) map[string]bool {
	t.Helper()
	rz, err := s.Routez(&nats_server.RoutezOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range rz.Routes {
		ids[r.RemoteID] = true
	}
	return ids
}
