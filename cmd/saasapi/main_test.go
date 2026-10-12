package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/valkey-io/valkey-go"

	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/saasapi"
)

// newOnlineSproutStore returns a miniredis holding the heartbeat key farmer's
// listener would write for tenantID/sproutID. internal/heartbeat's key
// format is unexported, so it's repeated here; the wired case below fails
// if it ever drifts.
func newOnlineSproutStore(t *testing.T, tenantID, sproutID string) *miniredis.Miniredis {
	t.Helper()
	mr := miniredis.RunT(t)
	if err := mr.Set("imas:heartbeat:{"+tenantID+":"+sproutID+"}", "1"); err != nil {
		t.Fatalf("setting heartbeat key: %v", err)
	}
	return mr
}

func resetHeartbeatClient(t *testing.T) {
	t.Helper()
	heartbeat.SetClient(nil)
	t.Cleanup(func() { heartbeat.SetClient(nil) })
}

// TestInitHeartbeatClientWired: with a Valkey client (SAASAPI_VALKEY_ADDRS
// set), heartbeat.IsOnline reads live keys through it.
func TestInitHeartbeatClientWired(t *testing.T) {
	resetHeartbeatClient(t)
	mr := newOnlineSproutStore(t, "t_acme", "web-01")
	vc, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatalf("creating valkey client: %v", err)
	}
	t.Cleanup(vc.Close)

	initHeartbeatClient(vc)

	ctx := context.Background()
	if !heartbeat.IsOnline(ctx, "t_acme", "web-01") {
		t.Fatal("IsOnline = false for a sprout with a live heartbeat key; client not wired")
	}
	if heartbeat.IsOnline(ctx, "t_acme", "web-02") {
		t.Fatal("IsOnline = true for a sprout with no heartbeat key")
	}
	if heartbeat.IsOnline(ctx, "t_other", "web-01") {
		t.Fatal("IsOnline = true for another tenant's same-named sprout")
	}
}

// TestInitHeartbeatClientUnwired: with SAASAPI_VALKEY_ADDRS unset, main's vc
// is nil. initHeartbeatClient must not panic and must leave heartbeat
// unwired, so IsOnline degrades to false — even for a sprout that a
// reachable Valkey would report as online.
func TestInitHeartbeatClientUnwired(t *testing.T) {
	resetHeartbeatClient(t)
	newOnlineSproutStore(t, "t_acme", "web-01")

	initHeartbeatClient(nil)

	if heartbeat.IsOnline(context.Background(), "t_acme", "web-01") {
		t.Fatal("IsOnline = true with no Valkey client configured; want false (connected: false)")
	}
}

// TestNewRouterFleetUpdateRoutes: the §1.8 dispatch routes are registered
// if and only if SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED is true, going
// through the same LoadConfig → newRouter path main uses. The catalog and
// policy routes are always there.
func TestNewRouterFleetUpdateRoutes(t *testing.T) {
	t.Cleanup(func() { saasapi.SetFleetUpdateDispatchEnabled(false) })

	dispatch := []struct{ method, path string }{
		{"POST", "/v1/tenants/t_acme/sprouts/updates"},
		{"GET", "/v1/tenants/t_acme/sprouts/updates/b_1"},
	}
	always := []struct{ method, path string }{
		{"GET", "/v1/versions"},
		{"PATCH", "/v1/tenants/t_acme/update-policy"},
	}
	registered := func(mux *http.ServeMux, method, path string) bool {
		_, pattern := mux.Handler(httptest.NewRequest(method, path, nil))
		return pattern != ""
	}

	for env, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, "1": true} {
		t.Run("env="+env, func(t *testing.T) {
			t.Setenv("SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED", env)
			cfg, err := saasapi.LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			mux := newRouter(cfg)
			for _, r := range dispatch {
				if got := registered(mux, r.method, r.path); got != want {
					t.Errorf("%s %s registered = %t, want %t", r.method, r.path, got, want)
				}
			}
			for _, r := range always {
				if !registered(mux, r.method, r.path) {
					t.Errorf("%s %s not registered", r.method, r.path)
				}
			}
		})
	}
}

// TestNewRouterFleetUpdateClockSkew: SAASAPI_FLEET_UPDATE_CLOCK_SKEW
// reaches the wave gate through the same LoadConfig → newRouter path main
// uses, and an unset one leaves 30s.
func TestNewRouterFleetUpdateClockSkew(t *testing.T) {
	t.Cleanup(func() { saasapi.SetFleetUpdateClockSkew(30 * time.Second) })
	for env, want := range map[string]time.Duration{"": 30 * time.Second, "45s": 45 * time.Second, "2m": 2 * time.Minute} {
		t.Setenv("SAASAPI_FLEET_UPDATE_CLOCK_SKEW", env)
		cfg, err := saasapi.LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig(%q): %v", env, err)
		}
		newRouter(cfg)
		if got := saasapi.FleetUpdateClockSkew(); got != want {
			t.Errorf("SAASAPI_FLEET_UPDATE_CLOCK_SKEW=%q: margin %s, want %s", env, got, want)
		}
	}
}

// TestNewRouterOutboxSettings: SAASAPI_OUTBOX_* reach the sweeper and the
// handlers' leases through the same LoadConfig → newRouter path main uses.
func TestNewRouterOutboxSettings(t *testing.T) {
	t.Cleanup(func() { saasapi.SetOutboxSweeperSettings(saasapi.DefaultOutboxSweeperSettings()) })
	t.Setenv("SAASAPI_OUTBOX_LEASE_TTL", "45s")
	t.Setenv("SAASAPI_OUTBOX_MAX_ATTEMPTS", "7")
	cfg, err := saasapi.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	newRouter(cfg)
	got := saasapi.CurrentOutboxSweeperSettings()
	if got.LeaseTTL != 45*time.Second || got.MaxAttempts != 7 || !got.Enabled {
		t.Fatalf("settings in use = %+v", got)
	}
}

const (
	testOperatorToken = "operator-token-0123456789abcdefghijklmnop"
	testOtherToken    = "other-token-0123456789abcdefghijklmnopqrst"
)

// operatorEnv sets the SAASAPI_OPERATOR_* settings the farmer chart sets
// with saasapi.operator.enabled, listening
// on addr with a fresh self-signed certificate, and returns the
// certificate so a client can trust it.
func operatorEnv(t *testing.T, addr string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "saasapi-operator"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Setenv("SAASAPI_OPERATOR_LISTEN_ADDR", addr)
	t.Setenv("SAASAPI_OPERATOR_TLS_CERT_FILE", write("tls.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	t.Setenv("SAASAPI_OPERATOR_TLS_KEY_FILE", write("tls.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	t.Setenv("SAASAPI_OPERATOR_TOKEN_FILE", write("operator-token", []byte(testOperatorToken+"\n")))
	return cert
}

// freeAddr returns a loopback address with a port nothing is listening on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestNewOperatorServer: with SAASAPI_OPERATOR_LISTEN_ADDR unset there is
// no operator server and no error; with it set, LoadConfig →
// newOperatorServer builds the HTTPS server on that address, and a
// setting it can't use is an error (fatal in main).
func TestNewOperatorServer(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		t.Setenv("SAASAPI_OPERATOR_LISTEN_ADDR", "")
		cfg, err := saasapi.LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		srv, err := newOperatorServer(cfg)
		if srv != nil || err != nil {
			t.Fatalf("newOperatorServer = %v, %v; want nil, nil", srv, err)
		}
	})
	t.Run("on", func(t *testing.T) {
		operatorEnv(t, ":8443")
		cfg, err := saasapi.LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		srv, err := newOperatorServer(cfg)
		if err != nil {
			t.Fatalf("newOperatorServer: %v", err)
		}
		if srv == nil || srv.Addr != ":8443" || srv.TLSConfig == nil || len(srv.TLSConfig.Certificates) != 1 {
			t.Fatalf("server = %+v", srv)
		}
	})
	t.Run("unreadable certificate", func(t *testing.T) {
		operatorEnv(t, ":8443")
		t.Setenv("SAASAPI_OPERATOR_TLS_CERT_FILE", filepath.Join(t.TempDir(), "missing.crt"))
		cfg, err := saasapi.LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		if srv, err := newOperatorServer(cfg); err == nil {
			t.Fatalf("newOperatorServer = %+v, nil; want an error", srv)
		}
	})
}

// newTenantServer is a stand-in for main's tenant API server on addr.
func newTenantServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("pong")) })
	return &http.Server{Addr: addr, Handler: mux}
}

// waitListening polls until something accepts connections on addr.
func waitListening(t *testing.T, addr string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
	}
	t.Fatalf("nothing listening on %s", addr)
}

// refusesConnections reports whether nothing accepts connections on addr.
func refusesConnections(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return true
	}
	c.Close()
	return false
}

// TestServeOperatorPlane: serve runs the tenant API and the operator
// plane side by side, the operator plane over TLS with its own routes and
// credential and none of the tenant API's, and a shutdown signal stops
// both.
func TestServeOperatorPlane(t *testing.T) {
	tenantAddr, opAddr := freeAddr(t), freeAddr(t)
	cert := operatorEnv(t, opAddr)
	cfg, err := saasapi.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	opSrv, err := newOperatorServer(cfg)
	if err != nil {
		t.Fatalf("newOperatorServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, newTenantServer(tenantAddr), opSrv, 5*time.Second) }()
	waitListening(t, tenantAddr)
	waitListening(t, opAddr)

	resp, err := http.Get("http://" + tenantAddr + "/ping")
	if err != nil {
		t.Fatalf("tenant API: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tenant API GET /ping = %d", resp.StatusCode)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}
	for _, tc := range []struct {
		method, path, token string
		want                int
	}{
		// The operator routes are served, and only for the operator token
		// (a wrong one is refused before the handler touches the database).
		{"POST", "/v1/operator/fleet-releases", "", http.StatusUnauthorized},
		{"POST", "/v1/operator/fleet-releases", testOtherToken, http.StatusUnauthorized},
		{"POST", "/v1/operator/fleet-releases/v2.4.1/revoke", "", http.StatusUnauthorized},
		// The tenant API's routes aren't.
		{"GET", "/v1/versions", "", http.StatusNotFound},
		{"GET", "/ping", "", http.StatusNotFound},
	} {
		req, err := http.NewRequest(tc.method, "https://"+opAddr+tc.path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("operator plane %s %s: %v", tc.method, tc.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("operator plane %s %s = %d, want %d", tc.method, tc.path, resp.StatusCode, tc.want)
		}
	}

	// TLS only: a plain-HTTP request to the operator listener gets
	// net/http's 400 for an HTTP request to an HTTPS server, never a route.
	if resp, err := http.Post("http://"+opAddr+"/v1/operator/fleet-releases", "application/json", strings.NewReader("{}")); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("plain HTTP to the operator plane = %d, want 400", resp.StatusCode)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after a shutdown signal = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve didn't return after a shutdown signal")
	}
	for _, addr := range []string{tenantAddr, opAddr} {
		if !refusesConnections(addr) {
			t.Errorf("%s still accepting connections after shutdown", addr)
		}
	}
}

// TestServeFailureStopsBoth: when either server fails — here, its address
// is taken — serve shuts the other one down too and returns the failure,
// which main makes fatal, without waiting for a shutdown signal.
func TestServeFailureStopsBoth(t *testing.T) {
	for _, failing := range []string{"tenant", "operator"} {
		t.Run(failing, func(t *testing.T) {
			taken, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer taken.Close()
			tenantAddr, opAddr := freeAddr(t), freeAddr(t)
			healthy := tenantAddr
			if failing == "tenant" {
				tenantAddr, healthy = taken.Addr().String(), opAddr
			} else {
				opAddr = taken.Addr().String()
			}
			operatorEnv(t, opAddr)
			cfg, err := saasapi.LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			opSrv, err := newOperatorServer(cfg)
			if err != nil {
				t.Fatalf("newOperatorServer: %v", err)
			}

			done := make(chan error, 1)
			go func() { done <- serve(context.Background(), newTenantServer(tenantAddr), opSrv, 5*time.Second) }()
			select {
			case err := <-done:
				var opErr *net.OpError
				if err == nil || !errors.As(err, &opErr) {
					t.Fatalf("serve = %v, want the listen error", err)
				}
				if failing == "operator" && !strings.Contains(err.Error(), "operator plane") {
					t.Errorf("serve = %v, want it to name the operator plane", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("serve didn't return after a server failed")
			}
			if !refusesConnections(healthy) {
				t.Errorf("the healthy server on %s is still accepting connections", healthy)
			}
		})
	}
}

// TestServeWaitsForLateServer: serve returns only after every server's
// ListenAndServe has returned, even one that starts after the shutdown
// (a goroutine the scheduler ran late, as in a busy CI). The healthy
// server's start is held back until the failing one has made serve shut
// both down; without the wait, serve returned while it was still to bind
// its port and the port stayed open after serve returned.
func TestServeWaitsForLateServer(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	healthyAddr := freeAddr(t)
	healthy := newTenantServer(healthyAddr)
	operatorEnv(t, taken.Addr().String())
	cfg, err := saasapi.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	opSrv, err := newOperatorServer(cfg)
	if err != nil {
		t.Fatalf("newOperatorServer: %v", err)
	}

	var healthyExited atomic.Bool
	orig := runServer
	t.Cleanup(func() { runServer = orig })
	runServer = func(s *http.Server, run func() error) error {
		if s != healthy {
			return run()
		}
		time.Sleep(200 * time.Millisecond)
		err := run()
		healthyExited.Store(true)
		return err
	}

	done := make(chan error, 1)
	go func() { done <- serve(context.Background(), healthy, opSrv, 5*time.Second) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "operator plane") {
			t.Fatalf("serve = %v, want the operator plane's listen error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve didn't return after a server failed")
	}
	if !healthyExited.Load() {
		t.Error("serve returned before the late server's ListenAndServe did")
	}
	if !refusesConnections(healthyAddr) {
		t.Errorf("the late server on %s is still accepting connections", healthyAddr)
	}
}

// TestServeWithoutOperatorPlane: with the operator plane off (nil), serve
// runs the tenant API alone and stops it on a shutdown signal.
func TestServeWithoutOperatorPlane(t *testing.T) {
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, newTenantServer(addr), nil, 5*time.Second) }()
	waitListening(t, addr)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve didn't return after a shutdown signal")
	}
	if !refusesConnections(addr) {
		t.Errorf("%s still accepting connections after shutdown", addr)
	}
}
