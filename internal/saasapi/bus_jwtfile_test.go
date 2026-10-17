package saasapi

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/pki"
)

// With SAASAPI_NATS_USER_JWT_FILE, a refreshed JWT reaches the running
// connection without a restart (CodeRabbit on PR 277: the JWT now
// expires, and an env var read at startup would keep the old one until
// the bus closed the connection). The file is re-read at every
// reconnect and watched; a new valid JWT forces a reconnect with it, and
// an unusable file content changes nothing.
func TestConnectBus_ReloadsTheJWTFile(t *testing.T) {
	newE2EEnv(t)
	first, _, err := pki.EnsureSaaSAPICredential()
	if err != nil {
		t.Fatal(err)
	}
	jwtFile := filepath.Join(t.TempDir(), "SAASAPI_NATS_USER_JWT")
	write := func(s string) {
		t.Helper()
		// As the kubelet updates a mounted Secret: a new file renamed in.
		tmp := jwtFile + ".tmp"
		if err := os.WriteFile(tmp, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, jwtFile); err != nil {
			t.Fatal(err)
		}
	}
	write(first)
	t.Setenv("SAASAPI_NATS_USER_JWT", "")
	t.Setenv("SAASAPI_NATS_USER_JWT_FILE", jwtFile)
	old := busJWTWatchInterval
	busJWTWatchInterval = 20 * time.Millisecond
	t.Cleanup(func() { busJWTWatchInterval = old })

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NATSUserJWT != first {
		t.Fatal("LoadConfig did not read the JWT from SAASAPI_NATS_USER_JWT_FILE")
	}
	nc, err := ConnectBus(cfg)
	if err != nil {
		t.Fatalf("ConnectBus: %v", err)
	}
	defer nc.Close()

	write("not-a-jwt")
	time.Sleep(200 * time.Millisecond)
	if r := nc.Stats().Reconnects; r != 0 || !nc.IsConnected() {
		t.Fatalf("an unusable JWT file: %d reconnects, connected %v", r, nc.IsConnected())
	}

	// A refreshed JWT: another lifetime, so another exp and other bytes.
	t.Setenv(pki.EnvSaaSAPIUserJWTTTL, "23h")
	second, _, err := pki.EnsureSaaSAPICredential()
	if err != nil || second == first {
		t.Fatalf("minting a second JWT: %v (same as the first: %v)", err, second == first)
	}
	write(second)
	deadline := time.Now().Add(10 * time.Second)
	for nc.Stats().Reconnects == 0 || !nc.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("no reconnect with the refreshed JWT")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("the connection with the refreshed JWT: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if r := nc.Stats().Reconnects; r != 1 {
		t.Fatalf("%d reconnects for one refreshed JWT, want 1", r)
	}
}
