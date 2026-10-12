package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nats_server "github.com/nats-io/nats-server/v2/server"

	"github.com/yogzblr/imas/internal/config"
)

// The in-process test bus's resolver (ConfigureNats) has a directory of
// its own per call, in the temp dir and not under FarmerPKI, removed when
// the server shuts down: nothing reads it again.
func TestConfigureNatsResolverDirPerCallRemovedOnShutdown(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)

	dirs := map[string]bool{}
	for range 2 {
		config.FarmerBusPort = "-1"
		opts := ConfigureNats()
		r, ok := opts.AccountResolver.(*tempDirResolver)
		if !ok {
			t.Fatalf("resolver %T, want the per-call temp dir resolver", opts.AccountResolver)
		}
		if dirs[r.dir] {
			t.Fatalf("two calls share the resolver directory %s", r.dir)
		}
		dirs[r.dir] = true
		if pki, _ := filepath.Abs(config.FarmerPKI); strings.HasPrefix(r.dir, pki+string(filepath.Separator)) {
			t.Fatalf("resolver directory %s is under FarmerPKI %s", r.dir, pki)
		}
		if !strings.HasPrefix(r.dir, filepath.Clean(os.TempDir())+string(filepath.Separator)) {
			t.Fatalf("resolver directory %s is not in the temp dir %s", r.dir, os.TempDir())
		}
		if _, err := r.Fetch(mustSysAccountPub(t)); err != nil {
			t.Fatalf("SYS Account not seeded: %v", err)
		}

		opts.LogFile, opts.NoLog = "", true
		srv, err := nats_server.NewServer(&opts)
		if err != nil {
			t.Fatal(err)
		}
		srv.SetLogger(testNoopLogger{}, false, false)
		go srv.Start()
		if !srv.ReadyForConnections(10 * time.Second) {
			t.Fatal("test bus did not start")
		}
		if _, err := os.Stat(r.dir); err != nil {
			t.Fatalf("resolver directory gone while the bus runs: %v", err)
		}
		srv.Shutdown()
		if _, err := os.Stat(r.dir); !os.IsNotExist(err) {
			t.Fatalf("resolver directory %s left after shutdown: %v", r.dir, err)
		}
	}
}

func mustSysAccountPub(t *testing.T) string {
	t.Helper()
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatal(err)
	}
	return mat.sysAccountPub
}
