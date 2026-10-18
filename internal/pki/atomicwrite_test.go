package pki

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// ensureNatsAuth re-mints the legacy tenant's Account JWT, without any
// revocations, when tenant.jwt doesn't decode. With a plain os.WriteFile
// a read landing mid-write saw a truncated file and did exactly that. This
// re-signs tenant.jwt through syncNatsAuth over and over (toggling an
// unrelated sprout) while other goroutines call ensureNatsAuth, and checks
// that the denied sprout's revocation is never lost.
func TestTenantJWTRewriteNeverDropsRevocations(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)

	mkSprout := func(id, state string) string {
		kp, _ := nkeys.CreateUser()
		pub, _ := kp.PublicKey()
		if err := upsertNKeyRow(nkeyRow{TenantID: currentTenantID(), SproutID: id, NKey: pub, State: state}); err != nil {
			t.Fatal(err)
		}
		return pub
	}
	deniedPub := mkSprout("web-denied", stateDenied)
	mkSprout("web-toggle", stateAccepted)
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syncNatsAuth(mat); err != nil {
		t.Fatal(err)
	}

	revoked := func(j string) bool {
		ac, err := jwt.DecodeAccountClaims(j)
		return err == nil && ac.Revocations[deniedPub] > 0
	}
	if !revoked(mat.tenantJWT) {
		t.Fatal("precondition: the denied sprout isn't revoked")
	}

	deadline := time.Now().Add(2 * time.Second)
	var lost atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // writer
		defer wg.Done()
		states := []string{stateDenied, stateAccepted}
		for i := 0; time.Now().Before(deadline); i++ {
			if err := setStateInTenant(currentTenantID(), "web-toggle", states[i%2]); err != nil {
				t.Error(err)
				return
			}
			m, err := ensureNatsAuth()
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := syncNatsAuth(m); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() { // readers
			defer wg.Done()
			for time.Now().Before(deadline) {
				m, err := ensureNatsAuth()
				if err != nil {
					t.Error(err)
					return
				}
				if !revoked(m.tenantJWT) {
					lost.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := lost.Load(); n > 0 {
		t.Fatalf("ensureNatsAuth returned a legacy tenant JWT without the denied sprout's revocation %d times (re-minted from a partly written tenant.jwt)", n)
	}
}

// The per-tenant counterpart: ensureTenantAccountMaterial re-mints a
// tenant's Account JWT when account.jwt doesn't decode, and
// syncTenantSprouts rewrites that file outside tenantAuthMu.
func TestTenantAccountJWTRewriteNeverDropsRevocations(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	const tenantID = "t_rewrite"
	_ = ProvisionTenant(tenantID, "Rewrite Co") // the push fails: no bus

	mkSprout := func(id, state string) string {
		kp, _ := nkeys.CreateUser()
		pub, _ := kp.PublicKey()
		if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: id, NKey: pub, State: state}); err != nil {
			t.Fatal(err)
		}
		return pub
	}
	deniedPub := mkSprout("web-denied", stateDenied)
	mkSprout("web-toggle", stateAccepted)
	resync := func() error {
		mat, err := ensureNatsAuth()
		if err != nil {
			return err
		}
		tam, err := loadTenantAccountMaterial(tenantID)
		if err != nil {
			return err
		}
		_, err = syncTenantSprouts(mat, tam, tenantID)
		return err
	}
	if err := resync(); err != nil {
		t.Fatal(err)
	}
	revoked := func(j string) bool {
		ac, err := jwt.DecodeAccountClaims(j)
		return err == nil && ac.Revocations[deniedPub] > 0
	}
	if tam, err := loadTenantAccountMaterial(tenantID); err != nil || !revoked(tam.jwt) {
		t.Fatalf("precondition: the denied sprout isn't revoked (%v)", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	var lost atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		states := []string{stateDenied, stateAccepted}
		for i := 0; time.Now().Before(deadline); i++ {
			if err := setStateInTenant(tenantID, "web-toggle", states[i%2]); err != nil {
				t.Error(err)
				return
			}
			if err := resync(); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				tam, err := loadTenantAccountMaterial(tenantID)
				if err != nil {
					t.Error(err)
					return
				}
				if !revoked(tam.jwt) {
					lost.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := lost.Load(); n > 0 {
		t.Fatalf("tenant %q's Account JWT came back without the denied sprout's revocation %d times (re-minted from a partly written account.jwt)", tenantID, n)
	}
}

// Security review 2026-10, I12: writeFileAtomic and writeFileOnce fsync
// the directory after the rename or link, so the new entry is durable.
func TestAtomicWritesSyncTheDirectory(t *testing.T) {
	dir := t.TempDir()
	var synced []string
	orig := syncDir
	syncDir = func(d string) error {
		synced = append(synced, d)
		return orig(d)
	}
	t.Cleanup(func() { syncDir = orig })

	path := filepath.Join(dir, "user.jwt")
	for _, write := range []func(string, []byte, os.FileMode) error{writeFileAtomic, writeFileOnce} {
		synced = nil
		_ = os.Remove(path)
		if err := write(path, []byte("jwt"), 0o600); err != nil {
			t.Fatal(err)
		}
		if len(synced) != 1 || synced[0] != dir {
			t.Errorf("directory syncs %v, want one of %s", synced, dir)
		}
		if b, err := os.ReadFile(path); err != nil || string(b) != "jwt" {
			t.Errorf("written file: %q, %v", b, err)
		}
	}
	// A credential directory that does not exist yet: each new
	// directory's entry is synced in its parent, then the file's.
	synced = nil
	nested := filepath.Join(dir, "a", "b", "user.jwt")
	if err := writeFileAtomic(nested, []byte("jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []string{dir, filepath.Join(dir, "a"), filepath.Join(dir, "a", "b")}
	slices.Sort(synced)
	if !slices.Equal(synced, want) {
		t.Errorf("directory syncs %v, want %v", synced, want)
	}
	if runtime.GOOS != "windows" {
		if err := orig(filepath.Join(dir, "missing")); err == nil {
			t.Error("syncing a directory that does not exist succeeded")
		}
	}
}
