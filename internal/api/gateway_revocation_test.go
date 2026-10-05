package api

// SEC.7c (security review 2026-10-b, B3): a gateway JWT is refused once
// its sub, the sprout's NKey, is revoked or no longer the NKey accepted
// for its (tenant_id, sprout_id). FLAG FOR SECURITY REVIEW.

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nats-io/nkeys"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/gatewayjwt"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/pki"
)

const (
	stagedRecipeFile    = "sprouts/t_acme/web-01/recipe.json"
	stagedRecipeContent = `{"job_id":"the new host's recipe, secrets included"}`
	otherTenantRecipe   = "sprouts/t_other/web-01/recipe.json"
)

// useRealGatewaySubjectCheck puts pki.VerifyGatewaySubject back as the
// revocation check (installGatewayKey stubs it), over a fresh in-memory
// pki database in which t_acme and t_other are provisioned tenants. It
// returns the database. Call it after installGatewayKey.
func useRealGatewaySubjectCheck(t *testing.T) *gorm.DB {
	t.Helper()
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	gdb, err := gorm.Open(sqlite.Open("file:"+name+"_pki?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatal(err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(nil) })
	for _, id := range []string{"t_acme", "t_other"} {
		exec(t, gdb, `INSERT INTO pki_tenants (id, name, deleted, created_at) VALUES (?, ?, ?, ?)`, id, id, false, time.Now().Unix())
	}

	// Accept and Delete reload the tenant's NATS Account afterwards; that
	// reload fails here (no operator material) and is only logged. Keep
	// whatever it writes out of the source tree.
	origPKI := config.FarmerPKI
	config.FarmerPKI = t.TempDir() + "/"
	t.Cleanup(func() { config.FarmerPKI = origPKI })

	orig := gatewaySubjectCheck
	gatewaySubjectCheck = pki.VerifyGatewaySubject
	t.Cleanup(func() { gatewaySubjectCheck = orig })
	return gdb
}

// acceptSprout enrols sproutID in tenant under a fresh NKey through the
// real pki Unaccept/Accept path, and returns the NKey.
func acceptSprout(t *testing.T, tenant, sproutID string) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	nkey, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.UnacceptNKey(tenant, sproutID, nkey); err != nil {
		t.Fatalf("UnacceptNKey(%s/%s): %v", tenant, sproutID, err)
	}
	if err := pki.AcceptNKey(tenant, sproutID); err != nil {
		t.Fatalf("AcceptNKey(%s/%s): %v", tenant, sproutID, err)
	}
	return nkey
}

// mintAs signs a gateway JWT for (tenantID, sproutID) with sub nkey, in
// the shape gatewayjwt.MintGatewayJWT produces.
func mintAs(t *testing.T, priv ed25519.PrivateKey, nkey, tenantID, sproutID string) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Subject(nkey).
		Issuer(gatewayjwt.GatewayIssuer).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(24*time.Hour)).
		Claim("tenant_id", tenantID).
		Claim("sprout_id", sproutID).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, "1"); err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + string(signed)
}

// newRevocationTestServer serves NewRouter over a store holding t_acme's
// and t_other's web-01 staged recipes.
func newRevocationTestServer(t *testing.T) string {
	t.Helper()
	store := objectstoretest.NewStore(t)
	objectstoretest.Seed(t, store, map[string]string{
		stagedRecipeFile:  stagedRecipeContent,
		otherTenantRecipe: "t_other's web-01 recipe",
	})
	handlers.SetRecipeStore(store)
	t.Cleanup(func() { handlers.SetRecipeStore(nil) })
	srv := httptest.NewServer(NewRouter(""))
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestFilesRoute_ReacceptedSproutIDRefusesOldHostsGatewayJWT is the
// review's B3 throwaway test, kept: accept web-01, delete it, re-accept
// web-01 under a new NKey, then present a gateway JWT with the old
// host's NKey as sub and (t_acme, web-01) claims. Without the subject
// check (the pre-SEC.7c behaviour) that token reads the new host's
// staged recipe; with it, 403.
func TestFilesRoute_ReacceptedSproutIDRefusesOldHostsGatewayJWT(t *testing.T) {
	key := installGatewayKey(t)
	useRealGatewaySubjectCheck(t)
	base := newRevocationTestServer(t)

	oldNKey := acceptSprout(t, "t_acme", "web-01")
	oldToken := mintAs(t, key.priv, oldNKey, "t_acme", "web-01")
	if code, _ := get(t, base+"/files/"+stagedRecipeFile, oldToken); code != http.StatusOK {
		t.Fatalf("before delete, web-01's own token: got %d, want 200", code)
	}

	if err := pki.DeleteNKey("t_acme", "web-01"); err != nil {
		t.Fatal(err)
	}
	newNKey := acceptSprout(t, "t_acme", "web-01")
	newToken := mintAs(t, key.priv, newNKey, "t_acme", "web-01")

	t.Run("reproduced without the subject check", func(t *testing.T) {
		orig := gatewaySubjectCheck
		gatewaySubjectCheck = func(string, string, string) error { return nil }
		defer func() { gatewaySubjectCheck = orig }()
		code, body := get(t, base+"/files/"+stagedRecipeFile, oldToken)
		if code != http.StatusOK || body != stagedRecipeContent {
			t.Fatalf("pre-fix reproduction: got %d %q, want the old host reading the new host's recipe", code, body)
		}
	})

	if code, body := get(t, base+"/files/"+stagedRecipeFile, oldToken); code != http.StatusForbidden {
		t.Errorf("old host's gateway JWT after re-accept: got %d %q, want 403", code, body)
	}
	if code, body := get(t, base+"/files/"+stagedRecipeFile, newToken); code != http.StatusOK || body != stagedRecipeContent {
		t.Errorf("new host's gateway JWT: got %d %q, want 200", code, body)
	}
}

// AcceptNKey's replace path: web-01_1 takes web-01's ID, and the
// replaced host is cut off at once.
func TestFilesRoute_ReplacedHostsGatewayJWTRefused(t *testing.T) {
	key := installGatewayKey(t)
	useRealGatewaySubjectCheck(t)
	base := newRevocationTestServer(t)

	oldNKey := acceptSprout(t, "t_acme", "web-01")
	oldToken := mintAs(t, key.priv, oldNKey, "t_acme", "web-01")
	newNKey := acceptSprout(t, "t_acme", "web-01_1") // accepting web-01_1 replaces web-01
	newToken := mintAs(t, key.priv, newNKey, "t_acme", "web-01")

	if code, _ := get(t, base+"/files/"+stagedRecipeFile, oldToken); code != http.StatusForbidden {
		t.Errorf("replaced host: got %d, want 403", code)
	}
	if code, _ := get(t, base+"/files/"+stagedRecipeFile, newToken); code != http.StatusOK {
		t.Errorf("new host as web-01: got %d, want 200", code)
	}
}

func TestFilesRoute_DeletedSproutsGatewayJWTRefused(t *testing.T) {
	key := installGatewayKey(t)
	useRealGatewaySubjectCheck(t)
	base := newRevocationTestServer(t)

	nkey := acceptSprout(t, "t_acme", "web-01")
	token := mintAs(t, key.priv, nkey, "t_acme", "web-01")
	if code, _ := get(t, base+"/files/"+stagedRecipeFile, token); code != http.StatusOK {
		t.Fatalf("live sprout: got %d, want 200", code)
	}
	if err := pki.DeleteNKey("t_acme", "web-01"); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, base+"/files/"+stagedRecipeFile, token); code != http.StatusForbidden {
		t.Errorf("deleted sprout: got %d, want 403", code)
	}
}

// A gateway JWT whose sub is not on record for its (tenant_id,
// sprout_id) — a sprout that never existed, or one only pending
// acceptance — is refused like a revoked one.
func TestFilesRoute_UnknownOrUnacceptedNKeyRefused(t *testing.T) {
	key := installGatewayKey(t)
	useRealGatewaySubjectCheck(t)
	base := newRevocationTestServer(t)

	if code, _ := get(t, base+"/files/"+stagedRecipeFile, mintAs(t, key.priv, "UNOSUCHNKEY", "t_acme", "web-01")); code != http.StatusForbidden {
		t.Errorf("no such sprout: got %d, want 403", code)
	}
	kp, _ := nkeys.CreateUser()
	pending, _ := kp.PublicKey()
	if err := pki.UnacceptNKey("t_acme", "web-01", pending); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, base+"/files/"+stagedRecipeFile, mintAs(t, key.priv, pending, "t_acme", "web-01")); code != http.StatusForbidden {
		t.Errorf("unaccepted sprout: got %d, want 403", code)
	}
}

// A database error refuses: the check fails closed.
func TestFilesRoute_GatewayJWTRefusedOnDatabaseError(t *testing.T) {
	key := installGatewayKey(t)
	gdb := useRealGatewaySubjectCheck(t)
	base := newRevocationTestServer(t)

	nkey := acceptSprout(t, "t_acme", "web-01")
	token := mintAs(t, key.priv, nkey, "t_acme", "web-01")
	if code, _ := get(t, base+"/files/"+stagedRecipeFile, token); code != http.StatusOK {
		t.Fatalf("before the database fails: got %d, want 200", code)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.Close()
	if code, _ := get(t, base+"/files/"+stagedRecipeFile, token); code != http.StatusForbidden {
		t.Errorf("database error: got %d, want 403", code)
	}

	pki.SetDB(nil)
	if code, _ := get(t, base+"/files/"+stagedRecipeFile, token); code != http.StatusForbidden {
		t.Errorf("no database: got %d, want 403", code)
	}
}

// Cross-tenant stays refused with the subject check in place: t_other's
// live web-01 cannot pass as t_acme's web-01 (the lookup is keyed on the
// token's tenant_id), and its own token reads only its own subtree.
func TestFilesRoute_CrossTenantGatewayJWTStillRefused(t *testing.T) {
	key := installGatewayKey(t)
	useRealGatewaySubjectCheck(t)
	base := newRevocationTestServer(t)

	acmeNKey := acceptSprout(t, "t_acme", "web-01")
	otherNKey := acceptSprout(t, "t_other", "web-01")

	for name, c := range map[string]struct{ token, file string }{
		"t_other's NKey claiming t_acme":     {mintAs(t, key.priv, otherNKey, "t_acme", "web-01"), stagedRecipeFile},
		"t_acme's NKey claiming t_other":     {mintAs(t, key.priv, acmeNKey, "t_other", "web-01"), otherTenantRecipe},
		"t_other's own token, t_acme's file": {mintAs(t, key.priv, otherNKey, "t_other", "web-01"), stagedRecipeFile},
		"t_acme's own token, t_other's file": {mintAs(t, key.priv, acmeNKey, "t_acme", "web-01"), otherTenantRecipe},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _ := get(t, base+"/files/"+c.file, c.token); code != http.StatusForbidden {
				t.Errorf("got %d, want 403", code)
			}
		})
	}
	if code, _ := get(t, base+"/files/"+otherTenantRecipe, mintAs(t, key.priv, otherNKey, "t_other", "web-01")); code != http.StatusOK {
		t.Errorf("t_other's own file: got %d, want 200", code)
	}
}

// GET /v1/sprout/update-manifest (sproutIdentityAuth) applies the same
// check: a live sprout is served, a deleted or replaced host's token and
// a database error are 403.
func TestUpdateManifestRoute_RevokedOrSupersededGatewayJWTRefused(t *testing.T) {
	f := newManifestFixture(t)
	gdb := useRealGatewaySubjectCheck(t)

	liveNKey := acceptSprout(t, "t_acme", "web-01")
	live := mintAs(t, f.gw.priv, liveNKey, "t_acme", "web-01")
	if code, body := f.get(t, live, "linux", "amd64", "v2.4.1"); code != http.StatusOK {
		t.Fatalf("live sprout: got %d %s, want 200", code, body)
	}

	deletedNKey := acceptSprout(t, "t_acme", "db-01")
	deleted := mintAs(t, f.gw.priv, deletedNKey, "t_acme", "db-01")
	if err := pki.DeleteNKey("t_acme", "db-01"); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.get(t, deleted, "linux", "amd64", "v2.4.1"); code != http.StatusForbidden {
		t.Errorf("deleted sprout: got %d, want 403", code)
	}

	acceptSprout(t, "t_acme", "web-01_1") // replaces web-01
	if code, _ := f.get(t, live, "linux", "amd64", "v2.4.1"); code != http.StatusForbidden {
		t.Errorf("replaced host: got %d, want 403", code)
	}

	newNKey, err := pki.GetNKey("t_acme", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	replacement := mintAs(t, f.gw.priv, newNKey, "t_acme", "web-01")
	if code, body := f.get(t, replacement, "linux", "amd64", "v2.4.1"); code != http.StatusOK {
		t.Fatalf("replacement host: got %d %s, want 200", code, body)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.Close()
	if code, _ := f.get(t, replacement, "linux", "amd64", "v2.4.1"); code != http.StatusForbidden {
		t.Errorf("database error: got %d, want 403", code)
	}
}
