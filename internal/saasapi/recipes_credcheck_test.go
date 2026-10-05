package saasapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// saasapiRecipePolicy is files/objectstore-policies/saasapi-recipes.json
// in the fake: read, write and delete under tenants/*/recipes/, create
// under tenants/*/recipe-audit/, list only within tenants/*/recipes/, and
// nothing else.
func saasapiRecipePolicy(op, key string) bool {
	p := strings.SplitN(key, "/", 4)
	if len(p) < 3 || p[0] != "tenants" || p[1] == "" {
		return true
	}
	switch p[2] {
	case "recipes":
		return false
	case "recipe-audit":
		return op != "PUT"
	}
	return true
}

func fastCredentialCheck(t *testing.T) {
	t.Helper()
	prev := recipeCredentialCheckPolicy
	recipeCredentialCheckPolicy = objectstore.RetryPolicy{MaxAttempts: 2, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond, AttemptTimeout: 2 * time.Second}
	t.Cleanup(func() { recipeCredentialCheckPolicy = prev })
}

func TestRecipeCredentialProbes(t *testing.T) {
	ps := recipeCredentialProbes("n1")
	var put, get, list int
	for _, p := range ps {
		switch p.Op {
		case objectstore.ProbePut:
			put++
		case objectstore.ProbeGet:
			get++
			if !strings.HasPrefix(p.Key, "sprouts/") {
				t.Errorf("read probe %s is not under sprouts/", p)
			}
		case objectstore.ProbeList:
			list++
			if p.Key != "sprouts/" {
				t.Errorf("list probe %s", p)
			}
		}
		// Every probe must be one the recipe policy denies: none may land
		// in tenants/.
		if strings.HasPrefix(p.Key, "tenants/") || !saasapiRecipePolicy(strings.ToUpper(string(p.Op)), p.Key) {
			t.Errorf("probe %s is inside the recipe policy", p)
		}
	}
	if put != 2 || get != 1 || list != 1 {
		t.Errorf("probes %v", ps)
	}
	if ps[0].Key == recipeCredentialProbes("n2")[0].Key {
		t.Error("probe keys don't depend on the nonce")
	}
}

func TestCheckRecipeCredentialScope(t *testing.T) {
	fastCredentialCheck(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		deny func(op, key string) bool
		want string // "" passes
	}{
		{"recipe policy", saasapiRecipePolicy, ""},
		{"no policy (farmer's or an admin key)", nil, "reaches beyond tenants/*/recipes/*"},
		{"writes limited, reads open", func(op, key string) bool { return op == "PUT" && saasapiRecipePolicy(op, key) }, "get sprouts/"},
		{"sprouts readable but not listable", func(op, key string) bool { return op == "LIST" || saasapiRecipePolicy(op, key) && op != "GET" }, "get sprouts/"},
		{"sprouts listable", func(op, key string) bool { return op != "LIST" && saasapiRecipePolicy(op, key) }, "list sprouts/"},
		{"root writable", func(op, key string) bool {
			return !strings.HasPrefix(key, recipeCredentialCheckPrefix) && saasapiRecipePolicy(op, key)
		}, "put " + recipeCredentialCheckPrefix},
		{"sprouts writable", func(op, key string) bool {
			return !((op == "PUT" || op == "DELETE") && strings.HasPrefix(key, "sprouts/")) && saasapiRecipePolicy(op, key)
		}, "put sprouts/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := objectstoretest.NewServer(t)
			srv.Deny(tc.deny)
			store, err := objectstore.Open(srv.Config())
			if err != nil {
				t.Fatal(err)
			}
			err = checkRecipeCredentialScope(ctx, store, "test-bucket")
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused a correctly limited credential: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "refusing to start") ||
				!errors.Is(err, objectstore.ErrAccessAllowed) && !strings.Contains(err.Error(), "objectstore-policies/saasapi-recipes.json") {
				t.Fatalf("got %v, want a refusal naming %q", err, tc.want)
			}
			// Whatever a wrongly allowed probe created is gone again.
			for _, k := range srv.Keys() {
				t.Errorf("probe object left behind: %s", k)
			}
		})
	}
}

// Fail closed: a store that can't be reached, or that rejects the
// credential outright, is not a store that denies.
func TestCheckRecipeCredentialScopeInconclusive(t *testing.T) {
	fastCredentialCheck(t)
	srv := objectstoretest.NewServer(t)
	srv.Deny(saasapiRecipePolicy)
	srv.FailNext(1, 403, "InvalidAccessKeyId")
	store, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	err = checkRecipeCredentialScope(context.Background(), store, "test-bucket")
	if !errors.Is(err, objectstore.ErrProbeInconclusive) || !strings.Contains(err.Error(), "could not verify") {
		t.Fatalf("rejected credential: got %v", err)
	}

	dead := httptest.NewServer(nil)
	cfg := srv.Config()
	cfg.Endpoint = strings.TrimPrefix(dead.URL, "http://")
	dead.Close()
	store, err = objectstore.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkRecipeCredentialScope(context.Background(), store, "test-bucket"); !errors.Is(err, objectstore.ErrProbeInconclusive) {
		t.Fatalf("unreachable store: got %v", err)
	}
}

// Through ConfigureRecipes, the startup step: with the check on, a broad
// credential stops saasapi and leaves recipe upload off; a limited one is
// installed; with the check off nothing is probed.
func TestConfigureRecipesCredentialCheck(t *testing.T) {
	fastCredentialCheck(t)
	prevSvc, prevLimits := recipeSvc, cook.CurrentRenderLimits()
	t.Cleanup(func() { recipeSvc = prevSvc; _ = cook.SetRenderLimits(prevLimits) })

	srv := objectstoretest.NewServer(t)
	cfg := srv.Config()
	keyFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(keyFile, []byte(cfg.SecretAccessKey), 0o600); err != nil {
		t.Fatal(err)
	}
	s := DefaultRecipeSettings()
	s.Endpoint, s.Bucket, s.AccessKeyID, s.SecretAccessKeyFile, s.UseSSL = cfg.Endpoint, cfg.Bucket, cfg.AccessKeyID, keyFile, false
	s.CredentialCheck = true

	if err := ConfigureRecipes(DefaultRecipeSettings(), nil); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureRecipes(s, nil); err == nil || !strings.Contains(err.Error(), "reaches beyond tenants/*/recipes/*") {
		t.Fatalf("broad credential: got %v", err)
	}
	if recipeSvc.store != nil {
		t.Fatal("recipe store installed although the check failed")
	}
	if keys := srv.Keys(); len(keys) != 0 {
		t.Fatalf("probe objects left behind: %v", keys)
	}

	srv.Deny(saasapiRecipePolicy)
	if err := ConfigureRecipes(s, nil); err != nil {
		t.Fatalf("limited credential: %v", err)
	}
	if recipeSvc.store == nil {
		t.Fatal("recipe store not installed")
	}

	// Off: no probe is made, so even a broad credential is accepted.
	srv.Deny(nil)
	s.CredentialCheck = false
	if err := ConfigureRecipes(s, nil); err != nil {
		t.Fatalf("check off: %v", err)
	}
}
