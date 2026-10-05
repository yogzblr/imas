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

// testPlatformPrefix is the platform recipe prefix farmer reads by
// default (cook.PlatformRecipePrefix of its default recipedir).
const testPlatformPrefix = "/srv/imas/recipes/prod/"

// denyAll is a job bucket the recipe credential has no grant on.
func denyAll(string, string) bool { return true }

func TestRecipeCredentialProbes(t *testing.T) {
	if p, err := cook.PlatformRecipePrefix(defaultPlatformRecipeDir); err != nil || p != testPlatformPrefix {
		t.Fatalf("default platform prefix %q, %v", p, err)
	}
	ps := recipeCredentialProbes("n1", testPlatformPrefix)
	var put, get, list, del, platformPut, platformDel int
	for _, p := range ps {
		underPlatform := strings.HasPrefix(p.Key, testPlatformPrefix+recipeCredentialCheckPrefix+"/")
		switch p.Op {
		case objectstore.ProbePut:
			put++
			if underPlatform {
				platformPut++
			}
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
		case objectstore.ProbeDelete:
			del++
			if underPlatform {
				platformDel++
			}
		}
		// Every probe must be one the recipe policy denies: none may land
		// in tenants/.
		if strings.HasPrefix(p.Key, "tenants/") || !saasapiRecipePolicy(strings.ToUpper(string(p.Op)), p.Key) {
			t.Errorf("probe %s is inside the recipe policy", p)
		}
	}
	if put != 3 || get != 1 || list != 1 || del != 1 || platformPut != 1 || platformDel != 1 {
		t.Errorf("probes %v", ps)
	}
	if ps[0].Key == recipeCredentialProbes("n2", testPlatformPrefix)[0].Key {
		t.Error("probe keys don't depend on the nonce")
	}
}

// FIX.5: every kind of access to the job bucket is probed.
func TestJobBucketCredentialProbes(t *testing.T) {
	ps := jobBucketCredentialProbes("n1")
	ops := map[objectstore.ProbeOp]int{}
	for _, p := range ps {
		ops[p.Op]++
		if p.Op != objectstore.ProbeList && !strings.HasPrefix(p.Key, "jobs/"+recipeCredentialCheckPrefix+"/") {
			t.Errorf("probe %s is not at a fresh key under jobs/", p)
		}
	}
	if ops[objectstore.ProbePut] != 1 || ops[objectstore.ProbeGet] != 1 || ops[objectstore.ProbeDelete] != 1 || ops[objectstore.ProbeList] != 2 {
		t.Errorf("probes %v", ps)
	}
	var lists []string
	for _, p := range ps {
		if p.Op == objectstore.ProbeList {
			lists = append(lists, p.Key)
		}
	}
	if strings.Join(lists, ",") != "jobs/," {
		t.Errorf("list probes %q, want jobs/ and the bucket root", lists)
	}
	if ps[0].Key == jobBucketCredentialProbes("n2")[0].Key {
		t.Error("probe keys don't depend on the nonce")
	}
}

// testScope is a credential check scope over two fake stores: the recipe
// bucket under recipeDeny and the job bucket under jobDeny.
func testScope(t *testing.T, recipeDeny, jobDeny func(op, key string) bool) (recipeCredentialScope, *objectstoretest.Server, *objectstoretest.Server) {
	t.Helper()
	open := func(deny func(op, key string) bool) (*objectstore.Store, *objectstoretest.Server) {
		srv := objectstoretest.NewServer(t)
		srv.Deny(deny)
		store, err := objectstore.Open(srv.Config())
		if err != nil {
			t.Fatal(err)
		}
		return store, srv
	}
	recipes, rs := open(recipeDeny)
	jobs, js := open(jobDeny)
	return recipeCredentialScope{recipes: recipes, recipeBucket: "test-bucket", platformPrefix: testPlatformPrefix,
		jobs: jobs, jobBucket: "test-jobs"}, rs, js
}

func TestCheckRecipeCredentialScope(t *testing.T) {
	fastCredentialCheck(t)
	ctx := context.Background()
	underPlatform := func(key string) bool { return strings.HasPrefix(key, testPlatformPrefix) }
	// allowJobs denies everything in the job bucket except op (and, for
	// LIST, only on prefix).
	allowJobs := func(op, prefix string) func(string, string) bool {
		return func(o, k string) bool { return !(o == op && (op != "LIST" || k == prefix)) }
	}
	for _, tc := range []struct {
		name       string
		deny, jobs func(op, key string) bool
		want       string // "" passes
		// leftover: the store allows the put probe but not deleting its
		// object again, so the refusal must name what was left behind.
		leftover bool
	}{
		{"recipe policy", saasapiRecipePolicy, denyAll, "", false},
		{"no policy (farmer's or an admin key)", nil, nil, "reaches beyond tenants/*/recipes/*", false},
		{"writes limited, reads open", func(op, key string) bool { return op == "PUT" && saasapiRecipePolicy(op, key) }, denyAll, "get sprouts/", false},
		{"sprouts readable but not listable", func(op, key string) bool { return op == "LIST" || saasapiRecipePolicy(op, key) && op != "GET" }, denyAll, "get sprouts/", false},
		{"sprouts listable", func(op, key string) bool { return op != "LIST" && saasapiRecipePolicy(op, key) }, denyAll, "list sprouts/", false},
		{"root writable", func(op, key string) bool {
			return !strings.HasPrefix(key, recipeCredentialCheckPrefix) && saasapiRecipePolicy(op, key)
		}, denyAll, "put " + recipeCredentialCheckPrefix, false},
		{"sprouts writable", func(op, key string) bool {
			return !((op == "PUT" || op == "DELETE") && strings.HasPrefix(key, "sprouts/")) && saasapiRecipePolicy(op, key)
		}, denyAll, "put sprouts/", false},
		// FIX.5: the platform recipe prefix.
		{"platform prefix writable", func(op, key string) bool {
			return !((op == "PUT" || op == "DELETE") && underPlatform(key)) && saasapiRecipePolicy(op, key)
		}, denyAll, "put " + testPlatformPrefix, false},
		{"platform prefix writable, not deletable", func(op, key string) bool {
			return !(op == "PUT" && underPlatform(key)) && saasapiRecipePolicy(op, key)
		}, denyAll, "put " + testPlatformPrefix, true},
		{"platform prefix deletable", func(op, key string) bool {
			return !(op == "DELETE" && underPlatform(key)) && saasapiRecipePolicy(op, key)
		}, denyAll, "delete " + testPlatformPrefix, false},
		// FIX.5: the job bucket, where every access must be refused.
		{"job bucket open", saasapiRecipePolicy, nil, "in job bucket test-jobs", false},
		{"job bucket writable", saasapiRecipePolicy, allowJobs("PUT", ""), "put jobs/", true},
		{"job bucket writable and deletable", saasapiRecipePolicy, func(op, key string) bool { return op != "PUT" && op != "DELETE" }, "put jobs/", false},
		{"job bucket readable", saasapiRecipePolicy, allowJobs("GET", ""), "get jobs/", false},
		{"job bucket deletable", saasapiRecipePolicy, allowJobs("DELETE", ""), "delete jobs/", false},
		{"jobs/ listable", saasapiRecipePolicy, allowJobs("LIST", "jobs/"), "list jobs/", false},
		{"job bucket root listable", saasapiRecipePolicy, allowJobs("LIST", ""), "list (bucket root)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, rs, js := testScope(t, tc.deny, tc.jobs)
			err := checkRecipeCredentialScope(ctx, sc)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused a correctly limited credential: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "refusing to start") ||
				!errors.Is(err, objectstore.ErrAccessAllowed) || !strings.Contains(err.Error(), "objectstore-policies/saasapi-recipes.json") {
				t.Fatalf("got %v, want a refusal naming %q", err, tc.want)
			}
			// Whatever a wrongly allowed probe created is gone again, in
			// both buckets, or the refusal says what is left.
			for _, k := range append(rs.Keys(), js.Keys()...) {
				if !tc.leftover {
					t.Errorf("probe object left behind: %s", k)
				} else if !strings.Contains(err.Error(), "probe objects left behind") || !strings.Contains(err.Error(), k) {
					t.Errorf("probe object %s left behind and not named in %v", k, err)
				}
			}
		})
	}
}

// A delete probe never removes an object a probe didn't write: one already
// at a key the store lets the credential delete is still there.
func TestCheckRecipeCredentialScopeDeleteProbeRemovesNothing(t *testing.T) {
	fastCredentialCheck(t)
	sc, rs, js := testScope(t, nil, nil)
	ctx := context.Background()
	for _, s := range []*objectstore.Store{sc.recipes, sc.jobs} {
		if err := s.Put(ctx, testPlatformPrefix+"base.imas", []byte("platform")); err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, "jobs/t_1/web-01/j1/meta.json", []byte("job")); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkRecipeCredentialScope(ctx, sc); !errors.Is(err, objectstore.ErrAccessAllowed) {
		t.Fatalf("got %v", err)
	}
	for _, srv := range []*objectstoretest.Server{rs, js} {
		if keys := srv.Keys(); strings.Join(keys, ",") != testPlatformPrefix+"base.imas,jobs/t_1/web-01/j1/meta.json" {
			t.Errorf("keys after the check: %v", keys)
		}
	}
}

// Fail closed: a store that can't be reached, or that rejects the
// credential outright, is not a store that denies; neither is a check
// that wasn't told where to look.
func TestCheckRecipeCredentialScopeInconclusive(t *testing.T) {
	fastCredentialCheck(t)
	sc, rs, _ := testScope(t, saasapiRecipePolicy, denyAll)
	rs.FailNext(1, 403, "InvalidAccessKeyId")
	err := checkRecipeCredentialScope(context.Background(), sc)
	if !errors.Is(err, objectstore.ErrProbeInconclusive) || !strings.Contains(err.Error(), "could not verify") {
		t.Fatalf("rejected credential: got %v", err)
	}

	// FIX.5: the job bucket doesn't answer.
	sc, _, js := testScope(t, saasapiRecipePolicy, denyAll)
	js.FailNext(1, 403, "InvalidAccessKeyId")
	err = checkRecipeCredentialScope(context.Background(), sc)
	if !errors.Is(err, objectstore.ErrProbeInconclusive) || !strings.Contains(err.Error(), "in job bucket test-jobs") {
		t.Fatalf("job bucket rejected the credential: got %v", err)
	}

	dead := httptest.NewServer(nil)
	cfg := rs.Config()
	cfg.Endpoint = strings.TrimPrefix(dead.URL, "http://")
	dead.Close()
	deadStore, err := objectstore.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*recipeCredentialScope){
		"recipe store unreachable": func(sc *recipeCredentialScope) { sc.recipes = deadStore },
		"job store unreachable":    func(sc *recipeCredentialScope) { sc.jobs = deadStore },
	} {
		sc, _, _ := testScope(t, saasapiRecipePolicy, denyAll)
		mutate(&sc)
		if err := checkRecipeCredentialScope(context.Background(), sc); !errors.Is(err, objectstore.ErrProbeInconclusive) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	for name, mutate := range map[string]func(*recipeCredentialScope){
		"no recipe store":    func(sc *recipeCredentialScope) { sc.recipes = nil },
		"no platform prefix": func(sc *recipeCredentialScope) { sc.platformPrefix = "" },
		"no job store":       func(sc *recipeCredentialScope) { sc.jobs, sc.jobBucket = nil, "" },
	} {
		sc, _, _ := testScope(t, saasapiRecipePolicy, denyAll)
		mutate(&sc)
		if err := checkRecipeCredentialScope(context.Background(), sc); err == nil || !strings.Contains(err.Error(), "refusing to start") {
			t.Fatalf("%s: got %v", name, err)
		}
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
	// The fake serves every bucket from one key space, and the recipe
	// policy denies everything under jobs/ and a bucket-wide listing, so
	// it stands in for a job bucket the credential has no grant on.
	s.JobBucket = "test-jobs"

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

// FIX.5 follow-up (owner decision): without the job bucket the check
// refuses to start, even for a credential the recipe bucket refuses
// everywhere it should, and makes no probe at all.
func TestCheckRecipeCredentialScopeWithoutJobBucket(t *testing.T) {
	fastCredentialCheck(t)
	sc, rs, _ := testScope(t, saasapiRecipePolicy, nil)
	sc.jobs, sc.jobBucket = nil, ""
	if err := checkRecipeCredentialScope(context.Background(), sc); err == nil ||
		!strings.Contains(err.Error(), "refusing to start") || !strings.Contains(err.Error(), "SAASAPI_RECIPES_JOB_BUCKET") {
		t.Fatalf("limited credential, no job bucket: got %v", err)
	}
	if keys := rs.Keys(); len(keys) != 0 {
		t.Fatalf("probe objects written without a job bucket: %v", keys)
	}
}

// recipeCredentialCheckScope refuses an unset job bucket too, behind
// validate, and opens the job bucket when one is set.
func TestRecipeCredentialCheckScopeJobBucket(t *testing.T) {
	s := DefaultRecipeSettings()
	s.Endpoint, s.Bucket, s.AccessKeyID, s.UseSSL = "minio:9000", "recipes", "saasapi", false
	if _, err := recipeCredentialCheckScope(s, nil, "secret"); err == nil || !strings.Contains(err.Error(), "SAASAPI_RECIPES_JOB_BUCKET") {
		t.Fatalf("no job bucket: got %v", err)
	}
	s.JobBucket = "jobs"
	sc, err := recipeCredentialCheckScope(s, nil, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if sc.jobs == nil || sc.jobBucket != "jobs" || sc.platformPrefix == "" {
		t.Fatalf("scope %+v", sc)
	}
}
