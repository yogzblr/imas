package objectstore_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// probe builds a Probe positionally: test object paths in keyed literals
// read as credentials to secret scanners.
func probe(op objectstore.ProbeOp, path string) objectstore.Probe {
	return objectstore.Probe{Op: op, Key: path}
}

// recipeOnly is the SaaS API's recipe policy in the fake: everything
// outside tenants/*/recipes/ is denied.
func recipeOnly(op, key string) bool {
	parts := strings.SplitN(key, "/", 4)
	return !(len(parts) >= 3 && parts[0] == "tenants" && parts[1] != "" && parts[2] == "recipes")
}

var probes = []objectstore.Probe{
	probe(objectstore.ProbePut, "probe/outside"),
	probe(objectstore.ProbePut, "sprouts/probe/outside"),
	probe(objectstore.ProbeGet, "sprouts/probe/missing"),
	probe(objectstore.ProbeList, "sprouts/"),
}

func quickPolicy() objectstore.RetryPolicy {
	return objectstore.RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, AttemptTimeout: 2 * time.Second}
}

func TestTryAccessClassifies(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	s := open(t, srv.Config())
	ctx := context.Background()
	if err := s.Put(ctx, "tenants/t1/recipes/existing", []byte("x")); err != nil {
		t.Fatal(err)
	}
	srv.Deny(recipeOnly)
	for _, tc := range []struct {
		p    objectstore.Probe
		want objectstore.Access
	}{
		{probe(objectstore.ProbePut, "outside"), objectstore.AccessDenied},
		{probe(objectstore.ProbeGet, "sprouts/x"), objectstore.AccessDenied},
		{probe(objectstore.ProbeList, "sprouts/"), objectstore.AccessDenied},
		{probe(objectstore.ProbePut, "tenants/t1/recipes/new"), objectstore.AccessAllowed},
		// An existing object: the precondition fails after authorization.
		{probe(objectstore.ProbePut, "tenants/t1/recipes/existing"), objectstore.AccessAllowed},
		// A missing key the store lets us look for.
		{probe(objectstore.ProbeGet, "tenants/t1/recipes/missing"), objectstore.AccessAllowed},
		{probe(objectstore.ProbeGet, "tenants/t1/recipes/existing"), objectstore.AccessAllowed},
		{probe(objectstore.ProbeList, "tenants/t1/recipes/"), objectstore.AccessAllowed},
		// FIX.5: delete probes, at fresh keys.
		{probe(objectstore.ProbeDelete, "platform/probe/missing"), objectstore.AccessDenied},
		{probe(objectstore.ProbeDelete, "tenants/t1/recipes/missing"), objectstore.AccessAllowed},
	} {
		got, err := s.TryAccess(ctx, tc.p)
		if got != tc.want || err != nil {
			t.Errorf("%s: %v, %v; want %v", tc.p, got, err, tc.want)
		}
	}
	if v, _ := srv.Object("tenants/t1/recipes/existing"); v != "x" {
		t.Errorf("a put probe replaced an existing object: %q", v)
	}
	if got, err := s.TryAccess(ctx, probe("copy", "k")); got != objectstore.AccessUnknown || err == nil {
		t.Errorf("unknown op: %v, %v", got, err)
	}
}

func TestExpectDeniedAllDenied(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	srv.Deny(recipeOnly)
	if err := open(t, srv.Config()).ExpectDenied(context.Background(), probes, quickPolicy()); err != nil {
		t.Fatalf("ExpectDenied: %v", err)
	}
	if keys := srv.Keys(); len(keys) != 0 {
		t.Errorf("probes left objects: %v", keys)
	}
}

func TestExpectDeniedReportsEveryAllowedProbe(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	// Writes are limited, reads are not: the read probes are allowed.
	srv.Deny(func(op, key string) bool { return op == "PUT" && recipeOnly(op, key) })
	err := open(t, srv.Config()).ExpectDenied(context.Background(), probes, quickPolicy())
	var ae *objectstore.AllowedError
	if !errors.As(err, &ae) || !errors.Is(err, objectstore.ErrAccessAllowed) {
		t.Fatalf("got %v, want an *AllowedError", err)
	}
	if len(ae.Allowed) != 2 || ae.Allowed[0] != probes[2] || ae.Allowed[1] != probes[3] {
		t.Errorf("allowed %v, want the get and list probes", ae.Allowed)
	}

	// No policy at all: every probe allowed, and the put probes' objects
	// are deleted again.
	srv.Deny(nil)
	err = open(t, srv.Config()).ExpectDenied(context.Background(), probes, quickPolicy())
	if !errors.As(err, &ae) || len(ae.Allowed) != 4 || len(ae.Leftovers) != 0 {
		t.Fatalf("got %v", err)
	}
	if keys := srv.Keys(); len(keys) != 0 {
		t.Errorf("probe objects left behind: %v", keys)
	}
	for _, want := range []string{"put probe/outside", "put sprouts/probe/outside", "get sprouts/probe/missing", "list sprouts/"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

// A put probe that finds its key taken still proves write access, but the
// object there is someone else's: it is left alone. One holding exactly
// what a probe writes (an earlier attempt whose answer was lost) is
// removed.
func TestExpectDeniedDeletesOnlyItsOwnObjects(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	s := open(t, srv.Config())
	ctx := context.Background()
	if err := s.Put(ctx, "probe/outside", []byte("someone else's")); err != nil {
		t.Fatal(err)
	}
	err := s.ExpectDenied(ctx, probes[:1], quickPolicy())
	var ae *objectstore.AllowedError
	if !errors.As(err, &ae) || len(ae.Allowed) != 1 || len(ae.Leftovers) != 0 {
		t.Fatalf("got %v", err)
	}
	if v, ok := srv.Object("probe/outside"); !ok || v != "someone else's" {
		t.Fatalf("an object the probe didn't write was changed or deleted: %q, %v", v, ok)
	}

	// Plant what the probe itself would have written.
	if err := s.Delete(ctx, "probe/outside"); err != nil {
		t.Fatal(err)
	}
	if err := s.ExpectDenied(ctx, probes[:1], quickPolicy()); !errors.As(err, &ae) {
		t.Fatal(err)
	}
	if len(srv.Keys()) != 0 {
		t.Fatalf("probe object left: %v", srv.Keys())
	}
	if a, err := s.TryAccess(ctx, probes[0]); a != objectstore.AccessAllowed || err != nil {
		t.Fatal(a, err)
	}
	probeData, _ := srv.Object("probe/outside")
	if err := s.ExpectDenied(ctx, probes[:1], quickPolicy()); !errors.As(err, &ae) || len(ae.Leftovers) != 0 {
		t.Fatalf("got %v", err)
	}
	if _, ok := srv.Object("probe/outside"); ok {
		t.Errorf("an earlier probe's object (%q) was not removed", probeData)
	}
}

func TestExpectDeniedReportsLeftovers(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	srv.Deny(func(op, key string) bool { return op == "DELETE" })
	err := open(t, srv.Config()).ExpectDenied(context.Background(), probes[:1], quickPolicy())
	var ae *objectstore.AllowedError
	if !errors.As(err, &ae) || len(ae.Leftovers) != 1 || !strings.Contains(err.Error(), "delete them by hand") {
		t.Fatalf("got %v", err)
	}
}

// Couldn't tell is never denied: a rejected credential at once, an
// unreachable store after the retries.
func TestExpectDeniedFailsClosed(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	srv.FailNext(1, 403, "InvalidAccessKeyId")
	srv.Deny(recipeOnly)
	err := open(t, srv.Config()).ExpectDenied(context.Background(), probes, quickPolicy())
	if !errors.Is(err, objectstore.ErrProbeInconclusive) || errors.Is(err, objectstore.ErrAccessAllowed) {
		t.Fatalf("rejected credential: got %v", err)
	}

	dead := httptest.NewServer(nil)
	cfg := srv.Config()
	cfg.Endpoint = strings.TrimPrefix(dead.URL, "http://")
	dead.Close()
	retries := 0
	rp := quickPolicy()
	rp.AttemptTimeout = 500 * time.Millisecond
	rp.OnRetry = func(int, time.Duration, error) { retries++ }
	err = open(t, cfg).ExpectDenied(context.Background(), probes[:1], rp)
	if !errors.Is(err, objectstore.ErrProbeInconclusive) || !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("unreachable: got %v", err)
	}
	if retries != 2 {
		t.Errorf("retries = %d, want 2", retries)
	}

	if err := open(t, srv.Config()).ExpectDenied(context.Background(), []objectstore.Probe{probe("copy", "k")}, rp); err == nil {
		t.Error("unknown op accepted")
	}
}

// FIX.5: a delete probe is classified like the others, never removes
// anything when denied, and is accepted by ExpectDenied, which never
// tries to clean up after it (it wrote nothing).
func TestDeleteProbe(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	s := open(t, srv.Config())
	ctx := context.Background()
	if err := s.Put(ctx, "platform/base.imas", []byte("x")); err != nil {
		t.Fatal(err)
	}
	del := probe(objectstore.ProbeDelete, "platform/probe/missing")

	srv.Deny(recipeOnly)
	if err := s.ExpectDenied(ctx, []objectstore.Probe{del}, quickPolicy()); err != nil {
		t.Fatalf("denied delete: %v", err)
	}

	srv.Deny(nil)
	err := s.ExpectDenied(ctx, []objectstore.Probe{del}, quickPolicy())
	var ae *objectstore.AllowedError
	if !errors.As(err, &ae) || len(ae.Allowed) != 1 || ae.Allowed[0] != del || len(ae.Leftovers) != 0 ||
		!strings.Contains(err.Error(), "delete platform/probe/missing") {
		t.Fatalf("allowed delete: got %v", err)
	}
	if v, ok := srv.Object("platform/base.imas"); !ok || v != "x" {
		t.Errorf("an object the probe didn't target changed: %q, %v", v, ok)
	}

	// A store that answers NoSuchKey for a missing key has authorized the
	// delete first.
	srv.FailNext(1, 404, "NoSuchKey")
	if a, err := s.TryAccess(ctx, del); a != objectstore.AccessAllowed || err != nil {
		t.Errorf("NoSuchKey: %v, %v", a, err)
	}
	// Anything else is inconclusive, not denied.
	srv.FailNext(1, 400, "InvalidRequest")
	if a, err := s.TryAccess(ctx, del); a != objectstore.AccessUnknown || err == nil {
		t.Errorf("InvalidRequest: %v, %v", a, err)
	}
}

func TestProbeString(t *testing.T) {
	if got := probe(objectstore.ProbeList, "").String(); got != "list (bucket root)" {
		t.Errorf("root list: %q", got)
	}
	if got := probe(objectstore.ProbeDelete, "jobs/x").String(); got != "delete jobs/x" {
		t.Errorf("delete: %q", got)
	}
}
