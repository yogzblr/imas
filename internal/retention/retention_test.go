package retention

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/lease"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// now is the sweeps' clock in these tests: 2026-10-18 12:00 UTC.
var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func putAll(t *testing.T, s *objectstore.Store, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if err := s.Put(context.Background(), k, []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
}

func openFake(t *testing.T) (*objectstoretest.Server, *objectstore.Store) {
	t.Helper()
	srv := objectstoretest.NewServer(t)
	s, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	return srv, s
}

func TestCutoff(t *testing.T) {
	// A retention of 30 days on 2026-10-18 keeps 2026-09-18 onwards.
	if got, want := Cutoff(now, 30), time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("Cutoff = %s, want %s", got, want)
	}
	// Taken in UTC whatever the clock's zone.
	if got := Cutoff(now.In(time.FixedZone("x", 13*3600)), 1); !got.Equal(time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("Cutoff in another zone = %s", got)
	}
}

func TestRecipeAuditDate(t *testing.T) {
	for key, want := range map[string]string{
		"tenants/t_a/recipe-audit/2026-10-17/rec-1.json": "2026-10-17",
		"tenants/t_a/recipe-audit/2026-10-17/x/y.json":   "2026-10-17",
		"tenants/t_a/recipes/web.imas":                   "",
		"tenants/t_a/recipes/2026-10-17/web.imas":        "",
		"tenants/t_a/recipe-audit/2026-1-07/a.json":      "",
		"tenants/t_a/recipe-audit/latest/a.json":         "",
		"tenants/t_a/recipe-audit/2026-10-17/":           "",
		"tenants//recipe-audit/2026-10-17/a.json":        "",
		"sprouts/t_a/web/recipe.json":                    "",
	} {
		d, ok := RecipeAuditDate(key)
		if got := map[bool]string{true: d.Format("2006-01-02")}[ok]; got != want {
			t.Errorf("RecipeAuditDate(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestLogDate(t *testing.T) {
	f := LogDate("logs/")
	for key, want := range map[string]string{
		"logs/2026/10/17/farmer-0-120000-abc.gz": "2026-10-17",
		"logs/2026/10/17/a/b.gz":                 "2026-10-17",
		"logs/2026/10/17/":                       "",
		"logs/2026/1/17/a.gz":                    "",
		"logs/2026/13/01/a.gz":                   "",
		"other/2026/10/17/a.gz":                  "",
		"logs/x.gz":                              "",
	} {
		d, ok := f(key)
		if got := map[bool]string{true: d.Format("2006-01-02")}[ok]; got != want {
			t.Errorf("LogDate(%q) = %q, want %q", key, got, want)
		}
	}
}

// An expired recipe audit record is removed, a younger one and every
// recipe are kept, for every tenant, and two tenants' records are dated
// each by its own key.
func TestSweepRecipeAuditDeletesExpiredKeepsYounger(t *testing.T) {
	srv, s := openFake(t)
	old := []string{
		"tenants/t_a/recipe-audit/2025-10-17/a.json", // 366 days
		"tenants/t_b/recipe-audit/2024-01-01/b.json",
	}
	keep := []string{
		"tenants/t_a/recipe-audit/2025-10-18/a.json", // exactly 365 days: kept
		"tenants/t_b/recipe-audit/2026-10-18/b.json",
		"tenants/t_a/recipes/2024-01-01.imas",
		"tenants/t_a/recipes/web.imas",
		"sprouts/t_a/web/recipe.json",
	}
	putAll(t, s, append(slices.Clone(old), keep...)...)
	r, err := SweepRecipeAudit(context.Background(), s, 365, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Deleted != 2 || r.Kept != 2 || r.Undated != 2 {
		t.Fatalf("result %+v, want 2 deleted, 2 kept, 2 undated (recipes)", r)
	}
	got := srv.Keys()
	want := slices.Clone(keep)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("left %v, want %v", got, want)
	}
}

// A failed delete is reported and does not stop the sweep.
func TestSweepDatedGoesOnAfterAFailedDelete(t *testing.T) {
	srv, s := openFake(t)
	putAll(t, s, "logs/2020/01/01/a.gz", "logs/2020/01/02/b.gz")
	srv.Deny(func(op, key string) bool { return op == "DELETE" && key == "logs/2020/01/01/a.gz" })
	r, err := SweepDated(context.Background(), s, "logs/", LogDate("logs/"), Cutoff(now, 30))
	if err == nil {
		t.Fatal("want the failed delete reported")
	}
	if r.Deleted != 1 {
		t.Fatalf("deleted %d, want 1", r.Deleted)
	}
	if got := srv.Keys(); !slices.Equal(got, []string{"logs/2020/01/01/a.gz"}) {
		t.Fatalf("left %v", got)
	}
}

type failingList struct{}

func (failingList) List(context.Context, string) ([]string, error) { return nil, errors.New("boom") }
func (failingList) Delete(context.Context, string) error           { return nil }

func TestSweepDatedListFailure(t *testing.T) {
	if _, err := SweepDated(context.Background(), failingList{}, "logs/", LogDate("logs/"), now); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}

func writeCreds(t *testing.T, id, secret string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, AccessKeyIDFile), []byte(id), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, SecretAccessKeyFile), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The CronJob's command: an expired log object is removed, a younger one
// and a key with no day are kept, and only under the prefix.
func TestRunLogRetentionDeletesExpiredKeepsYounger(t *testing.T) {
	srv, s := openFake(t)
	today := time.Now().UTC()
	young := "logs/" + today.Format("2006/01/02") + "/farmer-0.gz"
	edge := "logs/" + today.AddDate(0, 0, -30).Format("2006/01/02") + "/farmer-0.gz"
	old := "logs/" + today.AddDate(0, 0, -31).Format("2006/01/02") + "/farmer-0.gz"
	outside := "other/2020/01/01/x.gz"
	undated := "logs/README"
	putAll(t, s, young, edge, old, outside, undated)
	cfg := srv.Config()
	var stderr bytes.Buffer
	code := RunLogRetention([]string{"-endpoint", cfg.Endpoint, "-bucket", cfg.Bucket, "-prefix", "logs/",
		"-credentials-dir", writeCreds(t, "test", "test")}, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	want := []string{edge, young, outside, undated}
	slices.Sort(want)
	if got := srv.Keys(); !slices.Equal(got, want) {
		t.Fatalf("left %v, want %v", got, want)
	}
	if !strings.Contains(stderr.String(), "deleted 1 log objects, kept 2, 1 with no day") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

func TestRunLogRetentionRefusesBadConfig(t *testing.T) {
	creds := writeCreds(t, "test", "test")
	for name, args := range map[string][]string{
		"no endpoint":     {"-bucket", "b", "-credentials-dir", creds},
		"negative days":   {"-endpoint", "h:1", "-bucket", "b", "-credentials-dir", creds, "-days", "-1"},
		"too many days":   {"-endpoint", "h:1", "-bucket", "b", "-credentials-dir", creds, "-days", "3651"},
		"days not number": {"-endpoint", "h:1", "-bucket", "b", "-credentials-dir", creds, "-days", "30d"},
		"prefix no slash": {"-endpoint", "h:1", "-bucket", "b", "-credentials-dir", creds, "-prefix", "logs"},
		"root prefix":     {"-endpoint", "h:1", "-bucket", "b", "-credentials-dir", creds, "-prefix", "/logs/"},
		"no credentials":  {"-endpoint", "h:1", "-bucket", "b", "-credentials-dir", t.TempDir()},
		"newline in key":  {"-endpoint", "h:1", "-bucket", "b", "-credentials-dir", writeCreds(t, "id\n", "secret")},
	} {
		var stderr bytes.Buffer
		if code := RunLogRetention(args, &stderr); code != 2 {
			t.Errorf("%s: exit %d, want 2 (%s)", name, code, stderr.String())
		}
	}
}

func TestLogRetentionDays(t *testing.T) {
	for in, want := range map[int]int{0: 30, 1: 1, 30: 30, 3650: 3650} {
		if got, err := LogRetentionDays(in); err != nil || got != want {
			t.Errorf("LogRetentionDays(%d) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []int{-1, 3651} {
		if _, err := LogRetentionDays(in); err == nil {
			t.Errorf("LogRetentionDays(%d): want an error", in)
		}
	}
}

// Two replicas ticking at once sweep once: the job lease and its minimum
// interval keep the second out.
func TestRecipeAuditSweepRunsOncePerDayAcrossReplicas(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&lease.JobLease{}); err != nil {
		t.Fatal(err)
	}
	var lists int
	s := &countingStore{lists: &lists}
	clock := func() time.Time { return now }
	sweepRecipeAuditLeased(context.Background(), db, s, 365, clock)
	sweepRecipeAuditLeased(context.Background(), db, s, 365, clock)
	if lists != 1 {
		t.Fatalf("listed %d times, want 1", lists)
	}
	later := func() time.Time { return now.Add(recipeAuditMinInterval) }
	sweepRecipeAuditLeased(context.Background(), db, s, 365, later)
	if lists != 2 {
		t.Fatalf("listed %d times after a day, want 2", lists)
	}
}

type countingStore struct{ lists *int }

func (c *countingStore) List(context.Context, string) ([]string, error) { *c.lists++; return nil, nil }
func (c *countingStore) Delete(context.Context, string) error           { return nil }

// 0 keeps the records for ever: nothing is started.
func TestStartRecipeAuditSweeperZeroKeepsForEver(t *testing.T) {
	var lists int
	StartRecipeAuditSweeper(context.Background(), nil, &countingStore{lists: &lists}, 0)
	time.Sleep(50 * time.Millisecond)
	if lists != 0 {
		t.Fatalf("listed %d times with retention 0", lists)
	}
}

// TestRunLogRetentionFailsFastWhenUnreachable: a refused connection ends
// the run within -connect-timeout, exit 1, naming the endpoint, instead of
// the S3 client retrying until the Job's deadline.
func TestRunLogRetentionFailsFastWhenUnreachable(t *testing.T) {
	defer func(d time.Duration) { reachRetry = d }(reachRetry)
	reachRetry = 10 * time.Millisecond
	// A port nothing listens on: take one and close it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := l.Addr().String()
	l.Close()

	var stderr bytes.Buffer
	start := time.Now()
	code := RunLogRetention([]string{"-endpoint", endpoint, "-bucket", "imas-logs",
		"-credentials-dir", writeCreds(t, "test", "test"), "-connect-timeout", "300ms"}, &stderr)
	if code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, stderr.String())
	}
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("took %s to give up", el)
	}
	for _, want := range []string{endpoint, "did not accept a connection", "Ready"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr %q lacks %q", stderr.String(), want)
		}
	}
}

func TestWaitReachableRidesOutARestart(t *testing.T) {
	defer func(d time.Duration) { reachRetry = d }(reachRetry)
	reachRetry = 10 * time.Millisecond
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := l.Addr().String()
	l.Close()
	go func() {
		time.Sleep(100 * time.Millisecond)
		l2, err := net.Listen("tcp", endpoint)
		if err != nil {
			return
		}
		t.Cleanup(func() { l2.Close() })
		for {
			c, err := l2.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if err := waitReachable(context.Background(), endpoint, 5*time.Second); err != nil {
		t.Fatalf("the store came back after 100ms: %v", err)
	}
}
