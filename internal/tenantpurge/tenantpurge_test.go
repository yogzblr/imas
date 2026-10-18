package tenantpurge_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/glebarez/sqlite"
	"github.com/valkey-io/valkey-go"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/tenantpurge"
)

// memDBSeq numbers this package's in-memory sqlite test databases, so
// a DSN never repeats across `go test -count=N` runs of the same test.
var memDBSeq atomic.Int64

func openDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"-"+strconv.FormatInt(memDBSeq.Add(1), 10)+"?mode=memory&cache=shared"), &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			s.Close()
		}
	})
	if err := db.Exec("CREATE TABLE props (tenant_id TEXT NOT NULL, sprout_id TEXT NOT NULL, name TEXT NOT NULL, PRIMARY KEY (tenant_id, sprout_id, name))").Error; err != nil {
		t.Fatal(err)
	}
	return db
}

func count(t *testing.T, db *gorm.DB, tenant string) int64 {
	t.Helper()
	var n int64
	if err := db.Table("props").Where("tenant_id = ?", tenant).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// DeleteRows deletes one tenant's rows in batches, never another's (the
// same sprout and property names, and a tenant whose ID extends this
// one's), and is a no-op the second time.
func TestDeleteRows(t *testing.T) {
	db := openDB(t)
	for _, tenant := range []string{"t_a", "t_b", "t_ab"} {
		for i := range 7 {
			if err := db.Exec("INSERT INTO props VALUES (?, 'web-01', ?)", tenant, fmt.Sprintf("p%d", i)).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	n, err := tenantpurge.DeleteRows(context.Background(), db, "props", "t_a", 3)
	if err != nil || n != 7 {
		t.Fatalf("DeleteRows = %d, %v; want 7", n, err)
	}
	if count(t, db, "t_a") != 0 || count(t, db, "t_b") != 7 || count(t, db, "t_ab") != 7 {
		t.Fatalf("after the purge: t_a %d, t_b %d, t_ab %d", count(t, db, "t_a"), count(t, db, "t_b"), count(t, db, "t_ab"))
	}
	if n, err := tenantpurge.DeleteRows(context.Background(), db, "props", "t_a", 3); err != nil || n != 0 {
		t.Fatalf("second DeleteRows = %d, %v; want 0", n, err)
	}
	for _, bad := range []struct{ table, tenant string }{
		{"props", "t_a' OR '1'='1"}, {"props", ""}, {"props", "t/a"}, {"props;drop", "t_a"}, {"Props", "t_a"},
	} {
		if _, err := tenantpurge.DeleteRows(context.Background(), db, bad.table, bad.tenant, 3); err == nil {
			t.Errorf("DeleteRows(%q, %q): want an error", bad.table, bad.tenant)
		}
	}
	if count(t, db, "t_b") != 7 {
		t.Fatal("a refused call deleted rows")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tenantpurge.DeleteRows(ctx, db, "props", "t_b", 3); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled DeleteRows: %v", err)
	}
}

// DeleteObjects deletes every key under the tenant's prefix, a page at a
// time, never a key of a tenant whose ID extends this one's, and refuses
// a prefix whose last segment isn't the tenant.
func TestDeleteObjects(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	store, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var keys []string
	for _, tenant := range []string{"t_a", "t_b", "t_ab"} {
		for i := range 5 {
			keys = append(keys, fmt.Sprintf("tenants/%s/recipes/r%d.json", tenant, i))
		}
		keys = append(keys, "sprouts/"+tenant+"/web-01/recipe.json", tenant+"/web-01/h.jwt")
	}
	for _, k := range keys {
		if err := store.Put(ctx, k, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	n, err := tenantpurge.DeleteObjects(ctx, store, "tenants/t_a/", "t_a", 2)
	if err != nil || n != 5 {
		t.Fatalf("DeleteObjects = %d, %v; want 5", n, err)
	}
	if n, err := tenantpurge.DeleteObjects(ctx, store, "t_a/", "t_a", 2); err != nil || n != 1 {
		t.Fatalf("DeleteObjects at the bucket root = %d, %v; want 1", n, err)
	}
	if n, err := tenantpurge.DeleteObjects(ctx, store, "tenants/t_a/", "t_a", 2); err != nil || n != 0 {
		t.Fatalf("second DeleteObjects = %d, %v; want 0", n, err)
	}
	left := srv.Keys()
	if len(left) != len(keys)-6 {
		t.Fatalf("%d keys left, want %d: %v", len(left), len(keys)-6, left)
	}
	for _, k := range left {
		if k == "sprouts/t_a/web-01/recipe.json" {
			continue
		}
		if len(k) > 4 && (k[:4] == "t_a/" || (len(k) > 12 && k[:12] == "tenants/t_a/")) {
			t.Errorf("t_a key %s left", k)
		}
	}
	for _, bad := range []struct{ prefix, tenant string }{
		{"tenants/", "t_a"}, {"tenants/t_a", "t_a"}, {"tenants/t_ab/", "t_a"}, {"", "t_a"}, {"tenants/x/", "x/"},
	} {
		if _, err := tenantpurge.DeleteObjects(ctx, store, bad.prefix, bad.tenant, 2); err == nil {
			t.Errorf("DeleteObjects(%q, %q): want an error", bad.prefix, bad.tenant)
		}
	}
	srv.Deny(func(op, key string) bool { return op == "DELETE" })
	if n, err := tenantpurge.DeleteObjects(ctx, store, "tenants/t_b/", "t_b", 2); err == nil || n != 0 {
		t.Errorf("a refused delete: %d, %v; want 0 and an error", n, err)
	}
}

// DeleteValkeyKeys deletes the tenant's keys by the hash tag's tenant
// part, and no other tenant's, even for the same sprout ID or a tenant
// whose ID extends this one's.
func TestDeleteValkeyKeys(t *testing.T) {
	mr := miniredis.RunT(t)
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	for _, tenant := range []string{"t_a", "t_b", "t_ab"} {
		for i := range 4 {
			mr.Set(fmt.Sprintf("imas:heartbeat:{%s:web-%02d}", tenant, i), "1")
		}
		mr.Set("imas:accepted:{"+tenant+":web-00}", "1")
	}
	mr.Set("imas:replay:abc", "1")
	pattern := tenantpurge.ValkeyPattern(tenantpurge.ValkeyHeartbeatPrefix, "t_a")
	n, err := tenantpurge.DeleteValkeyKeys(context.Background(), client, pattern, 2)
	if err != nil || n != 4 {
		t.Fatalf("DeleteValkeyKeys = %d, %v; want 4", n, err)
	}
	if mr.Exists("imas:heartbeat:{t_a:web-00}") || !mr.Exists("imas:heartbeat:{t_ab:web-00}") || !mr.Exists("imas:heartbeat:{t_b:web-00}") ||
		!mr.Exists("imas:accepted:{t_a:web-00}") || !mr.Exists("imas:replay:abc") {
		t.Fatalf("wrong keys deleted: %v", mr.Keys())
	}
	if n, err := tenantpurge.DeleteValkeyKeys(context.Background(), client, pattern, 2); err != nil || n != 0 {
		t.Fatalf("second DeleteValkeyKeys = %d, %v; want 0", n, err)
	}
	if _, err := tenantpurge.DeleteValkeyKeys(context.Background(), nil, pattern, 2); err == nil {
		t.Error("no client: want an error")
	}
}

func TestValkeyPatternAndCategories(t *testing.T) {
	if got := tenantpurge.ValkeyPattern("imas:heartbeat:", "t_a"); got != "imas:heartbeat:{t_a:*" {
		t.Errorf("pattern %q", got)
	}
	seen := map[string]bool{}
	for _, p := range tenantpurge.PurgeValkeyPrefixes {
		c := tenantpurge.ValkeyCategory(p)
		if c == "valkey.other" || seen[c] {
			t.Errorf("prefix %s has category %s", p, c)
		}
		seen[c] = true
	}
	for _, p := range tenantpurge.ObjectPrefixes("t_a") {
		if seen[p.Category] {
			t.Errorf("category %s twice", p.Category)
		}
		seen[p.Category] = true
		if _, ok := tenantpurge.PurgeRoots[p.Bucket]; !ok {
			t.Errorf("prefix %s in unlisted bucket %s", p.Prefix, p.Bucket)
		}
	}
	if !tenantpurge.ValidTenantID("t_0123456789abcdef") || tenantpurge.ValidTenantID("t:a") || tenantpurge.ValidTenantID("t*") {
		t.Error("ValidTenantID disagrees with internal/pki's alphabet")
	}
}
