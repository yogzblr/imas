package jobs

import (
	"context"
	"testing"
)

// PurgeTenantObjects deletes jobs/<tenant>/ and nothing of a tenant whose
// ID extends it.
func TestPurgeTenantObjects(t *testing.T) {
	srv, obj := useTestObjServer(t)
	ctx := context.Background()
	for _, k := range []string{"jobs/t_a/web-01/j1/meta.json", "jobs/t_a/web-01/j1/events/1.jsonl", "jobs/t_ab/web-01/j1/meta.json", "jobs/t_b/web-01/j1/meta.json"} {
		if err := obj.Put(ctx, k, []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := PurgeTenantObjects(ctx, "t_a", 1); err != nil || n != 2 {
		t.Fatalf("PurgeTenantObjects = %d, %v", n, err)
	}
	if keys := srv.Keys(); len(keys) != 2 || keys[0] != "jobs/t_ab/web-01/j1/meta.json" || keys[1] != "jobs/t_b/web-01/j1/meta.json" {
		t.Fatalf("keys left: %v", keys)
	}
	if n, err := PurgeTenantObjects(ctx, "t_a", 1); err != nil || n != 0 {
		t.Errorf("second PurgeTenantObjects = %d, %v", n, err)
	}
	SetStore(nil)
	if _, err := PurgeTenantObjects(ctx, "t_a", 1); err == nil {
		t.Error("no store: want an error")
	}
}
