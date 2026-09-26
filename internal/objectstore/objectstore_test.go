package objectstore_test

import (
	"context"
	"testing"

	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

func TestGetPutRoundTrip(t *testing.T) {
	store := objectstoretest.NewStore(t)
	ctx := context.Background()

	if err := store.Put(ctx, "web.nginx.imas", []byte("hello recipe")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(ctx, "web.nginx.imas")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "hello recipe" {
		t.Errorf("Get() = %q, want %q", got, "hello recipe")
	}
}

func TestGetNotFound(t *testing.T) {
	store := objectstoretest.NewStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "does-not-exist.imas")
	if err == nil {
		t.Fatal("expected an error for a missing key")
	}
	if !objectstore.IsNotExist(err) {
		t.Errorf("expected IsNotExist(err) to be true, got: %v", err)
	}
}

func TestExists(t *testing.T) {
	store := objectstoretest.NewStore(t)
	ctx := context.Background()

	ok, err := store.Exists(ctx, "web.nginx.imas")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if ok {
		t.Error("expected Exists=false before Put")
	}

	if err := store.Put(ctx, "web.nginx.imas", []byte("content")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	ok, err = store.Exists(ctx, "web.nginx.imas")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !ok {
		t.Error("expected Exists=true after Put")
	}
}

func TestSize(t *testing.T) {
	store := objectstoretest.NewStore(t)
	ctx := context.Background()

	if err := store.Put(ctx, "web.nginx.imas", []byte("0123456789")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	size, err := store.Size(ctx, "web.nginx.imas")
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size != 10 {
		t.Errorf("Size() = %d, want 10", size)
	}

	if _, err := store.Size(ctx, "does-not-exist.imas"); err == nil {
		t.Error("expected an error for a missing key")
	}
}

func TestList(t *testing.T) {
	store := objectstoretest.NewStore(t)
	ctx := context.Background()

	for _, key := range []string{"web/init.imas", "web/nginx.imas", "db/init.imas"} {
		if err := store.Put(ctx, key, []byte("x")); err != nil {
			t.Fatalf("Put(%s): %v", key, err)
		}
	}

	keys, err := store.List(ctx, "web/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys under web/, got %d: %v", len(keys), keys)
	}
}

func TestDelete(t *testing.T) {
	store := objectstoretest.NewStore(t)
	ctx := context.Background()

	if err := store.Put(ctx, "jobs/a/j1/created.jsonl", []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Delete(ctx, "jobs/a/j1/created.jsonl"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	exists, err := store.Exists(ctx, "jobs/a/j1/created.jsonl")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Error("expected key to be gone after Delete")
	}

	// Deleting a missing key succeeds, matching S3's DeleteObject.
	if err := store.Delete(ctx, "jobs/a/j1/created.jsonl"); err != nil {
		t.Errorf("Delete of missing key: %v", err)
	}
}

func TestOpenValidation(t *testing.T) {
	if _, err := objectstore.Open(objectstore.Config{Bucket: "recipes"}); err == nil {
		t.Error("expected an error for an empty endpoint")
	}
	if _, err := objectstore.Open(objectstore.Config{Endpoint: "localhost:9000"}); err == nil {
		t.Error("expected an error for an empty bucket")
	}
	if _, err := objectstore.Open(objectstore.Config{Endpoint: "localhost:9000", Bucket: "x"}); err == nil {
		t.Error("expected an error for an invalid bucket name")
	}
}
