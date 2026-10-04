package objectstore_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

func TestPutConditional(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	s, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Create-only: succeeds once, then refuses.
	first, err := s.PutConditional(ctx, "k", []byte("one"), "text/plain", objectstore.PutCondition{IfNoneMatch: true})
	if err != nil || first.ETag == "" || first.Size != 3 {
		t.Fatalf("create: %+v, %v", first, err)
	}
	if _, err := s.PutConditional(ctx, "k", []byte("again"), "text/plain", objectstore.PutCondition{IfNoneMatch: true}); !errors.Is(err, objectstore.ErrPreconditionFailed) {
		t.Fatalf("second create: got %v, want ErrPreconditionFailed", err)
	}

	// Replace on the current ETag; a stale ETag is refused.
	second, err := s.PutConditional(ctx, "k", []byte("two"), "text/plain", objectstore.PutCondition{IfMatchETag: first.ETag})
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if _, err := s.PutConditional(ctx, "k", []byte("three"), "text/plain", objectstore.PutCondition{IfMatchETag: first.ETag}); !errors.Is(err, objectstore.ErrPreconditionFailed) {
		t.Fatalf("stale replace: got %v, want ErrPreconditionFailed", err)
	}
	if got, _ := srv.Object("k"); got != "two" {
		t.Fatalf("content after refused write: %q", got)
	}
	// If-Match on a missing key is refused.
	if _, err := s.PutConditional(ctx, "missing", []byte("x"), "text/plain", objectstore.PutCondition{IfMatchETag: second.ETag}); !errors.Is(err, objectstore.ErrPreconditionFailed) {
		t.Fatalf("replace missing: got %v", err)
	}
	// Exactly one condition.
	for _, c := range []objectstore.PutCondition{{}, {IfMatchETag: "x", IfNoneMatch: true}} {
		if _, err := s.PutConditional(ctx, "k", []byte("x"), "", c); !errors.Is(err, objectstore.ErrNoCondition) {
			t.Errorf("%+v: got %v, want ErrNoCondition", c, err)
		}
	}
}

func TestGetLimitedWithInfo(t *testing.T) {
	s := objectstoretest.NewStore(t)
	ctx := context.Background()
	put, err := s.PutConditional(ctx, "k", []byte("abc"), "", objectstore.PutCondition{IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	data, info, err := s.GetLimitedWithInfo(ctx, "k", 3)
	if err != nil || string(data) != "abc" || info.Size != 3 || info.ETag != put.ETag || info.LastModified.IsZero() {
		t.Fatalf("got %q %+v %v", data, info, err)
	}
	if _, _, err := s.GetLimitedWithInfo(ctx, "k", 2); !errors.Is(err, objectstore.ErrObjectTooLarge) {
		t.Errorf("over limit: got %v", err)
	}
	if _, _, err := s.GetLimitedWithInfo(ctx, "missing", 2); !objectstore.IsNotExist(err) {
		t.Errorf("missing: got %v", err)
	}
}

func TestListPage(t *testing.T) {
	s := objectstoretest.NewStore(t)
	ctx := context.Background()
	files := map[string]string{"other/x": "x"}
	for i := range 5 {
		files[fmt.Sprintf("p/%d", i)] = strings.Repeat("y", i)
	}
	objectstoretest.Seed(t, s, files)

	page, more, err := s.ListPage(ctx, "p/", "", 2)
	if err != nil || !more || len(page) != 2 || page[0].Key != "p/0" || page[1].Key != "p/1" || page[1].Size != 1 {
		t.Fatalf("first page: %+v more=%v %v", page, more, err)
	}
	page, more, err = s.ListPage(ctx, "p/", page[1].Key, 2)
	if err != nil || !more || len(page) != 2 || page[0].Key != "p/2" {
		t.Fatalf("second page: %+v more=%v %v", page, more, err)
	}
	page, more, err = s.ListPage(ctx, "p/", page[1].Key, 2)
	if err != nil || more || len(page) != 1 || page[0].Key != "p/4" {
		t.Fatalf("last page: %+v more=%v %v", page, more, err)
	}
	for _, bad := range []int{0, -1, objectstore.MaxListPage + 1} {
		if _, _, err := s.ListPage(ctx, "p/", "", bad); err == nil {
			t.Errorf("page size %d accepted", bad)
		}
	}
}
