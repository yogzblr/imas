package objectstore_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

func TestGetLimited(t *testing.T) {
	s := objectstoretest.NewStore(t)
	ctx := context.Background()
	objectstoretest.Seed(t, s, map[string]string{"small": "abc", "exact": "abcd", "big": strings.Repeat("x", 5)})

	for key, want := range map[string]string{"small": "abc", "exact": "abcd"} {
		got, err := s.GetLimited(ctx, key, 4)
		if err != nil || string(got) != want {
			t.Errorf("%s: got %q, %v", key, got, err)
		}
	}
	if _, err := s.GetLimited(ctx, "big", 4); !errors.Is(err, objectstore.ErrObjectTooLarge) {
		t.Errorf("big: got %v, want ErrObjectTooLarge", err)
	}
	if _, err := s.GetLimited(ctx, "missing", 4); !objectstore.IsNotExist(err) {
		t.Errorf("missing: got %v, want not-exist", err)
	}
	if _, err := s.GetLimited(ctx, "small", -1); err == nil {
		t.Error("negative limit accepted")
	}
}
