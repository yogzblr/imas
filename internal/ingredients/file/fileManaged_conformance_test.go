package file

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/config"
)

// UAT.9: findings from reading file.managed for the UAT gate
// (uat/cases/file/managed.yaml): it rewrote the destination and reported a
// change on every run, and ignored mode.

func managedFixture(t *testing.T, extra map[string]interface{}) (File, string) {
	t.Helper()
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	orig := config.CacheDir
	config.CacheDir = cache
	t.Cleanup(func() { config.CacheDir = orig })
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("imas uat source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The test provider (providers_test.go) only creates an empty file, so
	// put the source's content in the cache where the step will look for it
	// (skip_verify caches under skip_<id>-source).
	if err := os.WriteFile(filepath.Join(cache, "skip_managed-conformance-source"), []byte("imas uat source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	params := map[string]interface{}{"name": dst, "source": src, "skip_verify": true}
	for k, v := range extra {
		params[k] = v
	}
	return File{id: "managed-conformance", method: "managed", params: params}, dst
}

func TestManagedSecondRunChangesNothing(t *testing.T) {
	f, dst := managedFixture(t, nil)
	ctx := context.Background()
	res, err := f.managed(ctx, false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("first run: %+v, %v", res, err)
	}
	// Age the file: a rewrite would move its modification time.
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes(dst, old, old); err != nil {
		t.Fatal(err)
	}
	for _, test := range []bool{true, false} {
		res, err = f.managed(ctx, test)
		if err != nil || !res.Succeeded {
			t.Fatalf("second run (test=%v): %+v, %v", test, res, err)
		}
		if res.Changed {
			t.Errorf("second run (test=%v) reports a change although the file matches its source", test)
		}
	}
	st, _ := os.Stat(dst)
	if !st.ModTime().Equal(old) {
		t.Errorf("the destination was rewritten: mtime %v, want %v", st.ModTime(), old)
	}
}

func TestManagedRewritesWhenContentDiffers(t *testing.T) {
	f, dst := managedFixture(t, nil)
	if _, err := f.managed(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("drifted\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := f.managed(context.Background(), false)
	if err != nil || !res.Changed {
		t.Fatalf("drifted content: %+v, %v", res, err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "imas uat source\n" {
		t.Errorf("content %q, want the source back", b)
	}
}

func TestManagedAppliesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode is ignored on Windows")
	}
	f, dst := managedFixture(t, map[string]interface{}{"mode": "640"})
	ctx := context.Background()
	res, err := f.managed(ctx, false)
	if err != nil || !res.Changed {
		t.Fatalf("first run: %+v, %v", res, err)
	}
	if st, _ := os.Stat(dst); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, want 0640", st.Mode().Perm())
	}
	res, err = f.managed(ctx, false)
	if err != nil || res.Changed {
		t.Errorf("second run: %+v, %v; want no change", res, err)
	}
	// Mode drift alone is a change, fixed without rewriting the content.
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chmod(dst, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(dst, old, old); err != nil {
		t.Fatal(err)
	}
	res, err = f.managed(ctx, true)
	if err != nil || !res.Changed {
		t.Errorf("test mode with a drifted mode: %+v, %v; want a change", res, err)
	}
	if st, _ := os.Stat(dst); st.Mode().Perm() != 0o600 {
		t.Error("test mode changed the mode")
	}
	res, err = f.managed(ctx, false)
	if err != nil || !res.Changed {
		t.Fatalf("drifted mode: %+v, %v", res, err)
	}
	st, _ := os.Stat(dst)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, want 0640 restored", st.Mode().Perm())
	}
	if !st.ModTime().Equal(old) {
		t.Error("a mode fix rewrote the content")
	}
}

func TestManagedInvalidMode(t *testing.T) {
	for _, m := range []string{"rw-r--r--", "999", "07777777777"} {
		f, dst := managedFixture(t, map[string]interface{}{"mode": m})
		res, err := f.managed(context.Background(), false)
		if err == nil || !res.Failed {
			t.Errorf("mode %q: %+v, %v; want a failure", m, res, err)
		}
		if _, statErr := os.Stat(dst); statErr == nil {
			t.Errorf("mode %q: the file was written before the mode was checked", m)
		}
	}
}
