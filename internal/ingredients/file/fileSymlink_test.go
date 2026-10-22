package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

func TestSymlink(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := tempDir + "/test"
	tempTarget := tempDir + "/target"
	existingSymlink := tempDir + "/existingSymlink"
	os.Symlink(tempTarget, existingSymlink)
	tests := []struct {
		name     string
		params   map[string]interface{}
		expected cook.Result
		error    error
		test     bool
	}{
		{
			name: "IncorrectFilename",
			params: map[string]interface{}{
				"name": 1,
			},
			expected: cook.Result{
				Succeeded: false,
				Failed:    true,
				Notes:     []fmt.Stringer{},
			},
			error: ingredients.ErrMissingName,
		},
		{
			name: "SymlinkRoot",
			params: map[string]interface{}{
				"name": "/",
			},
			expected: cook.Result{
				Succeeded: false,
				Failed:    true,
				Notes:     []fmt.Stringer{},
			},
			error: ErrModifyRoot,
		},
		{
			name: "SymlinkMissingTarget",
			params: map[string]interface{}{
				"name": "/tmp/test",
			},
			expected: cook.Result{
				Succeeded: false,
				Failed:    true,
				Notes:     []fmt.Stringer{},
			},
			error: ErrMissingTarget,
		},
		{
			name: "SymlinkCreateTest",
			params: map[string]interface{}{
				"name":   tempFile,
				"target": tempTarget,
			},
			expected: cook.Result{
				Succeeded: true,
				Failed:    false,
				Changed:   false,
				Notes:     []fmt.Stringer{cook.Snprintf("would create symlink %s pointing to %s", tempFile, tempTarget)},
			},
			error: nil,
			test:  true,
		},
		{
			name: "SymlinkCreate",
			params: map[string]interface{}{
				"name":   tempFile,
				"target": tempTarget,
			},
			expected: cook.Result{
				Succeeded: true,
				Failed:    false,
				Changed:   true,
				Notes:     []fmt.Stringer{cook.Snprintf("created symlink %s pointing to %s", tempFile, tempTarget)},
			},
			error: nil,
		},
		{
			// The link exists and already points at the target (which is
			// missing: the link dangles): nothing to do.
			name: "SymlinkExistingCreate",
			params: map[string]interface{}{
				"name":   existingSymlink,
				"target": tempTarget,
			},
			expected: cook.Result{
				Succeeded: true,
				Failed:    false,
				Changed:   false,
				Notes:     []fmt.Stringer{cook.Snprintf("symlink %s already points to %s", existingSymlink, tempTarget)},
			},
			error: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := File{
				id:     "",
				method: "symlink",
				params: test.params,
			}
			result, err := f.symlink(context.TODO(), test.test)
			if test.error != nil && err.Error() != test.error.Error() {
				t.Errorf("expected error %v, got %v", test.error, err)
			}
			compareResults(t, result, test.expected)
		})
	}
}

// TestSymlinkCycle mirrors UAT I.file.symlink: test mode, a real run, test
// mode and a real run again. Every run after the first used to fail with
// "method symlink undefined" because os.Stat found the new link.
func TestSymlinkCycle(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("target\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	f := File{method: "symlink", params: map[string]interface{}{"name": link, "target": target}}

	steps := []struct {
		test, changed bool
	}{{true, true}, {false, true}, {true, false}, {false, false}}
	for i, st := range steps {
		res, err := f.symlink(context.Background(), st.test)
		if err != nil || !res.Succeeded || res.Changed != st.changed {
			t.Fatalf("run %d (test %v): %+v, %v; want success, changed %v", i, st.test, res, err, st.changed)
		}
	}
	if got, err := os.Readlink(link); err != nil || got != target {
		t.Fatalf("link points to %q (%v), want %q", got, err, target)
	}
}

func TestSymlinkRepointsAndRefusesNonLinks(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "old"), link); err != nil {
		t.Fatal(err)
	}
	f := File{method: "symlink", params: map[string]interface{}{"name": link, "target": filepath.Join(dir, "new")}}
	res, err := f.symlink(context.Background(), true)
	if err != nil || !res.Changed {
		t.Fatalf("test mode: %+v, %v; want a pending change", res, err)
	}
	if got, _ := os.Readlink(link); got != filepath.Join(dir, "old") {
		t.Fatalf("test mode repointed the link to %q", got)
	}
	res, err = f.symlink(context.Background(), false)
	if err != nil || !res.Changed {
		t.Fatalf("repoint: %+v, %v; want a change", res, err)
	}
	if got, _ := os.Readlink(link); got != filepath.Join(dir, "new") {
		t.Fatalf("link points to %q, want new", got)
	}

	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f = File{method: "symlink", params: map[string]interface{}{"name": regular, "target": filepath.Join(dir, "new")}}
	if _, err := f.symlink(context.Background(), false); !errors.Is(err, ErrPathExists) {
		t.Fatalf("a regular file in the way: err %v, want ErrPathExists", err)
	}
	if st, _ := os.Lstat(regular); st.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the regular file was replaced")
	}
}

func TestSymlinkMakedirs(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "a", "b", "link")
	f := File{method: "symlink", params: map[string]interface{}{"name": link, "target": "/x"}}
	if _, err := f.symlink(context.Background(), false); !errors.Is(err, ErrPathNotFound) {
		t.Fatalf("missing parent without makedirs: err %v, want ErrPathNotFound", err)
	}
	f.params["makedirs"] = true
	if res, err := f.symlink(context.Background(), false); err != nil || !res.Changed {
		t.Fatalf("with makedirs: %+v, %v", res, err)
	}
	if got, _ := os.Readlink(link); got != "/x" {
		t.Fatalf("link points to %q", got)
	}
}
