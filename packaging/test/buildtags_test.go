package packagingtest

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// No build, workflow or packaging file names the retired "no self update"
// tag (security review 2026-10, I5): nothing reads it, so passing it
// suggests a sprout built without self-update that does not exist.
// History under docs/ may still mention it. The needle is built from parts
// so this file does not match itself.
func TestNoSelfUpdateBuildTag(t *testing.T) {
	needle := []byte("no_" + "self_update")
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			switch rel {
			case ".git", "docs", "docs-site", "node_modules", "grlx-web-ui":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(rel, ".tgz") || strings.HasSuffix(rel, ".png") || strings.HasSuffix(rel, ".svg") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, needle) {
			t.Errorf("%s names the retired %s build tag", rel, needle)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
