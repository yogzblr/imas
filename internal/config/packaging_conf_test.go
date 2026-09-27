package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestPackagedConfigKeysAreRead checks that every top-level key in the
// sample configs shipped by the OS packages (packaging/etc/*.conf) is a key
// some non-test code in the module reads through jety. A key nothing reads
// is silently ignored, so a typo there (e.g. "farmeripoprt") only appears
// to work while its value happens to equal the default.
func TestPackagedConfigKeysAreRead(t *testing.T) {
	root := moduleRoot(t)
	known := jetyKeys(t, root)

	confs, err := filepath.Glob(filepath.Join(root, "packaging", "etc", "*.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(confs) == 0 {
		t.Fatal("no packaging/etc/*.conf files found")
	}
	for _, conf := range confs {
		t.Run(filepath.Base(conf), func(t *testing.T) {
			data, err := os.ReadFile(conf)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := yaml.Unmarshal(data, &m); err != nil {
				t.Fatalf("not valid YAML: %v", err)
			}
			for key := range m {
				if !known[strings.ToLower(key)] {
					t.Errorf("key %q is not read by any code (typo?)", key)
				}
			}
		})
	}
}

// TestJetyKeysFindsKnownKeys guards the source scan itself: if it stopped
// finding keys, TestPackagedConfigKeysAreRead would fail for the wrong
// reason, or pass vacuously if the configs were emptied.
func TestJetyKeysFindsKnownKeys(t *testing.T) {
	known := jetyKeys(t, moduleRoot(t))
	for _, key := range []string{"farmerapiport", "farmerinterface", "pubkeys", "props"} {
		if !known[key] {
			t.Errorf("source scan did not find key %q", key)
		}
	}
	if known["farmerurl"] {
		t.Error(`source scan found "farmerurl", which no code reads`)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above test directory")
		}
		dir = parent
	}
}

// jetyKeys returns the lower-cased top-level config keys passed as a string
// literal to any jety.Get*/Set*/IsSet call in the module's non-test Go
// files. A dotted key such as "props.static" contributes "props".
func jetyKeys(t *testing.T, root string) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "jety" {
				return true
			}
			name := sel.Sel.Name
			if !strings.HasPrefix(name, "Get") && !strings.HasPrefix(name, "Set") && name != "IsSet" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			key, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			key, _, _ = strings.Cut(strings.ToLower(key), ".")
			keys[key] = true
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("found no jety keys in module source")
	}
	return keys
}
