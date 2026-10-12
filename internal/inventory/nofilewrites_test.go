// Package inventory holds the P21 slice 3 inventory guard: farmer and
// saasapi keep no state on local disk, so their code must not write files
// outside the temp dir. The package has no code of its own, only this test.
package inventory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// enforceNoFileWrites turns the guard from report-only into a failing
// test. P21 slice 3 started report-only (PR 1) while later PRs moved each
// write to a shared store, and switched to enforcing in its last PR (PR
// 9), once the only calls left were the allow-listed ones below.
const enforceNoFileWrites = true

// moduleRoot is the repository root relative to this package's directory.
const moduleRoot = "../.."

// scannedDirs are the trees whose non-test Go files the guard reads: the
// farmer and saasapi binaries and the packages they keep state in
// (brief section 1.4).
var scannedDirs = []string{
	"cmd/farmer",
	"cmd/saasapi",
	"internal/pki",
	"internal/certs",
	"internal/audit",
	"internal/jobs",
	"internal/natsapi",
	"internal/saasapi",
}

// fileWriteCalls are the calls that create or write a file or directory,
// by import path and function name.
var fileWriteCalls = map[string][]string{
	"os":        {"WriteFile", "Create", "CreateTemp", "OpenFile", "Mkdir", "MkdirAll", "MkdirTemp"},
	"io/ioutil": {"WriteFile", "TempFile"},
}

// allowedFileWrites lists the calls that may stay, as
// "path:function:call#n" (path from the repository root, function the
// enclosing func or Type.Method, call as pkg.Name, n counting that call's
// uses in the function from 1 in source order). n gives each call its own
// entry, so allowing one write doesn't also allow a second write of the
// same kind in that function. Line numbers are left out so unrelated
// edits don't churn the list.
//
// A call is allowed only if, in farmer and saasapi, it writes under the
// pod's temp dir or another emptyDir, or if farmer and saasapi never run
// it. A new write to anything that must outlive the pod goes to PXC,
// Valkey, OpenBao or the object store instead, not onto this list.
var allowedFileWrites = []string{
	// farmerpki: the farmer chart points it into the tmp emptyDir
	// (deploy/helm/farmer, farmer-configmap.yaml). What farmer writes there
	// (the JWTs it signs for its own connections, cached Account JWTs) is
	// per replica and made again at start; Account and sprout User JWTs'
	// source of truth is Transit, PXC and the sprout JWT bucket.
	"internal/pki/pki.go:SetupPKIFarmer:os.MkdirAll#1",
	"internal/pki/jwtauth.go:ensurePlatformAuthLocked:os.MkdirAll#1",
	"internal/pki/jwtauth.go:ensurePlatformAuthLocked:os.MkdirAll#2",
	"internal/pki/jwtauth.go:ensurePlatformAuthLocked:os.MkdirAll#3",
	"internal/pki/jwtusers.go:mintOrReuseUserJWT:os.MkdirAll#1",
	"internal/pki/tenant.go:ensureTenantAccountMaterial:os.MkdirAll#1",
	"internal/pki/tenant.go:ensureTenantAccountMaterial:os.MkdirAll#2",
	"internal/pki/tenant.go:signLockedOutTenantJWT:os.MkdirAll#1",
	// The atomic and write-once helpers every write under farmerpki (and
	// the sprout's PKI dir) goes through: the temp file is made next to
	// the target, so in farmer it is in the tmp emptyDir too.
	"internal/pki/enrollclient.go:writeFileAtomic:os.MkdirAll#1",
	"internal/pki/enrollclient.go:writeFileAtomic:os.CreateTemp#1",
	"internal/pki/enrollclient.go:writeFileOnce:os.MkdirAll#1",
	"internal/pki/enrollclient.go:writeFileOnce:os.CreateTemp#1",
	// farmer's NKey, at nkeyfarmer*file under farmerpki (tmp emptyDir).
	// Per replica until it is read from a mounted Secret
	// (IMAS_FARMER_NKEY_SEED_FILE,
	// docs/briefs/P21-slice3-farmer-saasapi-state.md §5); the sprout's own NKey
	// otherwise.
	"internal/certs/nkey.go:GenNKey:os.WriteFile#1",
	"internal/certs/nkey.go:GenNKey:os.WriteFile#2",
	// farmer's API certificate from OpenBao PKI, into the TLS dir: a
	// memory emptyDir (tls.mode=openbao), issued again at every start.
	"internal/certs/tls.go:writeFile:os.OpenFile#1",
	// The sprout's PKI dir: sprout only.
	"internal/pki/pki.go:SetupPKISprout:os.MkdirAll#1",
	// The imas CLI's local job store: CLI only.
	"internal/jobs/clistore.go:NewCLIStore:os.MkdirAll#1",
	"internal/jobs/clistore.go:CLIStore.RecordJobStart:os.MkdirAll#1",
	"internal/jobs/clistore.go:CLIStore.RecordJobStart:os.WriteFile#1",
	"internal/jobs/clistore.go:CLIStore.RecordJobStart:os.Create#1",
	"internal/jobs/clistore.go:CLIStore.AppendStep:os.MkdirAll#1",
	"internal/jobs/clistore.go:CLIStore.AppendStep:os.OpenFile#1",
	// Test fixtures (package pkitest), writing into the test's own dirs.
	"internal/pki/pkitest/pkitest.go:Farmer:os.WriteFile#1",
	"internal/pki/pkitest/pkitest.go:Transit.WriteTrust:os.WriteFile#1",
}

// fileWrite is one call found in the scanned source.
type fileWrite struct {
	pos string // path:line, for the report
	key string // path:function:call#n, as allowedFileWrites spells it
}

// TestNoFileWrittenOutsideTmp reads the scanned trees' source and fails
// on every call that writes a file and isn't on the allow-list (only
// reports it while enforceNoFileWrites is false); an allow-list entry that
// no longer matches anything is reported the same way.
func TestNoFileWrittenOutsideTmp(t *testing.T) {
	writes := scanFileWrites(t, moduleRoot, scannedDirs)

	allowed := map[string]bool{}
	for _, a := range allowedFileWrites {
		allowed[a] = false
	}
	var unlisted []fileWrite
	for _, w := range writes {
		if _, ok := allowed[w.key]; ok {
			allowed[w.key] = true
			continue
		}
		unlisted = append(unlisted, w)
	}
	var stale []string
	for a, used := range allowed {
		if !used {
			stale = append(stale, a)
		}
	}
	slices.Sort(stale)

	report := t.Logf
	if enforceNoFileWrites {
		report = t.Errorf
	}
	for _, w := range unlisted {
		report("file write outside the temp dir: %s (%s)", w.pos, w.key)
	}
	for _, a := range stale {
		report("allow-list entry matches no call: %s", a)
	}
	t.Logf("%d file-write calls found, %d not allow-listed, %d stale allow-list entries (enforcing: %v)",
		len(writes), len(unlisted), len(stale), enforceNoFileWrites)
}

// scanFileWrites parses every non-test Go file under dirs (relative to
// root) and returns the file-write calls in them, in source order. A
// missing dir or a file that won't parse fails the test whatever the
// mode: a rename must not silently empty the scan.
func scanFileWrites(t *testing.T, root string, dirs []string) []fileWrite {
	t.Helper()
	var out []fileWrite
	fset := token.NewFileSet()
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			out = append(out, fileWritesIn(fset, f, filepath.ToSlash(rel))...)
			return nil
		})
		if err != nil {
			t.Fatalf("scanning %s: %v", dir, err)
		}
	}
	return out
}

// fileWritesIn returns the file-write calls in f, whose repository path is
// rel. A call is matched by the import it goes through, whatever name the
// file imports it under.
func fileWritesIn(fset *token.FileSet, f *ast.File, rel string) []fileWrite {
	names := map[string]string{} // local import name -> import path
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if _, ok := fileWriteCalls[p]; !ok {
			continue
		}
		local := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			local = imp.Name.Name
		}
		names[local] = p
	}
	if len(names) == 0 {
		return nil
	}
	var out []fileWrite
	for _, decl := range f.Decls {
		fn := "init"
		switch d := decl.(type) {
		case *ast.FuncDecl:
			fn = funcName(d)
		case *ast.GenDecl:
			fn = "var"
		}
		seen := map[string]int{} // function:call -> uses so far
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			p, ok := names[id.Name]
			if !ok || !slices.Contains(fileWriteCalls[p], sel.Sel.Name) {
				return true
			}
			callID := fn + ":" + p[strings.LastIndex(p, "/")+1:] + "." + sel.Sel.Name
			seen[callID]++
			out = append(out, fileWrite{
				pos: rel + ":" + strconv.Itoa(fset.Position(call.Pos()).Line),
				key: rel + ":" + callID + "#" + strconv.Itoa(seen[callID]),
			})
			return true
		})
	}
	return out
}

// funcName is d's name as allowedFileWrites spells it: Name, or
// Type.Name for a method.
func funcName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	typ := d.Recv.List[0].Type
	for {
		switch x := typ.(type) {
		case *ast.StarExpr:
			typ = x.X
			continue
		case *ast.IndexExpr:
			typ = x.X
			continue
		case *ast.IndexListExpr:
			typ = x.X
			continue
		case *ast.Ident:
			return x.Name + "." + d.Name.Name
		}
		return d.Name.Name
	}
}

// The scanner itself: it finds calls through renamed imports, names the
// enclosing function or method, numbers repeated calls in one function,
// and ignores look-alikes from other packages.
func TestScanFileWritesFindsCalls(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "pkg")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := `package pkg

import (
	stdos "os"
	"io/ioutil"
)

type store struct{}

type fake struct{}

func (fake) WriteFile(string, []byte, int) error { return nil }

var os fake

func (s *store) save() {
	_ = stdos.WriteFile("/var/lib/x", nil, 0o600)
	_ = ioutil.WriteFile("/var/lib/y", nil, 0o600)
}

func mk() {
	_ = stdos.MkdirAll("/var/lib/z", 0o755)
	_ = stdos.Mkdir("/var/lib/m", 0o755)
	_, _ = stdos.MkdirTemp("/var/lib", "t")
	_ = stdos.MkdirAll("/var/lib/z2", 0o755)
}

func notAWrite() { _ = os.WriteFile("a", nil, 0) }
`
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a_test.go"), []byte("package pkg\nimport \"os\"\nfunc x() { os.Create(\"t\") }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, w := range scanFileWrites(t, root, []string{"pkg"}) {
		keys = append(keys, w.key)
	}
	want := []string{
		"pkg/a.go:store.save:os.WriteFile#1",
		"pkg/a.go:store.save:ioutil.WriteFile#1",
		"pkg/a.go:mk:os.MkdirAll#1",
		"pkg/a.go:mk:os.Mkdir#1",
		"pkg/a.go:mk:os.MkdirTemp#1",
		"pkg/a.go:mk:os.MkdirAll#2",
	}
	if !slices.Equal(keys, want) {
		t.Fatalf("found %q, want %q", keys, want)
	}
}
