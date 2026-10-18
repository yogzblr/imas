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
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

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

// packageFileWriteCalls are a package's own helpers that write a file,
// by the package's directory: a call to one is a file write as much as
// the os call inside it, so each caller needs its own allow-list entry
// (spelled pkg.Name, pkg the directory's last element). internal/pki's
// two helpers are how farmer once wrote its JWTs under
// /tmp/farmer/pki; they are now called on the sprout's and the CLI's
// side only.
var packageFileWriteCalls = map[string][]string{
	"internal/pki": {"writeFileAtomic", "writeFileOnce"},
}

// farmerPKIDir is the directory farmer once kept the JWTs it signed in
// (the chart's farmerpki). TestNoFarmerPKIDir fails on any mention of it
// in the scanned code or the farmer chart.
const farmerPKIDir = "/tmp/farmer"

// allowedFileWrites lists the calls that may stay, as
// "path:function:call#n" (path from the repository root, function the
// enclosing func or Type.Method, call as pkg.Name, n counting that call's
// uses in the function from 1 in source order). n gives each call its own
// entry, so allowing one write doesn't also allow a second write of the
// same kind in that function. Line numbers are left out so unrelated
// edits don't churn the list.
//
// A call is allowed only if, in farmer and saasapi, it writes under the
// process's temp dir (os.MkdirTemp, made at start-up or per call and
// never read by a later process) or another emptyDir that holds nothing
// farmer must find again, or if farmer and saasapi never run it. A new
// write to anything that must outlive the process goes to PXC, Valkey,
// OpenBao or the object store instead, not onto this list. Farmer writes
// no JWT and no key at all (E3): Account JWTs are held in memory and kept
// in the accounts bucket, sprout User JWTs in the sprout JWT bucket, and
// the farmer's own User JWTs are signed on first use and held in memory.
var allowedFileWrites = []string{
	// The DMZ bus's PKI dir (cmd/farmerbus, on its data emptyDir; the
	// account loader refills its resolver at every start). Farmer does
	// not call it.
	"internal/pki/pki.go:SetupPKIFarmer:os.MkdirAll#1",
	// The in-process test bus's account resolver (ConfigureNats): a fresh
	// directory in the process's temp dir per call, removed when the
	// server closes the resolver. Farmer never embeds a bus.
	"internal/pki/nats.go:newTempDirResolver:os.MkdirTemp#1",
	// The atomic and write-once helpers (packageFileWriteCalls): the
	// temp file is made next to the target. Their callers below are the
	// sprout's and the CLI's.
	"internal/pki/enrollclient.go:mkdirAllDurable:os.MkdirAll#1",
	"internal/pki/enrollclient.go:writeFileAtomic:os.CreateTemp#1",
	"internal/pki/enrollclient.go:writeFileOnce:os.CreateTemp#1",
	// The sprout's PKI dir and enrolment state: sprout only.
	"internal/pki/busconnect.go:persistBusURLs:pki.writeFileAtomic#1",
	"internal/pki/enrollclient.go:EnsureSproutBoxKey:pki.writeFileOnce#1",
	"internal/pki/enrollclient.go:EnsureSproutBoxKey:pki.writeFileAtomic#1",
	"internal/pki/enrollclient.go:PersistEnrollment:pki.writeFileAtomic#1",
	"internal/pki/enrollclient.go:PersistEnrollment:pki.writeFileAtomic#2",
	"internal/pki/enrollclient.go:pinTenantX25519Pub:pki.writeFileOnce#1",
	"internal/pki/enrollclient.go:RefreshGatewayJWT:pki.writeFileAtomic#1",
	"internal/pki/enrollclient.go:RefreshGatewayJWT:pki.writeFileAtomic#2",
	"internal/pki/sproutbox.go:pinSproutTenant:pki.writeFileOnce#1",
	"internal/pki/sproutbox.go:pinSproutID:pki.writeFileOnce#1",
	"internal/pki/sproutbox.go:sproutGuard:pki.writeFileAtomic#1",
	"internal/pki/sproutbox.go:promoteSproutBoxKey:pki.writeFileAtomic#1",
	"internal/pki/sproutbox.go:promoteSproutBoxKey:pki.writeFileAtomic#2",
	"internal/pki/sproutbox.go:BeginSproutBoxKeyRotation:pki.writeFileOnce#1",
	"internal/pki/sproutbox.go:reconcileTenantKeyPin:pki.writeFileAtomic#1",
	// The root CA a sprout (TOFU) or the imas CLI fetches: not farmer.
	"internal/pki/pki.go:FetchRootCA:pki.writeFileOnce#1",
	// The imas CLI's box key: CLI only.
	"internal/pki/cliboxclient.go:writeFreshBoxKey:pki.writeFileAtomic#1",
	// The sprout's own NKey: sprout only. Farmer's NKey is the shared
	// Secret at IMAS_FARMER_NKEY_SEED_FILE (certs.LoadFarmerNKey), and
	// GenNKey(true) refuses before writing.
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
// on every call that writes a file and isn't on the allow-list; an
// allow-list entry that no longer matches anything fails it the same way.
// (P21 slice 3 ran it report-only until its last PR moved every other
// write to a shared store.)
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

	for _, w := range unlisted {
		t.Errorf("file write outside the temp dir: %s (%s)", w.pos, w.key)
	}
	for _, a := range stale {
		t.Errorf("allow-list entry matches no call: %s", a)
	}
	t.Logf("%d file-write calls found, %d not allow-listed, %d stale allow-list entries",
		len(writes), len(unlisted), len(stale))
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
	dir := path.Dir(rel)
	helpers := packageFileWriteCalls[dir]
	if len(names) == 0 && len(helpers) == 0 {
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
			var callID string
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				if !slices.Contains(helpers, fun.Name) {
					return true
				}
				callID = fn + ":" + path.Base(dir) + "." + fun.Name
			case *ast.SelectorExpr:
				id, ok := fun.X.(*ast.Ident)
				if !ok {
					return true
				}
				p, ok := names[id.Name]
				if !ok || !slices.Contains(fileWriteCalls[p], fun.Sel.Name) {
					return true
				}
				callID = fn + ":" + p[strings.LastIndex(p, "/")+1:] + "." + fun.Sel.Name
			default:
				return true
			}
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
	// A package's own write helper (packageFileWriteCalls) counts as a
	// write in that package only.
	pkiDir := filepath.Join(root, "internal", "pki")
	if err := os.MkdirAll(pkiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	helperSrc := "package pki\n\nfunc writeFileAtomic(string, []byte) error { return nil }\n\nfunc save() { _ = writeFileAtomic(\"/tmp/farmer/pki/x.jwt\", nil) }\n"
	if err := os.WriteFile(filepath.Join(pkiDir, "h.go"), []byte(helperSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.go"), []byte("package pkg\n\nfunc writeFileAtomic(string) {}\n\nfunc other() { writeFileAtomic(\"x\") }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
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
	keys = nil
	for _, w := range scanFileWrites(t, root, []string{"internal/pki"}) {
		keys = append(keys, w.key)
	}
	if want := []string{"internal/pki/h.go:save:pki.writeFileAtomic#1"}; !slices.Equal(keys, want) {
		t.Fatalf("found %q, want %q", keys, want)
	}
}

// farmerPKIScanned are the farmer chart and UAT files TestNoFarmerPKIDir
// reads besides the scanned Go trees, from the repository root: every
// template, values file and CI values file of the chart.
var farmerPKIScanned = []string{
	"deploy/helm/farmer/templates",
	"deploy/helm/farmer/values.yaml",
	"deploy/helm/farmer/ci",
	"uat/hub/core/values/farmer-uat.yaml",
}

// TestNoFarmerPKIDir fails on any mention of farmer's old JWT directory
// (farmerPKIDir) in the scanned Go trees' non-test source, and on any
// mention of it or of the farmerpki key in the farmer chart and its UAT
// values: farmer keeps no JWT or key under /tmp/farmer/pki, nor anywhere
// else on disk (E3). Writes under it through a helper or an os call are
// caught by TestNoFileWrittenOutsideTmp; this catches the path itself.
func TestNoFarmerPKIDir(t *testing.T) {
	check := func(path string, needles ...string) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, n := range needles {
			if strings.Contains(string(b), n) {
				t.Errorf("%s mentions %q: farmer keeps nothing under %s", path, n, farmerPKIDir)
			}
		}
	}
	walk := func(dir string, keep func(string) bool, needles ...string) {
		err := filepath.WalkDir(filepath.Join(moduleRoot, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && keep(p) {
				check(p, needles...)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scanning %s: %v", dir, err)
		}
	}
	for _, dir := range scannedDirs {
		walk(dir, func(p string) bool { return strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") }, farmerPKIDir)
	}
	for _, p := range farmerPKIScanned {
		walk(p, func(string) bool { return true }, farmerPKIDir, "farmerpki")
	}
}
