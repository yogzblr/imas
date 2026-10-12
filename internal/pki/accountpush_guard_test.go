package pki

// Source guards for the farmer account publisher (docs/briefs/
// E-followups.md, E6): every Account JWT that reaches the bus goes through
// pushAccountUpdate, and every Account JWT re-sign waits for a newer iat.
// Both read the source, so a new code path that breaks either rule fails
// here before it can reach a bus.

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

// repoRoot is the module root relative to this package's directory.
const repoRoot = "../.."

// parsedFile is one non-test Go file of the module.
type parsedFile struct {
	path string // from the module root, slash-separated
	fset *token.FileSet
	file *ast.File
}

// parseSources parses every non-test Go file under the module root's dirs
// (all of it when dirs is empty), skipping vendored and chart trees.
func parseSources(t *testing.T, dirs ...string) []parsedFile {
	t.Helper()
	if len(dirs) == 0 {
		dirs = []string{"."}
	}
	var out []parsedFile
	for _, d := range dirs {
		root := filepath.Join(repoRoot, d)
		err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() {
				switch e.Name() {
				case ".git", "vendor", "node_modules", "charts", "testdata":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(repoRoot, path)
			out = append(out, parsedFile{path: filepath.ToSlash(rel), fset: fset, file: f})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no Go source found under %v", dirs)
	}
	return out
}

// enclosing names the top-level declaration holding pos: a func as name or
// Type.Method, a const or var by its first name.
func enclosing(f *ast.File, pos token.Pos) string {
	for _, d := range f.Decls {
		if pos < d.Pos() || pos >= d.End() {
			continue
		}
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv != nil && len(d.Recv.List) == 1 {
				typ := d.Recv.List[0].Type
				if s, ok := typ.(*ast.StarExpr); ok {
					typ = s.X
				}
				if id, ok := typ.(*ast.Ident); ok {
					return id.Name + "." + d.Name.Name
				}
			}
			return d.Name.Name
		case *ast.GenDecl:
			for _, sp := range d.Specs {
				if vs, ok := sp.(*ast.ValueSpec); ok && pos >= vs.Pos() && pos < vs.End() {
					return vs.Names[0].Name
				}
			}
		}
	}
	return ""
}

// TestNoAccountJWTReachesBusWithoutPublisher fails if any code sends an
// Account JWT to the bus resolver ($SYS.REQ.CLAIMS.UPDATE) other than
// through pushAccountUpdate, where the installed AccountPublisher writes
// the accounts bucket before the push (§7.3). Search gate: CLAIMS.UPDATE.
//
// The only literals of the subject allowed are the ones below. In
// internal/pki the subject constant may be used only by pushToAllNodes,
// which only pushAccountUpdate (no publisher: the in-process test bus) and
// the publisher's own bus (natsAccountBus.pushAll, after the bucket write)
// call, and that bus's pushAll only by the publisher's pushAndAnnounce.
func TestNoAccountJWTReachesBusWithoutPublisher(t *testing.T) {
	allowedLiteral := map[string]string{
		// The subject constant pushToAllNodes uses.
		"internal/pki/resolver.go:claimsUpdateSubject": "",
		// A permission grant to the bus loader's SYS user, not a push.
		"internal/pki/natstrust.go:BusLoaderUserPermissions": "",
		// The bus-side account loader (cmd/farmerbus-loader): it pushes
		// to its own node only what it read from the accounts bucket.
		"internal/accountloader/node.go:claimsUpdateSubj": "",
		// The load-test fixture's bus, never linked into farmer.
		"tools/loadtest/fixture.go:claimsUpdateSubject": "",
	}
	// pkg-qualified identifiers and the declarations allowed to use them.
	allowedUse := map[string][]string{
		"claimsUpdateSubject": {"pushToAllNodes"},
		"pushToAllNodes":      {"pushAccountUpdate", "natsAccountBus.pushAll"},
		"pushAll":             {"natsAccountBus.pushAll", "s3AccountPublisher.pushAndAnnounce"},
		// The loader's node client: the loader binary only.
		"accountloader.DialNode": {"cmd/farmerbus-loader"},
		"accountloader.New":      {"cmd/farmerbus-loader"},
	}

	seen := map[string]bool{}
	for _, pf := range parseSources(t) {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BasicLit:
				if n.Kind != token.STRING {
					return true
				}
				v, err := strconv.Unquote(n.Value)
				if err != nil || !strings.Contains(v, "CLAIMS.UPDATE") {
					return true
				}
				key := pf.path + ":" + enclosing(pf.file, n.Pos())
				if _, ok := allowedLiteral[key]; !ok {
					t.Errorf("%s: %q outside pushAccountUpdate's path (%s); send Account JWTs through pushAccountUpdate", pf.fset.Position(n.Pos()), v, key)
				}
				seen[key] = true
			case *ast.SelectorExpr:
				if x, ok := n.X.(*ast.Ident); ok && x.Name == "accountloader" {
					name := "accountloader." + n.Sel.Name
					if dirs, ok := allowedUse[name]; ok && !slices.ContainsFunc(dirs, func(d string) bool { return strings.HasPrefix(pf.path, d+"/") }) {
						t.Errorf("%s: %s outside %v: only the bus loader pushes from the bucket", pf.fset.Position(n.Pos()), name, dirs)
					}
				}
				if strings.HasPrefix(pf.path, "internal/pki/") && n.Sel.Name == "pushAll" {
					checkUse(t, pf, n.Sel, "pushAll", allowedUse["pushAll"])
				}
			case *ast.Ident:
				if !strings.HasPrefix(pf.path, "internal/pki/") {
					return true
				}
				if allowed, ok := allowedUse[n.Name]; ok && n.Name != "pushAll" {
					checkUse(t, pf, n, n.Name, allowed)
				}
			}
			return true
		})
	}
	for k := range allowedLiteral {
		if !seen[k] {
			t.Errorf("allowed CLAIMS.UPDATE literal %s no longer exists; drop it from the list", k)
		}
	}
}

// checkUse fails unless id, a use (or the declaration) of name, is inside
// one of the allowed declarations.
func checkUse(t *testing.T, pf parsedFile, id *ast.Ident, name string, allowed []string) {
	t.Helper()
	in := enclosing(pf.file, id.Pos())
	if in == name || slices.Contains(allowed, in) {
		return
	}
	t.Errorf("%s: %s used in %s; only %v may, so every Account JWT goes through pushAccountUpdate", pf.fset.Position(id.Pos()), name, in, allowed)
}

// TestEveryAccountResignWaitsPastIssuedAt is TestEveryResignAdvancesIat's
// source half: every Account JWT signed in internal/pki (an Encode with
// the operator signing key) must call waitPastIssuedAt on the claims it
// signs, before the Encode, unless the claims are minted fresh in that
// function (jwt.NewAccountClaims only), which replace nothing. A re-sign
// in the same second as the JWT it replaces has the same jti, and the bus
// loaders would read it as the JWT they already hold.
func TestEveryAccountResignWaitsPastIssuedAt(t *testing.T) {
	checked := 0
	for _, pf := range parseSources(t, "internal/pki") {
		if strings.Count(strings.TrimPrefix(pf.path, "internal/pki/"), "/") > 0 {
			continue // subpackages sign no Account JWT
		}
		for _, d := range pf.file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, enc := range accountEncodes(fn) {
				checked++
				recv := enc.Fun.(*ast.SelectorExpr).X.(*ast.Ident).Name
				if mintedFresh(fn, recv, enc.Pos()) {
					continue
				}
				if !waitsBefore(fn, recv, enc.Pos()) {
					t.Errorf("%s: %s re-signs %s without waitPastIssuedAt(%s.IssuedAt) before the Encode",
						pf.fset.Position(enc.Pos()), fn.Name.Name, recv, recv)
				}
			}
		}
	}
	// jwtauth.go, jwtusers.go, tenant.go (three), saasapi_user.go, enroll.go.
	if checked < 7 {
		t.Fatalf("found %d Account JWT signs, want at least 7: the guard no longer sees them", checked)
	}
}

// accountEncodes returns fn's calls X.Encode(....operatorSigningKP) with X
// an identifier: the Account JWT signs.
func accountEncodes(fn *ast.FuncDecl) []*ast.CallExpr {
	var out []*ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || len(c.Args) != 1 {
			return true
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Encode" {
			return true
		}
		if _, ok := sel.X.(*ast.Ident); !ok {
			return true
		}
		if key, ok := c.Args[0].(*ast.SelectorExpr); ok && key.Sel.Name == "operatorSigningKP" {
			out = append(out, c)
		}
		return true
	})
	return out
}

// mintedFresh reports whether name, at pos, holds claims minted fresh
// in fn: its definition in scope there is name := jwt.NewAccountClaims(...)
// (or var name = ...), and nothing assigns name again between that
// definition and pos. A parameter is never fresh.
func mintedFresh(fn *ast.FuncDecl, name string, pos token.Pos) bool {
	for _, f := range fn.Type.Params.List {
		for _, n := range f.Names {
			if n.Name == name {
				return false
			}
		}
	}
	type def struct {
		at, scopeEnd token.Pos
		fresh        bool
	}
	var defs []def
	var reassigned []token.Pos
	var scopes []ast.Node // the enclosing scope nodes of the node visited
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil {
			scopes = scopes[:len(scopes)-1]
			return true
		}
		scope := n
		if len(scopes) > 0 {
			switch n.(type) {
			case *ast.BlockStmt, *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt,
				*ast.TypeSwitchStmt, *ast.CaseClause, *ast.CommClause:
			default:
				scope = scopes[len(scopes)-1]
			}
		}
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range n.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name != name {
					continue
				}
				fresh := len(n.Rhs) == len(n.Lhs) && isCall(n.Rhs[i], "jwt", "NewAccountClaims")
				if n.Tok == token.DEFINE {
					defs = append(defs, def{at: n.Pos(), scopeEnd: scope.End(), fresh: fresh})
				} else {
					reassigned = append(reassigned, n.Pos())
				}
			}
		case *ast.ValueSpec:
			for i, id := range n.Names {
				if id.Name == name {
					fresh := i < len(n.Values) && isCall(n.Values[i], "jwt", "NewAccountClaims")
					defs = append(defs, def{at: n.Pos(), scopeEnd: scope.End(), fresh: fresh})
				}
			}
		}
		scopes = append(scopes, scope)
		return true
	})
	var in *def
	for i := range defs {
		d := &defs[i]
		if d.at < pos && pos < d.scopeEnd && (in == nil || d.at > in.at) {
			in = d
		}
	}
	if in == nil || !in.fresh {
		return false
	}
	for _, r := range reassigned {
		if r > in.at && r < pos {
			return false
		}
	}
	return true
}

func isCall(e ast.Expr, pkg, name string) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == pkg
}

// waitsBefore reports whether fn calls waitPastIssuedAt(name.IssuedAt)
// before pos.
func waitsBefore(fn *ast.FuncDecl, name string, pos token.Pos) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || c.Pos() >= pos || len(c.Args) != 1 {
			return true
		}
		if id, ok := c.Fun.(*ast.Ident); !ok || id.Name != "waitPastIssuedAt" {
			return true
		}
		if sel, ok := c.Args[0].(*ast.SelectorExpr); ok && sel.Sel.Name == "IssuedAt" {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == name {
				found = true
			}
		}
		return true
	})
	return found
}

// The guards' own premise: the module root is where they look.
func TestGuardsSeeTheModule(t *testing.T) {
	if _, err := os.Stat(filepath.Join(repoRoot, "go.mod")); err != nil {
		t.Fatalf("module root not at %s: %v", repoRoot, err)
	}
}
