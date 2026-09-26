package saasapi

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestNewID(t *testing.T) {
	a, err := newID("t_")
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	b, err := newID("t_")
	if err != nil {
		t.Fatalf("newID: %v", err)
	}
	if !strings.HasPrefix(a, "t_") || !strings.HasPrefix(b, "t_") {
		t.Fatalf("expected t_ prefix, got %q and %q", a, b)
	}
	if a == b {
		t.Fatalf("expected two distinct random ids, got the same value twice: %q", a)
	}
	if strings.ToLower(a) != a {
		t.Fatalf("expected lowercase id, got %q", a)
	}
}

func TestNewEnrollmentSecret(t *testing.T) {
	a, err := newEnrollmentSecret()
	if err != nil {
		t.Fatalf("newEnrollmentSecret: %v", err)
	}
	b, err := newEnrollmentSecret()
	if err != nil {
		t.Fatalf("newEnrollmentSecret: %v", err)
	}
	if a == b {
		t.Fatalf("expected two distinct random secrets, got the same value twice")
	}
	// base64.RawURLEncoding of 32 bytes must not contain padding or
	// characters that would need URL-escaping.
	if strings.ContainsAny(a, "=+/") {
		t.Fatalf("secret contains non-URL-safe characters: %q", a)
	}
}

func TestHashSecret(t *testing.T) {
	secret := "some-secret-value"
	got := hashSecret(secret)

	want := sha256.Sum256([]byte(secret))
	wantHex := hex.EncodeToString(want[:])

	if got != wantHex {
		t.Fatalf("hashSecret(%q) = %q, want %q", secret, got, wantHex)
	}
	if got == secret {
		t.Fatalf("hashSecret must not return the raw secret")
	}

	other := hashSecret("a-different-secret")
	if other == got {
		t.Fatalf("expected different secrets to hash differently")
	}
}

// TestIdgenHasNoLoggingOrSecretBearingErrors pins the logging-safety
// comment at the top of idgen.go by parsing the file itself, so a
// well-meaning future debug line fails here instead of shipping. It
// checks that idgen.go:
//   - imports no logging package (internal/log, log, log/slog,
//     charmbracelet/log) and doesn't reference os (stdout/stderr);
//   - calls no print builtin and no fmt.Print*/Fprint*/Sprint* function;
//   - passes nothing but err as the arguments to fmt.Errorf, so a
//     returned error can never carry the secret, its bytes, or its hash
//     to whatever caller logs it.
func TestIdgenHasNoLoggingOrSecretBearingErrors(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "idgen.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing idgen.go: %v", err)
	}

	forbiddenImports := map[string]bool{
		"github.com/yogzblr/imas/internal/log": true,
		"log":                                  true,
		"log/slog":                             true,
		"github.com/charmbracelet/log":         true,
		"os":                                   true,
	}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatalf("unquoting import %s: %v", imp.Path.Value, err)
		}
		if forbiddenImports[path] {
			t.Errorf("%s: idgen.go imports %q; it handles raw enrollment secrets and must not log or write to stdout/stderr",
				fset.Position(imp.Pos()), path)
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		pos := fset.Position(call.Pos())
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "print" || fn.Name == "println" {
				t.Errorf("%s: idgen.go calls builtin %s", pos, fn.Name)
			}
		case *ast.SelectorExpr:
			pkg, ok := fn.X.(*ast.Ident)
			if !ok || pkg.Name != "fmt" {
				return true
			}
			if fn.Sel.Name != "Errorf" {
				t.Errorf("%s: idgen.go calls fmt.%s; only fmt.Errorf wrapping err is allowed", pos, fn.Sel.Name)
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			if _, ok := call.Args[0].(*ast.BasicLit); !ok {
				t.Errorf("%s: fmt.Errorf format must be a string literal", pos)
			}
			for _, arg := range call.Args[1:] {
				if id, ok := arg.(*ast.Ident); !ok || id.Name != "err" {
					t.Errorf("%s: fmt.Errorf in idgen.go may only wrap err, got another argument; an error can end up in a log line", pos)
				}
			}
		}
		return true
	})
}
