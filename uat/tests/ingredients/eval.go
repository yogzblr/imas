package ingredients

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
)

// The registry is read from the source, not from a running sprout: most
// ingredient packages build for one OS only (winiis only on Windows,
// firewall only on Linux), so no single test binary can import them all.
// This file is a deliberately small interpreter for the shapes the
// ingredient packages use to describe themselves (Methods() and
// PropertiesForMethod(): constant and literal returns, switches on the
// method, package-level prop tables, append wrappers). Anything outside
// that subset is an error naming the construct, so a new shape fails the
// unit tests loudly instead of being misread.

// pkgSrc is one package's files for one GOOS, indexed by declaration.
type pkgSrc struct {
	path    string // import path
	dir     string
	goos    string
	fset    *token.FileSet
	files   []*ast.File
	imports map[*ast.File]map[string]string // local name -> import path
	consts  map[string]declRef
	vars    map[string]declRef
	funcs   map[string]funcRef            // package-level functions
	methods map[string]map[string]funcRef // receiver type -> name -> method
	imps    []string                      // imports of the package, all files
}

type declRef struct {
	expr ast.Expr
	file *ast.File
}

type funcRef struct {
	decl *ast.FuncDecl
	file *ast.File
}

// srcLoader loads and caches packages of the module for one GOOS.
type srcLoader struct {
	root string
	goos string
	ctx  build.Context
	pkgs map[string]*pkgSrc
}

func newLoader(root, goos string) *srcLoader {
	ctx := build.Default
	ctx.GOOS = goos
	ctx.GOARCH = "amd64"
	ctx.CgoEnabled = false // the sprout is built CGO-free (CLAUDE.md)
	ctx.BuildTags = nil
	ctx.Dir = root
	return &srcLoader{root: root, goos: goos, ctx: ctx, pkgs: map[string]*pkgSrc{}}
}

// inModule reports whether an import path is a package of this module.
func inModule(path string) bool {
	return path == ModulePath || strings.HasPrefix(path, ModulePath+"/")
}

// load parses a package of the module with the loader's GOOS build
// constraints applied (file name suffixes and //go:build lines).
func (l *srcLoader) load(path string) (*pkgSrc, error) {
	if p, ok := l.pkgs[path]; ok {
		return p, nil
	}
	if !inModule(path) {
		return nil, fmt.Errorf("%s is outside module %s", path, ModulePath)
	}
	dir := filepath.Join(l.root, filepath.FromSlash(strings.TrimPrefix(strings.TrimPrefix(path, ModulePath), "/")))
	bp, err := l.ctx.ImportDir(dir, 0)
	if err != nil {
		var noGo *build.NoGoError
		if errors.As(err, &noGo) {
			p := &pkgSrc{path: path, dir: dir, goos: l.goos, fset: token.NewFileSet()}
			p.index()
			l.pkgs[path] = p
			return p, nil
		}
		return nil, fmt.Errorf("%s (GOOS=%s): %w", path, l.goos, err)
	}
	p := &pkgSrc{path: path, dir: dir, goos: l.goos, fset: token.NewFileSet()}
	for _, name := range bp.GoFiles {
		f, err := parser.ParseFile(p.fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		p.files = append(p.files, f)
	}
	p.imps = bp.Imports
	p.index()
	l.pkgs[path] = p
	return p, nil
}

func (p *pkgSrc) index() {
	p.imports = map[*ast.File]map[string]string{}
	p.consts = map[string]declRef{}
	p.vars = map[string]declRef{}
	p.funcs = map[string]funcRef{}
	p.methods = map[string]map[string]funcRef{}
	for _, f := range p.files {
		im := map[string]string{}
		for _, is := range f.Imports {
			ip, _ := strconv.Unquote(is.Path.Value)
			name := ip[strings.LastIndex(ip, "/")+1:]
			if is.Name != nil {
				name = is.Name.Name
			}
			im[name] = ip
		}
		p.imports[f] = im
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				if d.Tok != token.CONST && d.Tok != token.VAR {
					continue
				}
				for _, s := range d.Specs {
					vs, ok := s.(*ast.ValueSpec)
					if !ok || len(vs.Values) != len(vs.Names) {
						continue
					}
					for i, n := range vs.Names {
						ref := declRef{expr: vs.Values[i], file: f}
						if d.Tok == token.CONST {
							p.consts[n.Name] = ref
						} else {
							p.vars[n.Name] = ref
						}
					}
				}
			case *ast.FuncDecl:
				ref := funcRef{decl: d, file: f}
				if d.Recv == nil || len(d.Recv.List) == 0 {
					p.funcs[d.Name.Name] = ref
					continue
				}
				recv := recvTypeName(d.Recv.List[0].Type)
				if p.methods[recv] == nil {
					p.methods[recv] = map[string]funcRef{}
				}
				p.methods[recv][d.Name.Name] = ref
			}
		}
	}
}

func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvTypeName(t.X)
	}
	return ""
}

// Values of the interpreter.
type (
	// errValue is any error a function returns; only its presence matters.
	errValue struct{}
	// recvValue is the receiver of an evaluated method: a zero value of
	// the registered type, except that reading its "method" field yields
	// the method being described (see interp.recvMethodRead).
	recvValue struct{ method string }
	// propValue is one ingredients.MethodProps.
	propValue Prop
)

// interp evaluates expressions and statements of the loaded packages.
type interp struct {
	l *srcLoader
	// recvMethodRead is set when an evaluated body read the receiver's
	// "method" field instead of its own argument.
	recvMethodRead bool
	depth          int
}

type frame struct {
	pkg  *pkgSrc
	file *ast.File
	vars map[string]any
}

func (in *interp) errf(fr *frame, n ast.Node, format string, args ...any) error {
	pos := ""
	if fr != nil && fr.pkg != nil && n != nil {
		p := fr.pkg.fset.Position(n.Pos())
		pos = fmt.Sprintf("%s:%d: ", filepath.Base(p.Filename), p.Line)
	}
	return fmt.Errorf("%s%s", pos, fmt.Sprintf(format, args...))
}

// call runs a function or method body with its parameters bound and
// returns its results.
func (in *interp) call(pkg *pkgSrc, fn funcRef, recv any, args []any) ([]any, error) {
	in.depth++
	defer func() { in.depth-- }()
	if in.depth > 32 {
		return nil, errors.New("call depth exceeded")
	}
	fr := &frame{pkg: pkg, file: fn.file, vars: map[string]any{}}
	d := fn.decl
	if d.Recv != nil && len(d.Recv.List) > 0 && len(d.Recv.List[0].Names) > 0 {
		fr.vars[d.Recv.List[0].Names[0].Name] = recv
	}
	i := 0
	for _, field := range d.Type.Params.List {
		for _, n := range field.Names {
			if i < len(args) {
				fr.vars[n.Name] = args[i]
			}
			i++
		}
	}
	if d.Body == nil {
		return nil, in.errf(fr, d, "%s has no body", d.Name.Name)
	}
	done, res, err := in.block(fr, d.Body.List)
	if err != nil {
		return nil, err
	}
	if !done {
		return nil, in.errf(fr, d, "%s ended without a return the interpreter could follow", d.Name.Name)
	}
	return res, nil
}

func (in *interp) block(fr *frame, stmts []ast.Stmt) (bool, []any, error) {
	for _, s := range stmts {
		done, res, err := in.stmt(fr, s)
		if err != nil || done {
			return done, res, err
		}
	}
	return false, nil, nil
}

func (in *interp) stmt(fr *frame, s ast.Stmt) (bool, []any, error) {
	switch s := s.(type) {
	case *ast.ReturnStmt:
		var out []any
		for _, e := range s.Results {
			v, err := in.expr(fr, e, nil)
			if err != nil {
				return false, nil, err
			}
			out = append(out, v)
		}
		return true, out, nil
	case *ast.BlockStmt:
		return in.block(fr, s.List)
	case *ast.ExprStmt:
		return false, nil, nil // logging and the like
	case *ast.AssignStmt:
		return false, nil, in.assign(fr, s)
	case *ast.DeclStmt:
		gd, ok := s.Decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			return false, nil, in.errf(fr, s, "unsupported declaration")
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, n := range vs.Names {
				var v any
				if i < len(vs.Values) {
					var err error
					if v, err = in.expr(fr, vs.Values[i], nil); err != nil {
						return false, nil, err
					}
				}
				fr.vars[n.Name] = v
			}
		}
		return false, nil, nil
	case *ast.IfStmt:
		if s.Init != nil {
			if _, _, err := in.stmt(fr, s.Init); err != nil {
				return false, nil, err
			}
		}
		c, err := in.expr(fr, s.Cond, nil)
		if err != nil {
			return false, nil, err
		}
		b, ok := c.(bool)
		if !ok {
			return false, nil, in.errf(fr, s.Cond, "if condition is %T, not bool", c)
		}
		if b {
			return in.block(fr, s.Body.List)
		}
		if s.Else != nil {
			return in.stmt(fr, s.Else)
		}
		return false, nil, nil
	case *ast.SwitchStmt:
		if s.Init != nil {
			if _, _, err := in.stmt(fr, s.Init); err != nil {
				return false, nil, err
			}
		}
		var tag any = true
		if s.Tag != nil {
			var err error
			if tag, err = in.expr(fr, s.Tag, nil); err != nil {
				return false, nil, err
			}
		}
		var def *ast.CaseClause
		for _, c := range s.Body.List {
			cc := c.(*ast.CaseClause)
			if cc.List == nil {
				def = cc
				continue
			}
			for _, e := range cc.List {
				v, err := in.expr(fr, e, nil)
				if err != nil {
					return false, nil, err
				}
				if same(v, tag) {
					return in.block(fr, cc.Body)
				}
			}
		}
		if def != nil {
			return in.block(fr, def.Body)
		}
		return false, nil, nil
	}
	return false, nil, in.errf(fr, s, "unsupported statement %T", s)
}

func (in *interp) assign(fr *frame, s *ast.AssignStmt) error {
	if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
		return in.errf(fr, s, "unsupported assignment %s", s.Tok)
	}
	set := func(e ast.Expr, v any) error {
		id, ok := e.(*ast.Ident)
		if !ok {
			return in.errf(fr, e, "assignment to %T", e)
		}
		if id.Name != "_" {
			fr.vars[id.Name] = v
		}
		return nil
	}
	if len(s.Lhs) == 2 && len(s.Rhs) == 1 {
		ie, ok := s.Rhs[0].(*ast.IndexExpr)
		if !ok {
			return in.errf(fr, s, "unsupported two-value assignment")
		}
		m, err := in.expr(fr, ie.X, nil)
		if err != nil {
			return err
		}
		k, err := in.expr(fr, ie.Index, nil)
		if err != nil {
			return err
		}
		mm, ok := m.(map[string]any)
		if !ok {
			return in.errf(fr, ie, "index of %T", m)
		}
		ks, _ := k.(string)
		v, found := mm[ks]
		if err := set(s.Lhs[0], v); err != nil {
			return err
		}
		return set(s.Lhs[1], found)
	}
	if len(s.Lhs) != len(s.Rhs) {
		return in.errf(fr, s, "unsupported assignment of %d values to %d names", len(s.Rhs), len(s.Lhs))
	}
	for i := range s.Lhs {
		v, err := in.expr(fr, s.Rhs[i], nil)
		if err != nil {
			return err
		}
		if err := set(s.Lhs[i], v); err != nil {
			return err
		}
	}
	return nil
}

// global evaluates a package-level constant or variable.
func (in *interp) global(pkg *pkgSrc, name string, at ast.Node, fr *frame) (any, error) {
	if ref, ok := pkg.consts[name]; ok {
		return in.expr(&frame{pkg: pkg, file: ref.file, vars: map[string]any{}}, ref.expr, nil)
	}
	if ref, ok := pkg.vars[name]; ok {
		return in.expr(&frame{pkg: pkg, file: ref.file, vars: map[string]any{}}, ref.expr, nil)
	}
	return nil, in.errf(fr, at, "unknown name %s in %s", name, pkg.path)
}

// typeName is the last name of a type expression (ingredients.MethodPropsSet
// -> MethodPropsSet), or "" for a composite type.
func typeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

// expr evaluates an expression. elided is the type of a composite literal
// whose type was left out (the elements of a map or slice literal).
func (in *interp) expr(fr *frame, e ast.Expr, elided ast.Expr) (any, error) {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return in.expr(fr, e.X, elided)
	case *ast.BasicLit:
		switch e.Kind {
		case token.STRING:
			return strconv.Unquote(e.Value)
		case token.INT:
			return strconv.Atoi(e.Value)
		}
		return nil, in.errf(fr, e, "unsupported literal %s", e.Value)
	case *ast.Ident:
		if v, ok := fr.vars[e.Name]; ok {
			return v, nil
		}
		switch e.Name {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "nil":
			return nil, nil
		}
		return in.global(fr.pkg, e.Name, e, fr)
	case *ast.SelectorExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			if _, local := fr.vars[id.Name]; !local {
				if ip, isImport := fr.pkg.imports[fr.file][id.Name]; isImport {
					if !inModule(ip) {
						return nil, in.errf(fr, e, "%s.%s is outside the module", id.Name, e.Sel.Name)
					}
					other, err := in.l.load(ip)
					if err != nil {
						return nil, err
					}
					return in.global(other, e.Sel.Name, e, fr)
				}
			}
		}
		x, err := in.expr(fr, e.X, nil)
		if err != nil {
			return nil, err
		}
		if r, ok := x.(recvValue); ok && e.Sel.Name == "method" {
			in.recvMethodRead = true
			return r.method, nil
		}
		return nil, in.errf(fr, e, "unsupported selector .%s on %T", e.Sel.Name, x)
	case *ast.UnaryExpr:
		x, err := in.expr(fr, e.X, nil)
		if err != nil {
			return nil, err
		}
		switch e.Op {
		case token.NOT:
			b, ok := x.(bool)
			if !ok {
				return nil, in.errf(fr, e, "! of %T", x)
			}
			return !b, nil
		case token.AND:
			return x, nil
		}
		return nil, in.errf(fr, e, "unsupported unary %s", e.Op)
	case *ast.BinaryExpr:
		x, err := in.expr(fr, e.X, nil)
		if err != nil {
			return nil, err
		}
		if e.Op == token.LAND || e.Op == token.LOR {
			xb, ok := x.(bool)
			if !ok {
				return nil, in.errf(fr, e, "%s of %T", e.Op, x)
			}
			if (e.Op == token.LAND && !xb) || (e.Op == token.LOR && xb) {
				return xb, nil
			}
		}
		y, err := in.expr(fr, e.Y, nil)
		if err != nil {
			return nil, err
		}
		switch e.Op {
		case token.EQL:
			return same(x, y), nil
		case token.NEQ:
			return !same(x, y), nil
		case token.LAND, token.LOR:
			yb, ok := y.(bool)
			if !ok {
				return nil, in.errf(fr, e, "%s of %T", e.Op, y)
			}
			return yb, nil
		case token.ADD:
			xs, ok1 := x.(string)
			ys, ok2 := y.(string)
			if ok1 && ok2 {
				return xs + ys, nil
			}
		}
		return nil, in.errf(fr, e, "unsupported binary %s", e.Op)
	case *ast.IndexExpr:
		m, err := in.expr(fr, e.X, nil)
		if err != nil {
			return nil, err
		}
		k, err := in.expr(fr, e.Index, nil)
		if err != nil {
			return nil, err
		}
		mm, ok := m.(map[string]any)
		if !ok {
			return nil, in.errf(fr, e, "index of %T", m)
		}
		ks, _ := k.(string)
		return mm[ks], nil
	case *ast.CompositeLit:
		return in.composite(fr, e, elided)
	case *ast.CallExpr:
		return in.callExpr(fr, e)
	}
	return nil, in.errf(fr, e, "unsupported expression %T", e)
}

func (in *interp) composite(fr *frame, e *ast.CompositeLit, elided ast.Expr) (any, error) {
	t := e.Type
	if t == nil {
		t = elided
	}
	if t == nil {
		return nil, in.errf(fr, e, "composite literal of unknown type")
	}
	switch tn := typeName(t); tn {
	case "MethodProps":
		p := propValue{}
		for _, el := range e.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				return nil, in.errf(fr, el, "MethodProps without field names")
			}
			key, _ := kv.Key.(*ast.Ident)
			if key == nil {
				return nil, in.errf(fr, kv, "MethodProps field")
			}
			v, err := in.expr(fr, kv.Value, nil)
			if err != nil {
				return nil, err
			}
			switch key.Name {
			case "Key":
				p.Key, _ = v.(string)
			case "Type":
				p.Type, _ = v.(string)
			case "IsReq":
				p.Required, _ = v.(bool)
			case "Description":
				p.Description, _ = v.(string)
			}
		}
		return p, nil
	case "MethodPropsSet":
		out := []Prop{}
		for _, el := range e.Elts {
			v, err := in.expr(fr, el, &ast.Ident{Name: "MethodProps"})
			if err != nil {
				return nil, err
			}
			p, ok := v.(propValue)
			if !ok {
				return nil, in.errf(fr, el, "MethodPropsSet element %T", v)
			}
			out = append(out, Prop(p))
		}
		return out, nil
	case "":
	default:
		// A struct literal of the registered type (T{}).
		return recvValue{}, nil
	}
	switch t := t.(type) {
	case *ast.MapType:
		out := map[string]any{}
		for _, el := range e.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				return nil, in.errf(fr, el, "map element without a key")
			}
			k, err := in.expr(fr, kv.Key, nil)
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, in.errf(fr, kv.Key, "map key %T", k)
			}
			v, err := in.expr(fr, kv.Value, t.Value)
			if err != nil {
				return nil, err
			}
			out[ks] = v
		}
		return out, nil
	case *ast.ArrayType:
		if typeName(t.Elt) == "MethodProps" {
			return in.composite(fr, &ast.CompositeLit{Type: &ast.Ident{Name: "MethodPropsSet"}, Elts: e.Elts}, nil)
		}
		var out []any
		for _, el := range e.Elts {
			v, err := in.expr(fr, el, t.Elt)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, in.errf(fr, e, "unsupported composite literal %T", t)
}

func (in *interp) callExpr(fr *frame, e *ast.CallExpr) (any, error) {
	switch fn := e.Fun.(type) {
	case *ast.SelectorExpr:
		if id, ok := fn.X.(*ast.Ident); ok {
			if ip, isImport := fr.pkg.imports[fr.file][id.Name]; isImport {
				if _, local := fr.vars[id.Name]; !local {
					switch ip {
					case "errors", "fmt":
						return errValue{}, nil
					}
					return nil, in.errf(fr, e, "unsupported call %s.%s", id.Name, fn.Sel.Name)
				}
			}
		}
		if fn.Sel.Name == "ToMap" && len(e.Args) == 0 {
			x, err := in.expr(fr, fn.X, nil)
			if err != nil {
				return nil, err
			}
			if _, ok := x.([]Prop); !ok {
				return nil, in.errf(fr, e, "ToMap on %T", x)
			}
			return x, nil
		}
		return nil, in.errf(fr, e, "unsupported method call .%s", fn.Sel.Name)
	case *ast.Ident:
		if fn.Name == "append" {
			if len(e.Args) == 0 {
				return nil, in.errf(fr, e, "append without arguments")
			}
			base, err := in.expr(fr, e.Args[0], nil)
			if err != nil {
				return nil, err
			}
			for i, a := range e.Args[1:] {
				v, err := in.expr(fr, a, nil)
				if err != nil {
					return nil, err
				}
				spread := e.Ellipsis.IsValid() && i == len(e.Args)-2
				switch b := base.(type) {
				case []Prop:
					cp := append([]Prop(nil), b...)
					if spread {
						vs, ok := v.([]Prop)
						if !ok {
							return nil, in.errf(fr, a, "append of %T", v)
						}
						base = append(cp, vs...)
					} else {
						p, ok := v.(propValue)
						if !ok {
							return nil, in.errf(fr, a, "append of %T", v)
						}
						base = append(cp, Prop(p))
					}
				case []any:
					cp := append([]any(nil), b...)
					if spread {
						vs, ok := v.([]any)
						if !ok {
							return nil, in.errf(fr, a, "append of %T", v)
						}
						base = append(cp, vs...)
					} else {
						base = append(cp, v)
					}
				default:
					return nil, in.errf(fr, e, "append to %T", base)
				}
			}
			return base, nil
		}
		if ref, ok := fr.pkg.funcs[fn.Name]; ok {
			var args []any
			for _, a := range e.Args {
				v, err := in.expr(fr, a, nil)
				if err != nil {
					return nil, err
				}
				args = append(args, v)
			}
			res, err := in.call(fr.pkg, ref, nil, args)
			if err != nil {
				return nil, err
			}
			if len(res) == 0 {
				return nil, nil
			}
			return res[0], nil
		}
	}
	return nil, in.errf(fr, e, "unsupported call")
}

// same is == for the interpreter's comparable values (strings, bools,
// ints, nil); slices, maps and anything else are never equal.
func same(a, b any) bool {
	switch a.(type) {
	case string, bool, int, nil:
	default:
		return false
	}
	switch b.(type) {
	case string, bool, int, nil:
	default:
		return false
	}
	return a == b
}
