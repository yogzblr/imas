package ingredients

import (
	"errors"
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ModulePath is the Go module the registry is read from.
const ModulePath = "github.com/yogzblr/imas"

// SproutPackage is the binary whose imports decide which ingredients a
// sprout of each platform registers (cmd/sprout/include*.go).
const SproutPackage = ModulePath + "/cmd/sprout"

// Platforms the registry is read for, as GOOS values.
const (
	GOOSLinux   = "linux"
	GOOSWindows = "windows"
)

// Platforms lists them in report order.
var Platforms = []string{GOOSLinux, GOOSWindows}

// OSesOf maps a GOOS to the UAT sprout OSes that run it (uat.json's os
// values: Ubuntu 24.04 and AlmaLinux 9 for linux, Windows Server 2022 Core
// for windows).
var OSesOf = map[string][]string{
	GOOSLinux:   {"ubuntu", "alma"},
	GOOSWindows: {"windows"},
}

// GOOSOf is the GOOS of a UAT sprout OS.
func GOOSOf(os string) string {
	if os == "windows" {
		return GOOSWindows
	}
	return GOOSLinux
}

// Prop is one property a method declares in PropertiesForMethod.
type Prop struct {
	Key         string
	Type        string
	Required    bool
	Description string
}

// Method is one registered ingredient method: what a recipe names as
// <ingredient>.<method>.
type Method struct {
	Ingredient string
	Method     string
	// GOOS lists the platforms whose sprout registers it.
	GOOS []string
	// Package and Type are the registering package and the type passed
	// to ingredients.RegisterAllMethods.
	Package string
	Type    string
	// Props are the declared properties, in declaration order; PropsNote
	// says why they could not be read, or what is odd about them.
	Props     []Prop
	PropsNote string
}

// ID is the conformance case id, I.<ingredient>.<method>.
func (m Method) ID() string { return "I." + m.Ingredient + "." + m.Method }

// OSes are the UAT sprout OSes the method applies to.
func (m Method) OSes() []string {
	var out []string
	for _, g := range m.GOOS {
		out = append(out, OSesOf[g]...)
	}
	return out
}

// Backend is an entry of one of the registries ingredients delegate to:
// the sdb:// secret backends and the file source protocols.
type Backend struct {
	Registry string // "sdb" or "file source"
	Name     string
	GOOS     []string
	Package  string
}

// Registry is every registered method on every platform.
type Registry struct {
	Methods  []Method
	Backends []Backend
	// Unreachable are methods registered by a package under
	// internal/ingredients that cmd/sprout doesn't import on any platform:
	// a recipe naming them fails with "unknown ingredient" on every sprout.
	Unreachable []Method
	byID        map[string]*Method
}

// Get returns a method by case id.
func (r *Registry) Get(id string) (*Method, bool) {
	m, ok := r.byID[id]
	return m, ok
}

// NewRegistry builds a Registry from methods (and backends), sorting both
// and merging a method registered on several platforms into one entry.
// LoadRegistry uses it; tests build fake registries with it.
func NewRegistry(methods []Method, backends []Backend) *Registry {
	r := &Registry{}
	idx := map[string]int{}
	for _, m := range methods {
		if i, ok := idx[m.ID()]; ok {
			prev := &r.Methods[i]
			prev.GOOS = mergeSorted(prev.GOOS, m.GOOS)
			if prev.PropsNote == "" && len(prev.Props) == 0 {
				prev.Props, prev.PropsNote = m.Props, m.PropsNote
			}
			continue
		}
		m.GOOS = mergeSorted(nil, m.GOOS)
		idx[m.ID()] = len(r.Methods)
		r.Methods = append(r.Methods, m)
	}
	sort.Slice(r.Methods, func(i, j int) bool { return r.Methods[i].ID() < r.Methods[j].ID() })
	r.byID = map[string]*Method{}
	for i := range r.Methods {
		r.byID[r.Methods[i].ID()] = &r.Methods[i]
	}
	bidx := map[string]int{}
	for _, b := range backends {
		k := b.Registry + "\x00" + b.Name
		if i, ok := bidx[k]; ok {
			r.Backends[i].GOOS = mergeSorted(r.Backends[i].GOOS, b.GOOS)
			continue
		}
		b.GOOS = mergeSorted(nil, b.GOOS)
		bidx[k] = len(r.Backends)
		r.Backends = append(r.Backends, b)
	}
	sort.Slice(r.Backends, func(i, j int) bool {
		if r.Backends[i].Registry != r.Backends[j].Registry {
			return r.Backends[i].Registry < r.Backends[j].Registry
		}
		return r.Backends[i].Name < r.Backends[j].Name
	})
	return r
}

func mergeSorted(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range append(append([]string(nil), a...), b...) {
		set[s] = true
	}
	var out []string
	for _, p := range Platforms {
		if set[p] {
			out = append(out, p)
			delete(set, p)
		}
	}
	for s := range set {
		out = append(out, s)
	}
	return out
}

// FindRoot walks up from the working directory to the module's go.mod.
func FindRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && strings.Contains(string(b), "module "+ModulePath+"\n") {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod for %s above the working directory", ModulePath)
		}
		dir = parent
	}
}

// LoadRegistry reads, from the source under root, every ingredient method
// a sprout registers on each platform: the packages cmd/sprout imports
// for that GOOS (transitively, within the module), every
// ingredients.RegisterAllMethods(T{}) call in their init functions, and
// T's Methods() and PropertiesForMethod(). It also lists the sdb backends
// and file source protocols registered the same way.
func LoadRegistry(root string) (*Registry, error) {
	var methods []Method
	var backends []Backend
	reached := map[string]bool{}
	for _, goos := range Platforms {
		l := newLoader(root, goos)
		pkgs, err := closure(l, SproutPackage)
		if err != nil {
			return nil, err
		}
		found := 0
		for _, p := range pkgs {
			reached[p.path] = true
			ms, bs, err := registrations(l, p)
			if err != nil {
				return nil, fmt.Errorf("GOOS=%s %s: %w", goos, p.path, err)
			}
			found += len(ms)
			methods = append(methods, ms...)
			backends = append(backends, bs...)
		}
		if found == 0 {
			return nil, fmt.Errorf("GOOS=%s: no ingredient registrations found from %s", goos, SproutPackage)
		}
	}
	r := NewRegistry(methods, backends)
	unreachable, err := unreachableMethods(root, reached)
	if err != nil {
		return nil, err
	}
	r.Unreachable = NewRegistry(unreachable, nil).Methods
	return r, nil
}

// unreachableMethods lists the methods registered by packages under
// internal/ingredients that no platform's sprout imports.
func unreachableMethods(root string, reached map[string]bool) ([]Method, error) {
	base := filepath.Join(root, "internal", "ingredients")
	var dirs []string
	err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if d.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var out []Method
	for _, goos := range Platforms {
		l := newLoader(root, goos)
		for _, dir := range dirs {
			rel, _ := filepath.Rel(root, dir)
			ip := ModulePath + "/" + filepath.ToSlash(rel)
			if reached[ip] {
				continue
			}
			p, err := l.load(ip)
			if err != nil {
				return nil, err
			}
			ms, _, err := registrations(l, p)
			if err != nil {
				return nil, fmt.Errorf("GOOS=%s %s: %w", goos, ip, err)
			}
			out = append(out, ms...)
		}
	}
	return out, nil
}

// closure returns the module packages reachable from start for the
// loader's GOOS, in import path order.
func closure(l *srcLoader, start string) ([]*pkgSrc, error) {
	seen := map[string]bool{start: true}
	queue := []string{start}
	var out []*pkgSrc
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		p, err := l.load(path)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
		for _, ip := range p.imps {
			if inModule(ip) && !seen[ip] {
				seen[ip] = true
				queue = append(queue, ip)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

// registrations finds the registry calls in p's init functions.
func registrations(l *srcLoader, p *pkgSrc) ([]Method, []Backend, error) {
	var methods []Method
	var backends []Backend
	var errs []error
	for _, f := range p.files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name.Name != "init" || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
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
				ip := p.imports[f][id.Name]
				switch {
				case ip == ModulePath+"/internal/ingredients" && sel.Sel.Name == "RegisterAllMethods":
					ms, err := describe(l, p, f, call)
					if err != nil {
						errs = append(errs, err)
					}
					methods = append(methods, ms...)
				case ip == ModulePath+"/internal/ingredients/sdb" && sel.Sel.Name == "RegisterProvider" && len(call.Args) >= 1:
					in := &interp{l: l}
					v, err := in.expr(&frame{pkg: p, file: f, vars: map[string]any{}}, call.Args[0], nil)
					name, _ := v.(string)
					if err != nil || name == "" {
						errs = append(errs, fmt.Errorf("sdb backend name: %v", err))
						break
					}
					backends = append(backends, Backend{Registry: "sdb", Name: name, GOOS: []string{l.goos}, Package: p.path})
				case ip == ModulePath+"/internal/ingredients/file" && sel.Sel.Name == "RegisterProvider" && len(call.Args) == 1:
					protos, err := callMethodOfLiteral(l, p, call.Args[0], "Protocols")
					if err != nil {
						errs = append(errs, fmt.Errorf("file provider protocols: %w", err))
						break
					}
					for _, pr := range protos {
						if s, ok := pr.(string); ok {
							backends = append(backends, Backend{Registry: "file source", Name: s, GOOS: []string{l.goos}, Package: p.path})
						}
					}
				}
				return true
			})
		}
	}
	return methods, backends, errors.Join(errs...)
}

// literalType is T for an argument written T{} or &T{}.
func literalType(e ast.Expr) string {
	if u, ok := e.(*ast.UnaryExpr); ok {
		e = u.X
	}
	if cl, ok := e.(*ast.CompositeLit); ok {
		if id, ok := cl.Type.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

// callMethodOfLiteral evaluates T{}.<name>() for a literal argument and
// returns its first result as a list.
func callMethodOfLiteral(l *srcLoader, p *pkgSrc, arg ast.Expr, name string) ([]any, error) {
	t := literalType(arg)
	ref, ok := p.methods[t][name]
	if t == "" || !ok {
		return nil, fmt.Errorf("no %s method on %q", name, t)
	}
	in := &interp{l: l}
	res, err := in.call(p, ref, recvValue{}, nil)
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("%s.%s returned nothing", t, name)
	}
	list, ok := res[0].([]any)
	if !ok {
		return nil, fmt.Errorf("%s.%s returned %T", t, name, res[0])
	}
	return list, nil
}

// describe evaluates Methods() and PropertiesForMethod() of the type
// registered by one RegisterAllMethods call.
func describe(l *srcLoader, p *pkgSrc, f *ast.File, call *ast.CallExpr) ([]Method, error) {
	if len(call.Args) != 1 {
		return nil, fmt.Errorf("RegisterAllMethods with %d arguments", len(call.Args))
	}
	t := literalType(call.Args[0])
	if t == "" {
		return nil, fmt.Errorf("RegisterAllMethods argument is not a T{} literal")
	}
	mref, ok := p.methods[t]["Methods"]
	if !ok {
		return nil, fmt.Errorf("type %s has no Methods()", t)
	}
	in := &interp{l: l}
	res, err := in.call(p, mref, recvValue{}, nil)
	if err != nil {
		return nil, fmt.Errorf("%s.Methods(): %w", t, err)
	}
	if len(res) != 2 {
		return nil, fmt.Errorf("%s.Methods() returned %d values", t, len(res))
	}
	name, ok := res[0].(string)
	list, ok2 := res[1].([]any)
	if !ok || !ok2 || name == "" {
		return nil, fmt.Errorf("%s.Methods() returned %T, %T", t, res[0], res[1])
	}
	pref, hasProps := p.methods[t]["PropertiesForMethod"]
	var out []Method
	for _, mv := range list {
		mname, ok := mv.(string)
		if !ok || mname == "" {
			return nil, fmt.Errorf("%s.Methods() lists %T", t, mv)
		}
		m := Method{Ingredient: name, Method: mname, GOOS: []string{l.goos}, Package: p.path, Type: t}
		if !hasProps {
			m.PropsNote = "no PropertiesForMethod"
		} else {
			pin := &interp{l: l}
			r, err := pin.call(p, pref, recvValue{method: mname}, []any{mname})
			switch {
			case err != nil:
				m.PropsNote = "not read from the source: " + err.Error()
			case len(r) == 0:
				m.PropsNote = "PropertiesForMethod returned nothing"
			default:
				switch v := r[0].(type) {
				case []Prop:
					m.Props = v
				case map[string]any:
					m.Props = propsFromStringMap(v)
				case nil:
					if len(r) > 1 {
						if _, isErr := r[1].(errValue); isErr {
							m.PropsNote = "PropertiesForMethod returns an error for this method"
							break
						}
					}
					m.PropsNote = "declares no properties (PropertiesForMethod returns nil)"
				default:
					m.PropsNote = fmt.Sprintf("PropertiesForMethod returned %T", v)
				}
			}
			if pin.recvMethodRead {
				note := "PropertiesForMethod switches on the receiver's method field, not its argument: " + t + "{}.PropertiesForMethod(\"" + mname + "\") returns an error (finding)"
				if m.PropsNote != "" {
					note = m.PropsNote + "; " + note
				}
				m.PropsNote = note
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// propsFromStringMap reads the older "type,req" map form.
func propsFromStringMap(m map[string]any) []Prop {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Prop
	for _, k := range keys {
		s, _ := m[k].(string)
		typ, flag, _ := strings.Cut(s, ",")
		out = append(out, Prop{Key: k, Type: typ, Required: flag == "req"})
	}
	return out
}
