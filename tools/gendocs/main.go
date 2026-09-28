// Command gendocs walks internal/ingredients and regenerates the ingredient
// reference chapter of docs-site/ (an mdBook) directly from source: each
// ingredient's Methods() return value and PropertiesForMethod tables.
//
// This exists so the reference never drifts from the code: a new ingredient
// package under internal/ingredients, once it follows the self-registering
// pattern described in CLAUDE.md, appears in the docs the next time this
// runs — no hand-written page to remember to add.
//
// Usage (run from the tools/gendocs directory, which is its own Go module
// so the docs generator never needs the root module's go.mod toolchain
// version, and never needs to build for platforms most ingredients are
// constrained to):
//
//	go run . -src ../../internal/ingredients -out ../../docs-site/src/ingredients
//	go run . -src ../../internal/ingredients -out ../../docs-site/src/ingredients -check   # CI drift check
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ---- extracted metadata -----------------------------------------------

type prop struct {
	Key         string
	Type        string
	IsReq       bool
	Description string
}

type methodDoc struct {
	Method string
	Props  []prop
}

type pkgDoc struct {
	DirName    string // e.g. "winshortcut"
	Ingredient string // e.g. "win_shortcut"
	DocComment string
	Methods    []string
	MethodMeta []methodDoc
	BuildTags  []string
}

// category groups ingredients into reference chapters. Keyed by DirName.
var category = map[string]string{
	"cmd": "core", "cron": "core", "file": "core", "group": "core",
	"pkg": "core", "service": "core", "user": "core",
	"probe": "core", "wait": "core", "selfupdate": "core",

	"mount": "linux", "network": "linux", "firewall": "linux", "selinux": "linux",

	"registry": "windows", "lgpo": "windows", "winappx": "windows",
	"winauditpol": "windows", "wincertutil": "windows", "windacl": "windows",
	"windnsclient": "windows", "windsc": "windows", "winfirewall": "windows",
	"winiis": "windows", "winpki": "windows", "winpowercfg": "windows",
	"winpsget": "windows", "winservermanager": "windows", "winshortcut": "windows",
	"winsmtpserver": "windows", "winsnmp": "windows", "wintaskscheduler": "windows",
	"winupdate": "windows",
}

var categoryTitle = map[string]string{
	"core":    "Core (cross-platform)",
	"linux":   "Linux-specific",
	"windows": "Windows-specific",
}

var categoryOrder = []string{"core", "linux", "windows"}

// docOverride fills in a one-line description for ingredients whose Go
// source has no package doc comment (see the audit note in
// docs-site/src/ingredients/index.md for why these are called out).
var docOverride = map[string]string{
	"cmd":     "Runs an arbitrary shell command on the sprout, optionally as another user, with output streamed back over NATS.",
	"cron":    "Manages a single per-user crontab entry, keyed by name so repeated applies stay idempotent even if the schedule or command changes.",
	"file":    "Manages files on the sprout: content, existence, permissions, ownership, symlinks, directories, and targeted line/block edits.",
	"mount":   "Manages Linux mounts and their /etc/fstab entries.",
	"pkg":     "Manages OS packages (install, remove, upgrade, hold, repos, GPG keys) through the sprout's native package manager, via the snack backend.",
	"selinux": "Manages SELinux enforcement mode, booleans, and file contexts on Linux sprouts.",
	"service": "Manages system services (start/stop/enable/mask) across systemd, OpenRC, and rc.d service managers.",
}

// ingredientOverride / methodOverride fix the handful of packages whose
// ingredient name or method name is a constant re-exported from another
// package (fleetsign), which this AST-only walk can't resolve across
// package boundaries.
var ingredientOverride = map[string]string{"selfupdate": "selfupdate"}
var methodOverride = map[string][]string{"selfupdate": {"apply"}}
var methodMetaOverride = map[string][]methodDoc{
	"selfupdate": {{
		Method: "apply",
		Props: []prop{
			{Key: "version", Type: "string", IsReq: true, Description: "release version"},
			{Key: "artifact_url", Type: "string", IsReq: true, Description: "https URL of the release binary"},
			{Key: "checksum_sha256", Type: "string", IsReq: true, Description: "hex SHA-256 of the release binary"},
			{Key: "signature", Type: "string", IsReq: true, Description: "fleetreleaser's signature over version|artifact_url|checksum_sha256"},
		},
	}},
	"service": {}, // service takes only the implicit "name" (the service to target); no method-specific params
}

// ---- main ---------------------------------------------------------------

func main() {
	check := flag.Bool("check", false, "exit non-zero if generated files would change instead of writing them")
	ingredientsDir := flag.String("src", "internal/ingredients", "path to the ingredients package tree")
	outDir := flag.String("out", "docs-site/src/ingredients", "output directory for generated markdown")
	flag.Parse()

	docs, err := extractAll(*ingredientsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gendocs:", err)
		os.Exit(1)
	}

	files := render(docs, *outDir)

	if *check {
		dirty := false
		for path, content := range files {
			existing, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(existing, content) {
				fmt.Fprintf(os.Stderr, "gendocs: %s is out of date; run `go run ./tools/gendocs`\n", path)
				dirty = true
			}
		}
		if dirty {
			os.Exit(1)
		}
		fmt.Println("gendocs: up to date")
		return
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "gendocs:", err)
		os.Exit(1)
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "gendocs:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "gendocs:", err)
			os.Exit(1)
		}
	}
	fmt.Printf("gendocs: wrote %d files to %s\n", len(files), *outDir)
}

// ---- rendering ------------------------------------------------------------

func render(docs []pkgDoc, outDir string) map[string][]byte {
	out := map[string][]byte{}
	byCategory := map[string][]pkgDoc{}
	for _, d := range docs {
		c := category[d.DirName]
		if c == "" {
			c = "core"
		}
		byCategory[c] = append(byCategory[c], d)
	}

	var index strings.Builder
	index.WriteString("<!-- generated by tools/gendocs; do not edit by hand -->\n")
	index.WriteString("# Ingredient reference\n\n")
	index.WriteString("Every ingredient below is extracted directly from its package's " +
		"`Methods()` and `PropertiesForMethod()` in `internal/ingredients/`, so this page " +
		"tracks the code — re-run `go run ./tools/gendocs` after adding or changing an " +
		"ingredient.\n\n")

	for _, c := range categoryOrder {
		list := byCategory[c]
		if len(list) == 0 {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Ingredient < list[j].Ingredient })
		index.WriteString(fmt.Sprintf("## %s\n\n", categoryTitle[c]))
		index.WriteString("| Ingredient | Methods | Summary |\n|---|---|---|\n")
		for _, d := range list {
			index.WriteString(fmt.Sprintf("| [`%s`](%s.md) | %s | %s |\n",
				d.Ingredient, d.DirName, strings.Join(d.Methods, ", "), firstSentence(summaryFor(d))))
		}
		index.WriteString("\n")

		var page strings.Builder
		page.WriteString("<!-- generated by tools/gendocs; do not edit by hand -->\n")
		page.WriteString(fmt.Sprintf("# %s\n\n", categoryTitle[c]))
		for _, d := range list {
			renderIngredient(&page, d)
		}
		out[filepath.Join(outDir, c+".md")] = []byte(page.String())
	}

	out[filepath.Join(outDir, "index.md")] = []byte(index.String())
	return out
}

func summaryFor(d pkgDoc) string {
	if d.DocComment != "" {
		return d.DocComment
	}
	if o, ok := docOverride[d.DirName]; ok {
		return o
	}
	return "_undocumented in source (no package doc comment)_"
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.Join(strings.Fields(s), " ")
}

// firstSentence trims a (possibly long, multi-paragraph) doc comment down to
// its first sentence for use in a summary table; the full text still
// appears on the ingredient's own page via renderIngredient.
func firstSentence(s string) string {
	s = oneLine(s)
	// Package doc comments conventionally start with "Package <name> ...";
	// drop that lead-in so the summary reads naturally in a table cell.
	if rest, ok := strings.CutPrefix(s, "Package "); ok {
		if _, after, ok := strings.Cut(rest, " "); ok {
			s = after
			if len(s) > 0 {
				s = strings.ToUpper(s[:1]) + s[1:]
			}
		}
	}
	end := len(s)
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '.' && s[i+1] == ' ' {
			end = i + 1
			break
		}
	}
	trimmed := strings.TrimSpace(s[:end])
	if !strings.HasSuffix(trimmed, ".") {
		trimmed += "."
	}
	return trimmed
}

func renderIngredient(w *strings.Builder, d pkgDoc) {
	fmt.Fprintf(w, "## `%s`\n\n", d.Ingredient)
	if len(d.BuildTags) > 0 {
		fmt.Fprintf(w, "*Build constraint: `%s`*\n\n", strings.Join(uniq(d.BuildTags), ", "))
	}
	fmt.Fprintf(w, "%s\n\n", summaryFor(d))
	fmt.Fprintf(w, "Source: `internal/ingredients/%s/`\n\n", d.DirName)

	byMethod := map[string][]prop{}
	for _, m := range d.MethodMeta {
		byMethod[m.Method] = m.Props
	}

	for _, method := range d.Methods {
		fmt.Fprintf(w, "### `%s.%s`\n\n", d.Ingredient, method)
		props, ok := byMethod[method]
		if !ok || len(props) == 0 {
			w.WriteString("Takes the recipe step's implicit `name`; no method-specific parameters.\n\n")
			continue
		}
		sort.SliceStable(props, func(i, j int) bool {
			if props[i].IsReq != props[j].IsReq {
				return props[i].IsReq // required first
			}
			return false
		})
		w.WriteString("| Parameter | Type | Required | Description |\n|---|---|---|---|\n")
		for _, p := range props {
			req := ""
			if p.IsReq {
				req = "yes"
			}
			desc := p.Description
			if desc == "" {
				desc = "—"
			}
			fmt.Fprintf(w, "| `%s` | %s | %s | %s |\n", p.Key, orDash(p.Type), req, desc)
		}
		w.WriteString("\n")
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func uniq(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---- AST extraction (see design note below) --------------------------
//
// Each ingredient package self-describes via two methods on its
// cook.RecipeCooker implementation:
//
//	Methods() (string, []string)                     // ingredient name, method names
//	PropertiesForMethod(method string) (map[string]string, error)
//
// In practice PropertiesForMethod is built one of three ways across the
// tree (oldest to newest style): a raw map[string]string literal per
// case ("type,req"/"type,opt"), a switch returning an
// ingredients.MethodPropsSet{...}.ToMap() literal per case, or a lookup
// into a package-level `map[string]ingredients.MethodPropsSet` by method
// name. This walks the AST rather than importing the packages so it never
// needs to build for every ingredient's platform (many are
// windows/linux-only) or resolve go.mod/toolchain versions.

func extractAll(root string) ([]pkgDoc, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var docs []pkgDoc
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		d, ok, err := extractDir(filepath.Join(root, e.Name()), e.Name())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if ok {
			docs = append(docs, d)
		}
	}
	return docs, nil
}

func extractDir(dir, dirName string) (pkgDoc, bool, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		return pkgDoc{}, false, err
	}
	if len(pkgs) == 0 {
		return pkgDoc{}, false, nil
	}
	var pkg *ast.Package
	for _, p := range pkgs {
		pkg = p
		break
	}

	// pkg.Files is a map, so its iteration order is unspecified. Several
	// packages (e.g. group/user) have one doc comment per GOOS-tagged file;
	// picking "whichever the map yields first" makes the generated output
	// change from run to run with nothing in the source having changed.
	// Sort by filename once and use this slice for every pass below.
	files := make([]*ast.File, 0, len(pkg.Files))
	for _, f := range pkg.Files {
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool {
		return fset.Position(files[i].Package).Filename < fset.Position(files[j].Package).Filename
	})

	d := pkgDoc{DirName: dirName}
	consts := map[string]string{}
	methodPropsByVar := map[string][]prop{}
	methodPropsMapByVar := map[string]map[string][]prop{}
	wrapperExtra := map[string][]prop{}

	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != len(vs.Values) {
					continue
				}
				for i, name := range vs.Names {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
						if s, err := strconv.Unquote(lit.Value); err == nil {
							consts[name.Name] = s
						}
					}
				}
			}
		}
	}

	// Pass 2: package doc comment, build tags, and every package-level var
	// that holds a MethodPropsSet (directly, or as a map[string]MethodPropsSet)
	// -- collected across ALL files first, since e.g. probe's httpMethodProps
	// lives in probeHttp.go while PropertiesForMethod (pass 3) lives in
	// probe.go, and pkg.Files iteration order is unspecified.
	for _, f := range files {
		if f.Doc != nil && d.DocComment == "" {
			d.DocComment = cleanDoc(f.Doc.Text())
		}
		for _, cg := range f.Comments {
			if len(cg.List) == 0 {
				continue
			}
			line := strings.TrimSpace(cg.List[0].Text)
			if strings.HasPrefix(line, "//go:build") {
				d.BuildTags = append(d.BuildTags, strings.TrimSpace(strings.TrimPrefix(line, "//go:build")))
			}
		}

		ast.Inspect(f, func(n ast.Node) bool {
			gd, ok := n.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				return true
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				varName := vs.Names[0].Name
				cl, ok := vs.Values[0].(*ast.CompositeLit)
				if !ok {
					continue
				}
				if props := propsFromMethodPropsSetLit(cl); props != nil {
					methodPropsByVar[varName] = props
					continue
				}
				if mt, ok := cl.Type.(*ast.MapType); ok {
					if se, ok := mt.Value.(*ast.SelectorExpr); ok && se.Sel.Name == "MethodPropsSet" {
						methodPropsMapByVar[varName] = propsMapFromMapLit(cl, consts)
					}
				}
			}
			return true
		})
	}

	// Pass 2b: package-local helper funcs that wrap a MethodPropsSet with
	// shared extra props, e.g.
	//   func withGuardProps(base MethodPropsSet) MethodPropsSet {
	//       return append(append(MethodPropsSet{}, base...), extraVar...)
	//   }
	// Recorded so a `return withGuardProps(MethodPropsSet{...}).ToMap()` case
	// in pass 3 resolves to the case's own props plus extraVar's.
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			fd, ok := n.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || len(fd.Type.Params.List) != 1 {
				return true
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ret, ok := n.(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 1 {
					return true
				}
				extra := findAppendedExtraVar(ret.Results[0])
				if extra == "" {
					return true
				}
				if props, found := methodPropsByVar[extra]; found {
					wrapperExtra[fd.Name.Name] = props
				}
				return true
			})
			return true
		})
	}

	// Pass 3: Methods() and PropertiesForMethod(), now that every prop
	// table var (and wrapper func) is known regardless of which file
	// declared it.
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			fd, ok := n.(*ast.FuncDecl)
			if !ok || fd.Recv == nil {
				return true
			}
			switch fd.Name.Name {
			case "Methods":
				extractMethods(fd, &d, consts)
			case "PropertiesForMethod":
				extractPropertiesForMethod(fd, &d, methodPropsByVar, methodPropsMapByVar, consts, wrapperExtra)
			}
			return true
		})
	}

	if resolved, ok := consts[d.Ingredient]; ok {
		d.Ingredient = resolved
	}
	if o, ok := ingredientOverride[dirName]; ok {
		d.Ingredient = o
	}
	for i, m := range d.Methods {
		if resolved, ok := consts[m]; ok {
			d.Methods[i] = resolved
		}
	}
	if o, ok := methodOverride[dirName]; ok {
		d.Methods = o
	}
	if o, ok := methodMetaOverride[dirName]; ok {
		d.MethodMeta = o
	}

	if d.Ingredient == "" || len(d.Methods) == 0 {
		return d, false, nil
	}
	return d, true, nil
}

func cleanDoc(s string) string {
	s = strings.TrimSpace(s)
	// Keep just the first sentence/paragraph for the summary table; full
	// text still appears in the per-ingredient section.
	return s
}

// findAppendedExtraVar matches `append(append(<anything>, <anything>...), extraVar...)`
// (the shape ingredients.MethodPropsSet append-wrappers use) and returns
// extraVar's name, or "" if expr doesn't match.
func findAppendedExtraVar(expr ast.Expr) string {
	outer, ok := expr.(*ast.CallExpr)
	if !ok || len(outer.Args) != 2 {
		return ""
	}
	if id, ok := outer.Fun.(*ast.Ident); !ok || id.Name != "append" {
		return ""
	}
	if _, ok := outer.Args[0].(*ast.CallExpr); !ok {
		return "" // expect the inner append(...) as the first arg
	}
	extra, ok := outer.Args[1].(*ast.Ident)
	if !ok {
		return ""
	}
	return extra.Name
}

func extractMethods(fd *ast.FuncDecl, d *pkgDoc, consts map[string]string) {
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 2 {
			return true
		}
		switch v := ret.Results[0].(type) {
		case *ast.BasicLit:
			if s, err := strconv.Unquote(v.Value); err == nil {
				d.Ingredient = s
			}
		case *ast.Ident:
			if resolved, ok := consts[v.Name]; ok {
				d.Ingredient = resolved
			} else {
				d.Ingredient = v.Name
			}
		case *ast.SelectorExpr:
			d.Ingredient = v.Sel.Name
		}
		if cl, ok := ret.Results[1].(*ast.CompositeLit); ok {
			for _, elt := range cl.Elts {
				switch v := elt.(type) {
				case *ast.BasicLit:
					if s, err := strconv.Unquote(v.Value); err == nil {
						d.Methods = append(d.Methods, s)
					}
				case *ast.Ident:
					if resolved, ok := consts[v.Name]; ok {
						d.Methods = append(d.Methods, resolved)
					} else {
						d.Methods = append(d.Methods, v.Name)
					}
				case *ast.SelectorExpr:
					d.Methods = append(d.Methods, v.Sel.Name)
				}
			}
		}
		return true
	})
}

// resolvePropsExpr resolves a props-returning expression that may be, in any
// combination: a trailing `.ToMap()` call, a call to a single-argument
// package-local wrapper function that appends shared extra props (e.g.
// network's withGuardProps), a literal ingredients.MethodPropsSet{...} or
// map[string]string{...}, or a bare identifier naming a package-level var
// holding one of those.
func resolvePropsExpr(expr ast.Expr, byVar map[string][]prop, wrapperExtra map[string][]prop) []prop {
	// Strip a trailing method call, e.g. `<expr>.ToMap()`.
	if call, ok := expr.(*ast.CallExpr); ok {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			expr = sel.X
		}
	}
	// A call to a known single-arg wrapper function: resolve its argument
	// and append the wrapper's extra shared props.
	if call, ok := expr.(*ast.CallExpr); ok {
		if id, ok := call.Fun.(*ast.Ident); ok && len(call.Args) == 1 {
			if extra, known := wrapperExtra[id.Name]; known {
				base := resolvePropsExpr(call.Args[0], byVar, wrapperExtra)
				return append(append([]prop{}, base...), extra...)
			}
		}
	}
	switch v := expr.(type) {
	case *ast.CompositeLit:
		if props := propsFromMethodPropsSetLit(v); props != nil {
			return props
		}
		return propsFromRawStringMapLit(v)
	case *ast.Ident:
		return byVar[v.Name]
	}
	return nil
}

func extractPropertiesForMethod(fd *ast.FuncDecl, d *pkgDoc, byVar map[string][]prop, byVarMap map[string]map[string][]prop, consts map[string]string, wrapperExtra map[string][]prop) {
	// Pattern: `props, ok := methodProps[method]` then `return props.ToMap(), nil`.
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		ie, ok := as.Rhs[0].(*ast.IndexExpr)
		if !ok {
			return true
		}
		ident, ok := ie.X.(*ast.Ident)
		if !ok {
			return true
		}
		if m, found := byVarMap[ident.Name]; found {
			for method, props := range m {
				d.MethodMeta = append(d.MethodMeta, methodDoc{Method: method, Props: props})
			}
		}
		return true
	})
	if len(d.MethodMeta) > 0 {
		return
	}

	// Pattern: a switch on method with an inline MethodPropsSet / raw
	// map[string]string literal (optionally wrapped in .ToMap()) per case.
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			var methodNames []string
			for _, expr := range cc.List {
				switch v := expr.(type) {
				case *ast.BasicLit:
					if s, err := strconv.Unquote(v.Value); err == nil {
						methodNames = append(methodNames, s)
					}
				case *ast.Ident:
					if resolved, ok := consts[v.Name]; ok {
						methodNames = append(methodNames, resolved)
					} else {
						methodNames = append(methodNames, v.Name)
					}
				}
			}
			if len(methodNames) == 0 {
				continue
			}
			for _, bs := range cc.Body {
				ret, ok := bs.(*ast.ReturnStmt)
				if !ok || len(ret.Results) == 0 {
					continue
				}
				if props := resolvePropsExpr(ret.Results[0], byVar, wrapperExtra); props != nil {
					for _, mn := range methodNames {
						d.MethodMeta = append(d.MethodMeta, methodDoc{Method: mn, Props: props})
					}
				}
			}
		}
		return true
	})
}

func propsFromMethodPropsSetLit(cl *ast.CompositeLit) []prop {
	se, ok := cl.Type.(*ast.SelectorExpr)
	if !ok || se.Sel.Name != "MethodPropsSet" {
		return nil
	}
	return propsFromElts(cl.Elts)
}

func propsFromElts(elts []ast.Expr) []prop {
	var props []prop
	for _, elt := range elts {
		inner, ok := elt.(*ast.CompositeLit)
		if !ok {
			continue
		}
		p := prop{}
		for _, kv := range inner.Elts {
			kve, ok := kv.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kve.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "Key":
				p.Key = litString(kve.Value)
			case "Type":
				p.Type = litString(kve.Value)
			case "IsReq":
				if id, ok := kve.Value.(*ast.Ident); ok {
					p.IsReq = id.Name == "true"
				}
			case "Description":
				p.Description = litString(kve.Value)
			}
		}
		if p.Key != "" {
			props = append(props, p)
		}
	}
	return props
}

func propsMapFromMapLit(cl *ast.CompositeLit, consts map[string]string) map[string][]prop {
	m := map[string][]prop{}
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		var key string
		switch k := kv.Key.(type) {
		case *ast.BasicLit:
			if s, err := strconv.Unquote(k.Value); err == nil {
				key = s
			}
		case *ast.Ident:
			if resolved, ok := consts[k.Name]; ok {
				key = resolved
			} else {
				key = k.Name
			}
		}
		if key == "" {
			continue
		}
		if inner, ok := kv.Value.(*ast.CompositeLit); ok {
			if props := propsFromElts(inner.Elts); props != nil {
				m[key] = props
			}
		}
	}
	return m
}

func propsFromRawStringMapLit(cl *ast.CompositeLit) []prop {
	mt, ok := cl.Type.(*ast.MapType)
	if !ok {
		return nil
	}
	if id, ok := mt.Value.(*ast.Ident); !ok || id.Name != "string" {
		return nil
	}
	var props []prop
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key := litString(kv.Key)
		val := litString(kv.Value)
		if key == "" || val == "" {
			continue
		}
		parts := strings.SplitN(val, ",", 2)
		p := prop{Key: key, Type: parts[0]}
		if len(parts) == 2 && parts[1] == "req" {
			p.IsReq = true
		}
		props = append(props, p)
	}
	return props
}

func litString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		if s, err := strconv.Unquote(v.Value); err == nil {
			return s
		}
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}
