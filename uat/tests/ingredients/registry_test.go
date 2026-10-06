package ingredients

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeTree writes files (path -> content) under a new directory.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// fakeModule is a miniature of the repository: a sprout that imports a
// cross-platform ingredient, a Linux-only one and a Windows-only one, plus
// a package that registers but isn't imported, in the shapes the real
// packages use (switch with inline sets, a map of sets, a raw string map,
// an append wrapper, a receiver-field switch, a constant from another
// package).
var fakeModule = map[string]string{
	"go.mod": "module " + ModulePath + "\n\ngo 1.22\n",
	"cmd/sprout/main.go": `package main
import _ "` + ModulePath + `/internal/ingredients/alpha"
func main() {}
`,
	"cmd/sprout/include_linux.go": `//go:build linux

package main
import _ "` + ModulePath + `/internal/ingredients/penguin"
`,
	"cmd/sprout/include_windows.go": `//go:build windows

package main
import _ "` + ModulePath + `/internal/ingredients/winthing"
`,
	"internal/ingredients/ingredients.go": `package ingredients
type MethodProps struct { Key, Type string; IsReq bool; Description string }
type MethodPropsSet []MethodProps
func (m MethodPropsSet) ToMap() map[string]string { return nil }
func RegisterAllMethods(x any) {}
`,
	"internal/names/names.go": `package names
const Alpha = "alpha"
`,
	"internal/ingredients/alpha/alpha.go": `package alpha
import (
	"errors"
	"` + ModulePath + `/internal/ingredients"
	"` + ModulePath + `/internal/names"
)
const methodOne = "one"
type Alpha struct{ method string }
var shared = ingredients.MethodPropsSet{ingredients.MethodProps{Key: "guard", Type: "bool"}}
func withShared(base ingredients.MethodPropsSet) ingredients.MethodPropsSet {
	return append(append(ingredients.MethodPropsSet{}, base...), shared...)
}
func (a Alpha) Methods() (string, []string) { return names.Alpha, []string{methodOne, "two", "three"} }
func (a Alpha) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case methodOne:
		return withShared(ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "the name"},
		}).ToMap(), nil
	case "two":
		return map[string]string{"name": "string,req", "flag": "bool,opt"}, nil
	default:
		return nil, errors.New("undefined")
	}
}
func init() { ingredients.RegisterAllMethods(Alpha{}) }
`,
	"internal/ingredients/penguin/penguin.go": `//go:build linux

package penguin
import (
	"fmt"
	"` + ModulePath + `/internal/ingredients"
)
type P struct{ method string }
var methodProps = map[string]ingredients.MethodPropsSet{
	"swim": {ingredients.MethodProps{Key: "depth", Type: "string", IsReq: true}},
}
func (p P) Methods() (string, []string) { return "penguin", []string{"swim", "waddle"} }
func (p P) PropertiesForMethod(method string) (map[string]string, error) {
	switch p.method {
	case "waddle":
		return ingredients.MethodPropsSet{}.ToMap(), nil
	}
	props, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return props.ToMap(), nil
}
func init() { ingredients.RegisterAllMethods(P{}) }
`,
	"internal/ingredients/winthing/winthing.go": `//go:build windows

package winthing
import "` + ModulePath + `/internal/ingredients"
type W struct{}
func (w W) Methods() (string, []string) { return "win_thing", []string{"done"} }
func (w W) PropertiesForMethod(method string) (map[string]string, error) { return nil, nil }
func init() { ingredients.RegisterAllMethods(W{}) }
`,
	"internal/ingredients/orphan/orphan.go": `package orphan
import "` + ModulePath + `/internal/ingredients"
type O struct{}
func (o O) Methods() (string, []string) { return "orphan", []string{"lost"} }
func (o O) PropertiesForMethod(method string) (map[string]string, error) { return nil, nil }
func init() { ingredients.RegisterAllMethods(O{}) }
`,
}

func TestLoadRegistryFakeModule(t *testing.T) {
	root := writeTree(t, fakeModule)
	reg, err := LoadRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range reg.Methods {
		ids = append(ids, m.ID()+"="+strings.Join(m.GOOS, "+"))
	}
	want := []string{
		"I.alpha.one=linux+windows", "I.alpha.three=linux+windows", "I.alpha.two=linux+windows",
		"I.penguin.swim=linux", "I.penguin.waddle=linux", "I.win_thing.done=windows",
	}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("methods:\n got %v\nwant %v", ids, want)
	}
	one, _ := reg.Get("I.alpha.one")
	if len(one.Props) != 2 || one.Props[0] != (Prop{Key: "name", Type: "string", Required: true, Description: "the name"}) || one.Props[1].Key != "guard" {
		t.Errorf("alpha.one props (switch + append wrapper): %+v", one.Props)
	}
	two, _ := reg.Get("I.alpha.two")
	if len(two.Props) != 2 || two.Props[0].Key != "flag" || two.Props[1] != (Prop{Key: "name", Type: "string", Required: true}) {
		t.Errorf("alpha.two props (raw string map): %+v", two.Props)
	}
	three, _ := reg.Get("I.alpha.three")
	if !strings.Contains(three.PropsNote, "returns an error") {
		t.Errorf("alpha.three note %q", three.PropsNote)
	}
	swim, _ := reg.Get("I.penguin.swim")
	if len(swim.Props) != 1 || swim.Props[0].Key != "depth" || !swim.Props[0].Required {
		t.Errorf("penguin.swim props (map of sets): %+v", swim.Props)
	}
	waddle, _ := reg.Get("I.penguin.waddle")
	if !strings.Contains(waddle.PropsNote, "receiver's method field") {
		t.Errorf("penguin.waddle should note the receiver-field switch: %q", waddle.PropsNote)
	}
	done, _ := reg.Get("I.win_thing.done")
	if !strings.Contains(done.PropsNote, "declares no properties") {
		t.Errorf("win_thing.done note %q", done.PropsNote)
	}
	if len(reg.Unreachable) != 1 || reg.Unreachable[0].ID() != "I.orphan.lost" {
		t.Errorf("unreachable: %+v", reg.Unreachable)
	}
}

func TestLoadRegistryUnsupportedShapeFails(t *testing.T) {
	files := map[string]string{}
	for k, v := range fakeModule {
		files[k] = v
	}
	files["internal/ingredients/alpha/alpha.go"] = strings.Replace(files["internal/ingredients/alpha/alpha.go"],
		`return names.Alpha, []string{methodOne, "two", "three"}`, `for {}; return "", nil`, 1)
	if _, err := LoadRegistry(writeTree(t, files)); err == nil || !strings.Contains(err.Error(), "Methods()") {
		t.Fatalf("an unreadable Methods() must fail the load, got %v", err)
	}
}

// TestRegistryOfThisRepository pins what the source says today, so a
// change to the registry is a visible, reviewed change here and in
// INVENTORY.md.
func TestRegistryOfThisRepository(t *testing.T) {
	root, err := FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := LoadRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Methods) < 90 {
		t.Fatalf("only %d methods read from the source", len(reg.Methods))
	}
	goos := func(id string) string {
		m, ok := reg.Get(id)
		if !ok {
			return "missing"
		}
		return strings.Join(m.GOOS, "+")
	}
	for id, want := range map[string]string{
		"I.file.managed":              "linux+windows",
		"I.cmd.run":                   "linux+windows",
		"I.service.running":           "linux+windows",
		"I.cron.present":              "linux",
		"I.firewall.rule_present":     "linux",
		"I.selinux.enforcing":         "linux",
		"I.win_iis.started":           "windows",
		"I.registry.present":          "windows",
		"I.lgpo.present":              "windows",
		"I.selfupdate.apply":          "linux+windows",
		"I.win_task.present":          "windows",
		"I.network.route_absent":      "linux",
		"I.pkg.installed":             "linux+windows",
		"I.win_update.installed":      "windows",
		"I.win_shortcut.absent":       "windows",
		"I.mount.fstab_present":       "linux",
		"I.wait.poll":                 "linux+windows",
		"I.probe.database":            "linux+windows",
		"I.win_servermanager.removed": "windows",
	} {
		if got := goos(id); got != want {
			t.Errorf("%s: %s, want %s", id, got, want)
		}
	}
	reqProp := func(id, key string) bool {
		m, _ := reg.Get(id)
		for _, p := range m.Props {
			if p.Key == key {
				return p.Required
			}
		}
		return false
	}
	if !reqProp("I.selfupdate.apply", "version") || !reqProp("I.registry.present", "vdata") || !reqProp("I.firewall.rule_present", "action") {
		t.Errorf("required properties not read: selfupdate.apply version, registry.present vdata, firewall.rule_present action")
	}
	found := map[string]bool{}
	for _, b := range reg.Backends {
		found[b.Registry+":"+b.Name] = true
	}
	for _, k := range []string{"sdb:openbao", "sdb:azurekv", "file source:file", "file source:https"} {
		if !found[k] {
			t.Errorf("backend %s not found: %+v", k, reg.Backends)
		}
	}
}
