//go:build windows

package registry

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"

	"github.com/yogzblr/imas/internal/ingredients"
)

// fakeNode is an in-memory registry key: a set of named values plus
// whatever bookkeeping fakeBackend needs to synthesize subkey listings.
type fakeNode struct {
	values map[string]fakeVal
}

type fakeVal struct {
	vtype string
	data  interface{}
}

// fakeBackend is an in-memory stand-in for the real Windows registry,
// keyed by "hive:PATH" (path upper-cased, since the registry is
// case-insensitive).
type fakeBackend struct {
	nodes map[string]*fakeNode
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{nodes: map[string]*fakeNode{}}
}

func nodeKey(hive registry.Key, path string) string {
	return fmt.Sprintf("%d:%s", hive, strings.ToUpper(path))
}

func (f *fakeBackend) OpenKey(hive registry.Key, path string, _ uint32) (regKey, error) {
	n, ok := f.nodes[nodeKey(hive, path)]
	if !ok {
		return nil, registry.ErrNotExist
	}
	return &fakeKey{backend: f, hive: hive, path: path, node: n}, nil
}

func (f *fakeBackend) CreateKey(hive registry.Key, path string, _ uint32) (regKey, bool, error) {
	key := nodeKey(hive, path)
	n, existed := f.nodes[key]
	if !existed {
		n = &fakeNode{values: map[string]fakeVal{}}
		f.nodes[key] = n
	}
	return &fakeKey{backend: f, hive: hive, path: path, node: n}, existed, nil
}

func (f *fakeBackend) DeleteKey(hive registry.Key, path string) error {
	key := nodeKey(hive, path)
	if _, ok := f.nodes[key]; !ok {
		return registry.ErrNotExist
	}
	prefix := key + `\`
	for k := range f.nodes {
		if strings.HasPrefix(k, prefix) {
			return fmt.Errorf("key %q has subkeys", path)
		}
	}
	delete(f.nodes, key)
	return nil
}

type fakeKey struct {
	backend *fakeBackend
	hive    registry.Key
	path    string
	node    *fakeNode
}

func (k *fakeKey) Close() error { return nil }

func (k *fakeKey) GetStringValue(name string) (string, uint32, error) {
	v, ok := k.node.values[name]
	if !ok {
		return "", 0, registry.ErrNotExist
	}
	s, _ := v.data.(string)
	return s, 0, nil
}

func (k *fakeKey) GetIntegerValue(name string) (uint64, uint32, error) {
	v, ok := k.node.values[name]
	if !ok {
		return 0, 0, registry.ErrNotExist
	}
	switch n := v.data.(type) {
	case uint32:
		return uint64(n), 0, nil
	case uint64:
		return n, 0, nil
	default:
		return 0, 0, registry.ErrUnexpectedType
	}
}

func (k *fakeKey) GetStringsValue(name string) ([]string, uint32, error) {
	v, ok := k.node.values[name]
	if !ok {
		return nil, 0, registry.ErrNotExist
	}
	ss, _ := v.data.([]string)
	return ss, 0, nil
}

func (k *fakeKey) GetBinaryValue(name string) ([]byte, uint32, error) {
	v, ok := k.node.values[name]
	if !ok {
		return nil, 0, registry.ErrNotExist
	}
	b, _ := v.data.([]byte)
	return b, 0, nil
}

func (k *fakeKey) SetStringValue(name, value string) error {
	k.node.values[name] = fakeVal{vtype: "string", data: value}
	return nil
}

func (k *fakeKey) SetExpandStringValue(name, value string) error {
	k.node.values[name] = fakeVal{vtype: "expand_string", data: value}
	return nil
}

func (k *fakeKey) SetDWordValue(name string, value uint32) error {
	k.node.values[name] = fakeVal{vtype: "dword", data: value}
	return nil
}

func (k *fakeKey) SetQWordValue(name string, value uint64) error {
	k.node.values[name] = fakeVal{vtype: "qword", data: value}
	return nil
}

func (k *fakeKey) SetStringsValue(name string, value []string) error {
	k.node.values[name] = fakeVal{vtype: "multi_string", data: value}
	return nil
}

func (k *fakeKey) SetBinaryValue(name string, value []byte) error {
	k.node.values[name] = fakeVal{vtype: "binary", data: value}
	return nil
}

func (k *fakeKey) DeleteValue(name string) error {
	if _, ok := k.node.values[name]; !ok {
		return registry.ErrNotExist
	}
	delete(k.node.values, name)
	return nil
}

func (k *fakeKey) ReadSubKeyNames(_ int) ([]string, error) {
	prefix := nodeKey(k.hive, k.path) + `\`
	var names []string
	for key := range k.backend.nodes {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := strings.TrimPrefix(key, prefix)
		if !strings.Contains(rest, `\`) {
			names = append(names, rest)
		}
	}
	return names, nil
}

func (k *fakeKey) ReadValueNames(_ int) ([]string, error) {
	names := make([]string, 0, len(k.node.values))
	for name := range k.node.values {
		names = append(names, name)
	}
	return names, nil
}

func installFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()
	fb := newFakeBackend()
	orig := backend
	backend = fb
	t.Cleanup(func() { backend = orig })
	return fb
}

func newRegistry(method string, params map[string]interface{}) Registry {
	return Registry{id: "test-id", method: method, params: params}
}

// --- splitName ---

func TestSplitNameFullHive(t *testing.T) {
	hive, subkey, err := splitName(`HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\App`)
	if err != nil {
		t.Fatalf("splitName() error: %v", err)
	}
	if hive != registry.LOCAL_MACHINE {
		t.Errorf("hive = %v, want LOCAL_MACHINE", hive)
	}
	if subkey != `SOFTWARE\Contoso\App` {
		t.Errorf("subkey = %q, want %q", subkey, `SOFTWARE\Contoso\App`)
	}
}

func TestSplitNameAlias(t *testing.T) {
	hive, subkey, err := splitName(`hklm\SOFTWARE\Contoso`)
	if err != nil {
		t.Fatalf("splitName() error: %v", err)
	}
	if hive != registry.LOCAL_MACHINE {
		t.Errorf("hive = %v, want LOCAL_MACHINE", hive)
	}
	if subkey != `SOFTWARE\Contoso` {
		t.Errorf("subkey = %q, want %q", subkey, `SOFTWARE\Contoso`)
	}
}

func TestSplitNameUnknownHive(t *testing.T) {
	_, _, err := splitName(`NOT_A_HIVE\Foo`)
	if err == nil {
		t.Fatal("expected error for unknown hive")
	}
}

func TestSplitNameMissingSubkey(t *testing.T) {
	_, _, err := splitName(`HKLM`)
	if err == nil {
		t.Fatal("expected error for missing subkey")
	}
}

func TestSplitNameEmpty(t *testing.T) {
	_, _, err := splitName("")
	if err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

// --- Parse/validate ---

func TestParseMissingName(t *testing.T) {
	r := Registry{}
	_, err := r.Parse("id", "present", map[string]interface{}{"vdata": "x"})
	if err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParsePresentMissingData(t *testing.T) {
	r := Registry{}
	_, err := r.Parse("id", "present", map[string]interface{}{"name": `HKLM\Foo`})
	if err == nil {
		t.Fatal("expected error for missing vdata")
	}
}

func TestParseInvalidHive(t *testing.T) {
	r := Registry{}
	_, err := r.Parse("id", "key_present", map[string]interface{}{"name": `BOGUS\Foo`})
	if err == nil {
		t.Fatal("expected error for invalid hive")
	}
}

func TestParseValid(t *testing.T) {
	r := Registry{}
	got, err := r.Parse("id", "key_present", map[string]interface{}{"name": `HKLM\SOFTWARE\Foo`})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if _, ok := got.(Registry); !ok {
		t.Fatal("Parse() did not return a Registry")
	}
}

func TestMethodsAndProperties(t *testing.T) {
	r := Registry{}
	name, methods := r.Methods()
	if name != "registry" {
		t.Errorf("Methods() name = %q, want %q", name, "registry")
	}
	want := map[string]bool{"present": true, "absent": true, "key_present": true, "key_absent": true}
	for _, m := range methods {
		if !want[m] {
			t.Errorf("unexpected method %q", m)
		}
		delete(want, m)
	}
	if len(want) != 0 {
		t.Errorf("missing methods: %v", want)
	}
}

func TestUndefinedMethod(t *testing.T) {
	r := newRegistry("bogus", map[string]interface{}{"name": `HKLM\Foo`})
	if _, err := r.Apply(context.Background()); err == nil {
		t.Fatal("expected error for undefined method")
	}
}

// --- present ---

func TestPresentCreatesValue(t *testing.T) {
	installFakeBackend(t)
	r := newRegistry("present", map[string]interface{}{
		"name": `HKLM\SOFTWARE\Contoso`, "vname": "Setting", "vdata": "hello",
	})
	res, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Succeeded || !res.Changed {
		t.Errorf("res = %+v, want succeeded+changed", res)
	}

	res2, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("second Apply() error: %v", err)
	}
	if !res2.Succeeded || res2.Changed {
		t.Errorf("second Apply() res = %+v, want succeeded and unchanged", res2)
	}
}

func TestPresentTestModeDoesNotWrite(t *testing.T) {
	fb := installFakeBackend(t)
	r := newRegistry("present", map[string]interface{}{
		"name": `HKLM\SOFTWARE\Contoso`, "vname": "Setting", "vdata": "hello",
	})
	res, err := r.Test(context.Background())
	if err != nil {
		t.Fatalf("Test() error: %v", err)
	}
	if !res.Succeeded || !res.Changed {
		t.Errorf("res = %+v, want succeeded+changed", res)
	}
	if len(fb.nodes) != 0 {
		t.Errorf("Test() should not create any keys, found %d", len(fb.nodes))
	}
}

func TestPresentDword(t *testing.T) {
	installFakeBackend(t)
	r := newRegistry("present", map[string]interface{}{
		"name": `HKLM\SOFTWARE\Contoso`, "vname": "Count", "vtype": "dword", "vdata": float64(42),
	})
	res, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Changed {
		t.Errorf("expected change, got %+v", res)
	}
	res2, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("second Apply() error: %v", err)
	}
	if res2.Changed {
		t.Errorf("expected no change on second apply, got %+v", res2)
	}
}

func TestPresentMultiString(t *testing.T) {
	installFakeBackend(t)
	r := newRegistry("present", map[string]interface{}{
		"name": `HKLM\SOFTWARE\Contoso`, "vname": "List", "vtype": "multi_string",
		"vdata": []interface{}{"a", "b"},
	})
	res, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Changed {
		t.Errorf("expected change, got %+v", res)
	}
}

func TestPresentInvalidHive(t *testing.T) {
	installFakeBackend(t)
	r := newRegistry("present", map[string]interface{}{
		"name": `BOGUS\Foo`, "vdata": "x",
	})
	res, err := r.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid hive")
	}
	if res.Succeeded {
		t.Errorf("expected failure result, got %+v", res)
	}
}

func TestPresentMissingVData(t *testing.T) {
	r := newRegistry("present", map[string]interface{}{"name": `HKLM\Foo`})
	if _, err := r.Apply(context.Background()); err != ErrMissingValueData {
		t.Errorf("expected ErrMissingValueData, got %v", err)
	}
}

// --- absent ---

func TestAbsentKeyMissing(t *testing.T) {
	installFakeBackend(t)
	r := newRegistry("absent", map[string]interface{}{"name": `HKLM\SOFTWARE\Nope`, "vname": "X"})
	res, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Succeeded || res.Changed {
		t.Errorf("res = %+v, want succeeded and unchanged", res)
	}
}

func TestAbsentRemovesValue(t *testing.T) {
	fb := installFakeBackend(t)
	hive, subkey, _ := splitName(`HKLM\SOFTWARE\Contoso`)
	k, _, _ := fb.CreateKey(hive, subkey, 0)
	k.SetStringValue("Setting", "hello")

	r := newRegistry("absent", map[string]interface{}{"name": `HKLM\SOFTWARE\Contoso`, "vname": "Setting"})
	res, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Succeeded || !res.Changed {
		t.Errorf("res = %+v, want succeeded+changed", res)
	}

	res2, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("second Apply() error: %v", err)
	}
	if res2.Changed {
		t.Errorf("second Apply() res = %+v, want unchanged", res2)
	}
}

func TestAbsentTestModeDoesNotDelete(t *testing.T) {
	fb := installFakeBackend(t)
	hive, subkey, _ := splitName(`HKLM\SOFTWARE\Contoso`)
	k, _, _ := fb.CreateKey(hive, subkey, 0)
	k.SetStringValue("Setting", "hello")

	r := newRegistry("absent", map[string]interface{}{"name": `HKLM\SOFTWARE\Contoso`, "vname": "Setting"})
	res, err := r.Test(context.Background())
	if err != nil {
		t.Fatalf("Test() error: %v", err)
	}
	if !res.Changed {
		t.Errorf("expected change, got %+v", res)
	}
	if _, ok := fb.nodes[nodeKey(hive, subkey)].values["Setting"]; !ok {
		t.Error("Test() should not have deleted the value")
	}
}

// --- key_present / key_absent ---

func TestKeyPresentCreatesKey(t *testing.T) {
	fb := installFakeBackend(t)
	r := newRegistry("key_present", map[string]interface{}{"name": `HKLM\SOFTWARE\Contoso`})
	res, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Succeeded || !res.Changed {
		t.Errorf("res = %+v, want succeeded+changed", res)
	}
	hive, subkey, _ := splitName(`HKLM\SOFTWARE\Contoso`)
	if _, ok := fb.nodes[nodeKey(hive, subkey)]; !ok {
		t.Error("expected key to be created")
	}

	res2, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("second Apply() error: %v", err)
	}
	if res2.Changed {
		t.Errorf("second Apply() res = %+v, want unchanged", res2)
	}
}

func TestKeyAbsentRemovesKey(t *testing.T) {
	fb := installFakeBackend(t)
	hive, subkey, _ := splitName(`HKLM\SOFTWARE\Contoso`)
	fb.CreateKey(hive, subkey, 0)

	r := newRegistry("key_absent", map[string]interface{}{"name": `HKLM\SOFTWARE\Contoso`})
	res, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Succeeded || !res.Changed {
		t.Errorf("res = %+v, want succeeded+changed", res)
	}
	if _, ok := fb.nodes[nodeKey(hive, subkey)]; ok {
		t.Error("expected key to be removed")
	}
}

func TestKeyAbsentAlreadyGone(t *testing.T) {
	installFakeBackend(t)
	r := newRegistry("key_absent", map[string]interface{}{"name": `HKLM\SOFTWARE\Nope`})
	res, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Succeeded || res.Changed {
		t.Errorf("res = %+v, want succeeded and unchanged", res)
	}
}

func TestKeyAbsentWithSubkeysFailsWithoutForce(t *testing.T) {
	fb := installFakeBackend(t)
	hive, subkey, _ := splitName(`HKLM\SOFTWARE\Contoso`)
	fb.CreateKey(hive, subkey, 0)
	fb.CreateKey(hive, subkey+`\Sub`, 0)

	r := newRegistry("key_absent", map[string]interface{}{"name": `HKLM\SOFTWARE\Contoso`})
	res, err := r.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error deleting a key with subkeys")
	}
	if res.Succeeded {
		t.Errorf("expected failure result, got %+v", res)
	}
}

func TestKeyAbsentForceRemovesSubkeys(t *testing.T) {
	fb := installFakeBackend(t)
	hive, subkey, _ := splitName(`HKLM\SOFTWARE\Contoso`)
	fb.CreateKey(hive, subkey, 0)
	fb.CreateKey(hive, subkey+`\Sub`, 0)
	fb.CreateKey(hive, subkey+`\Sub\Deeper`, 0)

	r := newRegistry("key_absent", map[string]interface{}{"name": `HKLM\SOFTWARE\Contoso`, "force": true})
	res, err := r.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Succeeded || !res.Changed {
		t.Errorf("res = %+v, want succeeded+changed", res)
	}
	for k := range fb.nodes {
		if strings.HasPrefix(k, nodeKey(hive, subkey)) {
			t.Errorf("expected all nodes under %q to be removed, found %q", subkey, k)
		}
	}
}

// --- value coercion ---

func TestToUint64Types(t *testing.T) {
	cases := []interface{}{float64(5), int(5), int64(5), uint32(5), uint64(5), "5"}
	for _, c := range cases {
		n, err := toUint64(c)
		if err != nil {
			t.Errorf("toUint64(%v) error: %v", c, err)
		}
		if n != 5 {
			t.Errorf("toUint64(%v) = %d, want 5", c, n)
		}
	}
}

func TestToUint64Invalid(t *testing.T) {
	if _, err := toUint64(true); err == nil {
		t.Error("expected error for unsupported type")
	}
	if _, err := toUint64(float64(-1)); err == nil {
		t.Error("expected error for negative value")
	}
}

func TestToStringSliceVariants(t *testing.T) {
	got, err := toStringSlice([]interface{}{"a", "b"})
	if err != nil || len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("toStringSlice([]interface{}) = %v, %v", got, err)
	}
	got2, err := toStringSlice([]string{"c", "d"})
	if err != nil || len(got2) != 2 {
		t.Errorf("toStringSlice([]string) = %v, %v", got2, err)
	}
	if _, err := toStringSlice([]interface{}{1}); err == nil {
		t.Error("expected error for non-string element")
	}
	if _, err := toStringSlice("not a list"); err == nil {
		t.Error("expected error for non-slice input")
	}
}

func TestCoerceValueUnsupportedType(t *testing.T) {
	if _, err := coerceValue("bogus", "x"); err == nil {
		t.Error("expected error for unsupported vtype")
	}
}

func TestValuesEqual(t *testing.T) {
	if !valuesEqual([]byte{1, 2}, []byte{1, 2}) {
		t.Error("expected equal byte slices to match")
	}
	if valuesEqual([]byte{1, 2}, []byte{1, 3}) {
		t.Error("expected different byte slices to not match")
	}
	if !valuesEqual([]string{"a"}, []string{"a"}) {
		t.Error("expected equal string slices to match")
	}
	if valuesEqual([]string{"a"}, []string{"a", "b"}) {
		t.Error("expected different-length string slices to not match")
	}
	if !valuesEqual("x", "x") {
		t.Error("expected equal strings to match")
	}
}

func TestDisplayName(t *testing.T) {
	if displayName("") != "(Default)" {
		t.Errorf("displayName(\"\") = %q, want (Default)", displayName(""))
	}
	if displayName("Foo") != "Foo" {
		t.Errorf("displayName(\"Foo\") = %q, want Foo", displayName("Foo"))
	}
}
