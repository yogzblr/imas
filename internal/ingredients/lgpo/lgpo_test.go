package lgpo

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func newLGPO(method string, params map[string]interface{}) LGPO {
	return LGPO{id: "test-id", method: method, params: params}
}

func baseParams(t *testing.T, extra map[string]interface{}) map[string]interface{} {
	t.Helper()
	p := map[string]interface{}{
		"name":     "ExampleBoolean",
		"admx":     "testdata/example.admx",
		"adml":     "testdata/en-us/example.adml",
		"class":    "machine",
		"pol_path": filepath.Join(t.TempDir(), "registry.pol"),
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// --- Parse/validate ---

func TestLGPOParseMissingName(t *testing.T) {
	l := LGPO{}
	_, err := l.Parse("id", "present", map[string]interface{}{"admx": "x", "class": "machine", "state": "enabled"})
	if err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestLGPOParseMissingADMX(t *testing.T) {
	l := LGPO{}
	_, err := l.Parse("id", "present", map[string]interface{}{"name": "X", "class": "machine", "state": "enabled"})
	if err != ErrMissingADMX {
		t.Errorf("expected ErrMissingADMX, got %v", err)
	}
}

func TestLGPOParseInvalidClass(t *testing.T) {
	l := LGPO{}
	_, err := l.Parse("id", "present", map[string]interface{}{"name": "X", "admx": "x", "class": "bogus", "state": "enabled"})
	if err != ErrMissingClass {
		t.Errorf("expected ErrMissingClass, got %v", err)
	}
}

func TestLGPOParsePresentMissingState(t *testing.T) {
	l := LGPO{}
	_, err := l.Parse("id", "present", map[string]interface{}{"name": "X", "admx": "x", "class": "machine"})
	if err != ErrMissingState {
		t.Errorf("expected ErrMissingState, got %v", err)
	}
}

func TestLGPOParseAbsentDoesNotRequireState(t *testing.T) {
	l := LGPO{}
	_, err := l.Parse("id", "absent", map[string]interface{}{"name": "X", "admx": "x", "class": "machine"})
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
}

func TestLGPOMethodsAndProperties(t *testing.T) {
	l := LGPO{}
	name, methods := l.Methods()
	if name != "lgpo" {
		t.Errorf("Methods() name = %q, want lgpo", name)
	}
	want := map[string]bool{"present": true, "absent": true}
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

func TestLGPOUndefinedMethod(t *testing.T) {
	l := newLGPO("bogus", baseParams(t, nil))
	if _, err := l.Apply(context.Background()); err == nil {
		t.Fatal("expected an error for an undefined method")
	}
}

// --- present ---

func TestPresentEnablesPolicy(t *testing.T) {
	params := baseParams(t, map[string]interface{}{"state": "enabled"})
	l := newLGPO("present", params)
	res, err := l.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Succeeded || !res.Changed {
		t.Fatalf("res = %+v, want succeeded+changed", res)
	}

	f, err := readPolFile(params["pol_path"].(string))
	if err != nil {
		t.Fatalf("readPolFile() error: %v", err)
	}
	e, ok := f.Find(`Software\Policies\Imas\Example`, "EnableFeature")
	if !ok {
		t.Fatal("expected the value to be present in registry.pol")
	}
	if e.Type != RegDWORD || e.Data[0] != 1 {
		t.Errorf("unexpected entry: %+v", e)
	}

	// Second apply should be a no-op.
	res2, err := l.Apply(context.Background())
	if err != nil {
		t.Fatalf("second Apply() error: %v", err)
	}
	if res2.Changed {
		t.Errorf("second Apply() res = %+v, want unchanged", res2)
	}
}

func TestPresentTestModeDoesNotWrite(t *testing.T) {
	params := baseParams(t, map[string]interface{}{"state": "enabled"})
	l := newLGPO("present", params)
	res, err := l.Test(context.Background())
	if err != nil {
		t.Fatalf("Test() error: %v", err)
	}
	if !res.Succeeded || !res.Changed {
		t.Fatalf("res = %+v, want succeeded+changed", res)
	}
	f, err := readPolFile(params["pol_path"].(string))
	if err != nil {
		t.Fatalf("readPolFile() error: %v", err)
	}
	if len(f.Entries) != 0 {
		t.Errorf("Test() should not have written any entries, found %d", len(f.Entries))
	}
}

func TestPresentTogglingEnabledToDisabled(t *testing.T) {
	params := baseParams(t, map[string]interface{}{"state": "enabled"})
	l := newLGPO("present", params)
	if _, err := l.Apply(context.Background()); err != nil {
		t.Fatalf("Apply() error: %v", err)
	}

	params["state"] = "disabled"
	l2 := newLGPO("present", params)
	res, err := l2.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected a change switching from enabled to disabled, got %+v", res)
	}

	f, err := readPolFile(params["pol_path"].(string))
	if err != nil {
		t.Fatalf("readPolFile() error: %v", err)
	}
	e, _ := f.Find(`Software\Policies\Imas\Example`, "EnableFeature")
	if e.Data[0] != 0 {
		t.Errorf("expected dword 0 after disabling, got %v", e.Data)
	}
}

func TestPresentWrongClass(t *testing.T) {
	params := baseParams(t, map[string]interface{}{"state": "enabled", "class": "user"})
	l := newLGPO("present", params)
	if _, err := l.Apply(context.Background()); err == nil {
		t.Fatal("expected an error requesting a Machine policy under class user")
	}
}

func TestPresentUnknownPolicy(t *testing.T) {
	params := baseParams(t, map[string]interface{}{"state": "enabled", "name": "NoSuchPolicy"})
	l := newLGPO("present", params)
	if _, err := l.Apply(context.Background()); err == nil {
		t.Fatal("expected an error for an unknown policy name")
	}
}

func TestPresentElementsRoundTrip(t *testing.T) {
	params := baseParams(t, map[string]interface{}{
		"name": "ExampleElements", "class": "user", "state": "enabled",
		"elements": map[string]interface{}{"MyBool": true, "MyNum": float64(5), "MyText": "hi"},
	})
	l := newLGPO("present", params)
	res, err := l.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Succeeded || !res.Changed {
		t.Fatalf("res = %+v", res)
	}
	f, err := readPolFile(params["pol_path"].(string))
	if err != nil {
		t.Fatalf("readPolFile() error: %v", err)
	}
	if len(f.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(f.Entries))
	}
}

// --- absent ---

func TestAbsentOnFreshFile(t *testing.T) {
	params := baseParams(t, nil)
	l := newLGPO("absent", params)
	res, err := l.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Succeeded || !res.Changed {
		t.Fatalf("res = %+v, want succeeded+changed (writing a delete marker)", res)
	}

	res2, err := l.Apply(context.Background())
	if err != nil {
		t.Fatalf("second Apply() error: %v", err)
	}
	if res2.Changed {
		t.Errorf("second Apply() res = %+v, want unchanged", res2)
	}
}

func TestAbsentRemovesEnabledPolicy(t *testing.T) {
	params := baseParams(t, map[string]interface{}{"state": "enabled"})
	present := newLGPO("present", params)
	if _, err := present.Apply(context.Background()); err != nil {
		t.Fatalf("Apply() error: %v", err)
	}

	absent := newLGPO("absent", params)
	res, err := absent.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected a change removing a previously-enabled policy, got %+v", res)
	}

	f, err := readPolFile(params["pol_path"].(string))
	if err != nil {
		t.Fatalf("readPolFile() error: %v", err)
	}
	var found bool
	for _, e := range f.Entries {
		if name, ok := e.IsDeleteMarker(); ok && name == "EnableFeature" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a **del.EnableFeature marker entry in the file, got %+v", f.Entries)
	}
}

func TestAbsentTestModeDoesNotWrite(t *testing.T) {
	params := baseParams(t, nil)
	l := newLGPO("absent", params)
	res, err := l.Test(context.Background())
	if err != nil {
		t.Fatalf("Test() error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("res = %+v, want changed", res)
	}
	f, err := readPolFile(params["pol_path"].(string))
	if err != nil {
		t.Fatalf("readPolFile() error: %v", err)
	}
	if len(f.Entries) != 0 {
		t.Errorf("Test() should not have written anything, found %d entries", len(f.Entries))
	}
}

// --- defaultPolPath ---

func TestDefaultPolPath(t *testing.T) {
	m := defaultPolPath("Machine")
	u := defaultPolPath("User")
	if m == u {
		t.Error("expected Machine and User default paths to differ")
	}
	if filepath.Base(m) != "registry.pol" || filepath.Base(u) != "registry.pol" {
		t.Errorf("expected both default paths to end in registry.pol: %q / %q", m, u)
	}
}
