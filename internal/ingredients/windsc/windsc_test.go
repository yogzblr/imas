//go:build windows

package windsc

import (
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseRequiresName(t *testing.T) {
	if _, err := (Dsc{}).Parse("id1", methodApplied, map[string]interface{}{"path": `C:\dsc`}); err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseRequiresPath(t *testing.T) {
	_, err := (Dsc{}).Parse("id1", methodApplied, map[string]interface{}{"name": "web-config"})
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Dsc{}).Parse("id1", "bogus", map[string]interface{}{"name": "web-config", "path": `C:\dsc`})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestParseOK(t *testing.T) {
	cooker, err := (Dsc{}).Parse("id1", methodApplied, map[string]interface{}{"name": "web-config", "path": `C:\dsc`})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d, ok := cooker.(Dsc)
	if !ok {
		t.Fatalf("expected Dsc, got %T", cooker)
	}
	if d.path != `C:\dsc` {
		t.Errorf("expected path C:\\dsc, got %q", d.path)
	}
}

func TestMethods(t *testing.T) {
	name, methods := Dsc{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 1 || methods[0] != methodApplied {
		t.Errorf("unexpected methods: %v", methods)
	}
}
