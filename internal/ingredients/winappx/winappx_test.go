//go:build windows

package winappx

import (
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseRequiresName(t *testing.T) {
	if _, err := (Package{}).Parse("id1", methodRemoved, map[string]interface{}{}); err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseInstalledRequiresPath(t *testing.T) {
	_, err := (Package{}).Parse("id1", methodInstalled, map[string]interface{}{"name": "Contoso.App"})
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestParseRemovedNoPathNeeded(t *testing.T) {
	_, err := (Package{}).Parse("id1", methodRemoved, map[string]interface{}{"name": "Contoso.App"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Package{}).Parse("id1", "bogus", map[string]interface{}{"name": "Contoso.App"})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestMethods(t *testing.T) {
	name, methods := Package{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(methods))
	}
}
