//go:build windows

package winpsget

import (
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseRequiresName(t *testing.T) {
	if _, err := (PSGet{}).Parse("id1", methodInstalled, map[string]interface{}{}); err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (PSGet{}).Parse("id1", "bogus", map[string]interface{}{"name": "Pester"})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestParseOK(t *testing.T) {
	cooker, err := (PSGet{}).Parse("id1", methodInstalled, map[string]interface{}{"name": "Pester", "version": "5.4.0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p, ok := cooker.(PSGet)
	if !ok {
		t.Fatalf("expected PSGet, got %T", cooker)
	}
	if p.name != "Pester" {
		t.Errorf("expected name Pester, got %q", p.name)
	}
}

func TestMethods(t *testing.T) {
	name, methods := PSGet{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(methods))
	}
}
