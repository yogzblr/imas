//go:build windows

package winiis

import (
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseRequiresName(t *testing.T) {
	if _, err := (Site{}).Parse("id1", methodStarted, map[string]interface{}{}); err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Site{}).Parse("id1", "bogus", map[string]interface{}{"name": "Default Web Site"})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestParseOK(t *testing.T) {
	cooker, err := (Site{}).Parse("id1", methodStopped, map[string]interface{}{"name": "Default Web Site"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := cooker.(Site)
	if !ok {
		t.Fatalf("expected Site, got %T", cooker)
	}
	if s.method != methodStopped {
		t.Errorf("expected method %q, got %q", methodStopped, s.method)
	}
}

func TestMethods(t *testing.T) {
	name, methods := Site{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(methods))
	}
}
