//go:build windows

package winfirewall

import (
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseRequiresName(t *testing.T) {
	if _, err := (Rule{}).Parse("id1", methodRulePresent, map[string]interface{}{}); err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Rule{}).Parse("id1", "bogus", map[string]interface{}{"name": "Allow RDP"})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestParseOK(t *testing.T) {
	cooker, err := (Rule{}).Parse("id1", methodRulePresent, map[string]interface{}{
		"name": "Allow RDP", "protocol": "TCP", "localport": "3389",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r, ok := cooker.(Rule)
	if !ok {
		t.Fatalf("expected Rule, got %T", cooker)
	}
	if r.name != "Allow RDP" {
		t.Errorf("expected name %q, got %q", "Allow RDP", r.name)
	}
}

func TestMethods(t *testing.T) {
	name, methods := Rule{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(methods))
	}
}
