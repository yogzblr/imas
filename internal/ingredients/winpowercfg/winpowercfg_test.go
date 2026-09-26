//go:build windows

package winpowercfg

import (
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseRequiresName(t *testing.T) {
	if _, err := (Scheme{}).Parse("id1", methodActiveScheme, map[string]interface{}{}); err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Scheme{}).Parse("id1", "bogus", map[string]interface{}{"name": "381b4222-f694-41f0-9685-ff5bb260df2e"})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestGUIDRegex(t *testing.T) {
	out := "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)"
	if got := guidRE.FindString(out); got != "381b4222-f694-41f0-9685-ff5bb260df2e" {
		t.Errorf("expected extracted GUID, got %q", got)
	}
}

func TestMethods(t *testing.T) {
	name, methods := Scheme{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 1 {
		t.Errorf("expected 1 method, got %d", len(methods))
	}
}
