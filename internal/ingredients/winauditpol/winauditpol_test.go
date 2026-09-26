//go:build windows

package winauditpol

import (
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseRequiresName(t *testing.T) {
	if _, err := (Subcategory{}).Parse("id1", methodConfigured, map[string]interface{}{}); err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseDefaults(t *testing.T) {
	cooker, err := (Subcategory{}).Parse("id1", methodConfigured, map[string]interface{}{"name": "Logon"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := cooker.(Subcategory)
	if !ok {
		t.Fatalf("expected Subcategory, got %T", cooker)
	}
	if !s.success || !s.failure {
		t.Errorf("expected success/failure to default to true, got %v/%v", s.success, s.failure)
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Subcategory{}).Parse("id1", "bogus", map[string]interface{}{"name": "Logon"})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestEnableDisable(t *testing.T) {
	if enableDisable(true) != "enable" {
		t.Error("expected enable")
	}
	if enableDisable(false) != "disable" {
		t.Error("expected disable")
	}
}

func TestMethods(t *testing.T) {
	name, methods := Subcategory{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 1 {
		t.Errorf("expected 1 method, got %d", len(methods))
	}
}
