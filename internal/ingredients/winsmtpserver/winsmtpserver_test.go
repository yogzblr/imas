//go:build windows

package winsmtpserver

import (
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseRequiresName(t *testing.T) {
	_, err := (Setting{}).Parse("id1", methodSetting, map[string]interface{}{"value": "100"})
	if err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseRequiresValue(t *testing.T) {
	_, err := (Setting{}).Parse("id1", methodSetting, map[string]interface{}{"name": "MaxRecipients"})
	if err == nil {
		t.Fatal("expected error for missing value")
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Setting{}).Parse("id1", "bogus", map[string]interface{}{"name": "MaxRecipients", "value": "100"})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestParseOK(t *testing.T) {
	cooker, err := (Setting{}).Parse("id1", methodSetting, map[string]interface{}{"name": "MaxRecipients", "value": "100"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := cooker.(Setting)
	if !ok {
		t.Fatalf("expected Setting, got %T", cooker)
	}
	if s.value != "100" {
		t.Errorf("expected value 100, got %q", s.value)
	}
}

func TestMethods(t *testing.T) {
	name, methods := Setting{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 1 {
		t.Errorf("expected 1 method, got %d", len(methods))
	}
}
