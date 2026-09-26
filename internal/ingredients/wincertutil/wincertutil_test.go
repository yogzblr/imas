//go:build windows

package wincertutil

import (
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseRequiresName(t *testing.T) {
	_, err := (Cert{}).Parse("id1", methodCertAbsent, map[string]interface{}{"thumbprint": "ABC123"})
	if err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseRequiresThumbprint(t *testing.T) {
	_, err := (Cert{}).Parse("id1", methodCertAbsent, map[string]interface{}{"name": "mycert"})
	if err == nil {
		t.Fatal("expected error for missing thumbprint")
	}
}

func TestParsePresentRequiresPath(t *testing.T) {
	_, err := (Cert{}).Parse("id1", methodCertPresent, map[string]interface{}{"name": "mycert", "thumbprint": "ABC123"})
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Cert{}).Parse("id1", "bogus", map[string]interface{}{"name": "mycert", "thumbprint": "ABC123"})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestStoreDefault(t *testing.T) {
	c := Cert{params: map[string]interface{}{}}
	if got := c.store(); got != "My" {
		t.Errorf("expected default store My, got %q", got)
	}
}

func TestMethods(t *testing.T) {
	name, methods := Cert{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(methods))
	}
}
