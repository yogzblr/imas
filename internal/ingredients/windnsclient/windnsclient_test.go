//go:build windows

package windnsclient

import (
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseRequiresName(t *testing.T) {
	_, err := (Interface{}).Parse("id1", methodConfigured, map[string]interface{}{"servers": []string{"1.1.1.1"}})
	if err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseRequiresServers(t *testing.T) {
	_, err := (Interface{}).Parse("id1", methodConfigured, map[string]interface{}{"name": "Ethernet"})
	if err == nil {
		t.Fatal("expected error for missing servers")
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Interface{}).Parse("id1", "bogus", map[string]interface{}{"name": "Ethernet", "servers": []string{"1.1.1.1"}})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestSameServers(t *testing.T) {
	if !sameServers([]string{"1.1.1.1", "8.8.8.8"}, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Error("expected equal slices to match")
	}
	if sameServers([]string{"1.1.1.1"}, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Error("expected different-length slices to not match")
	}
	if sameServers([]string{"1.1.1.1", "8.8.8.8"}, []string{"8.8.8.8", "1.1.1.1"}) {
		t.Error("expected order to matter")
	}
}

func TestMethods(t *testing.T) {
	name, methods := Interface{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 1 {
		t.Errorf("expected 1 method, got %d", len(methods))
	}
}
