//go:build windows

package winsnmp

import (
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseRequiresName(t *testing.T) {
	if _, err := (Community{}).Parse("id1", methodCommunityPresent, map[string]interface{}{}); err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseInvalidPermission(t *testing.T) {
	_, err := (Community{}).Parse("id1", methodCommunityPresent, map[string]interface{}{
		"name": "public", "permission": "bogus",
	})
	if err == nil {
		t.Fatal("expected error for invalid permission")
	}
}

func TestParseDefaultPermission(t *testing.T) {
	cooker, err := (Community{}).Parse("id1", methodCommunityPresent, map[string]interface{}{"name": "public"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cooker.(Community); !ok {
		t.Fatalf("expected Community, got %T", cooker)
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Community{}).Parse("id1", "bogus", map[string]interface{}{"name": "public"})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestMethods(t *testing.T) {
	name, methods := Community{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(methods))
	}
}
