package main

import (
	"errors"
	"testing"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/ingredients"
)

// Every sprout build links the self-update ingredient (include.go): there
// is no build without it (security review 2026-10, I5).
func TestSproutLinksSelfUpdate(t *testing.T) {
	_, err := ingredients.NewRecipeCooker("su", cook.Ingredient(fleetsign.SelfUpdateIngredient), fleetsign.SelfUpdateMethod, map[string]interface{}{})
	if errors.Is(err, ingredients.ErrUnknownIngredient) || errors.Is(err, ingredients.ErrUnknownMethod) {
		t.Fatalf("%s.%s is not registered in the sprout: %v", fleetsign.SelfUpdateIngredient, fleetsign.SelfUpdateMethod, err)
	}
}
