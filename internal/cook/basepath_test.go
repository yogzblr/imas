package cook

import (
	"testing"

	"github.com/yogzblr/imas/internal/config"
)

func TestGetBasePathEnvOverride(t *testing.T) {
	old := config.RecipeDir
	defer func() { config.RecipeDir = old }()
	config.RecipeDir = "/srv/imas/recipes/prod"

	t.Setenv(RecipeDirEnvVar, "/srv/imas/recipes/feature-branch")
	if got := getBasePath(); got != "/srv/imas/recipes/feature-branch" {
		t.Errorf("expected env override to win, got %q", got)
	}
}

func TestGetBasePathFallsBackToConfig(t *testing.T) {
	old := config.RecipeDir
	defer func() { config.RecipeDir = old }()
	config.RecipeDir = "/srv/imas/recipes/prod"

	// Empty env var must fall back to the configured recipe dir.
	t.Setenv(RecipeDirEnvVar, "")
	if got := getBasePath(); got != "/srv/imas/recipes/prod" {
		t.Errorf("expected config.RecipeDir fallback, got %q", got)
	}
}
