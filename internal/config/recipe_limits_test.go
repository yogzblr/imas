package config

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var recipeLimitEnvs = []string{
	EnvRecipeMaxSourceBytes, EnvRecipeMaxRenderedBytes, EnvRecipeMaxValueBytes,
	EnvRecipeRenderTimeout, EnvRecipeMaxRangeIterations,
}

// RecipeLimits come from the IMAS_RECIPE_* variables the farmer chart's
// farmer.recipes.templateLimits renders; unset means cook's defaults.
func TestLoadConfig_FarmerRecipeLimits(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		for _, e := range recipeLimitEnvs {
			t.Setenv(e, "")
		}
		loadFarmerWithConfig(t, "")
		if RecipeLimits != (RecipeTemplateLimits{}) {
			t.Errorf("RecipeLimits = %+v, want zero (cook's defaults)", RecipeLimits)
		}
	})
	t.Run("from env", func(t *testing.T) {
		t.Setenv(EnvRecipeMaxSourceBytes, "1000")
		t.Setenv(EnvRecipeMaxRenderedBytes, "4000")
		t.Setenv(EnvRecipeMaxValueBytes, "2000")
		t.Setenv(EnvRecipeRenderTimeout, "500ms")
		t.Setenv(EnvRecipeMaxRangeIterations, "7")
		loadFarmerWithConfig(t, "")
		want := RecipeTemplateLimits{1000, 4000, 2000, 500 * time.Millisecond, 7}
		if RecipeLimits != want {
			t.Errorf("RecipeLimits = %+v, want %+v", RecipeLimits, want)
		}
	})
}

func TestRecipeTemplateLimitsFromEnv_Invalid(t *testing.T) {
	for env, bad := range map[string]string{
		EnvRecipeMaxSourceBytes:     "256Ki",
		EnvRecipeMaxRenderedBytes:   "0",
		EnvRecipeMaxValueBytes:      "-1",
		EnvRecipeRenderTimeout:      "2",
		EnvRecipeMaxRangeIterations: "1.5",
	} {
		for _, e := range recipeLimitEnvs {
			t.Setenv(e, "")
		}
		t.Setenv(env, bad)
		if _, err := recipeTemplateLimitsFromEnv(); err == nil || !strings.Contains(err.Error(), env) {
			t.Errorf("%s=%q: got %v, want an error naming the variable", env, bad, err)
		}
	}
	t.Setenv(EnvRecipeRenderTimeout, "-2s")
	if _, err := recipeTemplateLimitsFromEnv(); err == nil {
		t.Error("negative timeout accepted")
	}
}

// An invalid IMAS_RECIPE_* value stops farmer. log.Fatalf exits, so this
// runs in a subprocess.
func TestLoadConfig_FarmerRecipeLimitsInvalidExits(t *testing.T) {
	if v := os.Getenv("IMAS_TEST_RECIPE_LIMIT_SUBPROCESS"); v != "" {
		t.Setenv(EnvRecipeMaxSourceBytes, v)
		loadFarmerWithConfig(t, "")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLoadConfig_FarmerRecipeLimitsInvalidExits$")
	cmd.Env = append(os.Environ(), "IMAS_TEST_RECIPE_LIMIT_SUBPROCESS=lots")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("farmer config loaded with an invalid limit; want it to exit")
	}
	if !strings.Contains(string(out), EnvRecipeMaxSourceBytes) {
		t.Errorf("exit message doesn't name the variable:\n%s", out)
	}
}
