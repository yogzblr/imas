package main

import (
	"errors"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
)

// installRecipeLimits hands every IMAS_RECIPE_* limit, the per-cook
// budget and the include cap among them (S4), to cook.SetRenderLimits:
// the include cap's hard maximum, 256, is accepted and 257 refused (which
// stops farmer, initRecipeLimits).
func TestInstallRecipeLimits(t *testing.T) {
	orig := cook.CurrentRenderLimits()
	t.Cleanup(func() {
		if err := cook.SetRenderLimits(orig); err != nil {
			t.Fatal(err)
		}
	})
	l := config.RecipeTemplateLimits{
		MaxSourceBytes: 1000, MaxRenderedBytes: 4000, MaxValueBytes: 2000, RenderTimeout: time.Second, MaxRangeIterations: 5,
		CookRenderTimeout: 3 * time.Second, CookMaxRenderedBytes: 9000, CookMaxRangeIterations: 50, MaxIncludes: 256,
	}
	if err := installRecipeLimits(l); err != nil {
		t.Fatal(err)
	}
	want := cook.RenderLimits{
		MaxSourceBytes: 1000, MaxRenderedBytes: 4000, MaxValueBytes: 2000, RenderTimeout: time.Second, MaxRangeIterations: 5,
		CookRenderTimeout: 3 * time.Second, CookMaxRenderedBytes: 9000, CookMaxRangeIterations: 50, MaxIncludes: 256,
	}
	if got := cook.CurrentRenderLimits(); got != want {
		t.Errorf("limits = %+v, want %+v", got, want)
	}
	for name, bad := range map[string]config.RecipeTemplateLimits{
		"257 includes":              {MaxIncludes: 257},
		"cook time below render":    {CookRenderTimeout: 500 * time.Millisecond},
		"cook bytes below render":   {CookMaxRenderedBytes: 3000},
		"cook iterations above max": {CookMaxRangeIterations: 100_000_001},
	} {
		if err := installRecipeLimits(bad); !errors.Is(err, cook.ErrRenderLimits) {
			t.Errorf("%s: got %v, want cook.ErrRenderLimits", name, err)
		}
	}
}
