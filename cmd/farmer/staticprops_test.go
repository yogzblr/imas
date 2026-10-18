package main

import (
	"reflect"
	"testing"

	"github.com/yogzblr/imas/internal/facts"
)

func TestStaticPropsWithoutFacts(t *testing.T) {
	if got := staticPropsWithoutFacts(nil); got != nil {
		t.Fatalf("nil config: got %v, want nil", got)
	}
	cfg := map[string]any{
		"s1": map[string]any{
			"role":                  "web",
			facts.PropHostname:      "spoofed",
			"OS":                    "spoofed", // reserved names match case-insensitively
			facts.PropSproutVersion: "v0.0.0",
		},
		"s2":  map[string]any{"rack": 7},
		"bad": "not a map",
	}
	want := map[string]any{
		"s1":  map[string]any{"role": "web"},
		"s2":  map[string]any{"rack": 7},
		"bad": "not a map",
	}
	got := staticPropsWithoutFacts(cfg)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if len(cfg["s1"].(map[string]any)) != 4 {
		t.Error("staticPropsWithoutFacts modified its input")
	}
	for _, name := range facts.ReservedPropNames() {
		out := staticPropsWithoutFacts(map[string]any{"s": map[string]any{name: "x"}})
		if len(out["s"].(map[string]any)) != 0 {
			t.Errorf("reserved name %q was kept", name)
		}
	}
}
