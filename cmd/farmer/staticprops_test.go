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
			"hóstname":              "spoofed", // PXC folds the accent onto "hostname"
			"o\x01s":                "spoofed", // and ignores the control character
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
	if len(cfg["s1"].(map[string]any)) != 6 {
		t.Error("staticPropsWithoutFacts modified its input")
	}
	for _, name := range facts.ReservedPropNames() {
		out := staticPropsWithoutFacts(map[string]any{"s": map[string]any{name: "x"}})
		if len(out["s"].(map[string]any)) != 0 {
			t.Errorf("reserved name %q was kept", name)
		}
	}
}

// The startup sweep drops what the loader refuses: reserved names and
// names outside props.ValidName, which PXC could fold onto a reserved row.
func TestStaticPropNameRefused(t *testing.T) {
	for name, want := range map[string]bool{
		"role": false, "rack-7": false, "a.b:c_d": false,
		"hostname": true, "OS": true, "hóstname": true, "o\x01s": true, "": true,
	} {
		if got := staticPropNameRefused(name); got != want {
			t.Errorf("staticPropNameRefused(%q) = %t, want %t", name, got, want)
		}
	}
}
