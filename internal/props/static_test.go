package props

import (
	"strings"
	"testing"
)

func TestLoadStaticProps(t *testing.T) {
	newTestDB(t)

	cfg := map[string]interface{}{
		"web-1": map[string]interface{}{
			"role": "webserver",
			"env":  "production",
			"port": "8080",
		},
		"db-1": map[string]interface{}{
			"role": "database",
			"env":  "production",
		},
	}

	LoadStaticProps(cfg)

	// Verify props loaded.
	if got := GetStringProp("web-1", "role"); got != "webserver" {
		t.Errorf("web-1 role = %q, want %q", got, "webserver")
	}
	if got := GetStringProp("web-1", "env"); got != "production" {
		t.Errorf("web-1 env = %q, want %q", got, "production")
	}
	if got := GetStringProp("web-1", "port"); got != "8080" {
		t.Errorf("web-1 port = %q, want %q", got, "8080")
	}
	if got := GetStringProp("db-1", "role"); got != "database" {
		t.Errorf("db-1 role = %q, want %q", got, "database")
	}

	// Verify IsStaticProp.
	if !IsStaticProp("web-1", "role") {
		t.Error("web-1 role should be static")
	}
	if IsStaticProp("web-1", "nonexistent") {
		t.Error("nonexistent should not be static")
	}
	if IsStaticProp("unknown-sprout", "role") {
		t.Error("unknown sprout should not have static props")
	}
}

func TestLoadStaticPropsNil(t *testing.T) {
	newTestDB(t)
	// Should not panic.
	LoadStaticProps(nil)
}

func TestClearStaticProps(t *testing.T) {
	newTestDB(t)

	cfg := map[string]interface{}{
		"web-1": map[string]interface{}{
			"role": "webserver",
		},
	}
	LoadStaticProps(cfg)

	// Also set a dynamic prop.
	setPropWithTTL(tenantID(), "web-1", "dynamic-key", "dynamic-val", DefaultPropTTL)

	// Clear static.
	ClearStaticProps()

	// Static prop should be gone.
	if got := GetStringProp("web-1", "role"); got != "" {
		t.Errorf("static prop role should be cleared, got %q", got)
	}
	// Dynamic prop should remain.
	if got := GetStringProp("web-1", "dynamic-key"); got != "dynamic-val" {
		t.Errorf("dynamic prop should remain, got %q", got)
	}
	// IsStaticProp should return false.
	if IsStaticProp("web-1", "role") {
		t.Error("role should no longer be static after clear")
	}
}

func TestLoadStaticPropsInvalidEntry(t *testing.T) {
	newTestDB(t)

	// "bad-sprout" has a non-map value — should be skipped without panic.
	cfg := map[string]interface{}{
		"good-sprout": map[string]interface{}{
			"key": "val",
		},
		"bad-sprout": "not-a-map",
	}
	LoadStaticProps(cfg)

	if got := GetStringProp("good-sprout", "key"); got != "val" {
		t.Errorf("good-sprout key = %q, want 'val'", got)
	}
	// bad-sprout should have nothing.
	if got := GetStringProp("bad-sprout", "key"); got != "" {
		t.Errorf("bad-sprout key should be empty, got %q", got)
	}
}

func TestDropStaticProps(t *testing.T) {
	newTestDB(t)
	LoadStaticProps(map[string]interface{}{
		"web-1": map[string]interface{}{"role": "webserver", "os": "spoofed"},
		"web-2": map[string]interface{}{"OS": "spoofed"},
	})
	// A dynamic prop of the same name is the sprout's own: never dropped.
	setPropWithTTL(tenantID(), "web-3", "os", "linux", DefaultPropTTL)

	isOS := func(name string) bool { return strings.EqualFold(name, "os") }
	if got := DropStaticProps(isOS); got != 2 {
		t.Fatalf("dropped %d, want 2", got)
	}
	if IsStaticProp("web-1", "os") || IsStaticProp("web-2", "OS") {
		t.Error("a static prop named os is left")
	}
	if got := GetStringProp("web-1", "role"); got != "webserver" {
		t.Errorf("web-1 role = %q, want webserver", got)
	}
	if got := GetStringProp("web-3", "os"); got != "linux" {
		t.Errorf("web-3's own os = %q, want linux", got)
	}
}
