//go:build linux

package selinux

import (
	"context"
	"testing"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestMethods(t *testing.T) {
	name, methods := SELinux{}.Methods()
	if name != "selinux" {
		t.Fatalf("expected ingredient name selinux, got %s", name)
	}
	want := map[string]bool{
		"enforcing": true, "permissive": true,
		"boolean_on": true, "boolean_off": true,
		"context_present": true,
	}
	if len(methods) != len(want) {
		t.Fatalf("unexpected method count: %v", methods)
	}
	for _, m := range methods {
		if !want[m] {
			t.Fatalf("unexpected method %s", m)
		}
	}
}

func TestParseUnknownMethod(t *testing.T) {
	if _, err := (SELinux{}).Parse("t", "bogus", nil); err == nil {
		t.Fatal("expected error for unknown method")
	}
}

func TestParseBooleanRequiresName(t *testing.T) {
	if _, err := (SELinux{}).Parse("t", "boolean_on", map[string]interface{}{}); err != ingredients.ErrMissingName {
		t.Fatalf("expected ErrMissingName, got %v", err)
	}
}

func TestParseContextPresentRequiresContext(t *testing.T) {
	_, err := (SELinux{}).Parse("t", "context_present", map[string]interface{}{"name": "/etc/foo"})
	if err == nil {
		t.Fatal("expected error for missing context property")
	}
}

func TestParseModeMethodsNeedNoProperties(t *testing.T) {
	if _, err := (SELinux{}).Parse("t", "enforcing", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := (SELinux{}).Parse("t", "permissive", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProperties(t *testing.T) {
	s := SELinux{params: map[string]interface{}{"name": "httpd_can_network_connect"}}
	props, err := s.Properties()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if props["name"] != "httpd_can_network_connect" {
		t.Fatalf("unexpected properties: %v", props)
	}
}

func TestApplyTestUndefinedMethod(t *testing.T) {
	s := SELinux{id: "t", method: "bogus"}
	ctx := context.Background()
	if _, err := s.Apply(ctx); err == nil {
		t.Fatal("expected error for undefined method on Apply")
	}
	if _, err := s.Test(ctx); err == nil {
		t.Fatal("expected error for undefined method on Test")
	}
}
