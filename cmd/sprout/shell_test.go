package main

import (
	"slices"
	"testing"

	"github.com/taigrr/jety"
)

// The sprout's shell policy comes from its config: disableshell (default
// false), shellallowlist (default empty: /etc/shells) and
// shellmaxsessions.
func TestShellPolicyFromConfig(t *testing.T) {
	t.Cleanup(func() {
		jety.Set("disableshell", false)
		jety.Set("shellallowlist", []string{})
		jety.Set("shellmaxsessions", 0)
	})
	if p := shellPolicyFromConfig(); p.Disabled || len(p.AllowedShells) != 0 || p.MaxSessions != 0 {
		t.Fatalf("defaults: %+v", p)
	}
	jety.Set("disableshell", true)
	jety.Set("shellallowlist", []string{"/bin/bash", "/bin/sh"})
	jety.Set("shellmaxsessions", 3)
	p := shellPolicyFromConfig()
	if !p.Disabled || !slices.Equal(p.AllowedShells, []string{"/bin/bash", "/bin/sh"}) || p.MaxSessions != 3 {
		t.Fatalf("configured: %+v", p)
	}
}
