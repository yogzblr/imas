//go:build linux

package firewall

import (
	"context"
	"errors"
	"testing"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

func TestMethodsAdvertisesAllSix(t *testing.T) {
	name, methods := Firewall{}.Methods()
	if name != "firewall" {
		t.Fatalf("ingredient name = %q, want firewall", name)
	}
	want := map[string]bool{
		MethodTablePresent: true, MethodTableAbsent: true,
		MethodChainPresent: true, MethodChainAbsent: true,
		MethodRulePresent: true, MethodRuleAbsent: true,
	}
	if len(methods) != len(want) {
		t.Fatalf("Methods() = %v, want 6 entries", methods)
	}
	for _, m := range methods {
		if !want[m] {
			t.Errorf("unexpected method %q", m)
		}
	}
}

func TestParseMissingRequiredProperty(t *testing.T) {
	if _, err := (Firewall{}).Parse("t1", MethodTablePresent, map[string]interface{}{}); !errors.Is(err, ErrMissingProperty) {
		t.Fatalf("missing name: want ErrMissingProperty, got %v", err)
	}
	if _, err := (Firewall{}).Parse("t1", MethodRulePresent, map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input",
	}); !errors.Is(err, ErrMissingProperty) {
		t.Fatalf("missing action: want ErrMissingProperty, got %v", err)
	}
}

func TestParseInvalidMethod(t *testing.T) {
	if _, err := (Firewall{}).Parse("t1", "bogus_method", nil); !errors.Is(err, ingredients.ErrInvalidMethod) {
		t.Fatalf("bogus method: want ErrInvalidMethod, got %v", err)
	}
}

func TestRegisteredWithIngredientsRegistry(t *testing.T) {
	step, err := ingredients.NewRecipeCooker("step1", "firewall", MethodTablePresent, map[string]interface{}{
		"name": "imas",
	})
	if err != nil {
		t.Fatalf("NewRecipeCooker: %v", err)
	}
	if _, ok := step.(Firewall); !ok {
		t.Fatalf("NewRecipeCooker returned %T, want Firewall", step)
	}
}

func TestApplyEndToEndTableChainRule(t *testing.T) {
	conn := newFakeConn()
	cleanup := withFakeDial(conn)
	defer cleanup()

	steps := []struct {
		method string
		params map[string]interface{}
	}{
		{MethodTablePresent, map[string]interface{}{"name": "filter", "family": "inet"}},
		{MethodChainPresent, map[string]interface{}{
			"name": "input", "table": "filter", "family": "inet",
			"hook": "input", "priority": "0", "policy": "accept",
		}},
		{MethodRulePresent, map[string]interface{}{
			"name": "allow-ssh", "table": "filter", "chain": "input", "family": "inet",
			"protocol": "tcp", "dport": "22", "action": "accept",
		}},
	}

	for _, s := range steps {
		fw, err := (Firewall{}).Parse("id", s.method, s.params)
		if err != nil {
			t.Fatalf("Parse(%s): %v", s.method, err)
		}
		if _, err := fw.Test(context.Background()); err != nil {
			t.Fatalf("Test(%s): %v", s.method, err)
		}
		res, err := fw.Apply(context.Background())
		if err != nil || !res.Succeeded || !res.Changed {
			t.Fatalf("Apply(%s): res=%+v err=%v", s.method, res, err)
		}
	}

	if len(conn.tables) != 1 || len(conn.chains) != 1 || len(conn.rules[ruleKey("filter", "input")]) != 1 {
		t.Fatalf("unexpected end state: tables=%d chains=%d rules=%d",
			len(conn.tables), len(conn.chains), len(conn.rules[ruleKey("filter", "input")]))
	}

	// Re-applying the same three steps must be a fully idempotent no-op.
	for _, s := range steps {
		fw, err := (Firewall{}).Parse("id", s.method, s.params)
		if err != nil {
			t.Fatalf("re-Parse(%s): %v", s.method, err)
		}
		res, err := fw.Apply(context.Background())
		if err != nil || res.Changed {
			t.Fatalf("re-Apply(%s) should be a no-op: res=%+v err=%v", s.method, res, err)
		}
	}
}

func TestPropertiesRoundTrip(t *testing.T) {
	params := map[string]interface{}{"name": "imas", "family": "ip"}
	fw, err := (Firewall{}).Parse("id", MethodTablePresent, params)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := fw.Properties()
	if err != nil {
		t.Fatalf("Properties: %v", err)
	}
	if got["name"] != "imas" {
		t.Fatalf("Properties()[name] = %v, want imas", got["name"])
	}
}

var _ cook.RecipeCooker = Firewall{}
