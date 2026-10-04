package natsapi

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/props"
)

// SEC.4 / security review H2: props.set and props.delete refuse the names
// only the sprout's own facts report may write, in any case, and names
// the database collation could fold onto them.
func TestPropsSetDelete_ReservedNamesRefused(t *testing.T) {
	tenant := props.CurrentTenantID()
	const sprout = "reserved-sprout"
	if err := props.SetPropForTenant(tenant, sprout, facts.PropSproutVersion, "v1.0.0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { props.DeletePropForTenant(tenant, sprout, facts.PropSproutVersion) })

	names := append(facts.ReservedPropNames(), "OS", "Sprout_Version", "HOSTNAME", "System_UUID")
	for _, name := range names {
		params, _ := json.Marshal(PropsParams{SproutID: sprout, Name: name, Value: "v9.9.9"})
		if _, err := handlePropsSet(tenant, params); !errors.Is(err, ErrReservedPropName) {
			t.Errorf("props.set %q: got %v, want ErrReservedPropName", name, err)
		}
		if _, err := handlePropsDelete(tenant, params); !errors.Is(err, ErrReservedPropName) {
			t.Errorf("props.delete %q: got %v, want ErrReservedPropName", name, err)
		}
	}
	if got := props.GetStringPropForTenant(tenant, sprout, facts.PropSproutVersion); got != "v1.0.0" {
		t.Errorf("sprout_version = %q after refused writes, want v1.0.0", got)
	}

	for _, name := range []string{"ös", "o\x01s", "os ", " os", "o s", "", string(make([]byte, 192))} {
		params, _ := json.Marshal(PropsParams{SproutID: sprout, Name: name, Value: "x"})
		if _, err := handlePropsSet(tenant, params); err == nil {
			t.Errorf("props.set %q accepted", name)
		}
		if _, err := handlePropsDelete(tenant, params); err == nil {
			t.Errorf("props.delete %q accepted", name)
		}
	}

	for _, sid := range []string{"Bad_Upper", "-dash", "a/b"} {
		params, _ := json.Marshal(PropsParams{SproutID: sid, Name: "role", Value: "x"})
		if _, err := handlePropsSet(tenant, params); err == nil {
			t.Errorf("props.set for sprout %q accepted", sid)
		}
	}

	// Ordinary names still work.
	for _, name := range []string{"role", "rack:row", "app.version", "os_family"} {
		params, _ := json.Marshal(PropsParams{SproutID: sprout, Name: name, Value: "x"})
		if _, err := handlePropsSet(tenant, params); err != nil {
			t.Errorf("props.set %q: %v", name, err)
		}
		if _, err := handlePropsDelete(tenant, params); err != nil {
			t.Errorf("props.delete %q: %v", name, err)
		}
	}
}
