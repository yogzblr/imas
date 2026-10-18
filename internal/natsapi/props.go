package natsapi

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
)

// ErrReservedPropName is returned by props.set and props.delete for a name
// that only the sprout's own facts report may write (facts.ReservedPropNames:
// os, arch, hostname, sprout_version, ip_addresses, the hardware keys and
// the rest). saasapi's rollout gate and planning, dynamic cohorts and
// recipe templates all trust those names to be what the sprout reported,
// so a caller with only the props action must not be able to forge or
// clear them (security review H2). FLAG FOR SECURITY REVIEW.
var ErrReservedPropName = errors.New("prop name is reserved for facts the sprout reports")

// ErrInvalidPropName is returned by props.set and props.delete for a name
// that is not 1 to props.MaxNameLen characters of ASCII letters, digits,
// '_', '-', '.' and ':'.
var ErrInvalidPropName = errors.New("prop name must be 1-191 ASCII letters, digits, '_', '-', '.' or ':'")

// validPropName reports whether name may be written: props.ValidName,
// plain ASCII from a small set (see there for why).
func validPropName(name string) bool { return props.ValidName(name) }

// checkWritablePropName is the name check props.set and props.delete share.
func checkWritablePropName(name string) error {
	if !validPropName(name) {
		return ErrInvalidPropName
	}
	if facts.IsReservedPropName(name) {
		return fmt.Errorf("%w: %q", ErrReservedPropName, name)
	}
	return nil
}

// PropsParams holds the sprout and property identifiers.
type PropsParams struct {
	SproutID string `json:"sprout_id"`
	Name     string `json:"name,omitempty"`
	Value    string `json:"value,omitempty"`
}

func handlePropsGetAll(tenantID string, params json.RawMessage) (any, error) {
	var p PropsParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.SproutID == "" {
		return nil, fmt.Errorf("sprout_id is required")
	}
	allProps := props.GetPropsForTenant(tenantID, p.SproutID)
	if allProps == nil {
		allProps = make(map[string]interface{})
	}
	return allProps, nil
}

func handlePropsGet(tenantID string, params json.RawMessage) (any, error) {
	var p PropsParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.SproutID == "" || p.Name == "" {
		return nil, fmt.Errorf("sprout_id and name are required")
	}
	value := props.GetStringPropForTenant(tenantID, p.SproutID, p.Name)
	return map[string]string{
		"sprout_id": p.SproutID,
		"name":      p.Name,
		"value":     value,
	}, nil
}

func handlePropsSet(tenantID string, params json.RawMessage) (any, error) {
	var p PropsParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.SproutID == "" || p.Name == "" {
		return nil, fmt.Errorf("sprout_id and name are required")
	}
	if !pki.IsValidSproutID(p.SproutID) {
		return nil, fmt.Errorf("invalid sprout_id")
	}
	if err := checkWritablePropName(p.Name); err != nil {
		return nil, err
	}
	if err := props.SetPropForTenant(tenantID, p.SproutID, p.Name, p.Value); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePropsDelete(tenantID string, params json.RawMessage) (any, error) {
	var p PropsParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.SproutID == "" || p.Name == "" {
		return nil, fmt.Errorf("sprout_id and name are required")
	}
	if !pki.IsValidSproutID(p.SproutID) {
		return nil, fmt.Errorf("invalid sprout_id")
	}
	if err := checkWritablePropName(p.Name); err != nil {
		return nil, err
	}
	if err := props.DeletePropForTenant(tenantID, p.SproutID, p.Name); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}
