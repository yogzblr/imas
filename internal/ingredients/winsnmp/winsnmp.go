//go:build windows

// Package winsnmp wraps the community-string part of Salt's win_snmp
// module. The Windows SNMP service has no dedicated PowerShell cmdlets
// for community management, so — same as Salt's own module — this reads
// and writes the service's registry-backed community list via
// PowerShell (Get/New/Remove-ItemProperty against
// HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities).
// See G.8 in docs/design/imas-windows-parity-addendum.md.
package winsnmp

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_snmp"

const (
	methodCommunityPresent = "community_present"
	methodCommunityAbsent  = "community_absent"
)

// permissionValues mirrors the SNMP service's ValidCommunities REG_DWORD
// permission values.
var permissionValues = map[string]int{
	"none":        1,
	"notify":      2,
	"read only":   4,
	"read write":  8,
	"read create": 16,
}

const communitiesKey = `HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities`

var methodProps = map[string]ingredients.MethodPropsSet{
	methodCommunityPresent: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "permission", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
	methodCommunityAbsent: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Community{}

// Community manages a single SNMP community string by name.
type Community struct {
	id     string
	method string
	name   string
	params map[string]interface{}
}

func (c Community) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	if _, ok := methodProps[method]; !ok {
		return nil, ingredients.ErrInvalidMethod
	}
	name, ok := winexec.StringParam(params, "name")
	if !ok || name == "" {
		return nil, ingredients.ErrMissingName
	}
	if method == methodCommunityPresent {
		perm := winexec.StringParamOr(params, "permission", "read only")
		if _, ok := permissionValues[perm]; !ok {
			return nil, fmt.Errorf("invalid permission %q", perm)
		}
	}
	return Community{id: id, method: method, name: name, params: params}, nil
}

func (c Community) Methods() (string, []string) {
	return ingredientName, []string{methodCommunityPresent, methodCommunityAbsent}
}

func (c Community) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return p.ToMap(), nil
}

func (c Community) Properties() (map[string]interface{}, error) {
	return c.params, nil
}

func (c Community) exists(ctx context.Context) (bool, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(c.params, "timeout", ""))
	if err != nil {
		return false, err
	}
	script := fmt.Sprintf(
		"[bool](Get-ItemProperty -Path %s -Name %s -ErrorAction SilentlyContinue)",
		winexec.PSQuote(communitiesKey), winexec.PSQuote(c.name),
	)
	out, err := winexec.RunPowerShell(ctx, script, timeout)
	if err != nil {
		return false, err
	}
	return out == "True", nil
}

func (c Community) Test(ctx context.Context) (cook.Result, error) {
	present, err := c.exists(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch c.method {
	case methodCommunityPresent:
		if present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("community %s is already present", c.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("community %s would be added", c.name))}}, nil
	case methodCommunityAbsent:
		if !present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("community %s is already absent", c.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("community %s would be removed", c.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func (c Community) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(c.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	present, err := c.exists(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch c.method {
	case methodCommunityPresent:
		if present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("community %s is already present", c.name))}}, nil
		}
		perm := winexec.StringParamOr(c.params, "permission", "read only")
		script := fmt.Sprintf(
			"New-ItemProperty -Path %s -Name %s -PropertyType DWord -Value %d -Force",
			winexec.PSQuote(communitiesKey), winexec.PSQuote(c.name), permissionValues[perm],
		)
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("community %s has been added", c.name))}}, nil
	case methodCommunityAbsent:
		if !present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("community %s is already absent", c.name))}}, nil
		}
		script := fmt.Sprintf(
			"Remove-ItemProperty -Path %s -Name %s -ErrorAction SilentlyContinue",
			winexec.PSQuote(communitiesKey), winexec.PSQuote(c.name),
		)
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("community %s has been removed", c.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func init() {
	ingredients.RegisterAllMethods(Community{})
}
