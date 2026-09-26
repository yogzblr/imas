//go:build linux

// Package network implements the "network" ingredient: interface link
// state, IP address, and route configuration on Linux via netlink, matching
// the surface of Salt's network/linux_ip/debian_ip modules.
//
// Every mutation capable of cutting the sprout off from farmer (link state,
// route add/remove, address removal) is wrapped by a connectivity guard: see
// guard.go for the "verify connectivity survives the change, or roll back"
// pattern.
package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

var ErrNetworkMethodUndefined = errors.New("network method undefined")

// Compile-time interface check.
var _ cook.RecipeCooker = Network{}

type Network struct {
	id     string
	method string
	params map[string]interface{}
}

func (n Network) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := Network{
		id: id, method: method,
		params: params,
	}
	if err := parsed.validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (n Network) validate() error {
	set, err := n.PropertiesForMethod(n.method)
	if err != nil {
		return err
	}
	propSet, err := ingredients.PropMapToPropSet(set)
	if err != nil {
		return err
	}
	for _, v := range propSet {
		if v.IsReq {
			if v.Key == "name" {
				name, ok := n.params[v.Key].(string)
				if !ok || name == "" {
					return ingredients.ErrMissingName
				}
			} else if _, ok := n.params[v.Key]; !ok {
				return fmt.Errorf("missing required property %s", v.Key)
			}
		}
	}
	return nil
}

func (n Network) Test(ctx context.Context) (cook.Result, error) {
	switch n.method {
	case "link":
		return n.link(ctx, true)
	case "address_present":
		return n.addressPresent(ctx, true)
	case "address_absent":
		return n.addressAbsent(ctx, true)
	case "route_present":
		return n.routePresent(ctx, true)
	case "route_absent":
		return n.routeAbsent(ctx, true)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrNetworkMethodUndefined, fmt.Errorf("method %s undefined", n.method))
	}
}

func (n Network) Apply(ctx context.Context) (cook.Result, error) {
	switch n.method {
	case "link":
		return n.link(ctx, false)
	case "address_present":
		return n.addressPresent(ctx, false)
	case "address_absent":
		return n.addressAbsent(ctx, false)
	case "route_present":
		return n.routePresent(ctx, false)
	case "route_absent":
		return n.routeAbsent(ctx, false)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrNetworkMethodUndefined, fmt.Errorf("method %s undefined", n.method))
	}
}

// connectivityGuardProps are the properties shared by every method whose
// Apply can sever the sprout's own connectivity. See guard.go.
var connectivityGuardProps = ingredients.MethodPropsSet{
	ingredients.MethodProps{
		Key: "verify_connectivity", Type: "bool", IsReq: false,
		Description: "after applying, verify connectivity to connectivity_target (or the pre-change default gateway) still works, rolling back on failure (default true)",
	},
	ingredients.MethodProps{
		Key: "connectivity_target", Type: "string", IsReq: false,
		Description: "host:port (TCP-dialed) or bare IP (route-checked) to verify reachability to after the change; defaults to the pre-change default gateway",
	},
	ingredients.MethodProps{
		Key: "connectivity_timeout", Type: "string", IsReq: false,
		Description: "timeout for the post-change connectivity check, e.g. \"5s\" (default 5s)",
	},
	ingredients.MethodProps{
		Key: "rollback_on_failure", Type: "bool", IsReq: false,
		Description: "automatically revert the change if the connectivity check fails (default true)",
	},
}

func withGuardProps(base ingredients.MethodPropsSet) ingredients.MethodPropsSet {
	return append(append(ingredients.MethodPropsSet{}, base...), connectivityGuardProps...)
}

func (n Network) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case "link":
		return withGuardProps(ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "the interface name"},
			ingredients.MethodProps{Key: "state", Type: "string", IsReq: true, Description: "\"up\" or \"down\""},
			ingredients.MethodProps{Key: "mtu", Type: "string", IsReq: false, Description: "set the interface MTU"},
		}).ToMap(), nil
	case "address_present":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "the interface name"},
			ingredients.MethodProps{Key: "address", Type: "string", IsReq: true, Description: "IP address in CIDR form, e.g. 10.0.0.5/24"},
			ingredients.MethodProps{Key: "label", Type: "string", IsReq: false, Description: "address label"},
		}.ToMap(), nil
	case "address_absent":
		return withGuardProps(ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "the interface name"},
			ingredients.MethodProps{Key: "address", Type: "string", IsReq: true, Description: "IP address in CIDR form to remove"},
		}).ToMap(), nil
	case "route_present":
		return withGuardProps(ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "destination", Type: "string", IsReq: true, Description: "destination CIDR, or \"default\""},
			ingredients.MethodProps{Key: "gateway", Type: "string", IsReq: false, Description: "gateway IP"},
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: false, Description: "outbound interface (dev)"},
			ingredients.MethodProps{Key: "metric", Type: "string", IsReq: false, Description: "route metric/priority"},
			ingredients.MethodProps{Key: "table", Type: "string", IsReq: false, Description: "routing table ID (default: main)"},
		}).ToMap(), nil
	case "route_absent":
		return withGuardProps(ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "destination", Type: "string", IsReq: true, Description: "destination CIDR, or \"default\""},
			ingredients.MethodProps{Key: "gateway", Type: "string", IsReq: false, Description: "gateway IP, to disambiguate multiple routes to the same destination"},
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: false, Description: "outbound interface (dev), to disambiguate multiple routes to the same destination"},
			ingredients.MethodProps{Key: "table", Type: "string", IsReq: false, Description: "routing table ID (default: main)"},
		}).ToMap(), nil
	default:
		return nil, errors.Join(ErrNetworkMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
}

func (n Network) Methods() (string, []string) {
	return "network", []string{"link", "address_present", "address_absent", "route_present", "route_absent"}
}

func (n Network) Properties() (map[string]interface{}, error) {
	out := map[string]interface{}{}
	b, err := json.Marshal(n.params)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}

func init() {
	ingredients.RegisterAllMethods(Network{})
}
