//go:build linux

package firewall

import (
	"context"
	"fmt"

	nft "github.com/google/nftables"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

const ingredientName = "firewall"

const (
	MethodTablePresent = "table_present"
	MethodTableAbsent  = "table_absent"
	MethodChainPresent = "chain_present"
	MethodChainAbsent  = "chain_absent"
	MethodRulePresent  = "rule_present"
	MethodRuleAbsent   = "rule_absent"
)

var methodProps = map[string]ingredients.MethodPropsSet{
	MethodTablePresent: {
		{Key: "name", Type: "string", IsReq: true, Description: "table name"},
		{Key: "family", Type: "string", IsReq: false, Description: "ip, ip6, inet (default), arp, bridge, netdev"},
	},
	MethodTableAbsent: {
		{Key: "name", Type: "string", IsReq: true, Description: "table name"},
		{Key: "family", Type: "string", IsReq: false, Description: "ip, ip6, inet (default), arp, bridge, netdev"},
	},
	MethodChainPresent: {
		{Key: "name", Type: "string", IsReq: true, Description: "chain name"},
		{Key: "table", Type: "string", IsReq: true, Description: "table this chain belongs to"},
		{Key: "family", Type: "string", IsReq: false, Description: "ip, ip6, inet (default), arp, bridge, netdev"},
		{Key: "hook", Type: "string", IsReq: false, Description: "prerouting/input/forward/output/postrouting/ingress/egress; omit for a non-base chain"},
		{Key: "type", Type: "string", IsReq: false, Description: "filter (default), nat, route; only meaningful with hook"},
		{Key: "priority", Type: "string", IsReq: false, Description: "base chain priority, integer, default 0"},
		{Key: "policy", Type: "string", IsReq: false, Description: "accept or drop; only meaningful with hook"},
	},
	MethodChainAbsent: {
		{Key: "name", Type: "string", IsReq: true, Description: "chain name"},
		{Key: "table", Type: "string", IsReq: true, Description: "table this chain belongs to"},
		{Key: "family", Type: "string", IsReq: false, Description: "ip, ip6, inet (default), arp, bridge, netdev"},
	},
	MethodRulePresent: {
		{Key: "name", Type: "string", IsReq: true, Description: "unique rule name, stored as the nft rule comment; used to detect this rule again"},
		{Key: "table", Type: "string", IsReq: true, Description: "table this rule belongs to"},
		{Key: "chain", Type: "string", IsReq: true, Description: "chain this rule belongs to"},
		{Key: "family", Type: "string", IsReq: false, Description: "ip, ip6, inet (default), arp, bridge, netdev"},
		{Key: "protocol", Type: "string", IsReq: false, Description: "tcp, udp, icmp, icmpv6; required if sport/dport is set"},
		{Key: "saddr", Type: "string", IsReq: false, Description: "source address or CIDR"},
		{Key: "daddr", Type: "string", IsReq: false, Description: "destination address or CIDR"},
		{Key: "sport", Type: "string", IsReq: false, Description: "source port or inclusive range (\"1024-2048\")"},
		{Key: "dport", Type: "string", IsReq: false, Description: "destination port or inclusive range"},
		{Key: "iifname", Type: "string", IsReq: false, Description: "inbound interface name"},
		{Key: "oifname", Type: "string", IsReq: false, Description: "outbound interface name"},
		{Key: "action", Type: "string", IsReq: true, Description: "accept, drop, or reject"},
		{Key: "counter", Type: "bool", IsReq: false, Description: "attach a packet/byte counter (default false)"},
		{Key: "position", Type: "string", IsReq: false, Description: "existing rule handle to insert before; appends to the chain if omitted"},
	},
	MethodRuleAbsent: {
		{Key: "name", Type: "string", IsReq: true, Description: "rule name to remove, as set by rule_present"},
		{Key: "table", Type: "string", IsReq: true, Description: "table this rule belongs to"},
		{Key: "chain", Type: "string", IsReq: true, Description: "chain this rule belongs to"},
		{Key: "family", Type: "string", IsReq: false, Description: "ip, ip6, inet (default), arp, bridge, netdev"},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Firewall{}

// Firewall is a single table/chain/rule desired-state step. spec holds the
// method-specific parsed properties (tableSpec, chainSpec, or ruleSpec) so
// Test and Apply share exactly one parse/validate pass.
type Firewall struct {
	id     string
	method string
	params map[string]interface{}
	spec   interface{}
}

func (f Firewall) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	if _, ok := methodProps[method]; !ok {
		return nil, ingredients.ErrInvalidMethod
	}
	parsed := Firewall{id: id, method: method, params: params}
	spec, err := buildSpec(method, params)
	if err != nil {
		return nil, err
	}
	parsed.spec = spec
	return parsed, nil
}

func buildSpec(method string, params map[string]interface{}) (interface{}, error) {
	switch method {
	case MethodTablePresent, MethodTableAbsent:
		return parseTableSpec(params)
	case MethodChainPresent, MethodChainAbsent:
		return parseChainSpec(params)
	case MethodRulePresent:
		return parseRuleSpec(params, true)
	case MethodRuleAbsent:
		return parseRuleSpec(params, false)
	default:
		return nil, fmt.Errorf("%w: %s", ErrMethodUndefined, method)
	}
}

func (f Firewall) Methods() (string, []string) {
	return ingredientName, []string{
		MethodTablePresent, MethodTableAbsent,
		MethodChainPresent, MethodChainAbsent,
		MethodRulePresent, MethodRuleAbsent,
	}
}

func (f Firewall) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMethodUndefined, method)
	}
	return p.ToMap(), nil
}

func (f Firewall) Properties() (map[string]interface{}, error) {
	return f.params, nil
}

func (f Firewall) run(ctx context.Context, dryRun bool) (cook.Result, error) {
	conn, err := dialConn()
	if err != nil {
		return cook.Result{Failed: true}, fmt.Errorf("dialing nftables netlink socket: %w", err)
	}

	switch f.method {
	case MethodTablePresent:
		return tablePresent(conn, f.spec.(tableSpec), dryRun)
	case MethodTableAbsent:
		return tableAbsent(conn, f.spec.(tableSpec), dryRun)
	case MethodChainPresent:
		return chainPresent(conn, f.spec.(chainSpec), dryRun)
	case MethodChainAbsent:
		return chainAbsent(conn, f.spec.(chainSpec), dryRun)
	case MethodRulePresent:
		return rulePresent(conn, f.spec.(ruleSpec), dryRun)
	case MethodRuleAbsent:
		return ruleAbsent(conn, f.spec.(ruleSpec), dryRun)
	default:
		return cook.Result{Failed: true}, fmt.Errorf("%w: %s", ErrMethodUndefined, f.method)
	}
}

func (f Firewall) Test(ctx context.Context) (cook.Result, error) {
	return f.run(ctx, true)
}

func (f Firewall) Apply(ctx context.Context) (cook.Result, error) {
	return f.run(ctx, false)
}

func init() {
	ingredients.RegisterAllMethods(Firewall{})
}

// tableFamilyLabel is a small formatting helper shared by table/chain/rule
// notes so messages consistently show e.g. "inet" rather than the raw byte
// value of a nft.TableFamily.
func tableFamilyLabel(f nft.TableFamily) string { return familyName(f) }
