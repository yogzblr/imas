//go:build linux

package firewall

import (
	"fmt"

	nft "github.com/google/nftables"

	"github.com/yogzblr/imas/internal/cook"
)

type chainSpec struct {
	name     string
	table    string
	family   nft.TableFamily
	hook     *nft.ChainHook // nil => regular (non-base) chain
	ctype    nft.ChainType
	priority int32
	policy   *nft.ChainPolicy
}

func (c chainSpec) isBase() bool { return c.hook != nil }

func parseChainSpec(params map[string]interface{}) (chainSpec, error) {
	name, err := requireString(params, "name")
	if err != nil {
		return chainSpec{}, err
	}
	table, err := requireString(params, "table")
	if err != nil {
		return chainSpec{}, err
	}
	family, err := parseFamily(paramStringOr(params, "family", ""))
	if err != nil {
		return chainSpec{}, err
	}
	hook, err := parseHook(paramStringOr(params, "hook", ""))
	if err != nil {
		return chainSpec{}, err
	}
	ctype, err := parseChainType(paramStringOr(params, "type", ""))
	if err != nil {
		return chainSpec{}, err
	}
	priority, err := parsePriority(paramStringOr(params, "priority", ""))
	if err != nil {
		return chainSpec{}, err
	}
	policy, err := parseChainPolicy(paramStringOr(params, "policy", ""))
	if err != nil {
		return chainSpec{}, err
	}
	if policy != nil && hook == nil {
		return chainSpec{}, fmt.Errorf("%w: policy is only meaningful on a base chain (set hook)", ErrInvalidProperty)
	}
	return chainSpec{
		name: name, table: table, family: family,
		hook: hook, ctype: ctype, priority: priority, policy: policy,
	}, nil
}

func findChain(conn nftConn, spec chainSpec) (*nft.Chain, error) {
	chains, err := conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("listing chains: %w", err)
	}
	for _, c := range chains {
		if c.Name == spec.name && c.Table != nil && c.Table.Name == spec.table && c.Table.Family == spec.family {
			return c, nil
		}
	}
	return nil, nil
}

func chainPresent(conn nftConn, spec chainSpec, dryRun bool) (cook.Result, error) {
	existing, err := findChain(conn, spec)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if existing != nil {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("chain %s in table %s is already present", spec.name, spec.table),
		}}, nil
	}
	if dryRun {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("chain %s in table %s would be created", spec.name, spec.table),
		}}, nil
	}
	table := &nft.Table{Name: spec.table, Family: spec.family}
	chain := &nft.Chain{
		Name:  spec.name,
		Table: table,
	}
	if spec.isBase() {
		priority := nft.ChainPriority(spec.priority)
		chain.Hooknum = spec.hook
		chain.Priority = &priority
		chain.Type = spec.ctype
		chain.Policy = spec.policy
	}
	conn.AddChain(chain)
	if err := conn.Flush(); err != nil {
		return cook.Result{Failed: true}, fmt.Errorf("creating chain %s in table %s: %w", spec.name, spec.table, err)
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("chain %s in table %s has been created", spec.name, spec.table),
	}}, nil
}

func chainAbsent(conn nftConn, spec chainSpec, dryRun bool) (cook.Result, error) {
	existing, err := findChain(conn, spec)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if existing == nil {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("chain %s in table %s is already absent", spec.name, spec.table),
		}}, nil
	}
	if dryRun {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("chain %s in table %s would be removed, along with all rules it contains", spec.name, spec.table),
		}}, nil
	}
	conn.DelChain(existing)
	if err := conn.Flush(); err != nil {
		return cook.Result{Failed: true}, fmt.Errorf("removing chain %s in table %s: %w", spec.name, spec.table, err)
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("chain %s in table %s has been removed", spec.name, spec.table),
	}}, nil
}
