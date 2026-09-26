//go:build linux

package firewall

import (
	"fmt"

	nft "github.com/google/nftables"

	"github.com/yogzblr/imas/internal/cook"
)

type tableSpec struct {
	name   string
	family nft.TableFamily
}

func parseTableSpec(params map[string]interface{}) (tableSpec, error) {
	name, err := requireString(params, "name")
	if err != nil {
		return tableSpec{}, err
	}
	family, err := parseFamily(paramStringOr(params, "family", ""))
	if err != nil {
		return tableSpec{}, err
	}
	return tableSpec{name: name, family: family}, nil
}

// findTable returns the table matching name+family, or nil if none exists.
func findTable(conn nftConn, spec tableSpec) (*nft.Table, error) {
	tables, err := conn.ListTablesOfFamily(spec.family)
	if err != nil {
		return nil, fmt.Errorf("listing %s tables: %w", tableFamilyLabel(spec.family), err)
	}
	for _, t := range tables {
		if t.Name == spec.name {
			return t, nil
		}
	}
	return nil, nil
}

func tablePresent(conn nftConn, spec tableSpec, dryRun bool) (cook.Result, error) {
	existing, err := findTable(conn, spec)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if existing != nil {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("table %s (%s) is already present", spec.name, tableFamilyLabel(spec.family)),
		}}, nil
	}
	if dryRun {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("table %s (%s) would be created", spec.name, tableFamilyLabel(spec.family)),
		}}, nil
	}
	conn.AddTable(&nft.Table{Name: spec.name, Family: spec.family})
	if err := conn.Flush(); err != nil {
		return cook.Result{Failed: true}, fmt.Errorf("creating table %s: %w", spec.name, err)
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("table %s (%s) has been created", spec.name, tableFamilyLabel(spec.family)),
	}}, nil
}

// tableAbsent deletes the table, which (per nftables semantics) also
// deletes every chain and rule it contains. Callers should be deliberate
// about which table they point this at -- there is no partial/soft delete.
func tableAbsent(conn nftConn, spec tableSpec, dryRun bool) (cook.Result, error) {
	existing, err := findTable(conn, spec)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if existing == nil {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("table %s (%s) is already absent", spec.name, tableFamilyLabel(spec.family)),
		}}, nil
	}
	if dryRun {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("table %s (%s) would be removed, along with all chains/rules it contains", spec.name, tableFamilyLabel(spec.family)),
		}}, nil
	}
	conn.DelTable(existing)
	if err := conn.Flush(); err != nil {
		return cook.Result{Failed: true}, fmt.Errorf("removing table %s: %w", spec.name, err)
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("table %s (%s) has been removed", spec.name, tableFamilyLabel(spec.family)),
	}}, nil
}
