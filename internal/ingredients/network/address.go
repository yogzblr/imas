//go:build linux

package network

import (
	"context"
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/yogzblr/imas/internal/cook"
)

func (n Network) addressPresent(_ context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	name := stringParam(n.params, "name")
	addrStr := stringParam(n.params, "address")
	label := stringParam(n.params, "label")

	want, err := netlink.ParseAddr(addrStr)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.address_present: invalid address %q: %w", addrStr, err)
	}
	want.Label = label

	l, err := linkByName(name)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.address_present: interface %s: %w", name, err)
	}

	existing, err := addrList(l, netlink.FAMILY_ALL)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.address_present: listing addresses on %s: %w", name, err)
	}
	if findAddr(existing, want) != nil {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s already has address %s", name, addrStr)))
		return result, nil
	}

	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s would gain address %s", name, addrStr)))
		return result, nil
	}

	// Additive: adding an address never removes existing reachability, so
	// this path isn't wrapped by the connectivity guard (unlike
	// addressAbsent, link, and the route methods).
	if err := addrAdd(l, want); err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.address_present: adding %s to %s: %w", addrStr, name, err)
	}
	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("added %s to %s", addrStr, name)))
	return result, nil
}

func (n Network) addressAbsent(_ context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	name := stringParam(n.params, "name")
	addrStr := stringParam(n.params, "address")

	target, err := netlink.ParseAddr(addrStr)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.address_absent: invalid address %q: %w", addrStr, err)
	}

	l, err := linkByName(name)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.address_absent: interface %s: %w", name, err)
	}

	existing, err := addrList(l, netlink.FAMILY_ALL)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.address_absent: listing addresses on %s: %w", name, err)
	}
	match := findAddr(existing, target)
	if match == nil {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s already lacks address %s", name, addrStr)))
		return result, nil
	}

	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s would lose address %s", name, addrStr)))
		return result, nil
	}

	opts := guardOptionsFromParams(n.params)
	gw := defaultGatewayIP()

	err = runGuarded(opts, gw, &result,
		func() error { return addrDel(l, match) },
		func() error { return addrAdd(l, match) },
	)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.address_absent: %s: %w", name, err)
	}

	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("removed %s from %s", addrStr, name)))
	return result, nil
}

// findAddr returns the entry in existing matching want by IP and prefix
// length (netlink.Addr.Equal ignores the label), or nil.
func findAddr(existing []netlink.Addr, want *netlink.Addr) *netlink.Addr {
	for i := range existing {
		if existing[i].Equal(*want) {
			return &existing[i]
		}
	}
	return nil
}
