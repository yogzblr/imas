//go:build linux

package network

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/yogzblr/imas/internal/cook"
)

func (n Network) routePresent(_ context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	destStr := stringParam(n.params, "destination")
	dst, err := parseDestination(destStr)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.route_present: invalid destination %q: %w", destStr, err)
	}

	gatewayStr := stringParam(n.params, "gateway")
	var gw net.IP
	if gatewayStr != "" {
		if gw = net.ParseIP(gatewayStr); gw == nil {
			result.Failed = true
			return result, fmt.Errorf("network.route_present: invalid gateway %q", gatewayStr)
		}
	}

	devName := stringParam(n.params, "name")
	var devIndex int
	if devName != "" {
		l, err := linkByName(devName)
		if err != nil {
			result.Failed = true
			return result, fmt.Errorf("network.route_present: interface %s: %w", devName, err)
		}
		devIndex = l.Attrs().Index
	}

	if gw == nil && devName == "" {
		result.Failed = true
		return result, fmt.Errorf("network.route_present: at least one of gateway or name is required")
	}

	metric := intParam(n.params, "metric", 0)
	table := intParam(n.params, "table", 0)
	want := netlink.Route{Dst: dst, Gw: gw, LinkIndex: devIndex, Priority: metric, Table: table}

	existing, err := routeList(nil, netlink.FAMILY_ALL)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.route_present: listing routes: %w", err)
	}
	// Find whatever route currently occupies this destination (dst+table,
	// and dev if pinned), regardless of gateway, so a gateway/metric change
	// is detected as an update rather than missed as "already present".
	match := findRoute(existing, dst, table, devIndex, devName != "", nil, false)

	if match != nil && match.Gw.Equal(gw) && match.Priority == metric {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("route to %s already present", destKeyForNote(destStr))))
		return result, nil
	}

	if test {
		verb := "added"
		if match != nil {
			verb = "updated"
		}
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("route to %s would be %s", destKeyForNote(destStr), verb)))
		return result, nil
	}

	opts := guardOptionsFromParams(n.params)
	gwTarget := defaultGatewayIP()

	err = runGuarded(opts, gwTarget, &result,
		func() error {
			if match != nil {
				if err := routeDel(match); err != nil {
					return fmt.Errorf("removing previous route: %w", err)
				}
			}
			if err := routeAdd(&want); err != nil {
				return fmt.Errorf("adding route: %w", err)
			}
			return nil
		},
		func() error {
			_ = routeDel(&want)
			if match != nil {
				return routeAdd(match)
			}
			return nil
		},
	)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.route_present: %w", err)
	}

	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("route to %s set via %s", destKeyForNote(destStr), routeVia(gw, devName))))
	return result, nil
}

func (n Network) routeAbsent(_ context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	destStr := stringParam(n.params, "destination")
	dst, err := parseDestination(destStr)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.route_absent: invalid destination %q: %w", destStr, err)
	}

	gatewayStr := stringParam(n.params, "gateway")
	requireGw := gatewayStr != ""
	var gw net.IP
	if requireGw {
		if gw = net.ParseIP(gatewayStr); gw == nil {
			result.Failed = true
			return result, fmt.Errorf("network.route_absent: invalid gateway %q", gatewayStr)
		}
	}

	devName := stringParam(n.params, "name")
	requireDev := devName != ""
	var devIndex int
	if requireDev {
		l, err := linkByName(devName)
		if err != nil {
			result.Failed = true
			return result, fmt.Errorf("network.route_absent: interface %s: %w", devName, err)
		}
		devIndex = l.Attrs().Index
	}

	table := intParam(n.params, "table", 0)

	existing, err := routeList(nil, netlink.FAMILY_ALL)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.route_absent: listing routes: %w", err)
	}
	match := findRoute(existing, dst, table, devIndex, requireDev, gw, requireGw)
	if match == nil {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("route to %s already absent", destKeyForNote(destStr))))
		return result, nil
	}

	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("route to %s would be removed", destKeyForNote(destStr))))
		return result, nil
	}

	opts := guardOptionsFromParams(n.params)
	gwTarget := defaultGatewayIP()

	err = runGuarded(opts, gwTarget, &result,
		func() error { return routeDel(match) },
		func() error { return routeAdd(match) },
	)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.route_absent: %w", err)
	}

	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("removed route to %s", destKeyForNote(destStr))))
	return result, nil
}

// findRoute returns the route among existing matching dst+table (and dev,
// when requireDev) -- and, when requireGw, gw too -- or nil. Matching
// ignores ECMP multipath routes (MultiPath-only entries have a nil Gw and a
// zero LinkIndex); multipath routes are out of scope for this ingredient.
func findRoute(existing []netlink.Route, dst *net.IPNet, table, devIndex int, requireDev bool, gw net.IP, requireGw bool) *netlink.Route {
	for i := range existing {
		r := existing[i]
		if dstKey(r.Dst) != dstKey(dst) {
			continue
		}
		if normalizeTable(r.Table) != normalizeTable(table) {
			continue
		}
		if requireDev && r.LinkIndex != devIndex {
			continue
		}
		if requireGw && !r.Gw.Equal(gw) {
			continue
		}
		return &existing[i]
	}
	return nil
}

// parseDestination parses a route destination: "default"/"" means the
// default route (nil Dst), anything else must be a CIDR.
func parseDestination(s string) (*net.IPNet, error) {
	if s == "" || strings.EqualFold(s, "default") {
		return nil, nil
	}
	return netlink.ParseIPNet(s)
}

func destKeyForNote(s string) string {
	if s == "" {
		return "default"
	}
	return s
}

func dstKey(dst *net.IPNet) string {
	if dst == nil {
		return "default"
	}
	return dst.String()
}

func routeVia(gw net.IP, devName string) string {
	switch {
	case gw != nil && devName != "":
		return fmt.Sprintf("%s dev %s", gw, devName)
	case gw != nil:
		return gw.String()
	default:
		return "dev " + devName
	}
}
