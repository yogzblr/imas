//go:build linux

// Connectivity guard: the "verify connectivity survives the change, or roll
// back" pattern called out for this ingredient. Interface/route changes are
// a self-inflicted-outage class -- a bad `link down`, address removal, or
// route change can cut the sprout off from farmer with nothing left able to
// fix it remotely. Every mutation that can do that (link state, route
// add/remove, address removal; see network.go's use of runGuarded) is
// wrapped so that after applying the change, the sprout confirms it can
// still reach a target -- the recipe's explicit connectivity_target, or, by
// default, the gateway the default route pointed at before the change -- and
// automatically reverts if it can't.
package network

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/yogzblr/imas/internal/cook"
)

type guardOptions struct {
	verify   bool
	target   string
	timeout  time.Duration
	rollback bool
}

func guardOptionsFromParams(params map[string]interface{}) guardOptions {
	return guardOptions{
		verify:   boolParam(params, "verify_connectivity", true),
		target:   stringParam(params, "connectivity_target"),
		timeout:  durationParam(params, "connectivity_timeout", 5*time.Second),
		rollback: boolParam(params, "rollback_on_failure", true),
	}
}

// checkConnectivity reports whether target is reachable, and is the guard's
// mockable probe. A "host:port" target is verified with a TCP dial -- a real
// reachability check. A bare IP is verified with a kernel route lookup
// (RouteGet, equivalent to `ip route get`): it asks whether the kernel could
// still route a packet there without actually sending one, which is enough
// to catch a severed default route or a downed link -- the exact class of
// damage this guard exists to catch -- without requiring the recipe author
// to name a live TCP endpoint.
var checkConnectivity = func(target string, timeout time.Duration) error {
	if _, _, err := net.SplitHostPort(target); err == nil {
		conn, dialErr := net.DialTimeout("tcp", target, timeout)
		if dialErr != nil {
			return dialErr
		}
		return conn.Close()
	}
	ip := net.ParseIP(target)
	if ip == nil {
		return fmt.Errorf("invalid connectivity target %q", target)
	}
	routes, err := routeGet(ip)
	if err != nil {
		return err
	}
	if len(routes) == 0 {
		return fmt.Errorf("no route to %s", target)
	}
	return nil
}

// defaultGatewayIP returns the gateway of the current IPv4 default route, if
// any. It's captured before a mutation as the guard's fallback connectivity
// target, so a recipe that doesn't set connectivity_target still gets a
// meaningful check for free.
func defaultGatewayIP() string {
	routes, err := routeList(nil, netlink.FAMILY_V4)
	if err != nil {
		return ""
	}
	for _, r := range routes {
		if r.Dst == nil && r.Gw != nil {
			return r.Gw.String()
		}
	}
	return ""
}

// runGuarded performs apply(), then -- when verify_connectivity is enabled
// -- checks that connectivity to the guard's target still works. On
// failure, it calls revert() and reports the failure (rolled back or, if
// rollback is disabled or itself fails, not); the step is always treated as
// failed in that case, since the requested end state was not safely
// reached.
func runGuarded(opts guardOptions, defaultTarget string, result *cook.Result, apply func() error, revert func() error) error {
	if err := apply(); err != nil {
		return err
	}
	if !opts.verify {
		return nil
	}
	target := opts.target
	if target == "" {
		target = defaultTarget
	}
	if target == "" {
		result.Notes = append(result.Notes, cook.SimpleNote(
			"connectivity check skipped: no connectivity_target set and no default gateway found"))
		return nil
	}
	if err := checkConnectivity(target, opts.timeout); err != nil {
		return handleGuardFailure(target, err, opts, result, revert)
	}
	return nil
}

func handleGuardFailure(target string, checkErr error, opts guardOptions, result *cook.Result, revert func() error) error {
	note := fmt.Sprintf("connectivity check to %s failed after change: %v", target, checkErr)
	if !opts.rollback || revert == nil {
		result.Notes = append(result.Notes, cook.SimpleNote(note+" (rollback disabled; change left in place)"))
		return fmt.Errorf("%s (rollback disabled)", note)
	}
	if revertErr := revert(); revertErr != nil {
		result.Notes = append(result.Notes, cook.SimpleNote(note+"; ROLLBACK ALSO FAILED, manual intervention required"))
		return fmt.Errorf("%s; rollback also failed: %w -- manual intervention required", note, revertErr)
	}
	result.Notes = append(result.Notes, cook.SimpleNote(note+"; change rolled back"))
	return fmt.Errorf("%s; change rolled back", note)
}
