// Package envoycheck checks a parsed Envoy bootstrap config for what the
// sprout's enrollment client depends on. The nats chart's tests and the
// UAT DMZ tests run it on their rendered configs.
package envoycheck

import (
	"fmt"
	"strings"
)

// BusyRoutes are the routes whose 503 must reach the sprout: farmer
// answers 503 with a Retry-After when another replica holds the sprout's
// User JWT mint lease, and the sprout waits it out
// (internal/pki/enrollclient.go).
var BusyRoutes = []string{"/v1/enroll", "/v1/refresh"}

// noAnswerRetryOn are the retry_on conditions that fire only before
// farmer answered: no connection, or a stream it refused unprocessed.
// Every other condition (5xx, gateway-error, retriable-status-codes,
// reset, ...) can retry a request farmer answered, a 503 among them.
var noAnswerRetryOn = map[string]bool{"connect-failure": true, "refused-stream": true}

// BusyRetryProblems returns why cfg would let Envoy retry farmer's 503 on
// a BusyRoutes route instead of passing it, and its Retry-After, to the
// sprout: a route-level or virtual-host retry_policy whose retry_on names
// anything but noAnswerRetryOn's conditions, or that lists
// retriable_status_codes. A missing BusyRoutes route is a problem too.
// Nil means none.
func BusyRetryProblems(cfg map[string]any) []string {
	var problems []string
	check := func(where string, rp any) {
		if rp == nil {
			return
		}
		p, ok := rp.(map[string]any)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: retry_policy is %T", where, rp))
			return
		}
		if on, ok := p["retry_on"]; ok {
			for _, c := range strings.Split(fmt.Sprint(on), ",") {
				if c = strings.TrimSpace(c); c != "" && !noAnswerRetryOn[c] {
					problems = append(problems, fmt.Sprintf("%s: retry_on names %q, which can retry farmer's 503", where, c))
				}
			}
		}
		if codes, ok := p["retriable_status_codes"]; ok {
			problems = append(problems, fmt.Sprintf("%s: retriable_status_codes %v", where, codes))
		}
	}
	seen := map[string]bool{}
	for _, vh := range virtualHosts(cfg) {
		check(fmt.Sprintf("virtual host %v", vh["name"]), vh["retry_policy"])
		routes, _ := vh["routes"].([]any)
		for _, r := range routes {
			r, _ := r.(map[string]any)
			m, _ := r["match"].(map[string]any)
			for _, want := range BusyRoutes {
				if m["path"] == want || m["prefix"] == want {
					seen[want] = true
					route, _ := r["route"].(map[string]any)
					check("route "+want, route["retry_policy"])
				}
			}
		}
	}
	for _, want := range BusyRoutes {
		if !seen[want] {
			problems = append(problems, "no "+want+" route")
		}
	}
	return problems
}

// virtualHosts returns every HTTP connection manager's static virtual
// hosts in cfg.
func virtualHosts(cfg map[string]any) []map[string]any {
	var out []map[string]any
	sr, _ := cfg["static_resources"].(map[string]any)
	listeners, _ := sr["listeners"].([]any)
	for _, l := range listeners {
		l, _ := l.(map[string]any)
		chains, _ := l["filter_chains"].([]any)
		for _, fc := range chains {
			fc, _ := fc.(map[string]any)
			filters, _ := fc["filters"].([]any)
			for _, f := range filters {
				f, _ := f.(map[string]any)
				tc, _ := f["typed_config"].(map[string]any)
				rc, _ := tc["route_config"].(map[string]any)
				vhs, _ := rc["virtual_hosts"].([]any)
				for _, vh := range vhs {
					if vh, ok := vh.(map[string]any); ok {
						out = append(out, vh)
					}
				}
			}
		}
	}
	return out
}
