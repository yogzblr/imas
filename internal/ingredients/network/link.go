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

func (n Network) link(_ context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	name := stringParam(n.params, "name")
	state := strings.ToLower(stringParam(n.params, "state"))
	if state != "up" && state != "down" {
		result.Failed = true
		return result, fmt.Errorf("network.link: state must be \"up\" or \"down\", got %q", state)
	}
	mtu := intParam(n.params, "mtu", 0)

	l, err := linkByName(name)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.link: interface %s: %w", name, err)
	}
	attrs := l.Attrs()
	wasUp := attrs.Flags&net.FlagUp != 0
	wantUp := state == "up"
	stateChanged := wasUp != wantUp
	mtuChanged := mtu != 0 && attrs.MTU != mtu

	if !stateChanged && !mtuChanged {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s is already %s", name, state)))
		return result, nil
	}

	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s would be set %s", name, state)))
		return result, nil
	}

	opts := guardOptionsFromParams(n.params)
	gw := defaultGatewayIP()

	err = runGuarded(opts, gw, &result,
		func() error { return n.applyLinkChange(l, wantUp, stateChanged, mtu, mtuChanged) },
		func() error { return n.applyLinkChange(l, wasUp, stateChanged, attrs.MTU, mtuChanged) },
	)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("network.link: %s: %w", name, err)
	}

	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s set %s", name, state)))
	return result, nil
}

func (n Network) applyLinkChange(l netlink.Link, wantUp, stateChanged bool, mtu int, mtuChanged bool) error {
	if mtuChanged {
		if err := linkSetMTU(l, mtu); err != nil {
			return fmt.Errorf("set mtu %d: %w", mtu, err)
		}
	}
	if stateChanged {
		var err error
		if wantUp {
			err = linkSetUp(l)
		} else {
			err = linkSetDown(l)
		}
		if err != nil {
			return fmt.Errorf("set state: %w", err)
		}
	}
	return nil
}
