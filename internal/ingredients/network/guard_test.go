//go:build linux

package network

import (
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/yogzblr/imas/internal/cook"
)

func TestCheckConnectivityTCPDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	if err := checkConnectivity(ln.Addr().String(), time.Second); err != nil {
		t.Fatalf("expected successful dial, got %v", err)
	}
}

func TestCheckConnectivityTCPDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listening now

	if err := checkConnectivity(addr, 200*time.Millisecond); err == nil {
		t.Fatal("expected dial failure against a closed port")
	}
}

func TestCheckConnectivityRouteLookup(t *testing.T) {
	orig := routeGet
	defer func() { routeGet = orig }()

	routeGet = func(dst net.IP) ([]netlink.Route, error) {
		return []netlink.Route{{Dst: nil}}, nil
	}
	if err := checkConnectivity("192.168.1.1", time.Second); err != nil {
		t.Fatalf("expected route lookup to succeed, got %v", err)
	}

	routeGet = func(dst net.IP) ([]netlink.Route, error) {
		return nil, nil
	}
	if err := checkConnectivity("192.168.1.1", time.Second); err == nil {
		t.Fatal("expected route lookup with no results to fail")
	}
}

func TestCheckConnectivityInvalidTarget(t *testing.T) {
	if err := checkConnectivity("not-an-ip-or-hostport", time.Second); err == nil {
		t.Fatal("expected error for an unparseable target")
	}
}

func TestDefaultGatewayIP(t *testing.T) {
	withMockRouteList(t, []netlink.Route{
		{Dst: mustIPNet(t, "10.0.0.0/8"), Gw: net.ParseIP("10.0.0.1")},
		{Dst: nil, Gw: net.ParseIP("192.168.1.1")},
	})
	if got := defaultGatewayIP(); got != "192.168.1.1" {
		t.Fatalf("expected default gateway 192.168.1.1, got %q", got)
	}
}

func TestDefaultGatewayIPNoDefaultRoute(t *testing.T) {
	withMockRouteList(t, []netlink.Route{{Dst: mustIPNet(t, "10.0.0.0/8"), Gw: net.ParseIP("10.0.0.1")}})
	if got := defaultGatewayIP(); got != "" {
		t.Fatalf("expected no default gateway, got %q", got)
	}
}

func TestRunGuardedSkipsCheckWithNoTarget(t *testing.T) {
	connCalls := withMockConnectivity(t, errConnFailed)
	var result cook.Result
	applied := false
	err := runGuarded(guardOptions{verify: true, timeout: time.Second, rollback: true}, "", &result,
		func() error { applied = true; return nil },
		func() error { t.Fatal("revert should not be called"); return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !applied {
		t.Fatal("expected apply() to run")
	}
	if *connCalls != 0 {
		t.Fatalf("expected connectivity check to be skipped with no target, got %d calls", *connCalls)
	}
}

func TestRunGuardedDisabledSkipsCheck(t *testing.T) {
	connCalls := withMockConnectivity(t, errConnFailed)
	var result cook.Result
	err := runGuarded(guardOptions{verify: false}, "10.0.0.1", &result,
		func() error { return nil },
		func() error { t.Fatal("revert should not be called"); return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *connCalls != 0 {
		t.Fatalf("expected connectivity check to be skipped when disabled, got %d calls", *connCalls)
	}
}

func TestRunGuardedApplyErrorSkipsCheck(t *testing.T) {
	connCalls := withMockConnectivity(t, nil)
	var result cook.Result
	applyErr := errConnFailed
	err := runGuarded(guardOptions{verify: true, timeout: time.Second}, "10.0.0.1", &result,
		func() error { return applyErr },
		func() error { t.Fatal("revert should not be called"); return nil },
	)
	if err != applyErr {
		t.Fatalf("expected apply's own error to propagate, got %v", err)
	}
	if *connCalls != 0 {
		t.Fatalf("expected no connectivity check when apply itself fails, got %d calls", *connCalls)
	}
}
