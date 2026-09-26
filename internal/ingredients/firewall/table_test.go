//go:build linux

package firewall

import (
	"context"
	"testing"

	nft "github.com/google/nftables"
)

func TestTablePresentCreatesOnce(t *testing.T) {
	conn := newFakeConn()
	spec := tableSpec{name: "imas", family: nft.TableFamilyINet}

	res, err := tablePresent(conn, spec, false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("first apply: res=%+v err=%v", res, err)
	}
	if len(conn.tables) != 1 || conn.flushCalls != 1 {
		t.Fatalf("expected 1 table and 1 flush, got %d tables, %d flushes", len(conn.tables), conn.flushCalls)
	}

	res, err = tablePresent(conn, spec, false)
	if err != nil || !res.Succeeded || res.Changed {
		t.Fatalf("second apply should be a no-op: res=%+v err=%v", res, err)
	}
	if len(conn.tables) != 1 || conn.flushCalls != 1 {
		t.Fatalf("second apply should not touch the kernel: %d tables, %d flushes", len(conn.tables), conn.flushCalls)
	}
}

func TestTablePresentDryRunDoesNotMutate(t *testing.T) {
	conn := newFakeConn()
	spec := tableSpec{name: "imas", family: nft.TableFamilyINet}

	res, err := tablePresent(conn, spec, true)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("dry run: res=%+v err=%v", res, err)
	}
	if len(conn.tables) != 0 || conn.flushCalls != 0 {
		t.Fatalf("dry run must not mutate: %d tables, %d flushes", len(conn.tables), conn.flushCalls)
	}
}

func TestTableAbsentRemovesExisting(t *testing.T) {
	conn := newFakeConn()
	conn.AddTable(&nft.Table{Name: "imas", Family: nft.TableFamilyINet})
	spec := tableSpec{name: "imas", family: nft.TableFamilyINet}

	res, err := tableAbsent(conn, spec, false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("apply: res=%+v err=%v", res, err)
	}
	if len(conn.tables) != 0 {
		t.Fatalf("expected table to be removed, got %d", len(conn.tables))
	}

	res, err = tableAbsent(conn, spec, false)
	if err != nil || !res.Succeeded || res.Changed {
		t.Fatalf("second removal should be a no-op: res=%+v err=%v", res, err)
	}
}

func TestTableAbsentDifferentFamilyIsUntouched(t *testing.T) {
	conn := newFakeConn()
	conn.AddTable(&nft.Table{Name: "imas", Family: nft.TableFamilyIPv4})
	spec := tableSpec{name: "imas", family: nft.TableFamilyIPv6}

	res, err := tableAbsent(conn, spec, false)
	if err != nil || res.Changed {
		t.Fatalf("family-mismatched table must not be treated as present: res=%+v err=%v", res, err)
	}
	if len(conn.tables) != 1 {
		t.Fatalf("ipv4 table should be untouched, got %d tables", len(conn.tables))
	}
}

func TestFirewallRunDialFailure(t *testing.T) {
	cleanup := withFailingDial("permission denied")
	defer cleanup()

	fw, err := Firewall{}.Parse("t1", MethodTablePresent, map[string]interface{}{"name": "imas"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res, err := fw.Apply(context.Background())
	if err == nil || !res.Failed {
		t.Fatalf("expected dial failure to surface as a failed result, got res=%+v err=%v", res, err)
	}
}
