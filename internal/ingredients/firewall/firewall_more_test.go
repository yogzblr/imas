//go:build linux

package firewall

import (
	"bytes"
	"context"
	"errors"
	"testing"

	nft "github.com/google/nftables"
)

// --- params.go edge cases --------------------------------------------------------

func TestParseChainTypeInvalid(t *testing.T) {
	if _, err := parseChainType("bogus"); !errors.Is(err, ErrInvalidProperty) {
		t.Fatalf("want ErrInvalidProperty, got %v", err)
	}
	ct, err := parseChainType("nat")
	if err != nil || ct != nft.ChainTypeNAT {
		t.Fatalf("parseChainType(nat) = %v, %v", ct, err)
	}
}

func TestFamilyNameAllBranches(t *testing.T) {
	cases := map[nft.TableFamily]string{
		nft.TableFamilyINet:   "inet",
		nft.TableFamilyIPv4:   "ip",
		nft.TableFamilyIPv6:   "ip6",
		nft.TableFamilyARP:    "arp",
		nft.TableFamilyBridge: "bridge",
		nft.TableFamilyNetdev: "netdev",
	}
	for fam, want := range cases {
		if got := familyName(fam); got != want {
			t.Errorf("familyName(%v) = %q, want %q", fam, got, want)
		}
	}
	if got := familyName(nft.TableFamilyUnspecified); got != "unspecified" {
		t.Errorf("familyName(unspecified) = %q", got)
	}
}

func TestParamBoolWithBoolType(t *testing.T) {
	if !paramBool(map[string]interface{}{"x": true}, "x", false) {
		t.Fatal("expected true from a native bool param")
	}
	if paramBool(map[string]interface{}{"x": "not-a-bool"}, "x", false) {
		t.Fatal("unparseable bool string should fall back to default")
	}
	if !paramBool(map[string]interface{}{}, "x", true) {
		t.Fatal("missing key should fall back to default")
	}
}

func TestIfnameBytesPadsAndNullTerminates(t *testing.T) {
	b := ifnameBytes("eth0")
	if len(b) != 16 {
		t.Fatalf("len = %d, want 16", len(b))
	}
	if !bytes.HasPrefix(b, []byte("eth0\x00")) {
		t.Fatalf("expected null-terminated prefix, got %v", b)
	}
}

// --- rule.go: interface + IPv6 + position + error propagation --------------------

func TestBuildExprsIifOif(t *testing.T) {
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input",
		"iifname": "eth0", "oifname": "eth1", "action": "drop",
	})
	exprs, err := buildExprs(spec)
	if err != nil {
		t.Fatalf("buildExprs: %v", err)
	}
	if len(exprs) < 5 { // 2 meta/cmp pairs + verdict
		t.Fatalf("expected iifname+oifname+verdict exprs, got %d", len(exprs))
	}
}

func TestBuildExprsIPv6Addresses(t *testing.T) {
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input",
		"saddr": "2001:db8::/32", "daddr": "::1", "action": "accept",
	})
	exprs, err := buildExprs(spec)
	if err != nil {
		t.Fatalf("buildExprs: %v", err)
	}
	// saddr (Payload+Bitwise+Cmp) + daddr exact (Payload+Cmp) + verdict.
	if len(exprs) != 6 {
		t.Fatalf("got %d exprs, want 6: %+v", len(exprs), exprs)
	}
}

func TestRulePresentWithPositionInserts(t *testing.T) {
	conn := newFakeConn()
	first := mustRuleSpec(t, map[string]interface{}{
		"name": "first", "table": "filter", "chain": "input", "action": "accept",
	})
	if _, err := rulePresent(conn, first, false); err != nil {
		t.Fatalf("seed first: %v", err)
	}
	firstHandle := conn.rules[ruleKey("filter", "input")][0].Handle

	inserted, err := parseRuleSpec(map[string]interface{}{
		"name": "inserted", "table": "filter", "chain": "input", "action": "drop",
		"position": itoa(firstHandle),
	}, true)
	if err != nil {
		t.Fatalf("parseRuleSpec: %v", err)
	}
	if _, err := rulePresent(conn, inserted, false); err != nil {
		t.Fatalf("insert: %v", err)
	}
	rules := conn.rules[ruleKey("filter", "input")]
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if c, _ := ruleComment(rules[0]); c != "inserted" {
		t.Fatalf("expected inserted rule first, got %q", c)
	}
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func TestRulePresentPropagatesListError(t *testing.T) {
	conn := newFakeConn()
	conn.getRulesErr = errors.New("netlink says no")
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input", "action": "accept",
	})
	res, err := rulePresent(conn, spec, false)
	if err == nil || !res.Failed {
		t.Fatalf("expected failure to propagate, got res=%+v err=%v", res, err)
	}
}

func TestRulePresentPropagatesFlushError(t *testing.T) {
	conn := newFakeConn()
	conn.flushErr = errors.New("flush rejected by kernel")
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input", "action": "accept",
	})
	res, err := rulePresent(conn, spec, false)
	if err == nil || !res.Failed {
		t.Fatalf("expected flush failure to propagate, got res=%+v err=%v", res, err)
	}
}

func TestRuleAbsentPropagatesDelRuleError(t *testing.T) {
	conn := newFakeConn()
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input", "action": "accept",
	})
	if _, err := rulePresent(conn, spec, false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	conn.delRuleErr = errors.New("handle vanished")

	absent, err := parseRuleSpec(map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input",
	}, false)
	if err != nil {
		t.Fatalf("parseRuleSpec: %v", err)
	}
	res, err := ruleAbsent(conn, absent, false)
	if err == nil || !res.Failed {
		t.Fatalf("expected DelRule failure to propagate, got res=%+v err=%v", res, err)
	}
}

// --- table.go / chain.go: error propagation and dry-run absent -------------------

func TestTablePresentPropagatesListAndFlushErrors(t *testing.T) {
	conn := newFakeConn()
	conn.listErr = errors.New("boom")
	spec := tableSpec{name: "imas", family: nft.TableFamilyINet}
	if res, err := tablePresent(conn, spec, false); err == nil || !res.Failed {
		t.Fatalf("expected list error to propagate, got res=%+v err=%v", res, err)
	}

	conn2 := newFakeConn()
	conn2.flushErr = errors.New("flush boom")
	if res, err := tablePresent(conn2, spec, false); err == nil || !res.Failed {
		t.Fatalf("expected flush error to propagate, got res=%+v err=%v", res, err)
	}
}

func TestChainAbsentDryRunAndNoop(t *testing.T) {
	conn := newFakeConn()
	spec, err := parseChainSpec(map[string]interface{}{"name": "input", "table": "filter"})
	if err != nil {
		t.Fatalf("parseChainSpec: %v", err)
	}
	res, err := chainAbsent(conn, spec, false)
	if err != nil || res.Changed {
		t.Fatalf("absent-on-empty should be a no-op: res=%+v err=%v", res, err)
	}

	conn.AddChain(&nft.Chain{Name: "input", Table: &nft.Table{Name: "filter", Family: nft.TableFamilyINet}})
	res, err = chainAbsent(conn, spec, true)
	if err != nil || !res.Changed {
		t.Fatalf("dry run over existing chain: res=%+v err=%v", res, err)
	}
	if len(conn.chains) != 1 {
		t.Fatalf("dry run must not mutate, got %d chains", len(conn.chains))
	}
}

func TestChainPresentPropagatesListError(t *testing.T) {
	conn := newFakeConn()
	conn.listErr = errors.New("boom")
	spec, err := parseChainSpec(map[string]interface{}{"name": "input", "table": "filter"})
	if err != nil {
		t.Fatalf("parseChainSpec: %v", err)
	}
	if res, err := chainPresent(conn, spec, false); err == nil || !res.Failed {
		t.Fatalf("expected list error to propagate, got res=%+v err=%v", res, err)
	}
}

// --- firewall.go glue -------------------------------------------------------------

func TestPropertiesForMethod(t *testing.T) {
	props, err := (Firewall{}).PropertiesForMethod(MethodRulePresent)
	if err != nil {
		t.Fatalf("PropertiesForMethod: %v", err)
	}
	if props["action"] != "string,req" {
		t.Fatalf("action prop = %q, want string,req", props["action"])
	}
	if _, err := (Firewall{}).PropertiesForMethod("bogus"); err == nil {
		t.Fatal("expected an error for an unknown method")
	}
}

func TestTestDoesNotMutateAcrossAllMethods(t *testing.T) {
	conn := newFakeConn()
	cleanup := withFakeDial(conn)
	defer cleanup()

	fw, err := (Firewall{}).Parse("id", MethodTablePresent, map[string]interface{}{"name": "imas"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := fw.Test(context.Background()); err != nil {
		t.Fatalf("Test: %v", err)
	}
	if len(conn.tables) != 0 || conn.flushCalls != 0 {
		t.Fatalf("Test must never mutate kernel state: tables=%d flushes=%d", len(conn.tables), conn.flushCalls)
	}
}
