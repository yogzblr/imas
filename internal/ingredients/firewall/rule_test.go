//go:build linux

package firewall

import (
	"errors"
	"reflect"
	"testing"

	nft "github.com/google/nftables"
	"github.com/google/nftables/userdata"
)

func mustRuleSpec(t *testing.T, params map[string]interface{}) ruleSpec {
	t.Helper()
	spec, err := parseRuleSpec(params, true)
	if err != nil {
		t.Fatalf("parseRuleSpec: %v", err)
	}
	return spec
}

func TestParseRuleSpecPortsRequireProtocol(t *testing.T) {
	_, err := parseRuleSpec(map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input",
		"dport": "443", "action": "accept",
	}, true)
	if !errors.Is(err, ErrInvalidProperty) {
		t.Fatalf("dport without protocol: want ErrInvalidProperty, got %v", err)
	}
}

func TestParseRuleSpecPortsRejectIcmp(t *testing.T) {
	_, err := parseRuleSpec(map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input",
		"protocol": "icmp", "dport": "443", "action": "accept",
	}, true)
	if !errors.Is(err, ErrInvalidProperty) {
		t.Fatalf("dport with icmp: want ErrInvalidProperty, got %v", err)
	}
}

func TestParseRuleSpecInvalidAction(t *testing.T) {
	_, err := parseRuleSpec(map[string]interface{}{
		"name": "r1", "table": "filter", "chain": "input", "action": "yeet",
	}, true)
	if !errors.Is(err, ErrInvalidProperty) {
		t.Fatalf("bad action: want ErrInvalidProperty, got %v", err)
	}
}

func TestBuildExprsIsDeterministic(t *testing.T) {
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "22", "saddr": "10.0.0.0/24",
		"action": "accept", "counter": true,
	})
	e1, err := buildExprs(spec)
	if err != nil {
		t.Fatalf("buildExprs: %v", err)
	}
	e2, err := buildExprs(spec)
	if err != nil {
		t.Fatalf("buildExprs: %v", err)
	}
	if !reflect.DeepEqual(e1, e2) {
		t.Fatalf("buildExprs must be deterministic for the same spec:\n%+v\n%+v", e1, e2)
	}
}

func TestRulePresentAddsNoopsThenUpdatesOnDrift(t *testing.T) {
	conn := newFakeConn()
	table := &nft.Table{Name: "filter", Family: nft.TableFamilyINet}
	chain := &nft.Chain{Name: "input", Table: table}
	conn.AddTable(table)
	conn.AddChain(chain)

	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "22", "action": "accept",
	})

	res, err := rulePresent(conn, spec, false)
	if err != nil || !res.Changed {
		t.Fatalf("first apply: res=%+v err=%v", res, err)
	}
	if got := len(conn.rules[ruleKey("filter", "input")]); got != 1 {
		t.Fatalf("expected 1 rule, got %d", got)
	}

	res, err = rulePresent(conn, spec, false)
	if err != nil || res.Changed {
		t.Fatalf("second apply should be a no-op: res=%+v err=%v", res, err)
	}
	if got := len(conn.rules[ruleKey("filter", "input")]); got != 1 {
		t.Fatalf("no-op apply must not duplicate the rule, got %d", got)
	}

	// Same name, different match -- must be detected as drift and replaced,
	// not left stale alongside the old rule.
	drifted := mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "2222", "action": "accept",
	})
	res, err = rulePresent(conn, drifted, false)
	if err != nil || !res.Changed {
		t.Fatalf("drift apply: res=%+v err=%v", res, err)
	}
	rules := conn.rules[ruleKey("filter", "input")]
	if len(rules) != 1 {
		t.Fatalf("drift apply must replace, not duplicate: got %d rules", len(rules))
	}
	wantExprs, err := buildExprs(drifted)
	if err != nil {
		t.Fatalf("buildExprs: %v", err)
	}
	if !reflect.DeepEqual(rules[0].Exprs, wantExprs) {
		t.Fatalf("rule after drift apply does not match new spec:\n%+v\n%+v", rules[0].Exprs, wantExprs)
	}
}

func TestRulePresentDryRunDoesNotMutate(t *testing.T) {
	conn := newFakeConn()
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "22", "action": "accept",
	})
	res, err := rulePresent(conn, spec, true)
	if err != nil || !res.Changed {
		t.Fatalf("dry run: res=%+v err=%v", res, err)
	}
	if got := len(conn.rules[ruleKey("filter", "input")]); got != 0 {
		t.Fatalf("dry run must not mutate, got %d rules", got)
	}
}

func TestRuleAbsentRemovesByName(t *testing.T) {
	conn := newFakeConn()
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "22", "action": "accept",
	})
	if _, err := rulePresent(conn, spec, false); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	absentSpec, err := parseRuleSpec(map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
	}, false)
	if err != nil {
		t.Fatalf("parseRuleSpec absent: %v", err)
	}

	res, err := ruleAbsent(conn, absentSpec, false)
	if err != nil || !res.Changed {
		t.Fatalf("remove: res=%+v err=%v", res, err)
	}
	if got := len(conn.rules[ruleKey("filter", "input")]); got != 0 {
		t.Fatalf("expected rule removed, got %d", got)
	}

	res, err = ruleAbsent(conn, absentSpec, false)
	if err != nil || res.Changed {
		t.Fatalf("second removal should be a no-op: res=%+v err=%v", res, err)
	}
}

func TestRuleAbsentLeavesOtherNamedRulesAlone(t *testing.T) {
	conn := newFakeConn()
	specA := mustRuleSpec(t, map[string]interface{}{
		"name": "a", "table": "filter", "chain": "input", "action": "accept",
	})
	specB := mustRuleSpec(t, map[string]interface{}{
		"name": "b", "table": "filter", "chain": "input", "action": "drop",
	})
	if _, err := rulePresent(conn, specA, false); err != nil {
		t.Fatalf("seed a: %v", err)
	}
	if _, err := rulePresent(conn, specB, false); err != nil {
		t.Fatalf("seed b: %v", err)
	}

	absentA, err := parseRuleSpec(map[string]interface{}{
		"name": "a", "table": "filter", "chain": "input",
	}, false)
	if err != nil {
		t.Fatalf("parseRuleSpec: %v", err)
	}
	if _, err := ruleAbsent(conn, absentA, false); err != nil {
		t.Fatalf("remove a: %v", err)
	}

	rules := conn.rules[ruleKey("filter", "input")]
	if len(rules) != 1 {
		t.Fatalf("expected rule b to remain, got %d rules", len(rules))
	}
	if c, ok := ruleComment(rules[0]); !ok || c != "b" {
		t.Fatalf("remaining rule should be %q, got %q", "b", c)
	}
}

func TestRulePresentReject(t *testing.T) {
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "reject-all", "table": "filter", "chain": "input", "action": "reject",
	})
	exprs, err := buildExprs(spec)
	if err != nil {
		t.Fatalf("buildExprs: %v", err)
	}
	if len(exprs) == 0 {
		t.Fatal("expected at least the reject expr")
	}
}

// TestRuleCommentIsNULTerminated: nft shows a rule's comment only when it
// ends in NUL, as the nft CLI writes it. Without it, a rule this
// ingredient added was invisible to `nft list` by name (UAT
// I.firewall.rule_present).
func TestRuleCommentIsNULTerminated(t *testing.T) {
	conn := newFakeConn()
	table := &nft.Table{Name: "filter", Family: nft.TableFamilyINet}
	chain := &nft.Chain{Name: "input", Table: table}
	conn.AddTable(table)
	conn.AddChain(chain)
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "uat-rule", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "65000", "action": "accept",
	})
	if _, err := rulePresent(conn, spec, false); err != nil {
		t.Fatalf("rulePresent: %v", err)
	}
	rules, _ := conn.GetRules(table, chain)
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	raw := userdata.Get(rules[0].UserData, userdata.TypeComment)
	if string(raw) != "uat-rule\x00" {
		t.Fatalf("comment is %q, want %q", raw, "uat-rule\x00")
	}
}

// TestRulePresentRewritesUnterminatedComment: a rule an earlier sprout
// wrote without the NUL is rewritten once, then left alone.
func TestRulePresentRewritesUnterminatedComment(t *testing.T) {
	conn := newFakeConn()
	table := &nft.Table{Name: "filter", Family: nft.TableFamilyINet}
	chain := &nft.Chain{Name: "input", Table: table}
	conn.AddTable(table)
	conn.AddChain(chain)
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "uat-rule", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "65000", "action": "accept",
	})
	exprs, err := buildExprs(spec)
	if err != nil {
		t.Fatal(err)
	}
	conn.AddRule(&nft.Rule{Table: table, Chain: chain, Exprs: exprs,
		UserData: userdata.Append(nil, userdata.TypeComment, []byte("uat-rule"))})

	res, err := rulePresent(conn, spec, false)
	if err != nil || !res.Changed {
		t.Fatalf("first run: %+v, %v; want the rule rewritten", res, err)
	}
	res, err = rulePresent(conn, spec, false)
	if err != nil || res.Changed {
		t.Fatalf("second run: %+v, %v; want no change", res, err)
	}
	rules, _ := conn.GetRules(table, chain)
	if len(rules) != 1 || !commentTerminated(rules[0]) {
		t.Fatalf("want one rule with a terminated comment, got %d", len(rules))
	}
}

// TestRuleAbsentRemovesEveryRuleOfTheName: nftables doesn't keep comments
// unique. Removing only the first left the name present, so every run
// removed another (UAT I.firewall.rule_absent's second cook).
func TestRuleAbsentRemovesEveryRuleOfTheName(t *testing.T) {
	conn := newFakeConn()
	table := &nft.Table{Name: "filter", Family: nft.TableFamilyINet}
	chain := &nft.Chain{Name: "input", Table: table}
	conn.AddTable(table)
	conn.AddChain(chain)
	for i := 0; i < 2; i++ {
		conn.AddRule(&nft.Rule{Table: table, Chain: chain, UserData: ruleUserData("dup")})
	}
	conn.AddRule(&nft.Rule{Table: table, Chain: chain, UserData: ruleUserData("other")})
	spec, err := parseRuleSpec(map[string]interface{}{"name": "dup", "table": "filter", "chain": "input"}, false)
	if err != nil {
		t.Fatal(err)
	}

	res, err := ruleAbsent(conn, spec, false)
	if err != nil || !res.Changed {
		t.Fatalf("first run: %+v, %v; want a change", res, err)
	}
	res, err = ruleAbsent(conn, spec, false)
	if err != nil || res.Changed {
		t.Fatalf("second run: %+v, %v; want no change", res, err)
	}
	rules, _ := conn.GetRules(table, chain)
	if len(rules) != 1 {
		t.Fatalf("want only the other rule left, got %d rules", len(rules))
	}
	if c, _ := ruleComment(rules[0]); c != "other" {
		t.Fatalf("left %q, want other", c)
	}
}

// TestRulePresentRepairKeepsTheRulesPlace: repairing a rule (an old
// unterminated comment, or drifted expressions) must not move it behind
// the rules that followed it, such as a catch-all drop.
func TestRulePresentRepairKeepsTheRulesPlace(t *testing.T) {
	conn := newFakeConn()
	table := &nft.Table{Name: "filter", Family: nft.TableFamilyINet}
	chain := &nft.Chain{Name: "input", Table: table}
	conn.AddTable(table)
	conn.AddChain(chain)
	spec := mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "22", "action": "accept",
	})
	exprs, err := buildExprs(spec)
	if err != nil {
		t.Fatal(err)
	}
	conn.AddRule(&nft.Rule{Table: table, Chain: chain, Exprs: exprs,
		UserData: userdata.Append(nil, userdata.TypeComment, []byte("allow-ssh"))})
	conn.AddRule(&nft.Rule{Table: table, Chain: chain, UserData: ruleUserData("drop-all")})

	for _, s := range []ruleSpec{spec, mustRuleSpec(t, map[string]interface{}{
		"name": "allow-ssh", "table": "filter", "chain": "input",
		"protocol": "tcp", "dport": "2222", "action": "accept",
	})} {
		if res, err := rulePresent(conn, s, false); err != nil || !res.Changed {
			t.Fatalf("repair: %+v, %v; want a change", res, err)
		}
		rules, _ := conn.GetRules(table, chain)
		var names []string
		for _, r := range rules {
			c, _ := ruleComment(r)
			names = append(names, c)
		}
		if len(names) != 2 || names[0] != "allow-ssh" || names[1] != "drop-all" {
			t.Fatalf("rules in order %v, want [allow-ssh drop-all]", names)
		}
	}
}
