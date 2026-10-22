//go:build linux

package firewall

import (
	"bytes"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	nft "github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"

	"github.com/yogzblr/imas/internal/cook"
)

const (
	actionAccept = "accept"
	actionDrop   = "drop"
	actionReject = "reject"
)

type ruleSpec struct {
	name, table, chain string
	family             nft.TableFamily

	protocol     *byte
	saddr, daddr *addrMatch
	sport, dport *portMatch
	iifname      string
	oifname      string
	action       string
	counter      bool
	position     uint64
	hasPosition  bool
}

// parseRuleSpec parses rule_present/rule_absent properties. rule_absent
// only ever needs name/table/chain/family to find and remove the rule it
// created earlier, so the match/action fields are left zero for it --
// PropertiesForMethod(MethodRuleAbsent) doesn't advertise them and recipes
// can't set them for that method.
func parseRuleSpec(params map[string]interface{}, isPresent bool) (ruleSpec, error) {
	name, err := requireString(params, "name")
	if err != nil {
		return ruleSpec{}, err
	}
	table, err := requireString(params, "table")
	if err != nil {
		return ruleSpec{}, err
	}
	chain, err := requireString(params, "chain")
	if err != nil {
		return ruleSpec{}, err
	}
	family, err := parseFamily(paramStringOr(params, "family", ""))
	if err != nil {
		return ruleSpec{}, err
	}
	spec := ruleSpec{name: name, table: table, chain: chain, family: family}
	if !isPresent {
		return spec, nil
	}

	if protoStr := paramStringOr(params, "protocol", ""); protoStr != "" {
		p, err := parseProtocol(protoStr)
		if err != nil {
			return ruleSpec{}, err
		}
		spec.protocol = &p
	}
	if s := paramStringOr(params, "saddr", ""); s != "" {
		a, err := parseAddr(s)
		if err != nil {
			return ruleSpec{}, err
		}
		spec.saddr = &a
	}
	if s := paramStringOr(params, "daddr", ""); s != "" {
		a, err := parseAddr(s)
		if err != nil {
			return ruleSpec{}, err
		}
		spec.daddr = &a
	}
	if s := paramStringOr(params, "sport", ""); s != "" {
		p, err := parsePort(s)
		if err != nil {
			return ruleSpec{}, err
		}
		spec.sport = &p
	}
	if s := paramStringOr(params, "dport", ""); s != "" {
		p, err := parsePort(s)
		if err != nil {
			return ruleSpec{}, err
		}
		spec.dport = &p
	}
	if (spec.sport != nil || spec.dport != nil) && spec.protocol == nil {
		return ruleSpec{}, fmt.Errorf("%w: sport/dport requires protocol to be set (tcp or udp)", ErrInvalidProperty)
	}
	if spec.protocol != nil && (spec.sport != nil || spec.dport != nil) {
		if *spec.protocol != unix.IPPROTO_TCP && *spec.protocol != unix.IPPROTO_UDP {
			return ruleSpec{}, fmt.Errorf("%w: sport/dport only apply to tcp or udp", ErrInvalidProperty)
		}
	}
	spec.iifname = paramStringOr(params, "iifname", "")
	spec.oifname = paramStringOr(params, "oifname", "")
	spec.counter = paramBool(params, "counter", false)

	action, err := requireString(params, "action")
	if err != nil {
		return ruleSpec{}, err
	}
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case actionAccept, actionDrop, actionReject:
	default:
		return ruleSpec{}, fmt.Errorf("%w: action must be accept, drop, or reject, got %q", ErrInvalidProperty, action)
	}
	spec.action = action

	if s := paramStringOr(params, "position", ""); s != "" {
		pos, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return ruleSpec{}, fmt.Errorf("%w: invalid position %q", ErrInvalidProperty, s)
		}
		spec.position = pos
		spec.hasPosition = true
	}
	return spec, nil
}

func ifnameBytes(name string) []byte {
	b := make([]byte, 16)
	copy(b, name+"\x00")
	return b
}

// networkHeaderOffsets returns the (offset, length) of the source and
// destination address fields within the IPv4 or IPv6 fixed header.
func networkHeaderOffsets(v6 bool) (srcOff, dstOff, length uint32) {
	if v6 {
		return 8, 24, 16
	}
	return 12, 16, 4
}

// buildExprs deterministically builds the match+verdict expression list for
// a rule spec. It is called both to build a rule to add and, for drift
// detection, to compare against what's already in the kernel -- so the
// same spec must always produce byte-for-byte identical Exprs.
func buildExprs(spec ruleSpec) ([]expr.Any, error) {
	var exprs []expr.Any

	if spec.iifname != "" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(spec.iifname)},
		)
	}
	if spec.oifname != "" {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(spec.oifname)},
		)
	}
	if spec.protocol != nil {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{*spec.protocol}},
		)
	}
	for _, am := range []struct {
		m     *addrMatch
		isSrc bool
	}{{spec.saddr, true}, {spec.daddr, false}} {
		if am.m == nil {
			continue
		}
		srcOff, dstOff, length := networkHeaderOffsets(am.m.v6)
		offset := dstOff
		if am.isSrc {
			offset = srcOff
		}
		exprs = append(exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          length,
		})
		if isFullMask(am.m.mask) {
			exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: am.m.network})
		} else {
			exprs = append(exprs,
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            length,
					Xor:            make([]byte, length),
					Mask:           am.m.mask,
				},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: am.m.network},
			)
		}
	}
	for _, pm := range []struct {
		p      *portMatch
		offset uint32
	}{{spec.sport, 0}, {spec.dport, 2}} {
		if pm.p == nil {
			continue
		}
		exprs = append(exprs, &expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       pm.offset,
			Len:          2,
		})
		if pm.p.isRange() {
			exprs = append(exprs,
				&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: uint16be(pm.p.lo)},
				&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: uint16be(pm.p.hi)},
			)
		} else {
			exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: uint16be(pm.p.lo)})
		}
	}
	if spec.counter {
		exprs = append(exprs, &expr.Counter{})
	}

	switch spec.action {
	case actionAccept:
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
	case actionDrop:
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})
	case actionReject:
		// Protocol-independent "port unreachable" reject: valid for the
		// inet/ip/ip6 families this ingredient targets without needing to
		// special-case icmp vs. icmpv6.
		exprs = append(exprs, &expr.Reject{
			Type: unix.NFT_REJECT_ICMPX_UNREACH,
			Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH,
		})
	default:
		return nil, fmt.Errorf("%w: action %q", ErrInvalidProperty, spec.action)
	}
	return exprs, nil
}

func uint16be(v uint16) []byte {
	return []byte{byte(v >> 8), byte(v)}
}

// ruleUserData is the user data a rule named name carries: its name as an
// nftables comment, NUL-terminated as the nft CLI writes it. nft refuses
// to show a comment without the NUL, so such a rule was invisible to
// `nft list` by name (UAT I.firewall.rule_present).
func ruleUserData(name string) []byte {
	return userdata.AppendString(nil, userdata.TypeComment, name)
}

// commentTerminated reports whether the rule's comment ends in the NUL
// nft needs to show it. Rules written before ruleUserData lack it.
func commentTerminated(rule *nft.Rule) bool {
	c := userdata.Get(rule.UserData, userdata.TypeComment)
	return len(c) > 0 && c[len(c)-1] == 0
}

func ruleComment(rule *nft.Rule) (string, bool) {
	c := userdata.Get(rule.UserData, userdata.TypeComment)
	if c == nil {
		return "", false
	}
	return string(bytes.TrimRight(c, "\x00")), true
}

// findRuleByName scans every rule in the chain for one whose comment
// matches spec.name. Comments are how this ingredient makes an otherwise
// anonymous nftables rule addressable/idempotent by name (nftables rules
// have no native "name", only a numeric handle assigned on creation).
func findRuleByName(conn nftConn, table *nft.Table, chain *nft.Chain, name string) (*nft.Rule, error) {
	rules, err := findRulesByName(conn, table, chain, name)
	if err != nil || len(rules) == 0 {
		return nil, err
	}
	return rules[0], nil
}

// findRulesByName returns every rule in the chain named name. nftables
// doesn't keep comments unique, so a name added twice (by hand, or by a
// script run twice) is held by more than one rule.
func findRulesByName(conn nftConn, table *nft.Table, chain *nft.Chain, name string) ([]*nft.Rule, error) {
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return nil, fmt.Errorf("listing rules in chain %s: %w", chain.Name, err)
	}
	var found []*nft.Rule
	for _, r := range rules {
		if c, ok := ruleComment(r); ok && c == name {
			found = append(found, r)
		}
	}
	return found, nil
}

func rulePresent(conn nftConn, spec ruleSpec, dryRun bool) (cook.Result, error) {
	table := &nft.Table{Name: spec.table, Family: spec.family}
	chain := &nft.Chain{Name: spec.chain, Table: table}

	wantExprs, err := buildExprs(spec)
	if err != nil {
		return cook.Result{Failed: true}, err
	}

	named, err := findRulesByName(conn, table, chain, spec.name)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	// The first rule of the name is the one kept; any later ones are
	// removed, as rule_absent removes them all, so the name ends up on
	// exactly one rule.
	var existing *nft.Rule
	var extra []*nft.Rule
	if len(named) > 0 {
		existing, extra = named[0], named[1:]
	}
	matches := existing != nil && reflect.DeepEqual(existing.Exprs, wantExprs) && commentTerminated(existing)
	if matches && len(extra) == 0 {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("rule %s in %s/%s is already present and matches", spec.name, spec.table, spec.chain),
		}}, nil
	}

	verb := "added"
	switch {
	case matches:
		verb = "de-duplicated"
	case existing != nil:
		verb = "updated"
	}
	if dryRun {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("rule %s in %s/%s would be %s", spec.name, spec.table, spec.chain, verb),
		}}, nil
	}

	newRule := &nft.Rule{
		Table:    table,
		Chain:    chain,
		Exprs:    wantExprs,
		UserData: ruleUserData(spec.name),
	}
	for _, r := range extra {
		if err := conn.DelRule(r); err != nil {
			return cook.Result{Failed: true}, fmt.Errorf("removing a second rule named %s: %w", spec.name, err)
		}
	}
	switch {
	case matches:
		// Only the extra rules needed removing.
	case existing != nil && !spec.hasPosition:
		// Replace it where it is: deleting and appending would move it to
		// the end of the chain, behind any drop rule that followed it.
		newRule.Handle = existing.Handle
		conn.ReplaceRule(newRule)
	case existing != nil:
		// position asks for a place of its own: delete, then insert there.
		if err := conn.DelRule(existing); err != nil {
			return cook.Result{Failed: true}, fmt.Errorf("replacing rule %s: %w", spec.name, err)
		}
		newRule.Position = spec.position
		conn.InsertRule(newRule)
	case spec.hasPosition:
		newRule.Position = spec.position
		conn.InsertRule(newRule)
	default:
		conn.AddRule(newRule)
	}
	if err := conn.Flush(); err != nil {
		return cook.Result{Failed: true}, fmt.Errorf("writing rule %s to %s/%s: %w", spec.name, spec.table, spec.chain, err)
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("rule %s in %s/%s has been %s", spec.name, spec.table, spec.chain, verb),
	}}, nil
}

func ruleAbsent(conn nftConn, spec ruleSpec, dryRun bool) (cook.Result, error) {
	table := &nft.Table{Name: spec.table, Family: spec.family}
	chain := &nft.Chain{Name: spec.chain, Table: table}

	// Every rule of the name goes: removing only the first would leave the
	// name present, and the next run would remove another.
	existing, err := findRulesByName(conn, table, chain, spec.name)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if len(existing) == 0 {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("rule %s in %s/%s is already absent", spec.name, spec.table, spec.chain),
		}}, nil
	}
	if dryRun {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("rule %s in %s/%s would be removed", spec.name, spec.table, spec.chain),
		}}, nil
	}
	for _, r := range existing {
		if err := conn.DelRule(r); err != nil {
			return cook.Result{Failed: true}, fmt.Errorf("removing rule %s: %w", spec.name, err)
		}
	}
	if err := conn.Flush(); err != nil {
		return cook.Result{Failed: true}, fmt.Errorf("removing rule %s: %w", spec.name, err)
	}
	notes := []fmt.Stringer{cook.Snprintf("rule %s in %s/%s has been removed", spec.name, spec.table, spec.chain)}
	if len(existing) > 1 {
		notes = append(notes, cook.Snprintf("%d rules carried the name %s; all were removed", len(existing), spec.name))
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: notes}, nil
}
