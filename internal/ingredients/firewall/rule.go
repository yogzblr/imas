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
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return nil, fmt.Errorf("listing rules in chain %s: %w", chain.Name, err)
	}
	for _, r := range rules {
		if c, ok := ruleComment(r); ok && c == name {
			return r, nil
		}
	}
	return nil, nil
}

func rulePresent(conn nftConn, spec ruleSpec, dryRun bool) (cook.Result, error) {
	table := &nft.Table{Name: spec.table, Family: spec.family}
	chain := &nft.Chain{Name: spec.chain, Table: table}

	wantExprs, err := buildExprs(spec)
	if err != nil {
		return cook.Result{Failed: true}, err
	}

	existing, err := findRuleByName(conn, table, chain, spec.name)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if existing != nil && reflect.DeepEqual(existing.Exprs, wantExprs) {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("rule %s in %s/%s is already present and matches", spec.name, spec.table, spec.chain),
		}}, nil
	}

	verb := "added"
	if existing != nil {
		verb = "updated"
	}
	if dryRun {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("rule %s in %s/%s would be %s", spec.name, spec.table, spec.chain, verb),
		}}, nil
	}

	if existing != nil {
		if err := conn.DelRule(existing); err != nil {
			return cook.Result{Failed: true}, fmt.Errorf("replacing rule %s: %w", spec.name, err)
		}
	}
	newRule := &nft.Rule{
		Table:    table,
		Chain:    chain,
		Exprs:    wantExprs,
		UserData: userdata.Append(nil, userdata.TypeComment, []byte(spec.name)),
	}
	if spec.hasPosition {
		newRule.Position = spec.position
		conn.InsertRule(newRule)
	} else {
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

	existing, err := findRuleByName(conn, table, chain, spec.name)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if existing == nil {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("rule %s in %s/%s is already absent", spec.name, spec.table, spec.chain),
		}}, nil
	}
	if dryRun {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("rule %s in %s/%s would be removed", spec.name, spec.table, spec.chain),
		}}, nil
	}
	if err := conn.DelRule(existing); err != nil {
		return cook.Result{Failed: true}, fmt.Errorf("removing rule %s: %w", spec.name, err)
	}
	if err := conn.Flush(); err != nil {
		return cook.Result{Failed: true}, fmt.Errorf("removing rule %s: %w", spec.name, err)
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("rule %s in %s/%s has been removed", spec.name, spec.table, spec.chain),
	}}, nil
}
