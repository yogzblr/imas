//go:build linux

package firewall

import (
	"errors"
	"fmt"

	nft "github.com/google/nftables"
)

// fakeConn is an in-memory stand-in for *nft.Conn: it applies
// Add/Del{Table,Chain,Rule} immediately (unlike the real Conn, which
// buffers until Flush) so tests can assert on state without needing a
// live netlink socket or root/CAP_NET_ADMIN.
type fakeConn struct {
	tables []*nft.Table
	chains []*nft.Chain
	rules  map[string][]*nft.Rule // key: table.Name + "/" + chain.Name

	nextHandle uint64
	flushCalls int
	flushErr   error

	delRuleErr  error
	listErr     error
	getRulesErr error
}

func newFakeConn() *fakeConn {
	return &fakeConn{rules: map[string][]*nft.Rule{}}
}

func ruleKey(tableName, chainName string) string { return tableName + "/" + chainName }

func (f *fakeConn) ListTablesOfFamily(family nft.TableFamily) ([]*nft.Table, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []*nft.Table
	for _, t := range f.tables {
		if family == nft.TableFamilyUnspecified || t.Family == family {
			out = append(out, t)
		}
	}
	return out, nil
}

func (f *fakeConn) AddTable(t *nft.Table) *nft.Table {
	f.tables = append(f.tables, t)
	return t
}

func (f *fakeConn) DelTable(t *nft.Table) {
	out := f.tables[:0]
	for _, existing := range f.tables {
		if existing.Name == t.Name && existing.Family == t.Family {
			continue
		}
		out = append(out, existing)
	}
	f.tables = out
}

func (f *fakeConn) ListChains() ([]*nft.Chain, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.chains, nil
}

func (f *fakeConn) AddChain(c *nft.Chain) *nft.Chain {
	f.chains = append(f.chains, c)
	return c
}

func (f *fakeConn) DelChain(c *nft.Chain) {
	out := f.chains[:0]
	for _, existing := range f.chains {
		if existing.Name == c.Name && existing.Table.Name == c.Table.Name && existing.Table.Family == c.Table.Family {
			continue
		}
		out = append(out, existing)
	}
	f.chains = out
}

func (f *fakeConn) GetRules(t *nft.Table, c *nft.Chain) ([]*nft.Rule, error) {
	if f.getRulesErr != nil {
		return nil, f.getRulesErr
	}
	return append([]*nft.Rule{}, f.rules[ruleKey(t.Name, c.Name)]...), nil
}

func (f *fakeConn) AddRule(r *nft.Rule) *nft.Rule {
	f.nextHandle++
	r.Handle = f.nextHandle
	key := ruleKey(r.Table.Name, r.Chain.Name)
	f.rules[key] = append(f.rules[key], r)
	return r
}

func (f *fakeConn) InsertRule(r *nft.Rule) *nft.Rule {
	f.nextHandle++
	r.Handle = f.nextHandle
	key := ruleKey(r.Table.Name, r.Chain.Name)
	f.rules[key] = append([]*nft.Rule{r}, f.rules[key]...)
	return r
}

// ReplaceRule replaces the rule with r's handle in place, as the kernel
// does for a replace by handle.
func (f *fakeConn) ReplaceRule(r *nft.Rule) *nft.Rule {
	key := ruleKey(r.Table.Name, r.Chain.Name)
	for i, existing := range f.rules[key] {
		if existing.Handle == r.Handle {
			f.rules[key][i] = r
			return r
		}
	}
	return r
}

func (f *fakeConn) DelRule(r *nft.Rule) error {
	if f.delRuleErr != nil {
		return f.delRuleErr
	}
	if r.Handle == 0 {
		return errors.New("rule's handle cannot be 0")
	}
	key := ruleKey(r.Table.Name, r.Chain.Name)
	out := f.rules[key][:0]
	for _, existing := range f.rules[key] {
		if existing.Handle == r.Handle {
			continue
		}
		out = append(out, existing)
	}
	f.rules[key] = out
	return nil
}

func (f *fakeConn) Flush() error {
	f.flushCalls++
	return f.flushErr
}

// withFakeDial substitutes dialConn for the duration of a test.
func withFakeDial(conn *fakeConn) func() {
	orig := dialConn
	dialConn = func() (nftConn, error) { return conn, nil }
	return func() { dialConn = orig }
}

// withFailingDial makes dialConn always fail, for exercising the
// "can't reach netlink" error path.
func withFailingDial(msg string) func() {
	orig := dialConn
	dialConn = func() (nftConn, error) { return nil, fmt.Errorf("%s", msg) }
	return func() { dialConn = orig }
}
