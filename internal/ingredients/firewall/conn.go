//go:build linux

// Package firewall implements the H.2 imas-linux-parity-addendum ingredient:
// nftables table/chain/rule management via google/nftables, a pure-Go
// netlink client. It replaces the fragile "shell to iptables and parse
// iptables-save/iptables -L text" pattern Salt's iptables module uses with
// structured rule objects the kernel itself validates.
//
// FLAG FOR SECURITY REVIEW: a firewall ingredient can lock a host out of
// its own management plane or expose services that were meant to stay
// closed. Read internal/ingredients/firewall/doc.go and the PR description
// before relying on this in production.
package firewall

import (
	nft "github.com/google/nftables"
)

// nftConn is the subset of *nft.Conn this ingredient calls, narrowed to an
// interface so tests can substitute an in-memory fake instead of talking to
// a real netlink socket (which needs CAP_NET_ADMIN and a live nftables
// subsystem neither unit tests nor most CI runners have).
type nftConn interface {
	ListTablesOfFamily(family nft.TableFamily) ([]*nft.Table, error)
	AddTable(t *nft.Table) *nft.Table
	DelTable(t *nft.Table)

	ListChains() ([]*nft.Chain, error)
	AddChain(c *nft.Chain) *nft.Chain
	DelChain(c *nft.Chain)

	GetRules(t *nft.Table, c *nft.Chain) ([]*nft.Rule, error)
	AddRule(r *nft.Rule) *nft.Rule
	InsertRule(r *nft.Rule) *nft.Rule
	DelRule(r *nft.Rule) error

	Flush() error
}

// dialConn opens a one-shot (non-lasting) netlink connection: one socket
// per ingredient invocation, opened and closed around a single Flush. This
// avoids holding a privileged socket open across cook steps. Overridable
// in tests.
var dialConn = func() (nftConn, error) {
	return nft.New()
}
