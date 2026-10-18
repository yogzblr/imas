package main

import (
	"testing"

	"github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/accountrank/accountranktest"
)

// Security review 2026-10, L16: an Account JWT issued in the year 3000,
// re-merged from a peer or already in this node's resolver, never beats
// a current JWT in the fence's merge.
func TestFenceMergeRefusesFutureDatedJWT(t *testing.T) {
	op, _ := nkeys.CreateOperator()
	opPub, _ := op.PublicKey()
	acctKP, _ := nkeys.CreateAccount()
	acct, _ := acctKP.PublicKey()

	current := func() string {
		t.Helper()
		s, err := jwt.NewAccountClaims(acct).Encode(op)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}()
	future := func() string {
		t.Helper()
		ac := jwt.NewAccountClaims(acct)
		ac.Limits.Conn = -1
		s, err := accountranktest.EncodeAt(ac, op, accountranktest.Year3000)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}()

	newResolverFence := func(t *testing.T) *fence {
		t.Helper()
		dr, err := nats_server.NewDirAccResolver(t.TempDir(), 0, 0, nats_server.HardDelete)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(dr.Close)
		return &fence{resolver: dr, issuers: []string{opPub}}
	}
	held := func(t *testing.T, f *fence) string {
		t.Helper()
		s, err := f.resolver.LoadAcc(acct)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	t.Run("peer offers a future-dated JWT", func(t *testing.T) {
		f := newResolverFence(t)
		if err := f.merge(acct, []string{future, current}); err != nil {
			t.Fatal(err)
		}
		if got := held(t, f); got != current {
			t.Error("the year-3000 JWT won the merge over the current one")
		}
		if err := f.merge(acct, []string{future}); err != nil {
			t.Fatal(err)
		}
		if got := held(t, f); got != current {
			t.Error("a year-3000 JWT replaced the current one this node held")
		}
	})
	t.Run("node already holds a future-dated JWT", func(t *testing.T) {
		f := newResolverFence(t)
		if err := f.resolver.SaveAcc(acct, future); err != nil {
			t.Fatal(err)
		}
		if err := f.merge(acct, []string{current}); err != nil {
			t.Fatal(err)
		}
		if got := held(t, f); got != current {
			t.Error("the planted year-3000 JWT kept beating the current one")
		}
	})
}
