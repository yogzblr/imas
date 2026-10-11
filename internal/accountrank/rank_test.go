package accountrank

import (
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func newKP(t *testing.T, create func() (nkeys.KeyPair, error)) (nkeys.KeyPair, string) {
	t.Helper()
	kp, err := create()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return kp, pub
}

func signAccount(t *testing.T, signer nkeys.KeyPair, sub string, conn int64) string {
	t.Helper()
	ac := jwt.NewAccountClaims(sub)
	ac.Limits.Conn = conn
	s, err := ac.Encode(signer)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRank(t *testing.T) {
	op, opPub := newKP(t, nkeys.CreateOperator)
	sk, skPub := newKP(t, nkeys.CreateOperator)
	rogue, _ := newKP(t, nkeys.CreateOperator)
	_, acct := newKP(t, nkeys.CreateAccount)
	_, other := newKP(t, nkeys.CreateAccount)
	trusted := []string{opPub, skPub}

	live := signAccount(t, op, acct, -1)
	iat, jti, locked, err := Rank(live, trusted, acct)
	if err != nil {
		t.Fatalf("live JWT from the operator: %v", err)
	}
	ac, _ := jwt.DecodeAccountClaims(live)
	if iat != ac.IssuedAt || jti != ac.ID || jti == "" || locked {
		t.Errorf("got iat=%d jti=%q locked=%v, want iat=%d jti=%q locked=false", iat, jti, locked, ac.IssuedAt, ac.ID)
	}

	if _, _, locked, err := Rank(signAccount(t, sk, acct, 0), trusted, acct); err != nil || !locked {
		t.Errorf("lock-out from a signing key: locked=%v err=%v, want locked and no error", locked, err)
	}

	for name, tc := range map[string]struct {
		jwt, sub, want string
	}{
		"wrong subject":    {live, other, "does not match"},
		"untrusted issuer": {signAccount(t, rogue, acct, -1), acct, "not the trusted operator"},
		"bad signature":    {live[:len(live)-4] + "AAAA", acct, ""},
		"not a JWT":        {"garbage", acct, ""},
	} {
		_, _, _, err := Rank(tc.jwt, trusted, tc.sub)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
	if _, _, _, err := Rank(live, nil, acct); err == nil {
		t.Error("an empty trusted list accepted a JWT")
	}
}

func TestBetter(t *testing.T) {
	live := Claim{IAT: 10, Raw: "a"}
	locked := Claim{IAT: 10, LockedOut: true, Raw: "b"}
	newer := Claim{IAT: 11, Raw: "c"}
	if !Better(locked, live) || Better(live, locked) {
		t.Error("at the same issued-at a lock-out must win over a live JWT")
	}
	if !Better(newer, locked) || Better(locked, newer) {
		t.Error("a newer JWT (e.g. re-provisioning) must win over an older lock-out")
	}
	x, y := Claim{IAT: 10, Raw: "x"}, Claim{IAT: 10, Raw: "y"}
	if Better(x, y) == Better(y, x) {
		t.Error("ties must have exactly one winner so every node converges")
	}
	if Better(x, x) {
		t.Error("a claim must not beat itself")
	}
}
