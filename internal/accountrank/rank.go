// Package accountrank validates an Account JWT against the trusted
// operator and orders two Account JWTs for the same account, so every
// component that has to pick a winner (the bus fence, the account loader)
// picks the same one. FLAG FOR SECURITY REVIEW.
package accountrank

import (
	"fmt"
	"slices"

	"github.com/nats-io/jwt/v2"
)

// Claim is the part of an Account JWT that decides which of two JWTs for
// one account wins.
type Claim struct {
	IAT       int64
	JTI       string
	LockedOut bool // connection limit 0
	Raw       string
}

// Rank decodes theJWT (which verifies its signature) and checks that its
// subject is wantSub and its issuer is one of trusted (the operator and
// its signing keys). It returns the fields Better compares.
func Rank(theJWT string, trusted []string, wantSub string) (iat int64, jti string, lockedOut bool, err error) {
	ac, err := jwt.DecodeAccountClaims(theJWT)
	if err != nil {
		return 0, "", false, err
	}
	if ac.Subject != wantSub {
		return 0, "", false, fmt.Errorf("subject %s does not match", ac.Subject)
	}
	if !slices.Contains(trusted, ac.Issuer) {
		return 0, "", false, fmt.Errorf("issuer %s is not the trusted operator", ac.Issuer)
	}
	return ac.IssuedAt, ac.ID, ac.Limits.Conn == 0, nil
}

// Better reports whether a beats b: newest issued-at first; at the same
// issued-at a locked-out JWT beats a live one, so a tie never re-opens a
// tenant; the JWT text breaks any remaining tie so every node picks the
// same winner.
func Better(a, b Claim) bool {
	if a.IAT != b.IAT {
		return a.IAT > b.IAT
	}
	if a.LockedOut != b.LockedOut {
		return a.LockedOut
	}
	return a.Raw > b.Raw
}
