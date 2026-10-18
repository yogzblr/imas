// Package accountrank validates an Account JWT against the trusted
// operator and orders two Account JWTs for the same account, so every
// component that has to pick a winner (the bus fence, the account loader)
// picks the same one. FLAG FOR SECURITY REVIEW.
package accountrank

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nats-io/jwt/v2"
)

// MaxFutureSkew is how far ahead of this process's clock an Account
// JWT's issued-at may be (security review 2026-10, L16). Replica clocks
// agree to well within it; a JWT issued further ahead was not signed by
// a farmer with a sane clock. Such a JWT would outrank every later push
// (Better compares issued-at first), so Rank refuses it.
const MaxFutureSkew = 5 * time.Minute

// ErrFutureIssuedAt is an Account JWT issued more than MaxFutureSkew
// ahead of now.
var ErrFutureIssuedAt = errors.New("issued-at is in the future")

// CheckIssuedAt returns ErrFutureIssuedAt, wrapped with both times, when
// iat is more than MaxFutureSkew ahead of t.
func CheckIssuedAt(iat int64, t time.Time) error {
	if limit := t.Add(MaxFutureSkew).Unix(); iat > limit {
		return fmt.Errorf("%w: issued at %d, more than %s after now (%d)", ErrFutureIssuedAt, iat, MaxFutureSkew, t.Unix())
	}
	return nil
}

// Claim is the part of an Account JWT that decides which of two JWTs for
// one account wins.
type Claim struct {
	IAT       int64
	JTI       string
	LockedOut bool // connection limit 0
	Raw       string
}

// Rank decodes theJWT (which verifies its signature) and checks that its
// subject is wantSub, its issuer is one of trusted (the operator and its
// signing keys) and its issued-at is not more than MaxFutureSkew ahead of
// now (CheckIssuedAt). It returns the fields Better compares. Every
// component that ranks or merges Account JWTs from outside its own
// process (the bus fence, the account loader, farmer's accounts bucket
// reader) goes through Rank, so a future-dated JWT never takes part.
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
	if err := CheckIssuedAt(ac.IssuedAt, time.Now()); err != nil {
		return 0, "", false, err
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
