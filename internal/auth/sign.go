package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"
)

type UserAuth struct {
	Expires string `json:"expires"`
	Pubkey  string `json:"pubkey"`
	Sig     string `json:"sig"`
}

var (
	ErrExpired = errors.New("auth token expired")
	// ErrInvalidToken is returned for a token IsValid refuses for any
	// reason other than expiry or a malformed field. It is deliberately
	// generic: it doesn't say which check failed or what the limits are.
	ErrInvalidToken = errors.New("auth token invalid")
)

const (
	// TokenLifetime is how long a token NewToken creates stays valid.
	TokenLifetime = 5 * time.Minute

	// TokenClockSkewKey is the farmer config key that sets the clock
	// skew allowance, as a Go duration string ("10m", "90s").
	TokenClockSkewKey = "apitokenclockskew"
	// DefaultTokenClockSkew is the allowance when TokenClockSkewKey is
	// unset.
	DefaultTokenClockSkew = 10 * time.Minute
	// MaxTokenClockSkew is the largest allowance LoadPolicy accepts.
	// Every minute of allowance is a minute longer a token a compromised
	// bus mints stays valid, so it is bounded.
	MaxTokenClockSkew = 30 * time.Minute
)

// tokenClockSkew is how far ahead of farmer's clock a CLI's clock may run
// and still have its tokens accepted. LoadPolicy sets it from
// TokenClockSkewKey.
var tokenClockSkew atomic.Int64

func init() { tokenClockSkew.Store(int64(DefaultTokenClockSkew)) }

// TokenClockSkew returns the clock skew allowance in use.
func TokenClockSkew() time.Duration { return time.Duration(tokenClockSkew.Load()) }

// MaxTokenExpiry is the furthest in the future IsValid accepts a token's
// expiry to be: TokenLifetime plus TokenClockSkew (15 minutes by
// default).
//
// The token is an NKey signature over its expiry string, and the CLI
// signs the bus's nonce with the same key at connect. A compromised bus
// can send an expiry as its nonce (2099-01-01T00:00:00Z) and so obtain a
// valid signature over it. Without this cap that was a token valid until
// 2099. With it, the bus can still mint a token, but only one that
// expires within MaxTokenExpiry (SEC.0, stopgap 1 in
// docs/design/imas-payload-encryption-design.md; the real fix is
// Decision A there).
func MaxTokenExpiry() time.Duration { return TokenLifetime + TokenClockSkew() }

// parseTokenClockSkew validates a TokenClockSkewKey value: unset means
// DefaultTokenClockSkew, otherwise a duration from 0 to
// MaxTokenClockSkew. A bare number is refused because its unit would be
// a guess.
func parseTokenClockSkew(v any) (time.Duration, error) {
	var d time.Duration
	switch v := v.(type) {
	case nil:
		return DefaultTokenClockSkew, nil
	case time.Duration:
		d = v
	case string:
		if strings.TrimSpace(v) == "" {
			return DefaultTokenClockSkew, nil
		}
		var err error
		if d, err = time.ParseDuration(strings.TrimSpace(v)); err != nil {
			return 0, fmt.Errorf("%s = %q: want a duration such as \"10m\"", TokenClockSkewKey, v)
		}
	default:
		return 0, fmt.Errorf("%s = %v: want a duration string such as \"10m\"", TokenClockSkewKey, v)
	}
	if d < 0 || d > MaxTokenClockSkew {
		return 0, fmt.Errorf("%s = %s: must be between 0 and %s", TokenClockSkewKey, d, MaxTokenClockSkew)
	}
	return d, nil
}

// loadTokenClockSkew sets the allowance from farmer's config. On an
// invalid value it returns an error and leaves the allowance unchanged.
func loadTokenClockSkew() error {
	d, err := parseTokenClockSkew(jety.Get(TokenClockSkewKey))
	if err != nil {
		return err
	}
	tokenClockSkew.Store(int64(d))
	return nil
}

// Sign adds a signature digest to the UserAuth struct using the provided
// KeyPair. The signature digest is base64 encoded.
func (u UserAuth) Sign(kp nkeys.KeyPair) (UserAuth, error) {
	b, err := kp.Sign([]byte(u.Expires))
	if err != nil {
		return u, err
	}
	u.Sig = base64.StdEncoding.EncodeToString(b)
	return u, nil
}

// IsValid checks if the token is valid. It returns the public key
// if valid, or an error if not.
// Note this checks the signature using the public key in the token,
// which is not necessarily a public key that is trusted by the server.
//
// An expiry more than MaxTokenExpiry() in the future is refused with
// ErrInvalidToken, so a signature over a far-future timestamp is not a
// long-lived token.
func (u UserAuth) IsValid() (string, error) {
	return u.isValidAt(time.Now())
}

func (u UserAuth) isValidAt(now time.Time) (string, error) {
	exp, err := time.Parse(time.RFC3339, u.Expires)
	if err != nil {
		return "", err
	}
	if exp.Before(now) {
		return "", ErrExpired
	}
	if exp.After(now.Add(MaxTokenExpiry())) {
		return "", ErrInvalidToken
	}
	kp, err := nkeys.FromPublicKey(u.Pubkey)
	if err != nil {
		return "", err
	}
	sig, err := base64.StdEncoding.DecodeString(u.Sig)
	if err != nil {
		return "", err
	}
	return u.Pubkey, kp.Verify([]byte(u.Expires), sig)
}

// decodeToken decodes a base64 encoded token and returns the UserAuth
// struct. The token is not validated.
func decodeToken(token string) (UserAuth, error) {
	var ua UserAuth
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return ua, err
	}
	err = json.Unmarshal(b, &ua)
	return ua, err
}

// createSignedToken creates a signed token that can be used to authenticate
// with the server. The token is valid for TokenLifetime, and is base64
// encoded.
func createSignedToken(kp nkeys.KeyPair) (string, error) {
	pk, err := kp.PublicKey()
	if err != nil {
		log.Fatal("error getting public key", err)
	}

	ua := UserAuth{
		Expires: time.Now().Add(TokenLifetime).Format(time.RFC3339),
		Pubkey:  pk,
	}
	ua, err = ua.Sign(kp)
	if err != nil {
		log.Fatal("error signing", err)
	}
	b, err := json.Marshal(ua)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
