package saasapi

import (
	"strings"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// validateBusCredential refuses an expired SaaS API User JWT at boot
// (security review 2026-10, L14: the JWT now has an exp) and accepts one
// that is still valid or carries no exp.
func TestValidateBusCredentialExpiry(t *testing.T) {
	user, _ := nkeys.CreateUser()
	seed, _ := user.Seed()
	pub, _ := user.PublicKey()
	sys, _ := nkeys.CreateAccount()
	mint := func(exp int64) string {
		uc := jwt.NewUserClaims(pub)
		uc.Expires = exp
		s, err := uc.Encode(sys)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if err := validateBusCredential(string(seed), mint(time.Now().Add(time.Hour).Unix())); err != nil {
		t.Fatalf("valid JWT: %v", err)
	}
	if err := validateBusCredential(string(seed), mint(0)); err != nil {
		t.Fatalf("JWT without exp: %v", err)
	}
	err := validateBusCredential(string(seed), mint(time.Now().Add(-time.Minute).Unix()))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired JWT: err = %v, want an expiry error", err)
	}
}
