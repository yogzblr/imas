package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

// helper: create an nkeys account keypair for testing.
func mustCreateKeyPair(t *testing.T) nkeys.KeyPair {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("failed to create keypair: %v", err)
	}
	return kp
}

func TestUserAuthSignAndIsValid(t *testing.T) {
	kp := mustCreateKeyPair(t)
	pk, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	ua := UserAuth{
		Expires: time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		Pubkey:  pk,
	}

	signed, err := ua.Sign(kp)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if signed.Sig == "" {
		t.Fatal("Sign() produced empty signature")
	}
	if signed.Sig == ua.Sig {
		t.Error("Sign() should have changed the Sig field")
	}

	// IsValid should succeed for a freshly signed, non-expired token.
	gotPK, err := signed.IsValid()
	if err != nil {
		t.Fatalf("IsValid() error: %v", err)
	}
	if gotPK != pk {
		t.Errorf("IsValid() returned pubkey %q, want %q", gotPK, pk)
	}
}

func TestUserAuthIsValidExpired(t *testing.T) {
	kp := mustCreateKeyPair(t)
	pk, _ := kp.PublicKey()

	ua := UserAuth{
		Expires: time.Now().Add(-1 * time.Minute).Format(time.RFC3339),
		Pubkey:  pk,
	}
	signed, err := ua.Sign(kp)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	_, err = signed.IsValid()
	if err == nil {
		t.Error("IsValid() should fail for expired token")
	}
	if err != ErrExpired {
		t.Errorf("IsValid() error = %v, want ErrExpired", err)
	}
}

func TestUserAuthIsValidBadSignature(t *testing.T) {
	kp := mustCreateKeyPair(t)
	pk, _ := kp.PublicKey()

	ua := UserAuth{
		Expires: time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		Pubkey:  pk,
	}
	signed, _ := ua.Sign(kp)

	// Corrupt the signature.
	sigBytes, _ := base64.StdEncoding.DecodeString(signed.Sig)
	sigBytes[0] ^= 0xFF
	signed.Sig = base64.StdEncoding.EncodeToString(sigBytes)

	_, err := signed.IsValid()
	if err == nil {
		t.Error("IsValid() should fail for corrupted signature")
	}
}

func TestUserAuthIsValidBadExpiresFormat(t *testing.T) {
	ua := UserAuth{
		Expires: "not-a-date",
		Pubkey:  "ATEST",
		Sig:     "dGVzdA==",
	}
	_, err := ua.IsValid()
	if err == nil {
		t.Error("IsValid() should fail for unparseable expires")
	}
}

func TestUserAuthIsValidBadPubkey(t *testing.T) {
	ua := UserAuth{
		Expires: time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		Pubkey:  "NOTAVALIDNKEY",
		Sig:     base64.StdEncoding.EncodeToString([]byte("test")),
	}
	_, err := ua.IsValid()
	if err == nil {
		t.Error("IsValid() should fail for invalid pubkey")
	}
}

func TestUserAuthIsValidBadSigEncoding(t *testing.T) {
	kp := mustCreateKeyPair(t)
	pk, _ := kp.PublicKey()

	ua := UserAuth{
		Expires: time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		Pubkey:  pk,
		Sig:     "%%%not-base64%%%",
	}
	_, err := ua.IsValid()
	if err == nil {
		t.Error("IsValid() should fail for invalid base64 signature")
	}
}

func TestUserAuthIsValidWrongKey(t *testing.T) {
	// Sign with one key, but set Pubkey to a different key.
	kp1 := mustCreateKeyPair(t)
	kp2 := mustCreateKeyPair(t)
	pk2, _ := kp2.PublicKey()

	ua := UserAuth{
		Expires: time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		Pubkey:  pk2,
	}
	// Sign with kp1 but the token claims to be from pk2.
	signed, err := ua.Sign(kp1)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	_, err = signed.IsValid()
	if err == nil {
		t.Error("IsValid() should fail when signature doesn't match pubkey")
	}
}

func TestCreateSignedTokenAndDecodeToken(t *testing.T) {
	kp := mustCreateKeyPair(t)

	token, err := createSignedToken(kp)
	if err != nil {
		t.Fatalf("createSignedToken() error: %v", err)
	}
	if token == "" {
		t.Fatal("createSignedToken() returned empty token")
	}

	// Decode and validate.
	ua, err := decodeToken(token)
	if err != nil {
		t.Fatalf("decodeToken() error: %v", err)
	}

	pk, _ := kp.PublicKey()
	if ua.Pubkey != pk {
		t.Errorf("decoded pubkey = %q, want %q", ua.Pubkey, pk)
	}
	if ua.Sig == "" {
		t.Error("decoded token has empty signature")
	}
	if ua.Expires == "" {
		t.Error("decoded token has empty expires")
	}

	// The decoded token should be valid.
	gotPK, err := ua.IsValid()
	if err != nil {
		t.Fatalf("IsValid() after decode error: %v", err)
	}
	if gotPK != pk {
		t.Errorf("IsValid() pubkey = %q, want %q", gotPK, pk)
	}
}

func TestDecodeTokenInvalidBase64(t *testing.T) {
	_, err := decodeToken("%%%not-base64%%%")
	if err == nil {
		t.Error("decodeToken() should fail for invalid base64")
	}
}

func TestDecodeTokenInvalidJSON(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("not json"))
	_, err := decodeToken(encoded)
	if err == nil {
		t.Error("decodeToken() should fail for invalid JSON")
	}
}

func TestDecodeTokenValidJSON(t *testing.T) {
	ua := UserAuth{
		Expires: "2099-01-01T00:00:00Z",
		Pubkey:  "ATESTKEY",
		Sig:     "dGVzdA==",
	}
	data, _ := json.Marshal(ua)
	token := base64.StdEncoding.EncodeToString(data)

	decoded, err := decodeToken(token)
	if err != nil {
		t.Fatalf("decodeToken() error: %v", err)
	}
	if decoded.Pubkey != "ATESTKEY" {
		t.Errorf("Pubkey = %q, want ATESTKEY", decoded.Pubkey)
	}
	if decoded.Expires != "2099-01-01T00:00:00Z" {
		t.Errorf("Expires = %q", decoded.Expires)
	}
}

func TestSignPreservesOtherFields(t *testing.T) {
	kp := mustCreateKeyPair(t)
	pk, _ := kp.PublicKey()

	expires := time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	ua := UserAuth{
		Expires: expires,
		Pubkey:  pk,
	}

	signed, err := ua.Sign(kp)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Expires != expires {
		t.Errorf("Sign changed Expires: got %q, want %q", signed.Expires, expires)
	}
	if signed.Pubkey != pk {
		t.Errorf("Sign changed Pubkey: got %q, want %q", signed.Pubkey, pk)
	}
}

// signedAt returns a token for kp expiring at exp.
func signedAt(t *testing.T, kp nkeys.KeyPair, exp time.Time) UserAuth {
	t.Helper()
	pk, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	ua, err := UserAuth{Expires: exp.Format(time.RFC3339), Pubkey: pk}.Sign(kp)
	if err != nil {
		t.Fatal(err)
	}
	return ua
}

// TestUserAuthIsValidExpiryCap: SEC.0. The token is a signature over its
// expiry, which a compromised bus can obtain by sending an expiry as its
// connect nonce, so an expiry further out than MaxTokenExpiry is refused.
func TestUserAuthIsValidExpiryCap(t *testing.T) {
	kp := mustCreateKeyPair(t)
	pk, _ := kp.PublicKey()
	// RFC3339 carries whole seconds, so work from a whole second.
	now := time.Now().Truncate(time.Second)

	cases := []struct {
		name    string
		exp     time.Time
		wantErr error
	}{
		{"fresh token", now.Add(TokenLifetime), nil},
		{"at the cap", now.Add(MaxTokenExpiry), nil},
		{"one second past the cap", now.Add(MaxTokenExpiry + time.Second), ErrInvalidToken},
		{"one minute past the cap", now.Add(MaxTokenExpiry + time.Minute), ErrInvalidToken},
		{"far future", time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), ErrInvalidToken},
		{"expires now", now, nil},
		{"expired one second ago", now.Add(-time.Second), ErrExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := signedAt(t, kp, tc.exp).isValidAt(now)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("isValidAt = %q, %v; want error %v", got, err, tc.wantErr)
			}
			if tc.wantErr == nil && got != pk {
				t.Fatalf("isValidAt returned %q, want %q", got, pk)
			}
		})
	}
}

// TestUserAuthIsValidFarFutureRefused goes through the exported IsValid
// with the timestamp from the regression scenario.
func TestUserAuthIsValidFarFutureRefused(t *testing.T) {
	kp := mustCreateKeyPair(t)
	ua := signedAt(t, kp, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if ua.Expires != "2099-01-01T00:00:00Z" {
		t.Fatalf("Expires = %q", ua.Expires)
	}
	_, err := ua.IsValid()
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("IsValid = %v, want ErrInvalidToken", err)
	}
	// Generic: the error says neither the expiry nor the limit.
	if msg := err.Error(); strings.Contains(msg, "2099") || strings.Contains(msg, "minute") || strings.Contains(msg, "future") {
		t.Errorf("error is not generic: %q", msg)
	}
}

// TestCreateSignedTokenWithinCap: the only token creator (NewToken, via
// createSignedToken) must ask for no more than IsValid accepts, with room
// for the CLI's clock to run ahead.
func TestCreateSignedTokenWithinCap(t *testing.T) {
	if TokenLifetime > MaxTokenExpiry-TokenClockSkew {
		t.Fatalf("TokenLifetime %v leaves no clock skew room under MaxTokenExpiry %v", TokenLifetime, MaxTokenExpiry)
	}
	kp := mustCreateKeyPair(t)
	before := time.Now().Truncate(time.Second)
	token, err := createSignedToken(kp)
	if err != nil {
		t.Fatal(err)
	}
	ua, err := decodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := time.Parse(time.RFC3339, ua.Expires)
	if err != nil {
		t.Fatal(err)
	}
	if exp.After(time.Now().Add(TokenLifetime)) || exp.Before(before.Add(TokenLifetime)) {
		t.Fatalf("token expires %v, want about now + %v", exp, TokenLifetime)
	}
	// Farmer checks it at the moment it was created by a CLI clock
	// running exactly TokenClockSkew ahead: accepted.
	farmerNow := exp.Add(-TokenLifetime - TokenClockSkew)
	if _, err := ua.isValidAt(farmerNow); err != nil {
		t.Fatalf("token from a clock %v ahead refused: %v", TokenClockSkew, err)
	}
	// From a CLI clock one second further ahead: refused.
	if _, err := ua.isValidAt(farmerNow.Add(-time.Second)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("token from a clock more than %v ahead: got %v, want ErrInvalidToken", TokenClockSkew, err)
	}
}
