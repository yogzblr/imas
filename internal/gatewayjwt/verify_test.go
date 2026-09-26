package gatewayjwt

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestVerifyGatewayJWT_AcceptsMintedToken(t *testing.T) {
	srv := newMockTransitServer(t, "imas-gateway-jwt", 1)
	signer := newTestGatewaySigner(t, srv)
	ctx := t.Context()

	want := GatewayClaims{
		Subject:  "UABCDEF1234567890",
		TenantID: "t_test",
		SproutID: "web-01",
		Expiry:   time.Now().Add(time.Hour).Truncate(time.Second),
	}
	token, err := signer.MintGatewayJWT(ctx, want)
	if err != nil {
		t.Fatalf("MintGatewayJWT: %v", err)
	}

	got, err := signer.VerifyGatewayJWT(ctx, token)
	if err != nil {
		t.Fatalf("VerifyGatewayJWT: %v", err)
	}
	if got.Subject != want.Subject || got.TenantID != want.TenantID || got.SproutID != want.SproutID {
		t.Errorf("claims: got %+v, want %+v", got, want)
	}
	if !got.Expiry.Equal(want.Expiry) {
		t.Errorf("expiry: got %v, want %v", got.Expiry, want.Expiry)
	}
}

func TestVerifyGatewayJWT_RejectsTamperedToken(t *testing.T) {
	srv := newMockTransitServer(t, "imas-gateway-jwt", 1)
	signer := newTestGatewaySigner(t, srv)
	token, err := signer.MintGatewayJWT(t.Context(), GatewayClaims{
		Subject: "UABC", TenantID: "t_test", SproutID: "web-01", Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("MintGatewayJWT: %v", err)
	}
	tampered := token[:len(token)-4] + "AAAA"
	if _, err := signer.VerifyGatewayJWT(t.Context(), tampered); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered token: got err %v, want ErrInvalidToken", err)
	}
}

// staticKeys is a PublicKeySource over fixed in-memory key versions.
type staticKeys []TransitKeyVersion

func (s staticKeys) PublicKeys(context.Context) ([]TransitKeyVersion, error) { return s, nil }

// signRaw signs claims with priv directly (no Transit), giving each test
// full control over the header and claim set.
func signRaw(t *testing.T, priv ed25519.PrivateKey, kid string, build func(*jwt.Builder) *jwt.Builder) string {
	t.Helper()
	tok, err := build(jwt.NewBuilder()).Build()
	if err != nil {
		t.Fatalf("building token: %v", err)
	}
	hdrs := jws.NewHeaders()
	if kid != "" {
		if err := hdrs.Set(jws.KeyIDKey, kid); err != nil {
			t.Fatal(err)
		}
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return string(signed)
}

func validClaims(b *jwt.Builder) *jwt.Builder {
	return b.Subject("UABC").
		Issuer(GatewayIssuer).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("tenant_id", "t_test").
		Claim("sprout_id", "web-01")
}

func TestVerifyGatewayJWT_Rejections(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := staticKeys{{Version: 1, PublicKey: pub}}
	kid := strconv.Itoa(1)

	// Sanity: the baseline token verifies, so each rejection below is
	// down to the one thing it changes.
	if _, err := VerifyGatewayJWT(t.Context(), keys, signRaw(t, priv, kid, validClaims)); err != nil {
		t.Fatalf("baseline token rejected: %v", err)
	}

	cases := map[string]string{
		"signed by another key": signRaw(t, otherPriv, kid, validClaims),
		"unknown kid":           signRaw(t, priv, "2", validClaims),
		"no kid":                signRaw(t, priv, "", validClaims),
		"expired": signRaw(t, priv, kid, func(b *jwt.Builder) *jwt.Builder {
			return validClaims(b).Expiration(time.Now().Add(-time.Hour))
		}),
		"no exp": signRaw(t, priv, kid, func(b *jwt.Builder) *jwt.Builder {
			return b.Subject("UABC").Issuer(GatewayIssuer).
				Claim("tenant_id", "t_test").Claim("sprout_id", "web-01")
		}),
		"wrong issuer": signRaw(t, priv, kid, func(b *jwt.Builder) *jwt.Builder {
			return validClaims(b).Issuer("t_test")
		}),
		"no sprout_id": signRaw(t, priv, kid, func(b *jwt.Builder) *jwt.Builder {
			return validClaims(b).Claim("sprout_id", "")
		}),
		"no tenant_id": signRaw(t, priv, kid, func(b *jwt.Builder) *jwt.Builder {
			return b.Subject("UABC").Issuer(GatewayIssuer).
				Expiration(time.Now().Add(time.Hour)).Claim("sprout_id", "web-01")
		}),
		"non-string sprout_id": signRaw(t, priv, kid, func(b *jwt.Builder) *jwt.Builder {
			return validClaims(b).Claim("sprout_id", 42)
		}),
		// The native NATS User JWT's header alg, which is exactly what
		// Envoy can't verify and farmer must not accept here either.
		"ed25519-nkey alg": "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ." +
			strings.Split(signRaw(t, priv, kid, validClaims), ".")[1] + ".AAAA",
		"garbage": "not-a-jwt",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyGatewayJWT(t.Context(), keys, token); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("got err %v, want ErrInvalidToken", err)
			}
		})
	}
}

func TestVerifyGatewayJWT_NoKeysFailsClosed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := signRaw(t, priv, "1", validClaims)
	if _, err := VerifyGatewayJWT(t.Context(), staticKeys{}, token); err == nil {
		t.Error("empty key set: expected an error")
	}
	if _, err := VerifyGatewayJWT(t.Context(), nil, token); err == nil {
		t.Error("nil key source: expected an error")
	}
}
