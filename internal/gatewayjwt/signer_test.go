package gatewayjwt

import (
	"errors"
	"testing"
)

func TestNewGatewaySigner_MissingAddr(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "")
	if _, err := NewGatewaySigner("imas-gateway-jwt"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestNewGatewaySigner_MissingToken(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:1")
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, "")
	if _, err := NewGatewaySigner("imas-gateway-jwt"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestNewGatewaySigner_UnknownAuthMethod(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:1")
	t.Setenv(EnvOpenBaoAuthMethod, "carrier-pigeon")
	if _, err := NewGatewaySigner("imas-gateway-jwt"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestNewGatewaySigner_EmptyKeyName(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:1")
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, "x")
	if _, err := NewGatewaySigner(""); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestGatewaySigner_Sign_WrongTokenRejected(t *testing.T) {
	srv := newMockTransitServer(t, "imas-gateway-jwt", 1)
	ts := srv.start()
	t.Cleanup(ts.Close)
	t.Setenv(EnvOpenBaoAddr, ts.URL)
	t.Setenv(EnvOpenBaoTransitMount, srv.mount)
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, "not-the-real-token")

	signer, err := NewGatewaySigner(srv.keyName)
	if err != nil {
		t.Fatalf("NewGatewaySigner: %v", err)
	}
	if _, _, err := signer.Sign(t.Context(), []byte("hello")); err == nil {
		t.Fatal("expected Sign to fail with a wrong bearer token")
	}
}

func TestGatewaySigner_PublicKeys_CachesWithinTTL(t *testing.T) {
	srv := newMockTransitServer(t, "imas-gateway-jwt", 1)
	signer := newTestGatewaySigner(t, srv)
	ctx := t.Context()

	first, err := signer.PublicKeys(ctx)
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}

	// Add a second key version directly to the mock's backing state and
	// confirm the cached call doesn't see it yet (still within the TTL).
	srv.versions = append(srv.versions, srv.versions[0])
	second, err := signer.PublicKeys(ctx)
	if err != nil {
		t.Fatalf("PublicKeys (cached): %v", err)
	}
	if len(second) != len(first) {
		t.Errorf("expected cached PublicKeys to still return %d key(s), got %d", len(first), len(second))
	}
}

func TestGatewaySigner_PublicKeys_FiltersBelowMinEncryptionVersion(t *testing.T) {
	srv := newMockTransitServer(t, "imas-gateway-jwt", 3)
	srv.minEncryptionVersion = 2 // version 1 has aged out of the serving window
	signer := newTestGatewaySigner(t, srv)

	keys, err := signer.PublicKeys(t.Context())
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys (versions 2 and 3), got %d", len(keys))
	}
	for _, k := range keys {
		if k.Version < 2 {
			t.Errorf("expected no key below version 2, got version %d", k.Version)
		}
	}
}
