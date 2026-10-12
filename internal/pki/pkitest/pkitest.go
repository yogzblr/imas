// Package pkitest gives tests a natskeys.KeyStore without OpenBao: a
// natskeys.TransitKeyStore over the in-process fake Transit
// (natskeystest), with the three platform keys (operator, operator
// signing, SYS account) already created (P21 slice 1 brief §1.1, §2.7).
//
// It imports neither internal/pki nor anything that does, so pki's own
// tests can use it too.
package pkitest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki/natskeys"
	"github.com/yogzblr/imas/internal/pki/natskeys/natskeystest"
)

// Transit is a running fake Transit and a store signing through it.
type Transit struct {
	Fake  *natskeystest.Fake
	Store *natskeys.TransitKeyStore
	// TrustDir is the trust directory Farmer wrote; empty after New.
	TrustDir string
}

// New starts a fake Transit, creates the platform keys in it and builds
// a store over it as the farmer's identity (IMAS_NATSSIGN_*). It sets
// environment variables with t.Setenv, so t must not be parallel. The
// store is closed and the fake stopped when t ends.
func New(t testing.TB) *Transit {
	t.Helper()
	f := natskeystest.New(t)
	for _, name := range []string{
		natskeys.OperatorKey(),
		natskeys.OperatorSigningKey(),
		natskeys.SysAccountKey(),
	} {
		f.NewKey(name)
	}
	f.SetEnv(t, natskeys.EnvPrefixSign)
	cfg, err := natskeys.ConfigFromEnv(natskeys.EnvPrefixSign, os.Getenv)
	if err != nil {
		t.Fatalf("pkitest: %v", err)
	}
	s, err := natskeys.NewTransitKeyStore(cfg)
	if err != nil {
		t.Fatalf("pkitest: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return &Transit{Fake: f, Store: s}
}

// Environment the farmer reads its NATS trust and user seeds from; the
// values internal/pki uses (pki.NATSTrustDirEnv and its external seed
// convention), spelled out because this package cannot import pki.
const (
	envTrustDir            = "IMAS_NATS_TRUST_DIR"
	envSysUserSeedFile     = "IMAS_NATS_SYS_USER_SEED_FILE"
	envSaaSAPIUserSeedFile = "IMAS_NATS_SAASAPI_USER_SEED_FILE"
)

// Farmer is New plus everything else the farmer's NATS signing needs in
// a test: the public trust directory the bootstrap Job would have
// written (operator JWT signed by nats-operator, SYS account JWT signed
// by nats-operator-signing) under IMAS_NATS_TRUST_DIR, and SYS_USER and
// SAASAPI_USER seed files under IMAS_NATS_SYS_USER_SEED_FILE and
// IMAS_NATS_SAASAPI_USER_SEED_FILE: farmer requires both and generates
// neither. internal/pki finds the
// fake through the IMAS_NATSSIGN_* variables New sets. The fake's
// counters are reset after the trust is minted.
func Farmer(t testing.TB) *Transit {
	t.Helper()
	tr := New(t)
	dir := t.TempDir()
	tr.TrustDir = dir
	tr.WriteTrust(t)
	t.Setenv(envTrustDir, dir)

	for env, file := range map[string]string{
		envSysUserSeedFile:     "sys-user.nk",
		envSaaSAPIUserSeedFile: "saasapi-user.nk",
	} {
		user, err := nkeys.CreateUser()
		if err != nil {
			t.Fatalf("pkitest: %v", err)
		}
		seed, err := user.Seed()
		if err != nil {
			t.Fatalf("pkitest: %v", err)
		}
		seedFile := filepath.Join(t.TempDir(), file)
		if err := os.WriteFile(seedFile, seed, 0o600); err != nil {
			t.Fatalf("pkitest: %v", err)
		}
		t.Setenv(env, seedFile)
	}
	tr.Fake.ResetCounts()
	return tr
}

// WriteTrust (re)writes TrustDir from the platform keys as they are in
// the fake now, as the bootstrap Job does on a first install.
func (tr *Transit) WriteTrust(t testing.TB) {
	t.Helper()
	ctx := t.Context()
	pair := func(name string, prefix natskeys.Prefix) (nkeys.KeyPair, string) {
		kp, err := tr.Store.KeyPair(ctx, name, prefix)
		if err != nil {
			t.Fatalf("pkitest: %s: %v", name, err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			t.Fatalf("pkitest: %s: %v", name, err)
		}
		return kp, pub
	}
	opKP, opPub := pair(natskeys.OperatorKey(), nkeys.PrefixByteOperator)
	signKP, signPub := pair(natskeys.OperatorSigningKey(), nkeys.PrefixByteOperator)
	_, sysPub := pair(natskeys.SysAccountKey(), nkeys.PrefixByteAccount)

	oc := jwt.NewOperatorClaims(opPub)
	oc.Name = "imas-operator"
	oc.SystemAccount = sysPub
	oc.SigningKeys.Add(signPub)
	opJWT, err := oc.Encode(opKP)
	if err != nil {
		t.Fatalf("pkitest: operator jwt: %v", err)
	}
	ac := jwt.NewAccountClaims(sysPub)
	ac.Name = "SYS"
	sysJWT, err := ac.Encode(signKP)
	if err != nil {
		t.Fatalf("pkitest: sys account jwt: %v", err)
	}
	for name, v := range map[string]string{
		"operator.jwt":         opJWT,
		"operator.pub":         opPub,
		"operator-signing.pub": signPub,
		"sys-account.pub":      sysPub,
		"sys-account.jwt":      sysJWT,
	} {
		if err := os.WriteFile(filepath.Join(tr.TrustDir, name), []byte(v), 0o644); err != nil {
			t.Fatalf("pkitest: %v", err)
		}
	}
}

// Seed returns key name's current private key as an NKey seed with
// prefix: what a test hands a component that still takes seeds (the
// DMZ bus until it reads the trust directory) so it shares the fake's
// keys.
func (tr *Transit) Seed(t testing.TB, name string, prefix natskeys.Prefix) []byte {
	t.Helper()
	var priv []byte
	for v := 1; ; v++ {
		p := tr.Fake.PrivateKey(name, v)
		if p == nil {
			break
		}
		priv = p.Seed()
	}
	if priv == nil {
		t.Fatalf("pkitest: no key %s in the fake", name)
	}
	seed, err := nkeys.EncodeSeed(prefix, priv)
	if err != nil {
		t.Fatalf("pkitest: %v", err)
	}
	return seed
}
