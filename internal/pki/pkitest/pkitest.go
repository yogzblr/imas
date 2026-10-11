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
	"testing"

	"github.com/yogzblr/imas/internal/pki/natskeys"
	"github.com/yogzblr/imas/internal/pki/natskeys/natskeystest"
)

// Transit is a running fake Transit and a store signing through it.
type Transit struct {
	Fake  *natskeystest.Fake
	Store *natskeys.TransitKeyStore
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
