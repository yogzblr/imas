package natskeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/openbao"
	"github.com/yogzblr/imas/internal/pki/natskeys/natskeystest"
)

// newStore builds a store over f, configured through ConfigFromEnv as
// production does. mod, if not nil, adjusts the Config. Backoff is cut
// to a millisecond so retry tests stay fast.
func newStore(t *testing.T, f *natskeystest.Fake, mod func(*Config)) *TransitKeyStore {
	t.Helper()
	f.SetEnv(t, EnvPrefixSign)
	cfg, err := ConfigFromEnv(EnvPrefixSign, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := NewTransitKeyStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustPair(t *testing.T, s *TransitKeyStore, name string, prefix Prefix) nkeys.KeyPair {
	t.Helper()
	kp, err := s.KeyPair(t.Context(), name, prefix)
	if err != nil {
		t.Fatalf("KeyPair(%s): %v", name, err)
	}
	return kp
}

func TestKeyPairImplementsNKeys(t *testing.T) {
	f := natskeystest.New(t)
	s := newStore(t, f, nil)
	for _, tc := range []struct {
		name   string
		prefix Prefix
		valid  func(string) bool
	}{
		{OperatorSigningKey(), nkeys.PrefixByteOperator, nkeys.IsValidPublicOperatorKey},
		{SysAccountKey(), nkeys.PrefixByteAccount, nkeys.IsValidPublicAccountKey},
	} {
		f.NewKey(tc.name)
		kp := mustPair(t, s, tc.name, tc.prefix)
		pub, err := kp.PublicKey()
		if err != nil || !tc.valid(pub) {
			t.Fatalf("%s: PublicKey() = %q, %v", tc.name, pub, err)
		}
		msg := []byte("hello")
		sig, err := kp.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := kp.Verify(msg, sig); err != nil {
			t.Errorf("%s: Verify of own signature: %v", tc.name, err)
		}
		if err := kp.Verify([]byte("other"), sig); !errors.Is(err, nkeys.ErrInvalidSignature) {
			t.Errorf("%s: Verify of wrong message = %v", tc.name, err)
		}
		// Verify is local: no request for it.
		before := f.Count(natskeystest.OpSign) + f.Count(natskeystest.OpReadKey)
		_ = kp.Verify(msg, sig)
		if after := f.Count(natskeystest.OpSign) + f.Count(natskeystest.OpReadKey); after != before {
			t.Errorf("Verify sent %d requests", after-before)
		}
		// The public key of a pair from nkeys.FromPublicKey verifies too.
		pubOnly, _ := nkeys.FromPublicKey(pub)
		if err := pubOnly.Verify(msg, sig); err != nil {
			t.Errorf("%s: nkeys.FromPublicKey verify: %v", tc.name, err)
		}
		if _, err := kp.Seed(); !errors.Is(err, nkeys.ErrPublicKeyOnly) {
			t.Errorf("Seed() err = %v", err)
		}
		if _, err := kp.PrivateKey(); !errors.Is(err, nkeys.ErrPublicKeyOnly) {
			t.Errorf("PrivateKey() err = %v", err)
		}
		if _, err := kp.Seal(nil, ""); !errors.Is(err, nkeys.ErrInvalidNKeyOperation) {
			t.Errorf("Seal() err = %v", err)
		}
		if _, err := kp.SealWithRand(nil, "", nil); !errors.Is(err, nkeys.ErrInvalidNKeyOperation) {
			t.Errorf("SealWithRand() err = %v", err)
		}
		if _, err := kp.Open(nil, ""); !errors.Is(err, nkeys.ErrInvalidNKeyOperation) {
			t.Errorf("Open() err = %v", err)
		}
		kp.Wipe()
		if _, ok := kp.(ContextSigner); !ok {
			t.Error("pair does not implement ContextSigner")
		}
	}
	if _, err := s.KeyPair(t.Context(), SysAccountKey(), nkeys.PrefixByteUser); err == nil {
		t.Error("KeyPair with a user prefix: want an error")
	}
	for _, bad := range []string{"", "a/b", "../x", "nats-operator/config", strings.Repeat("a", 256)} {
		if _, err := s.KeyPair(t.Context(), bad, nkeys.PrefixByteAccount); err == nil || errors.Is(err, ErrKeyNotFound) {
			t.Errorf("KeyPair(%q) = %v, want an invalid-name error", bad, err)
		}
		if err := s.RetireKey(t.Context(), bad); err == nil {
			t.Errorf("RetireKey(%q): want an error", bad)
		}
	}
}

func TestPublicKeyEncodingMatchesLocalNKey(t *testing.T) {
	f := natskeystest.New(t)
	s := newStore(t, f, nil)
	for _, prefix := range []Prefix{nkeys.PrefixByteOperator, nkeys.PrefixByteAccount} {
		var seed [ed25519.SeedSize]byte
		rand.Read(seed[:])
		local, err := nkeys.FromRawSeed(prefix, seed[:])
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("k-%c", prefix.String()[0])
		f.PutPrivateKey(name, natskeystest.KeyOptions{}, ed25519.NewKeyFromSeed(seed[:]))
		kp := mustPair(t, s, name, prefix)
		got, _ := kp.PublicKey()
		want, _ := local.PublicKey()
		if got != want {
			t.Fatalf("%v: transit pair public key %s, local NKey %s", prefix, got, want)
		}
		// Ed25519 is deterministic: both pairs give the same signature.
		msg := []byte("header.payload")
		viaTransit, err := kp.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		viaLocal, _ := local.Sign(msg)
		if string(viaTransit) != string(viaLocal) {
			t.Errorf("%v: signatures differ", prefix)
		}
	}
}

// realTransitSignInput is the message internal/gatewayjwt's captured
// transit-sign-v*.json signed (internal/gatewayjwt/openbao_response_test.go).
const realTransitSignInput = "imas gatewayjwt fixture: signed by OpenBao v2.7.0 Transit"

const realTransitDir = "../../gatewayjwt/testdata/openbao-v2.7.0"

func TestSignIsRawEd25519OverJWTInput(t *testing.T) {
	f := natskeystest.New(t)
	s := newStore(t, f, nil)
	pub := f.NewKey(OperatorSigningKey())
	kp := mustPair(t, s, OperatorSigningKey(), nkeys.PrefixByteOperator)
	accountKP, _ := nkeys.CreateAccount()
	accountPub, _ := accountKP.PublicKey()
	token, err := jwt.NewAccountClaims(accountPub).Encode(kp)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %s", token)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature segment: %d bytes, %v", len(sig), err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("JWT signature is not Ed25519 over header.payload under the Transit key")
	}
	ac, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		t.Fatalf("jwt/v2 rejects the Transit-signed JWT: %v", err)
	}
	if issuer, _ := kp.PublicKey(); ac.Issuer != issuer {
		t.Errorf("issuer %s, want %s", ac.Issuer, issuer)
	}

	// The same parsing over real OpenBao responses: the captured key
	// read passes the hardening checks, and the captured signatures
	// verify under it.
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(realTransitDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var keys struct {
		Data keyInfo `json:"data"`
	}
	if err := json.Unmarshal(read("transit-keys.json"), &keys); err != nil {
		t.Fatal(err)
	}
	if _, _, err := keys.Data.publicKey("fixture"); err != nil {
		t.Fatalf("captured key read fails the checks: %v", err)
	}
	for _, v := range []int{1, 2} {
		var sr struct {
			Data struct {
				Signature string `json:"signature"`
			} `json:"data"`
		}
		if err := json.Unmarshal(read(fmt.Sprintf("transit-sign-v%d.json", v)), &sr); err != nil {
			t.Fatal(err)
		}
		info := keys.Data
		info.LatestVersion = v
		_, pub, err := info.publicKey("fixture")
		if err != nil {
			t.Fatal(err)
		}
		job := &signJob{pub: pub, input: []byte(realTransitSignInput)}
		if _, err := checkSignature(groupKey{name: "fixture", version: v}, job, sr.Data.Signature); err != nil {
			t.Errorf("captured v%d signature: %v", v, err)
		}
		if _, err := checkSignature(groupKey{name: "fixture", version: 3 - v}, job, sr.Data.Signature); !errors.Is(err, ErrBadSignature) {
			t.Errorf("captured v%d signature checked as the other version: %v", v, err)
		}
	}
}

func TestKeyVersionPinned(t *testing.T) {
	f := natskeystest.New(t)
	s := newStore(t, f, nil)
	name := OperatorSigningKey()
	v1 := f.NewKey(name)
	kp := mustPair(t, s, name, nkeys.PrefixByteOperator)
	v2 := f.Rotate(name)

	sig, err := kp.Sign([]byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(v1, []byte("m"), sig) || ed25519.Verify(v2, []byte("m"), sig) {
		t.Fatal("pair loaded at v1 did not sign with v1 after a rotation")
	}

	// A fresh load picks up v2, a different identity.
	kp2 := mustPair(t, s, name, nkeys.PrefixByteOperator)
	p1, _ := kp.PublicKey()
	p2, _ := kp2.PublicKey()
	if p1 == p2 {
		t.Fatal("reload after rotation kept the v1 public key")
	}
	if sig, err := kp2.Sign([]byte("m")); err != nil || !ed25519.Verify(v2, []byte("m"), sig) {
		t.Fatalf("v2 pair: %v", err)
	}

	// A signature labelled with another version is refused, even if its
	// bytes would verify.
	f.SetMutateSignature(func(_ string, _ int, _ []byte, sig string) string {
		return strings.Replace(sig, "vault:v1:", "vault:v2:", 1)
	})
	if _, err := kp.Sign([]byte("m")); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("mismatched version prefix: err = %v, want ErrBadSignature", err)
	}
}

func TestBatchingGroupsByKey(t *testing.T) {
	f := natskeystest.New(t)
	gate := make(chan struct{})
	f.SetSignGate(gate)
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	s := newStore(t, f, func(c *Config) { c.Workers = 1 })
	a, b := TenantSigningKey("a"), TenantSigningKey("b")
	pubA, pubB := f.NewKey(a), f.NewKey(b)
	kpA := mustPair(t, s, a, nkeys.PrefixByteAccount)
	kpB := mustPair(t, s, b, nkeys.PrefixByteAccount)
	f.SetItemError(func(input []byte) string {
		if string(input) == "bad" {
			return "injected item error"
		}
		return ""
	})

	type res struct {
		pub   ed25519.PublicKey
		input string
		sig   []byte
		err   error
	}
	results := make(chan res, 64)
	sign := func(kp nkeys.KeyPair, pub ed25519.PublicKey, input string) {
		sig, err := kp.Sign([]byte(input))
		results <- res{pub, input, sig, err}
	}

	// The first sign holds the only worker inside the fake...
	go sign(kpA, pubA, "first")
	waitFor(t, func() bool { return f.Count(natskeystest.OpSign) == 1 })
	// ...while 30 more queue up behind it.
	const nA, nB = 20, 10
	for i := range nA {
		input := fmt.Sprintf("a-%d", i)
		if i == 7 {
			input = "bad"
		}
		go sign(kpA, pubA, input)
	}
	for i := range nB {
		go sign(kpB, pubB, fmt.Sprintf("b-%d", i))
	}
	waitFor(t, func() bool { return len(s.d.queue) == nA+nB })
	release()

	for range 1 + nA + nB {
		r := <-results
		if r.input == "bad" {
			if !errors.Is(r.err, ErrSignFailed) || !strings.Contains(r.err.Error(), "injected item error") {
				t.Errorf("bad item: err = %v, want ErrSignFailed with the item's message", r.err)
			}
			continue
		}
		if r.err != nil {
			t.Errorf("%s: %v", r.input, r.err)
			continue
		}
		if !ed25519.Verify(r.pub, []byte(r.input), r.sig) {
			t.Errorf("%s: signature does not verify under its own key", r.input)
		}
	}
	// One plain request, then one batch per key.
	if got := f.Count(natskeystest.OpSign); got != 3 {
		t.Errorf("sign requests = %d, want 3 (1 plain + 1 batch per key)", got)
	}
	if got := f.Count(natskeystest.OpBatch); got != 2 {
		t.Errorf("batch requests = %d, want 2", got)
	}

	// An HTTP-level failure fails the whole batch.
	f.ResetCounts()
	gate2 := make(chan struct{})
	f.SetSignGate(gate2)
	t.Cleanup(func() {
		select {
		case <-gate2:
		default:
			close(gate2)
		}
	})
	go sign(kpA, pubA, "hold")
	waitFor(t, func() bool { return f.Count(natskeystest.OpSign) == 1 })
	f.FailNext(natskeystest.OpSign, 400, 1)
	for i := range 5 {
		go sign(kpA, pubA, fmt.Sprintf("x-%d", i))
	}
	waitFor(t, func() bool { return len(s.d.queue) == 5 })
	close(gate2)
	failed := 0
	for range 6 {
		if r := <-results; r.err != nil {
			if !errors.Is(r.err, ErrSignFailed) {
				t.Errorf("%s: err = %v, want ErrSignFailed", r.input, r.err)
			}
			failed++
		}
	}
	if failed != 5 {
		t.Errorf("%d signs failed, want the 5 in the failed batch", failed)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for condition")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRetryOnTransient(t *testing.T) {
	f := natskeystest.New(t)
	s := newStore(t, f, nil)
	f.NewKey(SysAccountKey())
	kp := mustPair(t, s, SysAccountKey(), nkeys.PrefixByteAccount)
	for _, status := range []int{503, 500, 429, natskeystest.DropConnection} {
		f.ResetCounts()
		f.FailNext(natskeystest.OpSign, status, 2)
		if _, err := kp.Sign([]byte("m")); err != nil {
			t.Errorf("status %d twice then success: %v", status, err)
		}
		if got := f.Count(natskeystest.OpSign); got != 3 {
			t.Errorf("status %d: %d requests, want 3", status, got)
		}
	}
	f.ResetCounts()
	f.FailNext(natskeystest.OpSign, 503, 5)
	if _, err := kp.Sign([]byte("m")); !errors.Is(err, ErrSignFailed) || openbao.StatusCode(err) != 503 {
		t.Errorf("503 every time: err = %v, want ErrSignFailed with status 503", err)
	}
	if got := f.Count(natskeystest.OpSign); got != maxAttempts {
		t.Errorf("503 every time: %d requests, want %d", got, maxAttempts)
	}
	// Key reads retry the same way.
	f.ResetCounts()
	f.FailNext(natskeystest.OpReadKey, 502, 2)
	mustPair(t, s, SysAccountKey(), nkeys.PrefixByteAccount)
	if got := f.Count(natskeystest.OpReadKey); got != 3 {
		t.Errorf("read: %d requests, want 3", got)
	}
}

func TestRetryNever400and404(t *testing.T) {
	f := natskeystest.New(t)
	s := newStore(t, f, nil)
	f.NewKey(SysAccountKey())
	kp := mustPair(t, s, SysAccountKey(), nkeys.PrefixByteAccount)
	for _, status := range []int{400, 404} {
		f.ResetCounts()
		f.FailNext(natskeystest.OpSign, status, 5)
		if _, err := kp.Sign([]byte("m")); !errors.Is(err, ErrSignFailed) {
			t.Errorf("status %d: err = %v, want ErrSignFailed", status, err)
		}
		if got := f.Count(natskeystest.OpSign); got != 1 {
			t.Errorf("status %d: %d requests, want 1", status, got)
		}
	}
	f.ResetCounts()
	if _, err := s.KeyPair(t.Context(), "nats-missing", nkeys.PrefixByteAccount); !errors.Is(err, ErrKeyNotFound) || !openbao.IsNotFound(err) {
		t.Errorf("missing key: err = %v, want ErrKeyNotFound wrapping a 404", err)
	}
	if got := f.Count(natskeystest.OpReadKey); got != 1 {
		t.Errorf("missing key: %d reads, want 1", got)
	}
}

func TestReloginOn403Once(t *testing.T) {
	f := natskeystest.New(t)
	f.EnableKubernetes("natssign")
	jwtPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtPath, []byte("sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.SetEnv(t, EnvPrefixSign)
	t.Setenv(EnvPrefixSign+EnvOpenBaoAuthMethod, openbao.AuthMethodKubernetes)
	t.Setenv(EnvPrefixSign+EnvOpenBaoK8sRole, "natssign")
	t.Setenv(EnvPrefixSign+EnvOpenBaoK8sJWTPath, jwtPath)
	cfg, err := ConfigFromEnv(EnvPrefixSign, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewTransitKeyStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.backoff = []time.Duration{time.Millisecond}

	f.NewKey(SysAccountKey())
	kp := mustPair(t, s, SysAccountKey(), nkeys.PrefixByteAccount)
	if got := f.Count(natskeystest.OpLogin); got != 1 {
		t.Fatalf("logins = %d, want 1", got)
	}
	// The cached token stops working: one 403, a fresh login, success.
	f.RevokeLoginTokens()
	if _, err := kp.Sign([]byte("m")); err != nil {
		t.Fatalf("sign after token revocation: %v", err)
	}
	if got := f.Count(natskeystest.OpLogin); got != 2 {
		t.Errorf("logins = %d, want 2", got)
	}
	// A 403 that survives the re-login is final.
	f.ResetCounts()
	f.FailNext(natskeystest.OpSign, 403, 5)
	if _, err := kp.Sign([]byte("m")); !errors.Is(err, ErrSignFailed) || openbao.StatusCode(err) != 403 {
		t.Errorf("persistent 403: err = %v, want ErrSignFailed with status 403", err)
	}
	if got, logins := f.Count(natskeystest.OpSign), f.Count(natskeystest.OpLogin); got != 2 || logins != 1 {
		t.Errorf("persistent 403: %d signs and %d logins, want 2 and 1", got, logins)
	}

	// With token auth there is nothing to re-login: a 403 is final at once.
	ts := newStore(t, f, nil)
	tkp := mustPair(t, ts, SysAccountKey(), nkeys.PrefixByteAccount)
	f.ResetCounts()
	f.FailNext(natskeystest.OpSign, 403, 5)
	if _, err := tkp.Sign([]byte("m")); !errors.Is(err, ErrSignFailed) {
		t.Errorf("token auth 403: err = %v", err)
	}
	if got := f.Count(natskeystest.OpSign); got != 1 {
		t.Errorf("token auth 403: %d requests, want 1", got)
	}
}

func TestRejectsBadSignature(t *testing.T) {
	f := natskeystest.New(t)
	s := newStore(t, f, nil)
	f.NewKey(OperatorSigningKey())
	kp := mustPair(t, s, OperatorSigningKey(), nkeys.PrefixByteOperator)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for name, mutate := range map[string]func(int, []byte, string) string{
		"another key's signature": func(v int, in []byte, _ string) string {
			return fmt.Sprintf("vault:v%d:%s", v, base64.StdEncoding.EncodeToString(ed25519.Sign(other, in)))
		},
		"short signature": func(v int, _ []byte, _ string) string {
			return fmt.Sprintf("vault:v%d:%s", v, base64.StdEncoding.EncodeToString(make([]byte, 63)))
		},
		"not base64": func(v int, _ []byte, _ string) string { return fmt.Sprintf("vault:v%d:***", v) },
		"no prefix":  func(_ int, _ []byte, sig string) string { return sig[strings.LastIndex(sig, ":")+1:] },
		"empty":      func(int, []byte, string) string { return "" },
	} {
		f.SetMutateSignature(func(_ string, v int, in []byte, sig string) string { return mutate(v, in, sig) })
		if _, err := kp.Sign([]byte("m")); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: err = %v, want ErrBadSignature", name, err)
		}
	}
}

func TestRejectsUnhardenedKeys(t *testing.T) {
	f := natskeystest.New(t)
	s := newStore(t, f, nil)
	for name, tc := range map[string]struct {
		opts natskeystest.KeyOptions
		want error
	}{
		"exportable":             {natskeystest.KeyOptions{Exportable: true}, ErrKeyNotHardened},
		"allow_plaintext_backup": {natskeystest.KeyOptions{AllowPlaintextBackup: true}, ErrKeyNotHardened},
		"imported":               {natskeystest.KeyOptions{ImportedKey: true}, ErrKeyNotHardened},
		"derived":                {natskeystest.KeyOptions{Derived: true}, ErrKeyNotHardened},
		"flags missing":          {natskeystest.KeyOptions{OmitFlags: true}, ErrKeyNotHardened},
		"wrong type":             {natskeystest.KeyOptions{Type: "ecdsa-p256"}, ErrKeyType},
		"soft-deleted":           {natskeystest.KeyOptions{SoftDeleted: true}, ErrKeyRetired},
	} {
		key := "nats-bad-" + strings.NewReplacer(" ", "-", "_", "-").Replace(name)
		f.PutKey(key, tc.opts)
		if _, err := s.KeyPair(t.Context(), key, nkeys.PrefixByteAccount); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
		// EnsureKeyPair never "repairs" a bad key by creating over it.
		if _, err := s.EnsureKeyPair(t.Context(), key, nkeys.PrefixByteAccount); !errors.Is(err, tc.want) {
			t.Errorf("%s: EnsureKeyPair err = %v, want %v", name, err, tc.want)
		}
	}
	if got := f.Count(natskeystest.OpCreateKey); got != 0 {
		t.Errorf("%d creates for existing keys", got)
	}
}

func TestEnsureKeyPairRace(t *testing.T) {
	f := natskeystest.New(t)
	s := newStore(t, f, nil)

	// Created when absent, with hardened parameters.
	kp, err := s.EnsureKeyPair(t.Context(), TenantSigningKey("t1"), nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Count(natskeystest.OpCreateKey); got != 1 {
		t.Fatalf("creates = %d, want 1", got)
	}
	again, err := s.EnsureKeyPair(t.Context(), TenantSigningKey("t1"), nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := kp.PublicKey()
	p2, _ := again.PublicKey()
	if p1 != p2 || f.Count(natskeystest.OpCreateKey) != 1 {
		t.Fatal("second EnsureKeyPair created or changed the key")
	}

	// Lost race: our read saw 404, another farmer created the key, our
	// create is refused (400 or 403); the re-read decides.
	for _, status := range []int{400, 403} {
		name := TenantAccountKey(fmt.Sprintf("race-%d", status))
		pub := f.NewKey(name)
		f.FailNext(natskeystest.OpReadKey, 404, 1)
		f.FailNext(natskeystest.OpCreateKey, status, 1)
		kp, err := s.EnsureKeyPair(t.Context(), name, nkeys.PrefixByteAccount)
		if err != nil {
			t.Fatalf("lost race with %d: %v", status, err)
		}
		want, _ := nkeys.Encode(nkeys.PrefixByteAccount, pub)
		if got, _ := kp.PublicKey(); got != string(want) {
			t.Errorf("lost race with %d: got %s, want the other farmer's key %s", status, got, want)
		}
	}

	// A refused create of a key that still doesn't exist is an error
	// naming both failures.
	f.FailNext(natskeystest.OpCreateKey, 403, 1)
	if _, err := s.EnsureKeyPair(t.Context(), TenantAccountKey("denied"), nkeys.PrefixByteAccount); !errors.Is(err, ErrKeyNotFound) || openbao.StatusCode(err) != 403 {
		t.Errorf("refused create: err = %v", err)
	}

	// Concurrent ensures of one new key agree on it.
	var wg sync.WaitGroup
	pubs := make([]string, 8)
	errs := make([]error, 8)
	for i := range pubs {
		wg.Go(func() {
			kp, err := s.EnsureKeyPair(t.Context(), TenantSigningKey("concurrent"), nkeys.PrefixByteAccount)
			errs[i] = err
			if err == nil {
				pubs[i], _ = kp.PublicKey()
			}
		})
	}
	wg.Wait()
	for i := range pubs {
		if errs[i] != nil || pubs[i] != pubs[0] {
			t.Fatalf("concurrent ensure %d: %s, %v (first %s)", i, pubs[i], errs[i], pubs[0])
		}
	}
}

func TestRetireKeyIdempotent(t *testing.T) {
	f := natskeystest.New(t)
	s := newStore(t, f, nil)
	name := TenantSigningKey("gone")
	f.NewKey(name)
	kp := mustPair(t, s, name, nkeys.PrefixByteAccount)
	if err := s.RetireKey(t.Context(), name); err != nil {
		t.Fatal(err)
	}
	if !f.SoftDeleted(name) || !f.Has(name) {
		t.Fatal("key not soft-deleted (or hard-deleted)")
	}
	if err := s.RetireKey(t.Context(), name); err != nil {
		t.Errorf("second retire: %v", err)
	}
	// A server that refuses the second soft delete is still success.
	f.FailNext(natskeystest.OpSoftDelete, 400, 1)
	if err := s.RetireKey(t.Context(), name); err != nil {
		t.Errorf("retire refused but already soft-deleted: %v", err)
	}
	if err := s.RetireKey(t.Context(), "nats-tsign-never"); err != nil {
		t.Errorf("retire of a missing key: %v", err)
	}
	if _, err := s.KeyPair(t.Context(), name, nkeys.PrefixByteAccount); !errors.Is(err, ErrKeyRetired) {
		t.Errorf("KeyPair after retire: %v, want ErrKeyRetired", err)
	}
	if _, err := kp.Sign([]byte("m")); !errors.Is(err, ErrSignFailed) {
		t.Errorf("sign with a pair loaded before retire: %v, want ErrSignFailed", err)
	}
	// A refused soft delete of a live key is an error.
	live := TenantSigningKey("live")
	f.NewKey(live)
	f.FailNext(natskeystest.OpSoftDelete, 403, 1)
	if err := s.RetireKey(t.Context(), live); err == nil || openbao.StatusCode(err) != 403 {
		t.Errorf("refused retire of a live key: %v", err)
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	if _, err := ConfigFromEnv(EnvPrefixSign, env(nil)); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no ADDR: err = %v, want ErrNotConfigured", err)
	}
	cfg, err := ConfigFromEnv(EnvPrefixSign, env(map[string]string{"IMAS_NATSSIGN_OPENBAO_ADDR": "https://bao:8200"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TransitMount != "transit" || cfg.Timeout != 15*time.Second || cfg.BatchMax != 64 || cfg.Workers != 4 {
		t.Errorf("defaults: %+v", cfg)
	}
	wantEnv := openbao.Env{
		Addr:       "IMAS_NATSSIGN_OPENBAO_ADDR",
		CACert:     "IMAS_NATSSIGN_OPENBAO_CACERT",
		AuthMethod: "IMAS_NATSSIGN_OPENBAO_AUTH_METHOD",
		Token:      "IMAS_NATSSIGN_OPENBAO_TOKEN",
		K8sRole:    "IMAS_NATSSIGN_OPENBAO_K8S_ROLE",
		K8sMount:   "IMAS_NATSSIGN_OPENBAO_K8S_MOUNT",
		K8sJWTPath: "IMAS_NATSSIGN_OPENBAO_K8S_JWT_PATH",
		Namespace:  "IMAS_NATSSIGN_OPENBAO_NAMESPACE",
	}
	if cfg.OpenBao != wantEnv {
		t.Errorf("OpenBao env names = %+v", cfg.OpenBao)
	}
	cfg, err = ConfigFromEnv(EnvPrefixBoot, env(map[string]string{
		"IMAS_NATSBOOT_OPENBAO_ADDR":          "https://bao:8200",
		"IMAS_NATSBOOT_OPENBAO_TRANSIT_MOUNT": "/nats-transit/",
		"IMAS_NATSBOOT_TIMEOUT":               "2s",
		"IMAS_NATSBOOT_BATCH_MAX":             "8",
		"IMAS_NATSBOOT_WORKERS":               "2",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TransitMount != "nats-transit" || cfg.Timeout != 2*time.Second || cfg.BatchMax != 8 || cfg.Workers != 2 ||
		cfg.OpenBao.Token != "IMAS_NATSBOOT_OPENBAO_TOKEN" {
		t.Errorf("overrides: %+v", cfg)
	}
	for k, v := range map[string]string{
		"IMAS_NATSSIGN_TIMEOUT":   "soon",
		"IMAS_NATSSIGN_BATCH_MAX": "0",
		"IMAS_NATSSIGN_WORKERS":   "-1",
	} {
		_, err := ConfigFromEnv(EnvPrefixSign, env(map[string]string{"IMAS_NATSSIGN_OPENBAO_ADDR": "x", k: v}))
		if !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%s=%s: err = %v, want ErrNotConfigured", k, v, err)
		}
	}
	// NewTransitKeyStore needs a token for token auth, read by
	// internal/openbao from the process environment.
	t.Setenv("IMAS_NATSSIGN_OPENBAO_ADDR", "http://127.0.0.1:1")
	t.Setenv("IMAS_NATSSIGN_OPENBAO_TOKEN", "")
	cfg, _ = ConfigFromEnv(EnvPrefixSign, os.Getenv)
	if _, err := NewTransitKeyStore(cfg); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no token: err = %v, want ErrNotConfigured", err)
	}
}

func TestKeyNames(t *testing.T) {
	for got, want := range map[string]string{
		OperatorKey():               "nats-operator",
		OperatorSigningKey():        "nats-operator-signing",
		SysAccountKey():             "nats-sys-account",
		TenantSigningKey("acme_01"): "nats-tsign-acme_01",
		TenantAccountKey("acme_01"): "nats-tacct-acme_01",
	} {
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
		if !keyNameMatcher.MatchString(got) {
			t.Errorf("%s is not a valid key name", got)
		}
	}
	// The longest tenant ID internal/pki accepts (191 characters) still
	// makes a valid key name.
	if long := TenantSigningKey(strings.Repeat("x", 191)); !keyNameMatcher.MatchString(long) {
		t.Error("a 191-character tenant ID makes an invalid key name")
	}
}

func TestSignTimeout(t *testing.T) {
	f := natskeystest.New(t)
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	f.NewKey(SysAccountKey())

	// The store's per-request timeout.
	s := newStore(t, f, func(c *Config) { c.Timeout = 50 * time.Millisecond })
	kp := mustPair(t, s, SysAccountKey(), nkeys.PrefixByteAccount)
	f.SetSignGate(gate)
	start := time.Now()
	_, err := kp.Sign([]byte("m"))
	if !errors.Is(err, ErrSignTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want ErrSignTimeout wrapping context.DeadlineExceeded", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("timed-out sign took %v (retried?)", time.Since(start))
	}

	// The caller's deadline returns early whatever the store allows.
	f.SetSignGate(nil)
	s2 := newStore(t, f, func(c *Config) { c.Timeout = time.Minute })
	kp2 := mustPair(t, s2, SysAccountKey(), nkeys.PrefixByteAccount)
	f.SetSignGate(gate)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := kp2.(ContextSigner).SignContext(ctx, []byte("m")); !errors.Is(err, ErrSignTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("caller deadline: err = %v", err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	if _, err := kp2.(ContextSigner).SignContext(ctx, []byte("m")); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err = %v, want context.Canceled", err)
	}
}

func TestCloseFailsPendingSigns(t *testing.T) {
	f := natskeystest.New(t)
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	f.NewKey(SysAccountKey())
	s := newStore(t, f, func(c *Config) { c.Workers = 1 })
	kp := mustPair(t, s, SysAccountKey(), nkeys.PrefixByteAccount)
	f.SetSignGate(gate)

	errs := make(chan error, 2)
	go func() { _, err := kp.Sign([]byte("in flight")); errs <- err }()
	waitFor(t, func() bool { return f.Count(natskeystest.OpSign) == 1 })
	go func() { _, err := kp.Sign([]byte("queued")); errs <- err }()
	waitFor(t, func() bool { return len(s.d.queue) == 1 })
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-errs; !errors.Is(err, ErrClosed) {
			t.Errorf("pending sign after Close: %v, want ErrClosed", err)
		}
	}
	if _, err := kp.Sign([]byte("after")); !errors.Is(err, ErrClosed) {
		t.Errorf("sign after Close: %v, want ErrClosed", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
