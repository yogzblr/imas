package pki

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki/natskeys"
	"github.com/yogzblr/imas/internal/pki/natskeys/natskeystest"
	"github.com/yogzblr/imas/internal/pki/pkitest"
)

func newFenceUserPub(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func bootstrap(t *testing.T, tr *pkitest.Transit, in BootstrapInput) *NATSTrust {
	t.Helper()
	trust, err := BootstrapNATSTrust(t.Context(), tr.Store, in)
	if err != nil {
		t.Fatalf("BootstrapNATSTrust: %v", err)
	}
	return trust
}

func TestBootstrapNATSTrustFirstRun(t *testing.T) {
	tr := pkitest.New(t)
	fence := newFenceUserPub(t)
	trust := bootstrap(t, tr, BootstrapInput{OperatorName: "imas-operator", BusFenceUserPub: fence})

	if n := tr.Fake.Count(natskeystest.OpCreateKey); n != 0 {
		t.Errorf("bootstrap created %d keys; it must only read them", n)
	}
	if err := trust.VerifyAgainst(t.Context(), tr.Store); err != nil {
		t.Fatalf("VerifyAgainst: %v", err)
	}
	if _, err := ParseNATSTrust(trust.Files()); err != nil {
		t.Fatalf("ParseNATSTrust of the bootstrap output: %v", err)
	}

	oc, err := jwt.DecodeOperatorClaims(trust.OperatorJWT)
	if err != nil {
		t.Fatal(err)
	}
	if oc.Issuer != trust.OperatorPub || oc.Subject != trust.OperatorPub {
		t.Errorf("operator jwt iss/sub = %s/%s, want self-signed by %s", oc.Issuer, oc.Subject, trust.OperatorPub)
	}
	if oc.Name != "imas-operator" || oc.SystemAccount != trust.SysAccountPub ||
		len(oc.SigningKeys) != 1 || !oc.SigningKeys.Contains(trust.OperatorSigningPub) {
		t.Errorf("operator claims = name %q, sys %s, signing %v", oc.Name, oc.SystemAccount, oc.SigningKeys)
	}
	ac, err := jwt.DecodeAccountClaims(trust.SysAccountJWT)
	if err != nil {
		t.Fatal(err)
	}
	if ac.Subject != trust.SysAccountPub || ac.Issuer != trust.OperatorSigningPub {
		t.Errorf("sys jwt sub/iss = %s/%s", ac.Subject, ac.Issuer)
	}
	uc, err := jwt.DecodeUserClaims(trust.BusFenceUserJWT)
	if err != nil {
		t.Fatal(err)
	}
	if uc.Subject != fence || uc.Issuer != trust.SysAccountPub || uc.IssuerAccount != "" {
		t.Errorf("fence jwt sub/iss/issuer_account = %s/%s/%q", uc.Subject, uc.Issuer, uc.IssuerAccount)
	}

	// The public keys are Transit's.
	for _, c := range []struct {
		name string
		got  string
	}{
		{natskeys.OperatorKey(), trust.OperatorPub},
		{natskeys.OperatorSigningKey(), trust.OperatorSigningPub},
		{natskeys.SysAccountKey(), trust.SysAccountPub},
	} {
		kp, err := nkeys.FromPublicKey(c.got)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("probe")
		sig := ed25519.Sign(tr.Fake.PrivateKey(c.name, 1), msg)
		if err := kp.Verify(msg, sig); err != nil {
			t.Errorf("%s public key is not Transit's: %v", c.name, err)
		}
	}

	// Without a fence user no fence JWT is minted.
	plain := bootstrap(t, tr, BootstrapInput{})
	if plain.BusFenceUserJWT != "" {
		t.Error("fence jwt minted without BusFenceUserPub")
	}
	if _, ok := plain.Files()[TrustBusFenceUserJWT]; ok {
		t.Error("Files has an empty fence jwt entry")
	}
}

// T4: a second run over the first run's output signs nothing and returns
// byte-identical data.
func TestBootstrapNATSTrustIdempotent(t *testing.T) {
	tr := pkitest.New(t)
	fence := newFenceUserPub(t)
	in := BootstrapInput{OperatorName: "imas-operator", BusFenceUserPub: fence}
	first := bootstrap(t, tr, in).Files()

	tr.Fake.ResetCounts()
	in.Existing = first
	second := bootstrap(t, tr, in).Files()
	if n := tr.Fake.Count(natskeystest.OpSign); n != 0 {
		t.Errorf("second run made %d sign requests, want 0", n)
	}
	if n := tr.Fake.Count(natskeystest.OpCreateKey); n != 0 {
		t.Errorf("second run created %d keys", n)
	}
	if !maps.EqualFunc(first, second, bytes.Equal) {
		t.Errorf("second run changed the trust:\nfirst  %q\nsecond %q", first, second)
	}

	// Trailing newlines (a ConfigMap edited by hand) are not a change.
	withNL := map[string][]byte{}
	for k, v := range first {
		withNL[k] = append(append([]byte{}, v...), '\n')
	}
	in.Existing = withNL
	third := bootstrap(t, tr, in).Files()
	if !maps.EqualFunc(first, third, bytes.Equal) {
		t.Error("trailing newlines changed the trust")
	}

	// A partial ConfigMap: only what is missing is minted.
	partial := maps.Clone(first)
	delete(partial, TrustSysAccountJWT)
	delete(partial, TrustBusFenceUserJWT)
	tr.Fake.ResetCounts()
	in.Existing = partial
	got := bootstrap(t, tr, in)
	if got.OperatorJWT != string(first[TrustOperatorJWT]) {
		t.Error("operator jwt re-minted although it was valid")
	}
	if n := tr.Fake.Count(natskeystest.OpSign); n != 2 {
		t.Errorf("partial run made %d sign requests, want 2 (sys and fence)", n)
	}

	// A different fence user is not an anchor change: only its JWT is re-minted.
	in.Existing = first
	in.BusFenceUserPub = newFenceUserPub(t)
	got = bootstrap(t, tr, in)
	if got.OperatorJWT != string(first[TrustOperatorJWT]) || got.SysAccountJWT != string(first[TrustSysAccountJWT]) {
		t.Error("new fence user changed the operator or sys jwt")
	}
	if uc, err := jwt.DecodeUserClaims(got.BusFenceUserJWT); err != nil || uc.Subject != in.BusFenceUserPub {
		t.Errorf("fence jwt not re-minted for the new user: %v", err)
	}

	// No fence user given: a valid existing fence jwt is kept.
	in.BusFenceUserPub = ""
	if got := bootstrap(t, tr, in); got.BusFenceUserJWT != string(first[TrustBusFenceUserJWT]) {
		t.Error("existing fence jwt dropped")
	}
}

func TestBootstrapNATSTrustRefusesChangedAnchor(t *testing.T) {
	// existing comes from another Transit: a different anchor.
	other := bootstrap(t, pkitest.New(t), BootstrapInput{OperatorName: "other"}).Files()

	cases := map[string]map[string][]byte{
		"everything":            other,
		"operator.pub only":     {TrustOperatorPub: other[TrustOperatorPub]},
		"operator-signing only": {TrustOperatorSigningPub: other[TrustOperatorSigningPub]},
		"sys-account.pub only":  {TrustSysAccountPub: other[TrustSysAccountPub]},
		"operator.jwt only":     {TrustOperatorJWT: other[TrustOperatorJWT]},
		"sys-account.jwt only":  {TrustSysAccountJWT: other[TrustSysAccountJWT]},
	}
	for name, existing := range cases {
		t.Run(name, func(t *testing.T) {
			tr := pkitest.New(t)
			tr.Fake.ResetCounts()
			got, err := BootstrapNATSTrust(t.Context(), tr.Store, BootstrapInput{Existing: existing})
			if !errors.Is(err, ErrTrustWouldChange) {
				t.Fatalf("err = %v, want ErrTrustWouldChange", err)
			}
			if got != nil {
				t.Error("returned trust despite the error")
			}
			if n := tr.Fake.Count(natskeystest.OpSign); n != 0 {
				t.Errorf("%d sign requests; nothing may be minted", n)
			}
		})
	}

	// Same Transit, but the operator signing key was replaced afterwards.
	tr := pkitest.New(t)
	first := bootstrap(t, tr, BootstrapInput{}).Files()
	tr.Fake.NewKey(natskeys.OperatorSigningKey())
	if _, err := BootstrapNATSTrust(t.Context(), tr.Store, BootstrapInput{Existing: first}); !errors.Is(err, ErrTrustWouldChange) {
		t.Fatalf("replaced signing key: err = %v, want ErrTrustWouldChange", err)
	}

	// An existing entry that does not decode is invalid, not overwritten.
	tr = pkitest.New(t)
	_, err := BootstrapNATSTrust(t.Context(), tr.Store, BootstrapInput{Existing: map[string][]byte{TrustOperatorJWT: []byte("garbage")}})
	if !errors.Is(err, ErrTrustInvalid) {
		t.Fatalf("garbage operator jwt: err = %v, want ErrTrustInvalid", err)
	}
	_, err = BootstrapNATSTrust(t.Context(), tr.Store, BootstrapInput{BusFenceUserPub: string(other[TrustSysAccountPub])})
	if !errors.Is(err, ErrTrustInvalid) {
		t.Fatalf("account key as fence user: err = %v, want ErrTrustInvalid", err)
	}
}

func TestVerifyAgainstDetectsMismatch(t *testing.T) {
	for _, name := range []string{natskeys.OperatorKey(), natskeys.OperatorSigningKey(), natskeys.SysAccountKey()} {
		t.Run(name, func(t *testing.T) {
			tr := pkitest.New(t)
			trust := bootstrap(t, tr, BootstrapInput{})
			if err := trust.VerifyAgainst(t.Context(), tr.Store); err != nil {
				t.Fatalf("before: %v", err)
			}
			tr.Fake.NewKey(name)
			if err := trust.VerifyAgainst(t.Context(), tr.Store); !errors.Is(err, ErrTrustMismatch) {
				t.Fatalf("err = %v, want ErrTrustMismatch", err)
			}
			tr.Fake.Delete(name)
			if err := trust.VerifyAgainst(t.Context(), tr.Store); !errors.Is(err, natskeys.ErrKeyNotFound) {
				t.Fatalf("missing key: err = %v, want ErrKeyNotFound", err)
			}
		})
	}
	tr := pkitest.New(t)
	trust := bootstrap(t, tr, BootstrapInput{})
	tr.Fake.ResetCounts()
	if err := trust.VerifyAgainst(t.Context(), tr.Store); err != nil {
		t.Fatal(err)
	}
	if n := tr.Fake.Count(natskeystest.OpSign) + tr.Fake.Count(natskeystest.OpCreateKey); n != 0 {
		t.Errorf("VerifyAgainst signed or created %d times; it must only read", n)
	}
}

func TestParseNATSTrustRejects(t *testing.T) {
	tr := pkitest.New(t)
	good := bootstrap(t, tr, BootstrapInput{BusFenceUserPub: newFenceUserPub(t)})

	// A SYS account JWT signed by the operator identity, not operator-signing.
	opKP, err := tr.Store.KeyPair(t.Context(), natskeys.OperatorKey(), nkeys.PrefixByteOperator)
	if err != nil {
		t.Fatal(err)
	}
	sysByOperator, err := jwt.NewAccountClaims(good.SysAccountPub).Encode(opKP)
	if err != nil {
		t.Fatal(err)
	}
	// A fence user issued by an account other than SYS.
	otherAcct, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	fenceByOther, err := jwt.NewUserClaims(newFenceUserPub(t)).Encode(otherAcct)
	if err != nil {
		t.Fatal(err)
	}
	// A JWT whose payload was altered after signing.
	tampered := []byte(good.OperatorJWT)
	tampered[len(tampered)-5] ^= 1

	cases := []struct {
		name   string
		mutate func(m map[string][]byte)
		want   error
	}{
		{"missing operator.jwt", func(m map[string][]byte) { delete(m, TrustOperatorJWT) }, ErrTrustIncomplete},
		{"empty sys-account.pub", func(m map[string][]byte) { m[TrustSysAccountPub] = []byte(" \n") }, ErrTrustIncomplete},
		{"operator.pub with account prefix", func(m map[string][]byte) { m[TrustOperatorPub] = []byte(good.SysAccountPub) }, ErrTrustInvalid},
		{"sys-account.pub with operator prefix", func(m map[string][]byte) { m[TrustSysAccountPub] = []byte(good.OperatorPub) }, ErrTrustInvalid},
		{"operator.pub differs from jwt", func(m map[string][]byte) { m[TrustOperatorPub] = []byte(good.OperatorSigningPub) }, ErrTrustInvalid},
		{"signing pub not in operator jwt", func(m map[string][]byte) { m[TrustOperatorSigningPub] = []byte(good.OperatorPub) }, ErrTrustInvalid},
		{"tampered operator jwt", func(m map[string][]byte) { m[TrustOperatorJWT] = tampered }, ErrTrustInvalid},
		{"sys jwt signed by operator identity", func(m map[string][]byte) { m[TrustSysAccountJWT] = []byte(sysByOperator) }, ErrTrustInvalid},
		{"operator jwt in place of sys jwt", func(m map[string][]byte) { m[TrustSysAccountJWT] = []byte(good.OperatorJWT) }, ErrTrustInvalid},
		{"fence user issued by another account", func(m map[string][]byte) { m[TrustBusFenceUserJWT] = []byte(fenceByOther) }, ErrTrustInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := maps.Clone(good.Files())
			c.mutate(m)
			if _, err := ParseNATSTrust(m); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestLoadNATSTrustDir(t *testing.T) {
	tr := pkitest.New(t)
	want := bootstrap(t, tr, BootstrapInput{})

	// A mounted ConfigMap: files are symlinks into a ..data directory.
	dir := t.TempDir()
	data := filepath.Join(dir, "..data")
	if err := os.Mkdir(data, 0o755); err != nil {
		t.Fatal(err)
	}
	for k, v := range want.Files() {
		if err := os.WriteFile(filepath.Join(data, k), append(v, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..data", k), filepath.Join(dir, k)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := LoadNATSTrustDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *want {
		t.Errorf("loaded %+v, want %+v", got, want)
	}

	if _, err := LoadNATSTrustDir(filepath.Join(dir, "absent")); !errors.Is(err, ErrTrustIncomplete) {
		t.Errorf("absent dir: err = %v, want ErrTrustIncomplete", err)
	}

	t.Setenv(NATSTrustDirEnv, "")
	if d := NATSTrustDir(); d != DefaultNATSTrustDir {
		t.Errorf("NATSTrustDir() = %q, want default", d)
	}
	t.Setenv(NATSTrustDirEnv, dir)
	if d := NATSTrustDir(); d != dir {
		t.Errorf("NATSTrustDir() = %q, want %q", d, dir)
	}
}

// The bus account loader's SYS user (P21 slice 2 PR 4, issue #197
// decisions 3 and 6): minted with exactly its grant, reused when current,
// re-minted for a new key or a different grant.
func TestBootstrapNATSTrustLoaderUser(t *testing.T) {
	tr := pkitest.New(t)
	loader := newFenceUserPub(t)
	in := BootstrapInput{OperatorName: "imas-operator", BusFenceUserPub: newFenceUserPub(t), BusLoaderUserPub: loader}
	first := bootstrap(t, tr, in)

	uc, err := jwt.DecodeUserClaims(first.BusLoaderUserJWT)
	if err != nil {
		t.Fatal(err)
	}
	if uc.Subject != loader || uc.Issuer != first.SysAccountPub || uc.IssuerAccount != "" || uc.Name != "imas-bus-loader" {
		t.Errorf("loader jwt sub/iss/issuer_account/name = %s/%s/%q/%q", uc.Subject, uc.Issuer, uc.IssuerAccount, uc.Name)
	}
	wantPub := []string{"$SYS.REQ.CLAIMS.UPDATE", "$SYS.REQ.CLAIMS.LIST", "$SYS.REQ.ACCOUNT.*.CLAIMS.LOOKUP"}
	wantSub := []string{"_INBOX.>", "imas.bus.accounts.changed"}
	if !slices.Equal(uc.Pub.Allow, wantPub) || !slices.Equal(uc.Sub.Allow, wantSub) ||
		len(uc.Pub.Deny) != 0 || len(uc.Sub.Deny) != 0 || uc.Resp != nil || uc.BearerToken {
		t.Errorf("loader permissions = %+v", uc.Permissions)
	}
	files := first.Files()
	if _, err := ParseNATSTrust(files); err != nil {
		t.Fatalf("ParseNATSTrust: %v", err)
	}

	// Idempotent: nothing signed over its own output.
	tr.Fake.ResetCounts()
	in.Existing = files
	if got := bootstrap(t, tr, in); got.BusLoaderUserJWT != first.BusLoaderUserJWT {
		t.Error("second run re-minted the loader jwt")
	}
	if n := tr.Fake.Count(natskeystest.OpSign); n != 0 {
		t.Errorf("second run made %d sign requests, want 0", n)
	}

	// No loader user given: a valid existing one is kept.
	in.BusLoaderUserPub = ""
	if got := bootstrap(t, tr, in); got.BusLoaderUserJWT != first.BusLoaderUserJWT {
		t.Error("existing loader jwt dropped")
	}

	// A new loader key: only its JWT is re-minted.
	in.BusLoaderUserPub = newFenceUserPub(t)
	tr.Fake.ResetCounts()
	got := bootstrap(t, tr, in)
	if uc, err := jwt.DecodeUserClaims(got.BusLoaderUserJWT); err != nil || uc.Subject != in.BusLoaderUserPub {
		t.Errorf("loader jwt not re-minted for the new user: %v", err)
	}
	if got.BusFenceUserJWT != first.BusFenceUserJWT || got.SysAccountJWT != first.SysAccountJWT {
		t.Error("a new loader user changed another jwt")
	}
	if n := tr.Fake.Count(natskeystest.OpSign); n != 1 {
		t.Errorf("new loader user: %d sign requests, want 1", n)
	}

	// An existing loader JWT with a wider grant (or an older one) is
	// invalid trust, and a bootstrap replaces it with the exact grant.
	sysKP, err := tr.Store.KeyPair(t.Context(), natskeys.SysAccountKey(), nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatal(err)
	}
	wide := jwt.NewUserClaims(loader)
	wide.Permissions = BusLoaderUserPermissions()
	wide.Pub.Allow.Add("$SYS.REQ.SERVER.>")
	wideJWT, err := wide.Encode(sysKP)
	if err != nil {
		t.Fatal(err)
	}
	stale := maps.Clone(files)
	stale[TrustBusLoaderUserJWT] = []byte(wideJWT)
	if _, err := ParseNATSTrust(stale); !errors.Is(err, ErrTrustInvalid) {
		t.Fatalf("wider loader grant: Parse err = %v, want ErrTrustInvalid", err)
	}
	in.Existing, in.BusLoaderUserPub = stale, loader
	got = bootstrap(t, tr, in)
	if uc, err := jwt.DecodeUserClaims(got.BusLoaderUserJWT); err != nil || !loaderPermissionsExact(uc) || uc.Subject != loader {
		t.Errorf("wider loader grant not re-minted: %v", err)
	}
	// With no loader key given, the stale grant is re-minted for the same
	// user rather than left in the ConfigMap.
	in.BusLoaderUserPub = ""
	got = bootstrap(t, tr, in)
	if uc, err := jwt.DecodeUserClaims(got.BusLoaderUserJWT); err != nil || !loaderPermissionsExact(uc) || uc.Subject != loader {
		t.Errorf("stale loader grant without a loader key: not re-minted for the same user: %v", err)
	}
	if _, err := ParseNATSTrust(got.Files()); err != nil {
		t.Errorf("result does not load back: %v", err)
	}
}

func TestBootstrapNATSTrustLoaderUserRejects(t *testing.T) {
	tr := pkitest.New(t)
	same := newFenceUserPub(t)
	if _, err := BootstrapNATSTrust(t.Context(), tr.Store, BootstrapInput{BusFenceUserPub: same, BusLoaderUserPub: same}); !errors.Is(err, ErrTrustInvalid) {
		t.Errorf("loader key equal to fence key: err = %v, want ErrTrustInvalid", err)
	}
	good := bootstrap(t, tr, BootstrapInput{})
	if _, err := BootstrapNATSTrust(t.Context(), tr.Store, BootstrapInput{BusLoaderUserPub: good.SysAccountPub}); !errors.Is(err, ErrTrustInvalid) {
		t.Errorf("account key as loader user: err = %v, want ErrTrustInvalid", err)
	}

	// Issued by an account other than SYS, with the right grant.
	otherAcct, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	uc := jwt.NewUserClaims(newFenceUserPub(t))
	uc.Permissions = BusLoaderUserPermissions()
	byOther, err := uc.Encode(otherAcct)
	if err != nil {
		t.Fatal(err)
	}
	m := good.Files()
	m[TrustBusLoaderUserJWT] = []byte(byOther)
	if _, err := ParseNATSTrust(m); !errors.Is(err, ErrTrustInvalid) {
		t.Errorf("loader user issued by another account: Parse err = %v, want ErrTrustInvalid", err)
	}
	if _, err := BootstrapNATSTrust(t.Context(), tr.Store, BootstrapInput{Existing: m}); !errors.Is(err, ErrTrustInvalid) {
		t.Errorf("loader user issued by another account: Bootstrap err = %v, want ErrTrustInvalid", err)
	}

	// The loader key equal to a retained fence JWT's subject (no fence
	// key given this run), and a new fence key equal to the retained
	// loader's subject: both refused.
	fence := newFenceUserPub(t)
	withFence := bootstrap(t, tr, BootstrapInput{BusFenceUserPub: fence}).Files()
	if _, err := BootstrapNATSTrust(t.Context(), tr.Store, BootstrapInput{Existing: withFence, BusLoaderUserPub: fence}); !errors.Is(err, ErrTrustInvalid) {
		t.Errorf("loader key equal to the retained fence user: err = %v, want ErrTrustInvalid", err)
	}
	loader := newFenceUserPub(t)
	withLoader := bootstrap(t, tr, BootstrapInput{BusLoaderUserPub: loader}).Files()
	if _, err := BootstrapNATSTrust(t.Context(), tr.Store, BootstrapInput{Existing: withLoader, BusFenceUserPub: loader}); !errors.Is(err, ErrTrustInvalid) {
		t.Errorf("fence key equal to the retained loader user: err = %v, want ErrTrustInvalid", err)
	}
	// Parse refuses a trust whose fence and loader JWTs share a subject.
	sameSubj := maps.Clone(withLoader)
	fenceKP, err := tr.Store.KeyPair(t.Context(), natskeys.SysAccountKey(), nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatal(err)
	}
	fj, err := jwt.NewUserClaims(loader).Encode(fenceKP)
	if err != nil {
		t.Fatal(err)
	}
	sameSubj[TrustBusFenceUserJWT] = []byte(fj)
	if _, err := ParseNATSTrust(sameSubj); !errors.Is(err, ErrTrustInvalid) {
		t.Errorf("fence and loader share a subject: Parse err = %v, want ErrTrustInvalid", err)
	}

	// A narrower grant is also not the loader's grant.
	sysKP, err := tr.Store.KeyPair(t.Context(), natskeys.SysAccountKey(), nkeys.PrefixByteAccount)
	if err != nil {
		t.Fatal(err)
	}
	narrow := jwt.NewUserClaims(newFenceUserPub(t))
	narrow.Permissions = BusLoaderUserPermissions()
	narrow.Sub.Allow = jwt.StringList{"_INBOX.>"}
	narrowJWT, err := narrow.Encode(sysKP)
	if err != nil {
		t.Fatal(err)
	}
	m[TrustBusLoaderUserJWT] = []byte(narrowJWT)
	if _, err := ParseNATSTrust(m); !errors.Is(err, ErrTrustInvalid) {
		t.Errorf("narrower loader grant: Parse err = %v, want ErrTrustInvalid", err)
	}
}
