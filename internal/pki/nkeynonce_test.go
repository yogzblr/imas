package pki

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func signedKeySubmission(t *testing.T, kp nkeys.KeyPair, nonce, id string) KeySubmission {
	t.Helper()
	pub, _ := kp.PublicKey()
	sig, err := kp.Sign(NKeySubmissionPayload(nonce, id, pub))
	if err != nil {
		t.Fatal(err)
	}
	return KeySubmission{NKey: pub, SproutID: id, Nonce: nonce, Sig: base64.RawURLEncoding.EncodeToString(sig)}
}

// VerifyNKeySubmission accepts a signature by the NKey over its own nonce
// once, and refuses an expired or spent nonce, another key's signature
// and a signature over another sprout ID (security review 2026-10, L12).
func TestVerifyNKeySubmission(t *testing.T) {
	now := time.Now()
	old := nkeyNonces
	nkeyNonces = newNKeyNonceStore(func() time.Time { return now })
	t.Cleanup(func() { nkeyNonces = old })
	kp, _ := nkeys.CreateUser()
	other, _ := nkeys.CreateUser()

	n, err := IssueNKeyNonce()
	if err != nil {
		t.Fatal(err)
	}
	good := signedKeySubmission(t, kp, n, "web-01")
	if err := VerifyNKeySubmission(good); err != nil {
		t.Fatalf("a valid submission: %v", err)
	}
	if err := VerifyNKeySubmission(good); !errors.Is(err, ErrNKeySubmissionUnproven) {
		t.Fatalf("a replayed submission: %v", err)
	}

	n, _ = IssueNKeyNonce()
	forged := signedKeySubmission(t, other, n, "web-01")
	forged.NKey = good.NKey
	if err := VerifyNKeySubmission(forged); !errors.Is(err, ErrNKeySubmissionUnproven) {
		t.Fatalf("another key's signature: %v", err)
	}

	n, _ = IssueNKeyNonce()
	moved := signedKeySubmission(t, kp, n, "web-01")
	moved.SproutID = "web-02"
	if err := VerifyNKeySubmission(moved); !errors.Is(err, ErrNKeySubmissionUnproven) {
		t.Fatalf("a signature over another ID: %v", err)
	}

	n, _ = IssueNKeyNonce()
	late := signedKeySubmission(t, kp, n, "web-01")
	now = now.Add(nkeyNonceTTL)
	if err := VerifyNKeySubmission(late); !errors.Is(err, ErrNKeySubmissionUnproven) {
		t.Fatalf("an expired nonce: %v", err)
	}
	if err := VerifyNKeySubmission(KeySubmission{NKey: good.NKey, SproutID: "web-01"}); !errors.Is(err, ErrNKeySubmissionUnproven) {
		t.Fatalf("no nonce: %v", err)
	}
}

// Issuing a nonce stores nothing, so a flood of GET /pki/nkeynonce can't
// crowd out a legitimate registration (CodeRabbit on PR 277); a nonce that
// another process issued, or one altered, is refused; and a submission
// whose signature fails does not spend its nonce.
func TestNKeyNonceStateless(t *testing.T) {
	now := time.Now()
	old := nkeyNonces
	nkeyNonces = newNKeyNonceStore(func() time.Time { return now })
	t.Cleanup(func() { nkeyNonces = old })
	for range 50000 {
		if _, err := IssueNKeyNonce(); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(nkeyNonces.spent); n != 0 {
		t.Fatalf("issuing nonces stored %d entries", n)
	}
	kp, _ := nkeys.CreateUser()
	other, _ := nkeys.CreateUser()

	n, _ := IssueNKeyNonce()
	bad := signedKeySubmission(t, other, n, "web-01")
	bad.NKey = signedKeySubmission(t, kp, n, "web-01").NKey
	if err := VerifyNKeySubmission(bad); !errors.Is(err, ErrNKeySubmissionUnproven) {
		t.Fatalf("a forged signature: %v", err)
	}
	if err := VerifyNKeySubmission(signedKeySubmission(t, kp, n, "web-01")); err != nil {
		t.Fatalf("a failed attempt spent the nonce: %v", err)
	}

	foreign := newNKeyNonceStore(func() time.Time { return now })
	fn, _ := foreign.issue()
	if err := VerifyNKeySubmission(signedKeySubmission(t, kp, fn, "web-01")); !errors.Is(err, ErrNKeySubmissionUnproven) {
		t.Fatalf("another process's nonce: %v", err)
	}
	n, _ = IssueNKeyNonce()
	raw, _ := base64.RawURLEncoding.DecodeString(n)
	raw[9] ^= 1
	altered := base64.RawURLEncoding.EncodeToString(raw)
	if err := VerifyNKeySubmission(signedKeySubmission(t, kp, altered, "web-01")); !errors.Is(err, ErrNKeySubmissionUnproven) {
		t.Fatalf("an altered nonce: %v", err)
	}

	// Spent entries are swept at most once per TTL (no scan per
	// submission), and go once their nonce has expired.
	for i := range 3 {
		n, _ = IssueNKeyNonce()
		if err := VerifyNKeySubmission(signedKeySubmission(t, kp, n, fmt.Sprintf("web-1%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(nkeyNonces.spent); got != 4 {
		t.Fatalf("%d spent entries, want 4", got)
	}
	swept := nkeyNonces.swept
	now = now.Add(nkeyNonceTTL)
	n, _ = IssueNKeyNonce()
	if err := VerifyNKeySubmission(signedKeySubmission(t, kp, n, "web-02")); err != nil {
		t.Fatal(err)
	}
	if got := len(nkeyNonces.spent); got != 1 || !nkeyNonces.swept.After(swept) {
		t.Fatalf("%d spent entries after the sweep, want 1", got)
	}
}

// An NKey that one row has accepted is never revoked because another row
// of the same tenant files it as unaccepted, denied or rejected (security
// review 2026-10, L12: a legacy PUT /pki/putnkey filing someone's public
// NKey as "rejected" revoked that sprout). A rejected row with its own
// NKey is still revoked. Both the legacy tenant's sync (syncNatsAuth) and
// a provisioned tenant's (syncTenantSprouts).
func TestSyncNeverRevokesAnotherRowsAcceptedNKey(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	const tenantID = "t_l12"
	_ = ProvisionTenant(tenantID, "L12 Co") // the push fails: no bus

	newPub := func() string {
		kp, _ := nkeys.CreateUser()
		pub, _ := kp.PublicKey()
		return pub
	}
	for _, tc := range []struct {
		name   string
		tenant string
		sync   func() (string, error)
	}{
		{"legacy tenant", currentTenantID(), func() (string, error) {
			mat, err := ensureNatsAuth()
			if err != nil {
				return "", err
			}
			if _, err := syncNatsAuth(mat); err != nil {
				return "", err
			}
			return mat.tenantJWT, nil
		}},
		{"provisioned tenant", tenantID, func() (string, error) {
			mat, err := ensureNatsAuth()
			if err != nil {
				return "", err
			}
			tam, err := loadTenantAccountMaterial(tenantID)
			if err != nil {
				return "", err
			}
			if _, err := syncTenantSprouts(mat, tam, tenantID); err != nil {
				return "", err
			}
			return tam.jwt, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			victim, own := newPub(), newPub()
			rows := []nkeyRow{
				{TenantID: tc.tenant, SproutID: "victim", NKey: victim, State: stateAccepted},
				{TenantID: tc.tenant, SproutID: "victim_1", NKey: victim, State: stateRejected},
				{TenantID: tc.tenant, SproutID: "squatter", NKey: victim, State: stateUnaccepted},
				{TenantID: tc.tenant, SproutID: "rogue", NKey: own, State: stateRejected},
			}
			for _, r := range rows {
				if err := upsertNKeyRow(r); err != nil {
					t.Fatal(err)
				}
			}
			signed, err := tc.sync()
			if err != nil {
				t.Fatal(err)
			}
			ac, err := jwt.DecodeAccountClaims(signed)
			if err != nil {
				t.Fatal(err)
			}
			if _, revoked := ac.Revocations[victim]; revoked {
				t.Fatal("the accepted sprout's NKey was revoked by another row")
			}
			if _, revoked := ac.Revocations[own]; !revoked {
				t.Fatal("a rejected row's own NKey was not revoked")
			}
		})
	}
}
