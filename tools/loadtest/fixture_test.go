package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	jwt "github.com/nats-io/jwt/v2"

	"github.com/yogzblr/imas/internal/pki"
)

func newTestTrust(t *testing.T) *trust {
	t.Helper()
	dir := t.TempDir()
	tr, files, err := newLocalTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The bus gets the public trust directory, as the bootstrap Job
	// writes it, and no seed.
	if len(files) != 1 || files[pki.NATSTrustDirEnv] == "" {
		t.Fatalf("local bus files %v, want only %s", files, pki.NATSTrustDirEnv)
	}
	nt, err := pki.LoadNATSTrustDir(files[pki.NATSTrustDirEnv])
	if err != nil {
		t.Fatalf("trust directory: %v", err)
	}
	signPub, _ := tr.operatorSigning.PublicKey()
	sysPub, _ := tr.sysAccount.PublicKey()
	if nt.OperatorSigningPub != signPub || nt.SysAccountPub != sysPub {
		t.Error("the trust directory names other keys than the fixture signs with")
	}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(p, ".nk") {
			t.Errorf("newLocalTrust wrote a seed file %s", p)
		}
		return nil
	})
	return tr
}

// TestTenantAccountShape checks the Account is signed and delegates the
// way internal/pki's ensureTenantAccountMaterial does it.
func TestTenantAccountShape(t *testing.T) {
	tr := newTestTrust(t)
	tf, err := tr.newTenant("loadtest-shape")
	if err != nil {
		t.Fatal(err)
	}
	ac, err := jwt.DecodeAccountClaims(tf.accountJWT)
	if err != nil {
		t.Fatal(err)
	}
	opSigning, _ := tr.operatorSigning.PublicKey()
	if ac.Issuer != opSigning || ac.Subject != tf.accountPub || ac.Name != "loadtest-shape" || !ac.SigningKeys.Contains(tf.signingPub) {
		t.Errorf("account claims: issuer %s subject %s name %s signing %v", ac.Issuer, ac.Subject, ac.Name, ac.SigningKeys)
	}
	core, err := jwt.DecodeUserClaims(tf.coreJWT)
	if err != nil {
		t.Fatal(err)
	}
	if core.Issuer != tf.signingPub || core.IssuerAccount != tf.accountPub || !reflect.DeepEqual(core.Permissions, pki.AllowAllPermissions()) {
		t.Errorf("core user: issuer %s account %s perms %+v", core.Issuer, core.IssuerAccount, core.Permissions)
	}
	if _, err := tr.newTenant("bad/name"); err == nil {
		t.Error("newTenant accepted an invalid tenant ID")
	}
}

// TestSproutJWTShape checks each sprout User JWT the way internal/pki's
// mintOrReuseUserJWT builds it, and against the exported checks pki
// itself applies to an enrolled sprout's JWT.
func TestSproutJWTShape(t *testing.T) {
	tr := newTestTrust(t)
	tf, err := tr.newTenant("loadtest-sprouts")
	if err != nil {
		t.Fatal(err)
	}
	creds, err := tf.mintSprouts("lt-x1", 37)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, c := range creds {
		if c.ID != sproutID("lt-x1", i) || !pki.IsValidSproutID(c.ID) || seen[c.ID] {
			t.Fatalf("sprout %d: bad or duplicate ID %q", i, c.ID)
		}
		seen[c.ID] = true
		uc, err := jwt.DecodeUserClaims(c.JWT)
		if err != nil {
			t.Fatal(err)
		}
		if uc.Name != c.ID || uc.Issuer != tf.signingPub || uc.IssuerAccount != tf.accountPub {
			t.Fatalf("sprout %s: name %s issuer %s account %s", c.ID, uc.Name, uc.Issuer, uc.IssuerAccount)
		}
		// The one shared definition: any difference between the grant
		// the simulated sprouts carry and the real one fails here.
		if !reflect.DeepEqual(uc.Permissions, pki.SproutPermissions(c.ID)) || !pki.SproutUserJWTHasFullGrant(c.JWT, c.ID) {
			t.Fatalf("sprout %s: permissions %+v, want pki.SproutPermissions", c.ID, uc.Permissions)
		}
		if err := pkiSanity(c); err != nil {
			t.Fatal(err)
		}
	}
	// The grants the sprout's natsInit, log shipping and heartbeat need.
	id := creds[0].ID
	p := pki.SproutPermissions(id)
	for _, want := range []string{"imas.sprouts.announce." + id, "_INBOX.>", "imas.sprouts." + id + ".facts", pki.SproutBoxKeySubmitSubject(id), pki.SproutHeartbeatSubject(id)} {
		if !p.Pub.Allow.Contains(want) {
			t.Errorf("publish grant %q missing", want)
		}
	}
	if !p.Sub.Allow.Contains("imas.sprouts."+id+".>") || len(p.Sub.Allow) != 1 {
		t.Errorf("subscribe grants %v", p.Sub.Allow)
	}
	for _, subj := range sproutSubjects(id) {
		if !strings.HasPrefix(subj, "imas.sprouts."+id+".") {
			t.Errorf("subscription %s is outside the sprout's grant", subj)
		}
	}
}
