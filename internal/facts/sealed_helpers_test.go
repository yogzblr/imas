package facts

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

// sealedFacts is farmer's key material (tenant keys in a mock OpenBao,
// sprout box keys on record in pki's store) plus each test sprout's own
// box private key, so a test can seal facts exactly as cmd/sprout does.
type sealedFacts struct {
	t     *testing.T
	privs map[[2]string]*[32]byte
}

// usePKIDB gives pki an in-memory store of its own for t.
func usePKIDB(t *testing.T) {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s-pki-%d?mode=memory&cache=shared", t.Name(), memDBSeq.Add(1))), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(append(pki.Models(), pki.SproutJWTModels()...)...); err != nil {
		t.Fatal(err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(nil) })
	// No saas schema in sqlite: no SaaS API credential recorded
	// (pki.UseSaaSAPICredentialState).
	t.Cleanup(pki.UseSaaSAPICredentialState(nil))
}

// newSealedFacts starts the mock OpenBao. pki's store must be set
// (usePKIDB or setupTenantIsolationPKI).
func newSealedFacts(t *testing.T, tenants ...string) *sealedFacts {
	t.Helper()
	tenantboxtest.Start(t)
	for _, tenant := range tenants {
		pki.InvalidateTenantBoxKeys(tenant)
		t.Cleanup(func() { pki.InvalidateTenantBoxKeys(tenant) })
	}
	return &sealedFacts{t: t, privs: map[[2]string]*[32]byte{}}
}

// enroll gives tenant's sprout a box key and records its public half
// farmer-side, as enrollment does.
func (s *sealedFacts) enroll(tenant, sprout string) {
	s.t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := pki.RotateSproutBoxKey(tenant, sprout, base64.StdEncoding.EncodeToString(pub[:]), time.Hour); err != nil {
		s.t.Fatal(err)
	}
	s.privs[[2]string{tenant, sprout}] = priv
}

// tenantPub is tenant's current box public key, as a sprout pins it.
func (s *sealedFacts) tenantPub(tenant string) *[32]byte {
	s.t.Helper()
	b64, err := pki.GetTenantX25519PublicKey(tenant)
	if err != nil {
		s.t.Fatal(err)
	}
	pub, err := pki.DecodeBoxPubKey(b64)
	if err != nil {
		s.t.Fatal(err)
	}
	return pub
}

// seal seals body as the facts report of (keyTenant, keySprout)'s key,
// naming msgTenant and msgSprout in the message; edit, if set, changes the
// message before it is sealed.
func (s *sealedFacts) sealAs(keyTenant, keySprout, msgTenant, msgSprout string, body any, edit func(*payloadbox.Message)) []byte {
	s.t.Helper()
	priv := s.privs[[2]string{keyTenant, keySprout}]
	if priv == nil {
		s.t.Fatalf("sprout %s/%s not enrolled", keyTenant, keySprout)
	}
	msg, err := payloadbox.NewMessage(payloadbox.PurposeFacts, msgTenant, msgSprout, "", body)
	if err != nil {
		s.t.Fatal(err)
	}
	if edit != nil {
		edit(&msg)
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: s.tenantPub(keyTenant), Priv: priv}})
	if err != nil {
		s.t.Fatal(err)
	}
	return data
}

// seal is an honest sprout's sealed report.
func (s *sealedFacts) seal(tenant, sprout string, sf SystemFacts) []byte {
	return s.sealAs(tenant, sprout, tenant, sprout, sf, nil)
}

// sealedHeader marks a message as a payloadbox envelope.
func sealedHeader() nats.Header {
	return nats.Header{payloadbox.Header: []string{payloadbox.HeaderBox1}}
}

// publish publishes data on sprout's facts subject over nc, sealed.
func publishSealed(t *testing.T, nc *nats.Conn, sprout string, data []byte) {
	t.Helper()
	m := nats.NewMsg("imas.sprouts." + sprout + ".facts")
	m.Header = sealedHeader()
	m.Data = data
	if err := nc.PublishMsg(m); err != nil {
		t.Fatal(err)
	}
}
