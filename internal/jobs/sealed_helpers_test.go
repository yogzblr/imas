package jobs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

// stepSealer seals step events exactly as a sprout does
// (cook.StepEvent, payloadbox.PurposeCookStep): tenant keys in a mock
// OpenBao, each test sprout's box key on record in an in-memory pki store,
// enrolled the first time the test seals for it. It also stands in for
// Valkey's cluster-wide claim, in memory, shared by every replica of the
// test.
type stepSealer struct {
	t       *testing.T
	mu      sync.Mutex
	privs   map[[2]string]*[32]byte
	tenants map[string]bool
	claims  map[string]bool
	// claimErr, if set, is what every claim returns (Valkey down).
	claimErr error
}

var (
	sealersMu sync.Mutex
	sealers   = map[*testing.T]*stepSealer{}
)

// sealerFor returns t's sealer, setting it up on first use.
func sealerFor(t *testing.T) *stepSealer {
	t.Helper()
	sealersMu.Lock()
	s := sealers[t]
	sealersMu.Unlock()
	if s != nil {
		return s
	}
	gdb, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s-pki-%d?mode=memory&cache=shared", t.Name(), memDBSeq.Add(1))), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := gdb.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatal(err)
	}
	pki.SetDB(gdb)
	tenantboxtest.Start(t)
	s = &stepSealer{t: t, privs: map[[2]string]*[32]byte{}, tenants: map[string]bool{}, claims: map[string]bool{}}
	origClaim, origGuard := claimStepEvent, stepGuard
	claimStepEvent = s.claim
	stepGuard = payloadbox.NewKeyedReplayGuard()
	sealersMu.Lock()
	sealers[t] = s
	sealersMu.Unlock()
	t.Cleanup(func() {
		claimStepEvent, stepGuard = origClaim, origGuard
		pki.SetDB(nil)
		s.mu.Lock()
		for tenant := range s.tenants {
			pki.InvalidateTenantBoxKeys(tenant)
		}
		s.mu.Unlock()
		sealersMu.Lock()
		delete(sealers, t)
		sealersMu.Unlock()
	})
	return s
}

func (s *stepSealer) claim(_ context.Context, tenantID, sproutID, msgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimErr != nil {
		return s.claimErr
	}
	key := tenantID + "\x00" + sproutID + "\x00" + msgID
	if s.claims[key] {
		return pki.ErrSealedReplayed
	}
	s.claims[key] = true
	return nil
}

// keys returns tenant's sprout's box private key, enrolling it (and
// creating the tenant's key) on first use, and the tenant public key.
func (s *stepSealer) keys(tenant, sprout string) (priv, tenantPub *[32]byte) {
	s.t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.tenants[tenant] {
		pki.InvalidateTenantBoxKeys(tenant)
		s.tenants[tenant] = true
	}
	priv = s.privs[[2]string{tenant, sprout}]
	if priv == nil {
		pub, p, err := box.GenerateKey(rand.Reader)
		if err != nil {
			s.t.Fatal(err)
		}
		if err := pki.RotateSproutBoxKey(tenant, sprout, base64.StdEncoding.EncodeToString(pub[:]), time.Hour); err != nil {
			s.t.Fatal(err)
		}
		s.privs[[2]string{tenant, sprout}] = p
		priv = p
	}
	b64, err := pki.GetTenantX25519PublicKey(tenant)
	if err != nil {
		s.t.Fatal(err)
	}
	if tenantPub, err = pki.DecodeBoxPubKey(b64); err != nil {
		s.t.Fatal(err)
	}
	return priv, tenantPub
}

// sealBody seals body as a step event from (keyTenant, keySprout)'s key,
// naming msgTenant and msgSprout; edit, if set, changes the message first.
func (s *stepSealer) sealBody(keyTenant, keySprout, msgTenant, msgSprout string, body any, edit func(*payloadbox.Message)) []byte {
	s.t.Helper()
	priv, tenantPub := s.keys(keyTenant, keySprout)
	msg, err := payloadbox.NewMessage(payloadbox.PurposeCookStep, msgTenant, msgSprout, "", body)
	if err != nil {
		s.t.Fatal(err)
	}
	if edit != nil {
		edit(&msg)
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: priv}})
	if err != nil {
		s.t.Fatal(err)
	}
	return data
}

// sealedStep is an honest sprout's sealed event of step for jid.
func (s *stepSealer) sealedStep(tenant, sprout, jid string, step cook.StepCompletion) *nats.Msg {
	s.t.Helper()
	return sealedNATSMsg(cook.StepEventSubject(sprout, jid), s.sealBody(tenant, sprout, tenant, sprout, cook.StepEvent{JobID: jid, Step: step}, nil))
}

func sealedNATSMsg(subject string, data []byte) *nats.Msg {
	m := nats.NewMsg(subject)
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = data
	return m
}

// sealedMsg is the step event a sprout of tenant would publish on
// subject carrying data, a JSON StepCompletion. A subject that doesn't
// name a sprout and job, or data that isn't a StepCompletion, still gives
// a message marked sealed, so the test sees farmer refuse it.
func sealedMsg(t *testing.T, tenant, subject string, data []byte) *nats.Msg {
	t.Helper()
	s := sealerFor(t)
	sprout, jid, ok := cook.StepEventSubjectIDs(subject)
	if !ok {
		return sealedNATSMsg(subject, []byte(`{"v":2,"s":[]}`))
	}
	var step cook.StepCompletion
	var body any = cook.StepEvent{JobID: jid}
	if err := json.Unmarshal(data, &step); err == nil {
		body = cook.StepEvent{JobID: jid, Step: step}
	} else {
		body = string(data)
	}
	return sealedNATSMsg(subject, s.sealBody(tenant, sprout, tenant, sprout, body, nil))
}
