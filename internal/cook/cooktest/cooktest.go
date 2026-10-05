// Package cooktest is a stub sprout for tests outside internal/cook that
// dispatch cook jobs through farmer's real path (cook.SendCookEvent,
// cook.SendStepsEvent).
//
// Since FIX.1 farmer sends nothing to a sprout with no box key on record:
// every dispatch is sealed to the sprout's box key, so a stub that reads
// plaintext no longer receives anything. A Sprout has a box key on record
// farmer-side and its own private half, opens each dispatch as a real
// sprout would (bound to its tenant and sprout ID) and seals its Ack.
//
// Only tests import it. It needs pki's store (pki.SetDB) and a tenant
// keypair source (internal/pki/tenantboxtest) set up first.
package cooktest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// Sprout is an enrolled stub sprout ID of Tenant.
type Sprout struct {
	Tenant, ID string
	priv       *[32]byte
	tenantPub  *[32]byte
}

// NewSprout records a fresh box key for tenantID's sproutID, as
// enrollment would, and pins the tenant's current public key.
func NewSprout(t testing.TB, tenantID, sproutID string) *Sprout {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.RotateSproutBoxKey(tenantID, sproutID, base64.StdEncoding.EncodeToString(pub[:]), time.Hour); err != nil {
		t.Fatalf("recording %s/%s's box key: %v", tenantID, sproutID, err)
	}
	tenantPubB64, err := pki.GetTenantX25519PublicKey(tenantID)
	if err != nil {
		t.Fatalf("reading %s's tenant key: %v", tenantID, err)
	}
	tenantPub, err := pki.DecodeBoxPubKey(tenantPubB64)
	if err != nil {
		t.Fatal(err)
	}
	return &Sprout{Tenant: tenantID, ID: sproutID, priv: priv, tenantPub: tenantPub}
}

// Acknowledge is the Ack a sprout sends for a dispatch it accepts.
func Acknowledge(env cook.RecipeEnvelope) cook.Ack {
	return cook.Ack{Acknowledged: true, JobID: env.JobID}
}

// Open opens data, an envelope farmer sealed for s under purpose.
func (s *Sprout) Open(data []byte, purpose string) (*payloadbox.Message, error) {
	return payloadbox.Open(data, []payloadbox.KeyPair{{PeerPub: s.tenantPub, Priv: s.priv}},
		payloadbox.Expect{Purpose: purpose, TenantID: s.Tenant, SproutID: s.ID})
}

// OpenStaged opens data, a staged recipe copy farmer sealed for s
// (cook.StagedRecipeKey), and returns its envelope.
func (s *Sprout) OpenStaged(data []byte) (cook.RecipeEnvelope, error) {
	var env cook.RecipeEnvelope
	m, err := s.Open(data, payloadbox.PurposeStagedRecipe)
	if err != nil {
		return env, err
	}
	err = json.Unmarshal(m.Body, &env)
	return env, err
}

// AnswerCooks subscribes nc to s's cook subject. Each dispatch must be
// sealed for s, or t fails; its envelope goes to the returned channel
// (buffered; a full channel drops it) and is answered with answer(env),
// sealed and bound to the dispatch.
func (s *Sprout) AnswerCooks(t testing.TB, nc *nats.Conn, answer func(cook.RecipeEnvelope) cook.Ack) <-chan cook.RecipeEnvelope {
	t.Helper()
	pushed := make(chan cook.RecipeEnvelope, 16)
	sub, err := nc.Subscribe(cook.CookSubject(s.ID), func(m *nats.Msg) {
		if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
			t.Errorf("cooktest: farmer sent %s a plaintext dispatch", s.ID)
			return
		}
		req, err := s.Open(m.Data, payloadbox.PurposeCookRequest)
		if err != nil {
			t.Errorf("cooktest: opening the dispatch to %s: %v", s.ID, err)
			return
		}
		var env cook.RecipeEnvelope
		if err := json.Unmarshal(req.Body, &env); err != nil {
			t.Errorf("cooktest: decoding the dispatch to %s: %v", s.ID, err)
			return
		}
		select {
		case pushed <- env:
		default:
		}
		reply, err := payloadbox.NewMessage(payloadbox.PurposeCookResponse, s.Tenant, s.ID, req.ID, answer(env))
		if err != nil {
			t.Error(err)
			return
		}
		r := nats.NewMsg("")
		r.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		if r.Data, err = payloadbox.Seal(reply, []payloadbox.KeyPair{{PeerPub: s.tenantPub, Priv: s.priv}}); err != nil {
			t.Error(err)
			return
		}
		_ = m.RespondMsg(r)
	})
	if err != nil {
		t.Fatalf("cooktest: subscribing %s: %v", s.ID, err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	return pushed
}
