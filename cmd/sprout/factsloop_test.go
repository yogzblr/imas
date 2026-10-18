package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
)

type fakePub struct {
	mu   sync.Mutex
	msgs []*nats.Msg
}

func (f *fakePub) PublishMsg(m *nats.Msg) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, m)
	return nil
}

func (f *fakePub) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.msgs)
}

// factsKeys gives the sprout box keys in a temporary directory and returns
// the key pair farmer opens its reports with: the sprout's box public key
// and the tenant's private key.
func factsKeys(t *testing.T, tenant string) payloadbox.KeyPair {
	t.Helper()
	useFactsKeyPaths(t)
	return writeFactsKeys(t, tenant)
}

// useFactsKeyPaths points the sprout's key files into a new temporary
// directory, with no keys in it yet.
func useFactsKeyPaths(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldPriv, oldPub := config.SproutBoxPrivFile, config.SproutTenantX25519PubFile
	t.Cleanup(func() { config.SproutBoxPrivFile, config.SproutTenantX25519PubFile = oldPriv, oldPub })
	config.SproutBoxPrivFile = filepath.Join(dir, "box.key")
	config.SproutTenantX25519PubFile = filepath.Join(dir, "tenant-x25519.pub")
}

// writeFactsKeys writes a sprout box key and a pinned tenant at the
// configured paths and returns the pair farmer opens reports with.
func writeFactsKeys(t *testing.T, tenant string) payloadbox.KeyPair {
	t.Helper()
	sproutPub, sproutPriv, _ := box.GenerateKey(rand.Reader)
	tenantPub, tenantPriv, _ := box.GenerateKey(rand.Reader)
	if err := os.WriteFile(pki.SproutTenantIDFile(), []byte(tenant), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(path string, b []byte) {
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(b)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(config.SproutTenantX25519PubFile, tenantPub[:])
	write(config.SproutBoxPrivFile, sproutPriv[:])
	return payloadbox.KeyPair{PeerPub: sproutPub, Priv: tenantPriv}
}

// Facts go out sealed (s2f.facts) on the sprout's own subject, and open
// under farmer's keys to this sprout's report.
func TestPublishFactsSealed(t *testing.T) {
	pair := factsKeys(t, "t_facts")
	p := &fakePub{}
	if err := publishFacts(p, "web-01"); err != nil {
		t.Fatal(err)
	}
	m := p.msgs[0]
	if m.Subject != "imas.sprouts.web-01.facts" || m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		t.Fatalf("subject %q, header %v", m.Subject, m.Header)
	}
	var plain facts.SystemFacts
	if json.Unmarshal(m.Data, &plain) == nil && plain.OS != "" {
		t.Fatal("facts went out in plaintext")
	}
	msg, err := payloadbox.Open(m.Data, []payloadbox.KeyPair{pair},
		payloadbox.Expect{Purpose: payloadbox.PurposeFacts, TenantID: "t_facts", SproutID: "web-01"})
	if err != nil {
		t.Fatal(err)
	}
	var sf facts.SystemFacts
	if err := json.Unmarshal(msg.Body, &sf); err != nil {
		t.Fatal(err)
	}
	if sf.SproutID != "web-01" || sf.OS == "" {
		t.Fatalf("facts %+v", sf)
	}
}

// A sprout without box keys sends nothing, and starts as soon as it has
// them.
func TestFactsRepublisherWaitsForKeys(t *testing.T) {
	useFactsKeyPaths(t)
	if err := publishFacts(&fakePub{}, "web-01"); err != pki.ErrSproutBoxNotReady {
		t.Fatalf("publishFacts without keys = %v", err)
	}
	p := &fakePub{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runFactsRepublisher(ctx, p, "web-01", 20*time.Millisecond); close(done) }()
	time.Sleep(100 * time.Millisecond)
	if p.count() != 0 {
		cancel()
		<-done
		t.Fatalf("published %d times without keys", p.count())
	}
	writeFactsKeys(t, "t_facts")
	deadline := time.Now().Add(2 * time.Second)
	for p.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if p.count() == 0 {
		t.Fatal("no facts sent once the sprout had keys")
	}
}

// facts.request is answered with the sealed report, or refused with
// no-keys: never with facts in plaintext.
func TestAnswerFactsRequest(t *testing.T) {
	pair := factsKeys(t, "t_facts")
	nc, stop := startFactsBus(t)
	defer stop()
	sub, _ := nc.Subscribe("imas.sprouts.web-01.facts.request", func(m *nats.Msg) { answerFactsRequest(m, "web-01") })
	defer sub.Unsubscribe()
	resp, err := nc.Request("imas.sprouts.web-01.facts.request", nil, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := payloadbox.Open(resp.Data, []payloadbox.KeyPair{pair},
		payloadbox.Expect{Purpose: payloadbox.PurposeFacts, TenantID: "t_facts", SproutID: "web-01"}); err != nil {
		t.Fatalf("reply did not open: %v", err)
	}
	config.SproutBoxPrivFile = filepath.Join(t.TempDir(), "gone.key")
	resp, err = nc.Request("imas.sprouts.web-01.facts.request", nil, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get(payloadbox.ErrorHeader) != payloadbox.ErrorCodeNoKeys || len(resp.Data) != 0 {
		t.Fatalf("reply without keys: %v %q", resp.Header, resp.Data)
	}
}

func TestFactsRepublisherRepeatsAndStops(t *testing.T) {
	factsKeys(t, "t_facts")
	p := &fakePub{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runFactsRepublisher(ctx, p, "web-01", 10*time.Millisecond); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for p.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if p.count() < 3 {
		t.Fatalf("published %d times, want at least 3", p.count())
	}
}

func startFactsBus(t *testing.T) (*nats.Conn, func()) {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	return nc, func() { nc.Close(); ns.Shutdown() }
}

func TestFactsRepublishBeatsPropTTL(t *testing.T) {
	if 2*factsRepublishInterval >= props.DefaultPropTTL {
		t.Fatalf("interval %v too long for TTL %v", factsRepublishInterval, props.DefaultPropTTL)
	}
	if factsKeyWait > factsRepublishInterval {
		t.Fatalf("key wait %v longer than the interval", factsKeyWait)
	}
}
