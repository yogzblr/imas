package accountloader

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// testTrust is an operator signing key and a SYS account.
type testTrust struct {
	op     nkeys.KeyPair
	opPub  string
	sysPub string
}

func newTrust(t *testing.T) *testTrust {
	t.Helper()
	op, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	opPub, _ := op.PublicKey()
	return &testTrust{op: op, opPub: opPub, sysPub: newAccountPub(t)}
}

func newAccountPub(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	return pub
}

// signAt signs an Account JWT for sub with the given issued-at (jwt/v2's
// Encode always stamps the current time, so the payload is re-signed).
// conn 0 is a lock-out; tag makes JWTs with the same iat differ.
func signAt(t *testing.T, signer nkeys.KeyPair, sub string, iat, conn int64, tag string) string {
	t.Helper()
	ac := jwt.NewAccountClaims(sub)
	ac.Limits.Conn = conn
	ac.Name = tag
	enc, err := ac.Encode(signer)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(enc, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["iat"] = iat
	m["jti"] = fmt.Sprintf("JTI%d%s", iat, tag)
	raw, _ = json.Marshal(m)
	toSign := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw)
	sig, err := signer.Sign([]byte(toSign))
	if err != nil {
		t.Fatal(err)
	}
	return toSign + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (tr *testTrust) jwt(t *testing.T, sub string, iat int64) string {
	return signAt(t, tr.op, sub, iat, -1, "")
}

func iatOf(t *testing.T, s string) int64 {
	t.Helper()
	ac, err := jwt.DecodeAccountClaims(s)
	if err != nil {
		t.Fatal(err)
	}
	return ac.IssuedAt
}

// bucket is the fake S3 server plus a writer client.
type bucket struct {
	srv *objectstoretest.Server
	w   *objectstore.Store
}

func newBucket(t *testing.T) *bucket {
	t.Helper()
	srv := objectstoretest.NewServer(t)
	w, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	return &bucket{srv: srv, w: w}
}

func (b *bucket) put(t *testing.T, key, body string) {
	t.Helper()
	if err := b.w.Put(context.Background(), key, []byte(body)); err != nil {
		t.Fatal(err)
	}
}

func (b *bucket) putAccount(t *testing.T, pub, j string) { b.put(t, AccountKey(pub), j) }

func (b *bucket) bumpIndex(t *testing.T, token string) {
	b.put(t, IndexKey, fmt.Sprintf(`{"v":1,"token":%q,"written":"2026-10-11T00:00:00Z"}`, token))
}

func (b *bucket) source(t *testing.T) *StoreSource {
	t.Helper()
	cfg := b.srv.Config()
	return NewStoreSource(func() (*objectstore.Store, error) { return objectstore.Open(cfg) })
}

// src is the bucket's source wrapped in a hookSource, which also hides
// the read-only self-check (the fake bucket lets everyone write).
func (b *bucket) src(t *testing.T) *hookSource {
	return &hookSource{ObjectSource: b.source(t)}
}

var errDown = errors.New("injected object store outage")

// hookSource wraps a source so a test can intercept Gets or take the
// store down.
type hookSource struct {
	ObjectSource
	mu        sync.Mutex
	beforeGet func(key string)
	down      atomic.Bool
}

func (h *hookSource) setBeforeGet(fn func(key string)) {
	h.mu.Lock()
	h.beforeGet = fn
	h.mu.Unlock()
}

func (h *hookSource) Index(ctx context.Context) (string, error) {
	if h.down.Load() {
		return "", errDown
	}
	return h.ObjectSource.Index(ctx)
}

func (h *hookSource) List(ctx context.Context) ([]ObjInfo, error) {
	if h.down.Load() {
		return nil, errDown
	}
	return h.ObjectSource.List(ctx)
}

func (h *hookSource) Get(ctx context.Context, key string) ([]byte, ObjInfo, error) {
	h.mu.Lock()
	fn := h.beforeGet
	h.mu.Unlock()
	if fn != nil {
		fn(key)
	}
	if h.down.Load() {
		return nil, ObjInfo{}, errDown
	}
	return h.ObjectSource.Get(ctx, key)
}

// fakeNode is an in-memory bus node: Push stores unconditionally, as the
// real CLAIMS.UPDATE handler does.
type fakeNode struct {
	mu        sync.Mutex
	id        string
	held      map[string]string
	pushes    []string // account pubs, in push order
	failPush  int      // the next n pushes fail
	afterPush func(pub, jwt string)
	peers     [][]byte // extra lookup answers, as from routed nodes
	subs      map[string]func([]byte)
	dropList  map[string]bool // ids ListIDs leaves out
}

func newFakeNode() *fakeNode {
	return &fakeNode{id: "NODE1", held: map[string]string{}, subs: map[string]func([]byte){}, dropList: map[string]bool{}}
}

func (n *fakeNode) Push(_ context.Context, pub string, j []byte) error {
	n.mu.Lock()
	if n.id == "" {
		n.mu.Unlock()
		return ErrNotConnected
	}
	if n.failPush > 0 {
		n.failPush--
		n.mu.Unlock()
		return fmt.Errorf("injected push failure")
	}
	n.held[pub] = string(j)
	n.pushes = append(n.pushes, pub)
	after := n.afterPush
	n.mu.Unlock()
	if after != nil {
		after(pub, string(j))
	}
	return nil
}

func (n *fakeNode) ListIDs(context.Context) (string, []string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.id == "" {
		return "", nil, ErrNotConnected
	}
	var ids []string
	for k := range n.held {
		if !n.dropList[k] {
			ids = append(ids, k)
		}
	}
	slices.Sort(ids)
	return n.id, ids, nil
}

func (n *fakeNode) Lookup(_ context.Context, pub string) ([][]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := [][]byte{[]byte(n.held[pub])}
	return append(out, n.peers...), nil
}

func (n *fakeNode) ConnectedServerID() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.id
}

func (n *fakeNode) Subscribe(subject string, fn func([]byte)) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.subs[subject] = fn
	return nil
}

func (n *fakeNode) pushCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.pushes)
}

func (n *fakeNode) holds(pub string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.held[pub]
}

// fastConfig is a Config with tiny waits.
func fastConfig(tr *testTrust, src ObjectSource, node NodeClient) Config {
	return Config{
		Source:             src,
		Node:               node,
		Trusted:            []string{tr.opPub},
		SysAccount:         tr.sysPub,
		ReconcileInterval:  time.Hour,
		FullResyncInterval: time.Hour,
		PushRate:           1e6,
		Backoff:            Backoff{Min: time.Millisecond, Max: 5 * time.Millisecond},
		PushBackoff:        Backoff{Min: time.Millisecond, Max: 2 * time.Millisecond},
		RequestTimeout:     5 * time.Second,
		EventWindow:        200 * time.Millisecond,
		LookupWindow:       50 * time.Millisecond,
	}
}

func newLoader(t *testing.T, cfg Config) *Loader {
	t.Helper()
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// run starts l.Run and stops it at the end of the test.
func run(t *testing.T, l *Loader) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
	return done
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
