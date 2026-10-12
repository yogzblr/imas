package pki

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/accountloader"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// pubTrust is a test operator signing key the publisher trusts.
type pubTrust struct {
	kp  nkeys.KeyPair
	pub string
}

func newPubTrust(t *testing.T) pubTrust {
	t.Helper()
	kp, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	return pubTrust{kp, pub}
}

func newAccount(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	return pub
}

// signAt signs an Account JWT for sub issued at iat (jwt/v2's Encode
// stamps the current time, so the payload is re-signed); lockedOut sets
// the connection limit to 0 and revoke adds user keys revoked as of a
// fixed time.
func (tr pubTrust) signAt(t *testing.T, sub string, iat int64, lockedOut bool, revoke ...string) string {
	t.Helper()
	ac := jwt.NewAccountClaims(sub)
	if lockedOut {
		ac.Limits.Conn = 0
	}
	for _, k := range revoke {
		ac.RevokeAt(k, time.Unix(50, 0))
	}
	enc, err := ac.Encode(tr.kp)
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
	m["jti"] = fmt.Sprintf("JTI%d%s%v", iat, sub, lockedOut)
	raw, _ = json.Marshal(m)
	toSign := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw)
	sig, err := tr.kp.Sign([]byte(toSign))
	if err != nil {
		t.Fatal(err)
	}
	return toSign + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func iatIn(t *testing.T, s string) int64 {
	t.Helper()
	ac, err := jwt.DecodeAccountClaims(s)
	if err != nil {
		t.Fatal(err)
	}
	return ac.IssuedAt
}

// seq is a shared, ordered record of what the fakes saw.
type seq struct {
	mu sync.Mutex
	ev []string
}

func (s *seq) add(e string) {
	s.mu.Lock()
	s.ev = append(s.ev, e)
	s.mu.Unlock()
}

func (s *seq) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.ev...)
}

func (s *seq) count(prefix string) int {
	n := 0
	for _, e := range s.all() {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

// recObjects records each PUT and can hold one before it is applied.
type recObjects struct {
	accountObjects
	seq       *seq
	beforePut func(key string)
}

func (r *recObjects) Put(ctx context.Context, key string, data []byte) error {
	if r.beforePut != nil {
		r.beforePut(key)
	}
	err := r.accountObjects.Put(ctx, key, data)
	if err == nil {
		r.seq.add("put " + key)
	}
	return err
}

// fakeBus records pushes and events.
type fakeBus struct {
	seq     *seq
	pushErr error
	missing int
	events  *[][]byte
	mu      *sync.Mutex
}

func (b fakeBus) pushAll(j string) (pushResult, error) {
	ac, _ := jwt.DecodeAccountClaims(j)
	b.seq.add(fmt.Sprintf("push %s %d", ac.Subject, ac.IssuedAt))
	return pushResult{acked: 1, missing: b.missing}, b.pushErr
}

func (b fakeBus) publish(subject string, payload []byte) error {
	b.seq.add("event " + subject)
	b.mu.Lock()
	*b.events = append(*b.events, payload)
	b.mu.Unlock()
	return nil
}

func (fakeBus) close() {}

type pubEnv struct {
	srv    *objectstoretest.Server
	store  *objectstore.Store
	tr     pubTrust
	seq    *seq
	objs   *recObjects
	p      *s3AccountPublisher
	events [][]byte
	mu     sync.Mutex
}

func newPubEnv(t *testing.T) *pubEnv {
	t.Helper()
	e := &pubEnv{srv: objectstoretest.NewServer(t), tr: newPubTrust(t), seq: &seq{}}
	st, err := objectstore.Open(e.srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	e.store = st
	e.objs = &recObjects{accountObjects: st, seq: e.seq}
	e.p = e.newPublisher()
	return e
}

// newPublisher is another replica's publisher on the same bucket.
func (e *pubEnv) newPublisher() *s3AccountPublisher {
	p := newS3AccountPublisher(e.objs, "", []string{e.tr.pub})
	p.openBus = func() (accountBus, error) { return fakeBus{seq: e.seq, events: &e.events, mu: &e.mu}, nil }
	p.local = func() ([]string, error) { return nil, nil }
	return p
}

func (e *pubEnv) object(t *testing.T, pub string) string {
	t.Helper()
	s, ok := e.srv.Object(accountloader.AccountKey(pub))
	if !ok {
		t.Fatalf("no object for %s", pub)
	}
	return s
}

func (e *pubEnv) seed(t *testing.T, pub, j string) {
	t.Helper()
	if err := e.store.Put(context.Background(), accountloader.AccountKey(pub), []byte(j)); err != nil {
		t.Fatal(err)
	}
}

func (e *pubEnv) eventAccounts(t *testing.T) []map[string]int64 {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []map[string]int64
	for _, b := range e.events {
		var ev struct {
			V        int              `json:"v"`
			Accounts map[string]int64 `json:"accounts"`
		}
		if err := json.Unmarshal(b, &ev); err != nil || ev.V != 1 {
			t.Fatalf("event %s: %v", b, err)
		}
		out = append(out, ev.Accounts)
	}
	return out
}

// §7.3: the object, then the index, then the push, then the event — the
// order the bus loaders (and cmd/farmerbus/loader_integration_test.go,
// which plays farmer) rely on.
func TestPublishOrderBucketThenIndexThenPushThenEvent(t *testing.T) {
	e := newPubEnv(t)
	pub := newAccount(t)
	j := e.tr.signAt(t, pub, 100, false)
	if err := e.p.Publish(context.Background(), pub, j); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"put " + accountloader.AccountKey(pub),
		"put " + accountloader.IndexKey,
		fmt.Sprintf("push %s 100", pub),
		"event imas.bus.accounts.changed",
	}
	if got := e.seq.all(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("order:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if e.object(t, pub) != j {
		t.Fatal("object does not hold the published JWT")
	}
	idx, _ := e.srv.Object(accountloader.IndexKey)
	var ix struct {
		V       int    `json:"v"`
		Token   string `json:"token"`
		Written string `json:"written"`
	}
	if err := json.Unmarshal([]byte(idx), &ix); err != nil || ix.V != 1 || len(ix.Token) != 26 || ix.Written == "" {
		t.Fatalf("index %q: %v", idx, err)
	}
	if evs := e.eventAccounts(t); len(evs) != 1 || evs[0][pub] != 100 {
		t.Fatalf("events %v, want one naming %s at 100", evs, pub)
	}

	// The same JWT again: no PUT and no event, but still pushed.
	if err := e.p.Publish(context.Background(), pub, j); err != nil {
		t.Fatal(err)
	}
	if e.seq.count("put ") != 2 || e.seq.count("push ") != 2 || e.seq.count("event ") != 1 {
		t.Fatalf("republishing the same JWT: %v", e.seq.all())
	}
}

func TestPublishRefusesToRegress(t *testing.T) {
	e := newPubEnv(t)
	pub := newAccount(t)
	newer := e.tr.signAt(t, pub, 200, false)
	e.seed(t, pub, newer)
	err := e.p.Publish(context.Background(), pub, e.tr.signAt(t, pub, 100, false))
	if !errors.Is(err, ErrAccountJWTSuperseded) {
		t.Fatalf("got %v, want ErrAccountJWTSuperseded", err)
	}
	if e.object(t, pub) != newer {
		t.Fatal("the older JWT replaced the newer one")
	}
	if n := len(e.seq.all()); n != 0 {
		t.Fatalf("an older JWT was written or pushed: %v", e.seq.all())
	}

	// At the same iat a lock-out outranks a live JWT, never the reverse.
	live := e.tr.signAt(t, pub, 300, false)
	locked := e.tr.signAt(t, pub, 300, true)
	if err := e.p.Publish(context.Background(), pub, locked); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Publish(context.Background(), pub, live); !errors.Is(err, ErrAccountJWTSuperseded) {
		t.Fatalf("live after lock-out at one iat: got %v, want ErrAccountJWTSuperseded", err)
	}
	if e.object(t, pub) != locked {
		t.Fatal("a live JWT replaced the lock-out of the same second")
	}
}

// An object that is not a trusted Account JWT for its key is replaced,
// whatever iat it claims.
func TestPublishReplacesUntrustedObject(t *testing.T) {
	e := newPubEnv(t)
	pub := newAccount(t)
	e.seed(t, pub, newPubTrust(t).signAt(t, pub, 9_999_999_999, false))
	j := e.tr.signAt(t, pub, 100, false)
	if err := e.p.Publish(context.Background(), pub, j); err != nil {
		t.Fatal(err)
	}
	if e.object(t, pub) != j {
		t.Fatal("an untrusted object kept the account from being published")
	}
}

// 7.3-T: two concurrent publishes for one account, iat 10 and 20, forced
// so the older one would reach its PUT last. Run as two replicas (two
// publishers sharing the database's row lease) and as one.
func TestPublishConcurrentOlderLandsLastKeepsNewer(t *testing.T) {
	for _, replicas := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d replicas", replicas), func(t *testing.T) {
			newTestDB(t)
			e := newPubEnv(t)
			a, b := e.p, e.p
			if replicas == 2 {
				b = e.newPublisher()
			}
			pub := newAccount(t)
			key := accountloader.AccountKey(pub)
			newer := e.tr.signAt(t, pub, 20, false)
			older := e.tr.signAt(t, pub, 10, false)

			inPut := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			e.objs.beforePut = func(k string) {
				if k == key {
					once.Do(func() { close(inPut); <-release })
				}
			}
			errs := make(chan error, 2)
			go func() { errs <- a.Publish(context.Background(), pub, newer) }()
			<-inPut // the newer one is inside its critical section, at its PUT
			go func() { errs <- b.Publish(context.Background(), pub, older) }()
			time.Sleep(300 * time.Millisecond) // the older one waits on the lock
			close(release)
			var got []error
			for range 2 {
				got = append(got, <-errs)
			}
			if got[0] != nil {
				t.Fatalf("newer publish: %v", got[0])
			}
			if !errors.Is(got[1], ErrAccountJWTSuperseded) {
				t.Fatalf("older publish: got %v, want ErrAccountJWTSuperseded", got[1])
			}
			if iat := iatIn(t, e.object(t, pub)); iat != 20 {
				t.Fatalf("object ended at iat %d, want 20", iat)
			}
		})
	}
}

func TestBucketFailureStillPushesLockout(t *testing.T) {
	e := newPubEnv(t)
	e.srv.Deny(func(op, _ string) bool { return op == http.MethodPut })
	for _, c := range []struct {
		name string
		jwt  func(pub string) string
	}{
		{"lock-out", func(pub string) string { return e.tr.signAt(t, pub, 100, true) }},
		{"revocation", func(pub string) string { return e.tr.signAt(t, pub, 100, false, newUserPub(t)) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			pub := newAccount(t)
			err := e.p.Publish(context.Background(), pub, c.jwt(pub))
			if err == nil || errors.Is(err, ErrAccountJWTSuperseded) {
				t.Fatalf("a failed bucket write returned %v, want the write error", err)
			}
			if e.seq.count("push "+pub) != 1 {
				t.Fatalf("the %s was not pushed: %v", c.name, e.seq.all())
			}
			if e.seq.count("event") != 0 {
				t.Fatalf("an event for an object that was never written: %v", e.seq.all())
			}
		})
	}
}

func TestBucketFailureNoPushForOrdinaryUpdate(t *testing.T) {
	e := newPubEnv(t)
	pub := newAccount(t)
	revoked := newUserPub(t)
	e.seed(t, pub, e.tr.signAt(t, pub, 100, false, revoked))
	e.srv.Deny(func(op, _ string) bool { return op == http.MethodPut })
	// Same revocation as the object holds: nothing tightens.
	err := e.p.Publish(context.Background(), pub, e.tr.signAt(t, pub, 200, false, revoked))
	if err == nil {
		t.Fatal("a failed bucket write returned nil")
	}
	if n := len(e.seq.all()); n != 0 {
		t.Fatalf("an ordinary update was pushed without its bucket write: %v", e.seq.all())
	}
}

// §7.5: a push that fails, or misses nodes, is not the caller's error.
func TestPublishPushFailureNotFatal(t *testing.T) {
	e := newPubEnv(t)
	e.p.openBus = func() (accountBus, error) {
		return fakeBus{seq: e.seq, events: &e.events, mu: &e.mu, pushErr: errors.New("no bus node answered"), missing: 3}, nil
	}
	pub := newAccount(t)
	if err := e.p.Publish(context.Background(), pub, e.tr.signAt(t, pub, 100, false)); err != nil {
		t.Fatalf("push failure returned %v, want nil (the bucket has it)", err)
	}
	e.p.openBus = func() (accountBus, error) { return nil, errors.New("bus down") }
	if err := e.p.Publish(context.Background(), pub, e.tr.signAt(t, pub, 101, false)); err != nil {
		t.Fatalf("bus unreachable returned %v, want nil", err)
	}
	if iat := iatIn(t, e.object(t, pub)); iat != 101 {
		t.Fatalf("object at %d, want 101", iat)
	}
}

func TestReconcileAllRepairsMissingAndRolledBackObjects(t *testing.T) {
	e := newPubEnv(t)
	missing, rolledBack, newerThere, same := newAccount(t), newAccount(t), newAccount(t), newAccount(t)
	local := []string{
		e.tr.signAt(t, missing, 100, false),
		e.tr.signAt(t, rolledBack, 300, false),
		e.tr.signAt(t, newerThere, 100, false),
		e.tr.signAt(t, same, 100, false),
		// A second, older copy of one account (the legacy tenant's two
		// files): the newer copy wins.
		e.tr.signAt(t, rolledBack, 250, false),
	}
	e.seed(t, rolledBack, e.tr.signAt(t, rolledBack, 200, false))
	newerJWT := e.tr.signAt(t, newerThere, 500, false)
	e.seed(t, newerThere, newerJWT)
	e.seed(t, same, local[3])
	e.p.local = func() ([]string, error) { return local, nil }

	if err := e.p.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.object(t, missing) != local[0] {
		t.Error("a missing object was not written")
	}
	if e.object(t, rolledBack) != local[1] {
		t.Error("a rolled-back object was not replaced by farmer's newer JWT")
	}
	if e.object(t, newerThere) != newerJWT {
		t.Error("ReconcileAll replaced a newer object")
	}
	if e.seq.count("put "+accountloader.IndexKey) != 1 {
		t.Errorf("index bumps: %v, want one", e.seq.all())
	}
	if e.seq.count("push ") != 0 {
		t.Errorf("ReconcileAll pushed: %v", e.seq.all())
	}
	evs := e.eventAccounts(t)
	if len(evs) != 1 || len(evs[0]) != 2 || evs[0][missing] != 100 || evs[0][rolledBack] != 300 {
		t.Fatalf("events %v, want one naming the two written accounts", evs)
	}

	// Nothing changed since: no GET of an unchanged object, no write.
	puts := e.seq.count("put ")
	if err := e.p.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.seq.count("put ") != puts || len(e.eventAccounts(t)) != 1 {
		t.Fatalf("a second ReconcileAll wrote or announced: %v", e.seq.all())
	}
}

// The writer credential farmer publishes with is one the loader refuses
// to start with: the loader's start-up check (brief §10) demands a
// credential that cannot write, and only a read-only one passes it.
func TestFarmerWriteCredentialCannotBeUsedByLoader(t *testing.T) {
	e := newPubEnv(t)
	pub := newAccount(t)
	if err := e.p.Publish(context.Background(), pub, e.tr.signAt(t, pub, 100, false)); err != nil {
		t.Fatalf("writer publish: %v", err)
	}
	rp := objectstore.RetryPolicy{MaxAttempts: 2, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond}
	writer := accountloader.NewStoreSource(func() (*objectstore.Store, error) { return e.store, nil })
	if err := writer.CheckReadOnly(context.Background(), rp); !errors.Is(err, objectstore.ErrAccessAllowed) {
		t.Fatalf("loader check with the writer credential: got %v, want ErrAccessAllowed", err)
	}
	e.srv.Deny(func(op, _ string) bool { return op == http.MethodPut || op == http.MethodDelete })
	if err := writer.CheckReadOnly(context.Background(), rp); err != nil {
		t.Fatalf("loader check with a read-only credential: %v", err)
	}
	if err := e.p.Publish(context.Background(), pub, e.tr.signAt(t, pub, 101, false)); err == nil {
		t.Fatal("a read-only credential could publish")
	}
}

// fakeNodes answers the server ping and the claims update on a plain
// nats-server as n bus nodes would; node i answers the claims update
// only from round answerFrom[i] on (0: the first), or never (-1).
func fakeNodes(t *testing.T, answerFrom []int, reject bool) *nats.Conn {
	t.Helper()
	opts := &nats_server.Options{Host: "127.0.0.1", Port: -1}
	s, err := nats_server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats-server not ready")
	}
	t.Cleanup(s.Shutdown)
	for i, from := range answerFrom {
		nc, err := nats.Connect(s.ClientURL())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(nc.Close)
		id := fmt.Sprintf("NODE%d", i)
		_, _ = nc.Subscribe(serverPingSubject, func(m *nats.Msg) {
			_ = m.Respond([]byte(fmt.Sprintf(`{"server":{"id":%q},"statsz":{}}`, id)))
		})
		var mu sync.Mutex
		round := 0
		_, _ = nc.Subscribe(claimsUpdateSubject, func(m *nats.Msg) {
			mu.Lock()
			r := round
			round++
			mu.Unlock()
			if from < 0 || r < from {
				return
			}
			resp := nats_server.ServerAPIClaimUpdateResponse{Server: &nats_server.ServerInfo{ID: id}}
			if reject {
				resp.Error = &nats_server.ClaimUpdateError{Code: 400, Description: "bad JWT"}
			} else {
				resp.Data = &nats_server.ClaimUpdateStatus{Code: 200, Message: "jwt updated"}
			}
			b, _ := json.Marshal(resp)
			_ = m.Respond(b)
		})
		_ = nc.Flush()
	}
	nc, err := nats.Connect(s.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func fastPushTimings(t *testing.T) {
	t.Helper()
	old := []time.Duration{discoverWait, discoverQuiet, pushRoundWait, pushBackoffMin, pushBackoffMax}
	discoverWait, discoverQuiet, pushRoundWait, pushBackoffMin, pushBackoffMax =
		500*time.Millisecond, 100*time.Millisecond, 300*time.Millisecond, 10*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() {
		discoverWait, discoverQuiet, pushRoundWait, pushBackoffMin, pushBackoffMax = old[0], old[1], old[2], old[3], old[4]
	})
}

// §7.4: the push waits for every node found by the ping, re-publishing
// for one that answers only a later round.
func TestPushToAllNodesWaitsForEveryNode(t *testing.T) {
	fastPushTimings(t)
	nc := fakeNodes(t, []int{0, 0, 2}, false)
	res, err := pushToAllNodes(nc, "JWT", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.acked != 3 || res.missing != 0 {
		t.Fatalf("got %+v, want all 3 nodes acked", res)
	}
}

func TestPushToAllNodesMissingNodeNonFatal(t *testing.T) {
	fastPushTimings(t)
	nc := fakeNodes(t, []int{0, 0, -1}, false)
	res, err := pushToAllNodes(nc, "JWT", 0)
	if err != nil {
		t.Fatalf("a missing node made the push fail: %v", err)
	}
	if res.acked != 2 || res.missing != 1 {
		t.Fatalf("got %+v, want 2 acked and 1 missing", res)
	}
	// IMAS_BUS_EXPECTED_NODES above what answers the ping counts too.
	res, err = pushToAllNodes(nc, "JWT", 5)
	if err != nil || res.acked != 2 || res.missing != 3 {
		t.Fatalf("expected 5: got %+v, %v; want 2 acked and 3 missing", res, err)
	}
}

func TestPushToAllNodesFailures(t *testing.T) {
	fastPushTimings(t)
	if _, err := pushToAllNodes(fakeNodes(t, []int{0}, true), "JWT", 0); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("a rejection: got %v", err)
	}
	if _, err := pushToAllNodes(fakeNodes(t, []int{-1}, false), "JWT", 0); err == nil {
		t.Fatal("no node accepting returned nil")
	}
}

// recordingPublisher stands in for the bucket in the pki flows: it
// records every Account JWT pushed.
type recordingPublisher struct {
	mu   sync.Mutex
	jwts map[string][]string
}

func (r *recordingPublisher) Publish(_ context.Context, pub, j string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.jwts == nil {
		r.jwts = map[string][]string{}
	}
	r.jwts[pub] = append(r.jwts[pub], j)
	return nil
}

func (*recordingPublisher) ReconcileAll(context.Context) error { return nil }

func (r *recordingPublisher) last(t *testing.T, pub string) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	js := r.jwts[pub]
	if len(js) == 0 {
		t.Fatalf("nothing published for %s", pub)
	}
	return js[len(js)-1]
}

func useRecordingPublisher(t *testing.T) *recordingPublisher {
	t.Helper()
	r := &recordingPublisher{}
	SetAccountPublisher(r)
	t.Cleanup(func() { SetAccountPublisher(nil) })
	return r
}

// §7.3 step 1: every re-sign gets a strictly newer iat than the JWT it
// replaces, so the bus loaders never read a change as the same JWT (the
// jti hashes only subject, issuer, name and iat).
func TestEveryResignAdvancesIat(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	rec := useRecordingPublisher(t)

	add := func(tenantID, sproutID string) {
		kp, _ := nkeys.CreateUser()
		pub, _ := kp.PublicKey()
		if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: sproutID, NKey: pub, State: stateAccepted}); err != nil {
			t.Fatal(err)
		}
	}
	// resign changes a sprout's state twice (deny, then accept again),
	// each followed by reload, and checks the second Account JWT pushed
	// is issued after the first.
	resign := func(what string, reload func() error, pub func() string, tenantID, sproutID string) {
		t.Run(what, func(t *testing.T) {
			var iats []int64
			for _, state := range []string{stateDenied, stateAccepted} {
				if err := setStateInTenant(tenantID, sproutID, state); err != nil {
					t.Fatal(err)
				}
				if err := reload(); err != nil {
					t.Fatal(err)
				}
				iats = append(iats, iatIn(t, rec.last(t, pub())))
			}
			if iats[1] <= iats[0] {
				t.Fatalf("re-signed at iat %d, not after %d", iats[1], iats[0])
			}
		})
	}

	legacy := currentTenantID()
	add(legacy, "web-a")
	if err := ReloadNKeys(); err != nil {
		t.Fatal(err)
	}
	resign("syncNatsAuth (jwtusers.go)", ReloadNKeys,
		func() string { mat, _ := ensureNatsAuth(); return mat.tenantPub }, legacy, "web-a")

	if err := ProvisionTenant("t_iat", "Iat Co"); err != nil {
		t.Fatal(err)
	}
	tenantPub := func() string {
		tam, err := loadTenantAccountMaterial("t_iat")
		if err != nil {
			t.Fatal(err)
		}
		return tam.pub
	}
	add("t_iat", "web-b")
	resign("syncTenantSprouts (tenant.go)", func() error { return ReloadNKeysForTenant("t_iat") }, tenantPub, "t_iat", "web-b")

	t.Run("SaaS API key rotation (saasapi_user.go)", func(t *testing.T) {
		state := useTestSaaSAPICredentialState(t)
		mat, err := ensurePlatformAuth()
		if err != nil {
			t.Fatal(err)
		}
		var iats []int64
		for range 3 {
			kp, _ := nkeys.CreateUser()
			seed, _ := kp.Seed()
			pub, _ := kp.PublicKey()
			t.Setenv("IMAS_NATS_SAASAPI_USER_SEED", string(seed))
			recordSaaSAPIKey(t, state, pub)
			if _, _, err := EnsureSaaSAPICredential(); err != nil {
				t.Fatal(err)
			}
			rec.mu.Lock()
			if js := rec.jwts[mat.sysAccountPub]; len(js) > 0 {
				iats = append(iats, iatIn(t, js[len(js)-1]))
			}
			rec.mu.Unlock()
		}
		if len(iats) < 2 || iats[len(iats)-1] <= iats[len(iats)-2] {
			t.Fatalf("SYS Account JWTs pushed at iats %v, want each rotation's later than the last", iats)
		}
	})

	t.Run("signLockedOutTenantJWT (tenant.go)", func(t *testing.T) {
		pub := tenantPub()
		before := iatIn(t, rec.last(t, pub))
		if err := DeprovisionTenant("t_iat"); err != nil {
			t.Fatal(err)
		}
		locked := rec.last(t, pub)
		if iatIn(t, locked) <= before {
			t.Fatalf("lock-out at iat %d, not after %d", iatIn(t, locked), before)
		}
		if err := DeprovisionTenant("t_iat"); err != nil {
			t.Fatal(err)
		}
		if again := rec.last(t, pub); iatIn(t, again) <= iatIn(t, locked) {
			t.Fatalf("second lock-out at iat %d, not after %d", iatIn(t, again), iatIn(t, locked))
		}
	})
}

// pushAccountUpdate, the choke point every push goes through: an older
// JWT than the bucket's is not pushed and is not the caller's error,
// unless it is a lock-out.
func TestPushAccountUpdateSupersededJWT(t *testing.T) {
	e := newPubEnv(t)
	SetAccountPublisher(e.p)
	t.Cleanup(func() { SetAccountPublisher(nil) })
	pub := newAccount(t)
	e.seed(t, pub, e.tr.signAt(t, pub, 200, false))
	if err := pushAccountUpdate(nil, e.tr.signAt(t, pub, 100, false)); err != nil {
		t.Fatalf("an older live JWT: got %v, want nil", err)
	}
	if err := pushAccountUpdate(nil, e.tr.signAt(t, pub, 100, true)); err == nil {
		t.Fatal("an older lock-out returned nil")
	}
	if n := e.seq.count("push "); n != 0 {
		t.Fatalf("an older JWT was pushed: %v", e.seq.all())
	}
}
