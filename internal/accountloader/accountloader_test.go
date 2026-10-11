package accountloader

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/objectstore"
)

// seed puts the SYS account and n tenant accounts at iat 100 and returns
// the tenant pubs.
func seed(t *testing.T, tr *testTrust, b *bucket, n int) []string {
	t.Helper()
	b.putAccount(t, tr.sysPub, tr.jwt(t, tr.sysPub, 100))
	var pubs []string
	for range n {
		p := newAccountPub(t)
		b.putAccount(t, p, tr.jwt(t, p, 100))
		pubs = append(pubs, p)
	}
	b.bumpIndex(t, "T0")
	return pubs
}

func TestLoadAllReadyOnlyAfterEveryKeyPushed(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	pubs := seed(t, tr, b, 5)
	src := b.src(t)
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	src.setBeforeGet(func(key string) {
		if key == AccountKey(pubs[3]) {
			once.Do(func() { close(held); <-release })
		}
	})
	cfg := fastConfig(tr, src, node)
	cfg.PushConcurrency = 1
	l := newLoader(t, cfg)
	run(t, l)

	<-held
	time.Sleep(50 * time.Millisecond)
	if l.Ready() {
		t.Fatal("ready while a Get was still held")
	}
	close(release)
	waitFor(t, "ready", l.Ready)
	if got := node.pushCount(); got != 6 {
		t.Errorf("pushes = %d, want 6", got)
	}
	st := l.Status()
	if st.Target != 6 || st.Applied != 6 || st.State != StateReady || st.LastIndexToken != "T0" {
		t.Errorf("status = %+v", st)
	}
}

func TestLoadAllWaitsForSysAccountObject(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	p := newAccountPub(t)
	b.putAccount(t, p, tr.jwt(t, p, 100))
	l := newLoader(t, fastConfig(tr, b.src(t), node))
	run(t, l)
	waitFor(t, "bucket not initialised", func() bool { return l.Status().State == StateNotInitialised })
	if l.Ready() {
		t.Fatal("ready without the SYS account object")
	}
	b.putAccount(t, tr.sysPub, tr.jwt(t, tr.sysPub, 100))
	waitFor(t, "ready", l.Ready)
	if node.holds(tr.sysPub) == "" || node.holds(p) == "" {
		t.Error("node does not hold both accounts")
	}
}

func TestInvalidSysAccountNotReady(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	rogue := newTrust(t)
	b.putAccount(t, tr.sysPub, rogue.jwt(t, tr.sysPub, 100))
	l := newLoader(t, fastConfig(tr, b.src(t), node))
	run(t, l)
	waitFor(t, "SYS invalid", func() bool { return l.Status().State == StateSysInvalid })
	b.putAccount(t, tr.sysPub, tr.jwt(t, tr.sysPub, 100))
	waitFor(t, "ready", l.Ready)
}

func TestTenantAddedDuringStartupIsLoaded(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	seed(t, tr, b, 2)
	late := newAccountPub(t)
	src := b.src(t)
	var once sync.Once
	src.setBeforeGet(func(string) {
		once.Do(func() { b.putAccount(t, late, tr.jwt(t, late, 100)) })
	})
	l := newLoader(t, fastConfig(tr, src, node))
	run(t, l)
	waitFor(t, "ready", l.Ready)
	if node.holds(late) == "" {
		t.Fatal("ready without the account added during start-up")
	}
	if st := l.Status(); st.Target != 4 {
		t.Errorf("target = %d, want 4", st.Target)
	}
}

func TestStartupNeverReadyWhileKeysKeepChanging(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	seed(t, tr, b, 1)
	src := b.src(t)
	var adding atomic.Bool
	adding.Store(true)
	src.setBeforeGet(func(string) {
		if adding.Load() {
			p := newAccountPub(t)
			b.putAccount(t, p, tr.jwt(t, p, 100))
		}
	})
	cfg := fastConfig(tr, src, node)
	cfg.MaxPasses = 3
	l := newLoader(t, cfg)
	run(t, l)
	waitFor(t, "initial load incomplete", func() bool { return l.Status().State == StateIncomplete })
	if l.Ready() {
		t.Fatal("ready with keys still changing")
	}
	adding.Store(false)
	waitFor(t, "ready", l.Ready)
}

func TestOwnNodeMissingAccountNotReady(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	pubs := seed(t, tr, b, 2)
	node.mu.Lock()
	node.dropList[pubs[1]] = true
	node.mu.Unlock()
	l := newLoader(t, fastConfig(tr, b.src(t), node))
	run(t, l)
	waitFor(t, "node missing", func() bool { return l.Status().State == StateNodeMissing })
	if l.Ready() {
		t.Fatal("ready while the node does not list an account")
	}
	node.mu.Lock()
	delete(node.dropList, pubs[1])
	node.mu.Unlock()
	waitFor(t, "ready", l.Ready)
}

func TestWaitsForNodeConnection(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	seed(t, tr, b, 1)
	node.mu.Lock()
	node.id = ""
	node.mu.Unlock()
	l := newLoader(t, fastConfig(tr, b.src(t), node))
	run(t, l)
	waitFor(t, "waiting for node", func() bool { return l.Status().State == StateWaitingNode })
	node.mu.Lock()
	node.id = "NODE1"
	node.mu.Unlock()
	waitFor(t, "ready", l.Ready)
}

// ready starts a loader over n seeded accounts and waits until it is ready.
func ready(t *testing.T, n int) (*testTrust, *bucket, *fakeNode, *hookSource, *Loader, []string) {
	t.Helper()
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	pubs := seed(t, tr, b, n)
	src := b.src(t)
	l := newLoader(t, fastConfig(tr, src, node))
	run(t, l)
	waitFor(t, "ready", l.Ready)
	return tr, b, node, src, l, pubs
}

func TestOlderJWTNotPushed(t *testing.T) {
	tr, b, node, _, l, pubs := ready(t, 0)
	p := newAccountPub(t)
	b.putAccount(t, p, tr.jwt(t, p, 200))
	b.bumpIndex(t, "T1")
	l.HandleEvent([]byte(`{"v":1,"token":"T1"}`))
	waitFor(t, "iat 200 pushed", func() bool { return node.holds(p) != "" })
	before := node.pushCount()

	b.putAccount(t, p, tr.jwt(t, p, 100))
	b.bumpIndex(t, "T2")
	l.HandleEvent([]byte(`{"v":1,"token":"T2"}`))
	waitFor(t, "stale counted", func() bool { return l.Status().Counters[CounterStaleSkipped] == 1 })
	if got := node.pushCount(); got != before {
		t.Errorf("pushes went from %d to %d for an older JWT", before, got)
	}
	if got := iatOf(t, node.holds(p)); got != 200 {
		t.Errorf("node holds iat %d, want 200", got)
	}
	_ = pubs
}

func TestEqualIatDifferentJtiLockoutWins(t *testing.T) {
	tr, b, node, _, l, pubs := ready(t, 1)
	p := pubs[0]
	locked := signAt(t, tr.op, p, 100, 0, "lock")
	b.putAccount(t, p, locked)
	l.HandleEvent([]byte(`{"v":1}`))
	waitFor(t, "lock-out pushed", func() bool { return node.holds(p) == locked })

	live := signAt(t, tr.op, p, 100, -1, "zzzz")
	b.putAccount(t, p, live)
	l.HandleEvent([]byte(`{"v":1}`))
	waitFor(t, "live JWT processed", func() bool { return !l.changed([]ObjInfo{{Key: AccountKey(p), ETag: etagOf(t, b, p)}}) })
	if node.holds(p) != locked {
		t.Error("a live JWT at the same issued-at replaced the lock-out")
	}
}

func etagOf(t *testing.T, b *bucket, pub string) string {
	t.Helper()
	_, info, err := b.w.GetLimitedWithInfo(context.Background(), AccountKey(pub), MaxJWTSize)
	if err != nil {
		t.Fatal(err)
	}
	return info.ETag
}

func TestInvalidJWTSkipped(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	pubs := seed(t, tr, b, 1)
	rogue := newTrust(t)
	wrongSub, badSig, untrusted, badKey := newAccountPub(t), newAccountPub(t), newAccountPub(t), "accounts/not-a-key.jwt"
	b.putAccount(t, wrongSub, tr.jwt(t, pubs[0], 100))
	good := tr.jwt(t, badSig, 100)
	b.putAccount(t, badSig, good[:len(good)-4]+"AAAA")
	b.putAccount(t, untrusted, rogue.jwt(t, untrusted, 100))
	b.put(t, badKey, good)
	l := newLoader(t, fastConfig(tr, b.src(t), node))
	run(t, l)
	waitFor(t, "ready", l.Ready)
	for _, p := range []string{wrongSub, badSig, untrusted} {
		if node.holds(p) != "" {
			t.Errorf("invalid JWT for %s pushed", p)
		}
	}
	st := l.Status()
	if len(st.Invalid) != 4 || st.Counters[CounterInvalid] != 4 || st.Target != 2 {
		t.Errorf("status = %+v, want 4 invalid and target 2", st)
	}

	// A valid account that later turns invalid keeps its held copy.
	held := node.holds(pubs[0])
	b.putAccount(t, pubs[0], rogue.jwt(t, pubs[0], 300))
	l.HandleEvent([]byte(`{"v":1}`))
	waitFor(t, "fifth invalid", func() bool { return l.Status().Counters[CounterInvalid] == 5 })
	if node.holds(pubs[0]) != held {
		t.Error("held copy replaced by an invalid JWT")
	}
}

func TestOversizedObjectRejected(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	pubs := seed(t, tr, b, 1)
	big := strings.Repeat("a", MaxJWTSize+1)
	tooBig := newAccountPub(t)
	b.putAccount(t, tooBig, big)
	l := newLoader(t, fastConfig(tr, b.src(t), node))
	run(t, l)
	waitFor(t, "ready despite an oversized object", l.Ready)
	if st := l.Status(); st.Counters[CounterInvalid] != 1 || len(st.Invalid) != 1 || st.Counters[CounterS3Errors] != 0 {
		t.Errorf("status = %+v, want one invalid object and no S3 error", st)
	}

	// An account that grows over the cap keeps its held copy.
	b.putAccount(t, pubs[0], big)
	l.HandleEvent([]byte(`{"v":1}`))
	waitFor(t, "second invalid", func() bool { return l.Status().Counters[CounterInvalid] == 2 })
	if iatOf(t, node.holds(pubs[0])) != 100 {
		t.Error("held copy lost")
	}
}

func TestObjectDisappearingKeepsHeldCopy(t *testing.T) {
	_, b, node, _, l, pubs := ready(t, 1)
	held := node.holds(pubs[0])
	if err := b.w.Delete(context.Background(), AccountKey(pubs[0])); err != nil {
		t.Fatal(err)
	}
	if err := l.processKey(context.Background(), AccountKey(pubs[0]), "stale-listing-etag"); err != nil {
		t.Fatal(err)
	}
	l.HandleEvent([]byte(`{"v":1}`))
	waitFor(t, "missing counted", func() bool { return l.Status().Counters[CounterObjectMissing] == 1 })
	if node.holds(pubs[0]) != held || l.Status().Applied != 2 {
		t.Error("held copy dropped after the object disappeared")
	}
	if l.changed([]ObjInfo{{Key: AccountKey(pubs[0]), ETag: "stale-listing-etag"}}) {
		t.Error("a listed object that has gone still counts as unprocessed")
	}
}

func TestS3DownAtStartNotReady(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	seed(t, tr, b, 2)
	b.srv.FailNext(40, 503, "SlowDown")
	var waits atomic.Int32
	cfg := fastConfig(tr, b.src(t), node)
	cfg.RequestTimeout = 200 * time.Millisecond
	cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		waits.Add(1)
		return sleepCtx(ctx, time.Millisecond)
	}
	l := newLoader(t, cfg)
	run(t, l)
	waitFor(t, "object store unreachable", func() bool { return l.Status().State == StateS3Unreachable })
	if l.Ready() {
		t.Fatal("ready while the object store is down")
	}
	waitFor(t, "ready after recovery", l.Ready)
	if waits.Load() == 0 || l.Status().Counters[CounterS3Errors] == 0 {
		t.Errorf("no backoff (%d) or no S3 errors counted", waits.Load())
	}
}

func TestS3DownWhileRunningStaysReady(t *testing.T) {
	tr, b, node, src, l, _ := ready(t, 1)
	src.down.Store(true)
	before := l.Status().Counters[CounterS3Errors]
	l.HandleEvent([]byte(`{"v":1}`))
	waitFor(t, "s3 error counted", func() bool { return l.Status().Counters[CounterS3Errors] > before })
	if !l.Ready() {
		t.Fatal("not ready during an object store outage after the initial load")
	}
	src.down.Store(false)
	p := newAccountPub(t)
	b.putAccount(t, p, tr.jwt(t, p, 100))
	l.HandleEvent([]byte(`{"v":1}`))
	waitFor(t, "new account after recovery", func() bool { return node.holds(p) != "" })
}

func TestEventFetchRetriesUntilIatCurrent(t *testing.T) {
	tr, b, node, _, l, pubs := ready(t, 1)
	_ = l
	p := pubs[0]
	l.cfg.EventWindow = 5 * time.Second
	l.HandleEvent([]byte(fmt.Sprintf(`{"v":1,"token":"T9","accounts":{%q:200}}`, p)))
	time.Sleep(30 * time.Millisecond)
	if iatOf(t, node.holds(p)) != 100 {
		t.Fatal("pushed before the object caught up")
	}
	b.putAccount(t, p, tr.jwt(t, p, 200))
	waitFor(t, "iat 200 pushed", func() bool { return iatOf(t, node.holds(p)) == 200 })
}

func TestEventForUnknownAccountLoadsIt(t *testing.T) {
	tr, b, node, _, l, _ := ready(t, 0)
	p := newAccountPub(t)
	b.putAccount(t, p, tr.jwt(t, p, 150))
	l.HandleEvent([]byte(fmt.Sprintf(`{"v":1,"accounts":{%q:150}}`, p)))
	waitFor(t, "pushed", func() bool { return node.holds(p) != "" })
}

func TestPushRereadsAndRepushesNewer(t *testing.T) {
	tr, b, node, _, l, pubs := ready(t, 1)
	p := pubs[0]
	newer := tr.jwt(t, p, 200)
	var once sync.Once
	node.mu.Lock()
	node.afterPush = func(pub, j string) {
		if pub == p && iatOf(t, j) == 150 {
			once.Do(func() { b.putAccount(t, p, newer) })
		}
	}
	node.mu.Unlock()
	b.putAccount(t, p, tr.jwt(t, p, 150))
	l.HandleEvent([]byte(`{"v":1}`))
	waitFor(t, "newer JWT pushed", func() bool { return node.holds(p) == newer })
	node.mu.Lock()
	var mine []string
	for _, q := range node.pushes {
		if q == p {
			mine = append(mine, q)
		}
	}
	node.mu.Unlock()
	if len(mine) != 3 { // start-up iat 100, then 150, then the re-read 200
		t.Errorf("pushes for the account = %d, want 3", len(mine))
	}
}

func TestPushRetried(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	seed(t, tr, b, 1)
	node.failPush = 3
	l := newLoader(t, fastConfig(tr, b.src(t), node))
	run(t, l)
	waitFor(t, "ready", l.Ready)
	if got := l.Status().Counters[CounterPushErrors]; got != 3 {
		t.Errorf("push errors = %d, want 3", got)
	}
}

func TestSampleCheckRepairsOlderJWTOnNode(t *testing.T) {
	tr, _, node, _, l, pubs := ready(t, 1)
	p := pubs[0]
	want := node.holds(p)
	node.mu.Lock()
	node.held[p] = tr.jwt(t, p, 50) // a stale push from another loader landed
	node.mu.Unlock()
	l.sampleCheck(context.Background())
	if node.holds(p) != want {
		t.Error("sample check did not re-push the applied JWT")
	}
	// A routed node answering "not held" is also repaired.
	node.mu.Lock()
	node.peers = [][]byte{nil}
	node.mu.Unlock()
	before := node.pushCount()
	l.sampleCheck(context.Background())
	if node.pushCount() == before {
		t.Error("an empty lookup answer did not cause a re-push")
	}
}

func TestSampleCheckNewerOnNodeRereadsBucket(t *testing.T) {
	tr, b, node, _, l, pubs := ready(t, 1)
	p := pubs[0]
	newer := tr.jwt(t, p, 300)
	b.putAccount(t, p, newer)
	node.mu.Lock()
	node.peers = [][]byte{[]byte(newer)}
	node.mu.Unlock()
	l.sampleCheck(context.Background())
	if node.holds(p) != newer {
		t.Error("a newer JWT seen on a peer did not make the loader read the bucket")
	}
}

func TestNodeReconnectRepushesMissing(t *testing.T) {
	_, _, node, _, l, pubs := ready(t, 2)
	node.mu.Lock()
	delete(node.held, pubs[1])
	node.mu.Unlock()
	l.NodeReconnected()
	waitFor(t, "re-pushed", func() bool { return node.holds(pubs[1]) != "" })
}

func TestTimerReconcilesOnIndexChange(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	seed(t, tr, b, 1)
	cfg := fastConfig(tr, b.src(t), node)
	cfg.ReconcileInterval = 20 * time.Millisecond
	l := newLoader(t, cfg)
	run(t, l)
	waitFor(t, "ready", l.Ready)
	p := newAccountPub(t)
	b.putAccount(t, p, tr.jwt(t, p, 100))
	time.Sleep(100 * time.Millisecond)
	if node.holds(p) != "" {
		t.Fatal("reconciled without an index change")
	}
	b.bumpIndex(t, "T1")
	waitFor(t, "timer picked up the new account", func() bool { return node.holds(p) != "" })
	waitFor(t, "token recorded", func() bool { return l.Status().LastIndexToken == "T1" })
}

func TestFullResyncIgnoresIndex(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	seed(t, tr, b, 1)
	cfg := fastConfig(tr, b.src(t), node)
	cfg.FullResyncInterval = 20 * time.Millisecond
	l := newLoader(t, cfg)
	run(t, l)
	waitFor(t, "ready", l.Ready)
	p := newAccountPub(t)
	b.putAccount(t, p, tr.jwt(t, p, 100))
	waitFor(t, "full resync picked up the new account", func() bool { return node.holds(p) != "" })
}

func TestHandleEventQueues(t *testing.T) {
	tr := newTrust(t)
	l := newLoader(t, fastConfig(tr, &hookSource{}, newFakeNode()))
	p := newAccountPub(t)
	for _, tc := range []struct {
		name, data string
		full       bool
		events     map[string]int64
	}{
		{"no accounts", `{"v":1,"token":"x"}`, true, nil},
		{"garbage", `not json`, true, nil},
		{"wrong version", `{"v":2,"accounts":{}}`, true, nil},
		{"accounts", fmt.Sprintf(`{"v":1,"accounts":{%q:5,"bogus":7}}`, p), false, map[string]int64{p: 5}},
	} {
		l.HandleEvent([]byte(tc.data))
		got := l.take()
		if got.full != tc.full || len(got.events) != len(tc.events) || (tc.events != nil && got.events[p] != tc.events[p]) {
			t.Errorf("%s: queued %+v", tc.name, got)
		}
	}
	l.HandleEvent(make([]byte, maxEventSize+1))
	if !l.take().full {
		t.Error("an oversized event did not ask for a full reconcile")
	}
}

func TestReadOnlyCredential(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	seed(t, tr, b, 1)

	l := newLoader(t, fastConfig(tr, b.source(t), node))
	err := l.Run(context.Background())
	if !errors.Is(err, objectstore.ErrAccessAllowed) {
		t.Fatalf("Run with a writable credential = %v, want ErrAccessAllowed", err)
	}
	if keys := b.srv.Keys(); slices.ContainsFunc(keys, func(k string) bool { return strings.Contains(k, "loader-write-probe") }) {
		t.Errorf("probe object left behind: %v", keys)
	}

	b.srv.Deny(func(op, _ string) bool { return op == "PUT" || op == "DELETE" })
	l = newLoader(t, fastConfig(tr, b.source(t), node))
	run(t, l)
	waitFor(t, "ready with a read-only credential", l.Ready)
}

func TestNewValidates(t *testing.T) {
	tr := newTrust(t)
	base := fastConfig(tr, &hookSource{}, newFakeNode())
	for name, mut := range map[string]func(*Config){
		"no source":       func(c *Config) { c.Source = nil },
		"no node":         func(c *Config) { c.Node = nil },
		"bad sys":         func(c *Config) { c.SysAccount = tr.opPub },
		"no trusted":      func(c *Config) { c.Trusted = nil },
		"account trusted": func(c *Config) { c.Trusted = []string{tr.sysPub} },
	} {
		c := base
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBackoff(t *testing.T) {
	b := Backoff{Min: 500 * time.Millisecond, Max: 30 * time.Second}
	for attempt, want := range map[int]time.Duration{1: 500 * time.Millisecond, 2: time.Second, 4: 4 * time.Second, 20: 30 * time.Second} {
		if got := b.Delay(attempt); got != want {
			t.Errorf("Delay(%d) = %s, want %s", attempt, got, want)
		}
		for range 50 {
			if j := b.Jittered(attempt); j < 0 || j > want {
				t.Fatalf("Jittered(%d) = %s, outside [0, %s]", attempt, j, want)
			}
		}
	}
	for range 50 {
		if j := jitter20(time.Second); j < 800*time.Millisecond || j > 1200*time.Millisecond {
			t.Fatalf("jitter20 = %s", j)
		}
	}
}

func TestAccountFromKey(t *testing.T) {
	p := newAccountPub(t)
	for key, want := range map[string][3]any{
		AccountKey(p):             {p, true, true},
		IndexKey:                  {"", false, false},
		"accounts/x.jwt":          {"x", true, false},
		"other/" + p + ".jwt":     {"", false, false},
		AccountsPrefix + ".probe": {"", false, false},
	} {
		pub, isJWT, ok := accountFromKey(key)
		if pub != want[0] || isJWT != want[1] || ok != want[2] {
			t.Errorf("%s: got %q %v %v", key, pub, isJWT, ok)
		}
	}
}

func TestStoreSourceIndex(t *testing.T) {
	b := newBucket(t)
	src := b.source(t)
	ctx := context.Background()
	if tok, err := src.Index(ctx); err != nil || tok != "" {
		t.Fatalf("missing index: %q %v", tok, err)
	}
	b.bumpIndex(t, "ABC")
	if tok, err := src.Index(ctx); err != nil || tok != "ABC" {
		t.Fatalf("index: %q %v", tok, err)
	}
	b.put(t, IndexKey, `{"v":2,"token":"x"}`)
	if _, err := src.Index(ctx); err == nil {
		t.Error("index version 2 accepted")
	}
	if _, _, err := src.Get(ctx, "accounts/nope.jwt"); !errors.Is(err, ErrNotExist) {
		t.Errorf("missing object: %v", err)
	}
}

func TestStoreSourceListPages(t *testing.T) {
	b := newBucket(t)
	for i := range listPageSize + 5 {
		b.put(t, fmt.Sprintf("accounts/k%05d.jwt", i), "x")
	}
	b.put(t, "elsewhere/x", "x")
	list, err := b.source(t).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != listPageSize+5 {
		t.Errorf("listed %d objects, want %d", len(list), listPageSize+5)
	}
}

func TestStoreSourceReopensAfterFailure(t *testing.T) {
	b := newBucket(t)
	var opens atomic.Int32
	cfg := b.srv.Config()
	src := NewStoreSource(func() (*objectstore.Store, error) {
		opens.Add(1)
		return objectstore.Open(cfg)
	})
	b.srv.FailNext(1, 403, "AccessDenied")
	if _, err := src.List(context.Background()); err == nil {
		t.Fatal("injected failure not seen")
	}
	if _, err := src.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if opens.Load() != 2 {
		t.Errorf("store opened %d times, want a re-open after the failure", opens.Load())
	}
}
