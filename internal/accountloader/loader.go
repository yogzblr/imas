// Package accountloader rebuilds a bus node's Account JWT store from the
// accounts bucket (docs/briefs/P21-slice2-bus-loader.md §5). It runs in
// the farmerbus-loader sidecar next to each bus node: it loads every
// account into the node at start and reports ready only once the node
// holds them all, then follows farmer's change events and a timer.
//
// FLAG FOR SECURITY REVIEW: the loader decides which Account JWT a node
// serves. It pushes only JWTs signed by a trusted operator key, about the
// account their key names, and never one that ranks below what it has
// already applied (accountrank.Better), so a tampered or rolled-back
// bucket cannot take a node backwards from what this loader has seen.
package accountloader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/accountrank"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/objectstore"
)

// Defaults (brief §4.5, §5.6, §5.7).
const (
	DefaultEventSubject       = "imas.bus.accounts.changed"
	DefaultReconcileInterval  = 30 * time.Second
	DefaultFullResyncInterval = 5 * time.Minute
	// DefaultInitialPollInterval caps the wait between start-up runs and
	// passes while the initial load is incomplete (P30).
	DefaultInitialPollInterval = 5 * time.Second
	DefaultPushConcurrency     = 8
	DefaultPushRate            = 200

	maxEventSize = 64 << 10
)

// States reported in Status.State.
const (
	StateStarting       = "starting"
	StateReadOnlyCheck  = "checking the credential is read-only"
	StateWaitingNode    = "waiting for the bus node"
	StateS3Unreachable  = "object store unreachable"
	StateNotInitialised = "bucket not initialised"
	StateIncomplete     = "initial load incomplete"
	StateSysInvalid     = "SYS account JWT invalid"
	StateNodeMissing    = "bus node is missing accounts"
	StateReady          = "ready"
)

// Config configures a Loader. Zero durations and counts take the
// defaults named on each field.
type Config struct {
	Source ObjectSource
	Node   NodeClient
	// Trusted are the operator public key and its signing keys: an
	// Account JWT must be issued by one of them.
	Trusted []string
	// SysAccount is the SYS account public key; the loader is not ready
	// until its object is loaded.
	SysAccount string

	EventSubject       string        // DefaultEventSubject
	ReconcileInterval  time.Duration // DefaultReconcileInterval, ±20% jitter
	FullResyncInterval time.Duration // DefaultFullResyncInterval
	PushConcurrency    int           // DefaultPushConcurrency
	PushRate           float64       // pushes per second, DefaultPushRate

	Backoff Backoff // between failed start-up runs: 500ms to 30s
	// InitialPollInterval (DefaultInitialPollInterval, ±20%) caps every
	// Backoff wait of the initial load, so a node waiting for farmer's
	// first Accounts picks them up within seconds; its timers take over
	// once the load is complete.
	InitialPollInterval time.Duration
	PushBackoff         Backoff       // between push attempts: 200ms to 5s
	PushAttempts        int           // 5
	RepushRounds        int           // re-read rounds after a push: 5
	RequestTimeout      time.Duration // one object store request: 15s
	MaxPasses           int           // start-up passes per run: 20
	EventWindow         time.Duration // how long an event fetch waits for the object: 30s
	SampleSize          int           // accounts looked up per reconcile: 50
	LookupWindow        time.Duration // how long a lookup collects answers: 1s

	// Sleep waits d or until ctx ends; tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error
	// Now is the clock for Status; tests replace it.
	Now func() time.Time
}

func (c *Config) setDefaults() {
	if c.EventSubject == "" {
		c.EventSubject = DefaultEventSubject
	}
	if c.ReconcileInterval <= 0 {
		c.ReconcileInterval = DefaultReconcileInterval
	}
	if c.FullResyncInterval <= 0 {
		c.FullResyncInterval = DefaultFullResyncInterval
	}
	if c.PushConcurrency <= 0 {
		c.PushConcurrency = DefaultPushConcurrency
	}
	if c.PushRate <= 0 {
		c.PushRate = DefaultPushRate
	}
	if c.InitialPollInterval <= 0 {
		c.InitialPollInterval = DefaultInitialPollInterval
	}
	if c.Backoff.Min <= 0 {
		c.Backoff = Backoff{Min: 500 * time.Millisecond, Max: 30 * time.Second}
	}
	if c.PushBackoff.Min <= 0 {
		c.PushBackoff = Backoff{Min: 200 * time.Millisecond, Max: 5 * time.Second}
	}
	if c.PushAttempts <= 0 {
		c.PushAttempts = 5
	}
	if c.RepushRounds <= 0 {
		c.RepushRounds = 5
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 15 * time.Second
	}
	if c.MaxPasses <= 0 {
		c.MaxPasses = 20
	}
	if c.EventWindow <= 0 {
		c.EventWindow = 30 * time.Second
	}
	if c.SampleSize <= 0 {
		c.SampleSize = 50
	}
	if c.LookupWindow <= 0 {
		c.LookupWindow = time.Second
	}
	if c.Sleep == nil {
		c.Sleep = sleepCtx
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Counter names in Status.Counters.
const (
	CounterStaleSkipped  = "loader_stale_skipped_total"
	CounterInvalid       = "loader_invalid_total"
	CounterObjectMissing = "loader_object_missing_total"
	CounterS3Errors      = "loader_s3_errors_total"
	CounterPushes        = "loader_pushes_total"
	CounterPushErrors    = "loader_push_errors_total"
)

// InvalidObject is an object that failed validation, kept out of the
// target set.
type InvalidObject struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// Status is the loader's state for /status. It holds no JWTs.
type Status struct {
	Ready          bool              `json:"ready"`
	State          string            `json:"status"`
	Applied        int               `json:"applied"`
	Target         int               `json:"target"`
	Invalid        []InvalidObject   `json:"invalid"`
	LastIndexToken string            `json:"lastIndexToken"`
	LastSuccess    time.Time         `json:"lastSuccess"`
	Counters       map[string]uint64 `json:"counters"`
}

// pending is work queued for the worker; queued work coalesces.
type pending struct {
	indexCheck bool
	full       bool
	recheck    bool
	events     map[string]int64 // account -> iat from the event
}

// Loader keeps one bus node's accounts in step with the bucket.
type Loader struct {
	cfg     Config
	limiter *limiter
	ready   atomic.Bool

	mu          sync.Mutex
	applied     map[string]accountrank.Claim // account -> what the node was given
	seen        map[string]string            // key -> ETag last processed
	invalid     map[string]string            // key -> why it was rejected
	state       string
	target      int
	lastToken   string
	lastSuccess time.Time
	lastWarn    time.Time
	counters    map[string]uint64
	cursor      int // where the next lookup sample starts
	queued      pending
	work        chan struct{}
}

// New returns a Loader; Run starts it.
func New(cfg Config) (*Loader, error) {
	if cfg.Source == nil || cfg.Node == nil {
		return nil, errors.New("accountloader: a source and a node client are required")
	}
	if !nkeys.IsValidPublicAccountKey(cfg.SysAccount) {
		return nil, fmt.Errorf("accountloader: SYS account %q is not an account public key", cfg.SysAccount)
	}
	if len(cfg.Trusted) == 0 {
		return nil, errors.New("accountloader: no trusted operator keys")
	}
	for _, k := range cfg.Trusted {
		if !nkeys.IsValidPublicOperatorKey(k) {
			return nil, fmt.Errorf("accountloader: trusted key %q is not an operator public key", k)
		}
	}
	cfg.setDefaults()
	return &Loader{
		cfg:      cfg,
		limiter:  newLimiter(cfg.PushRate),
		applied:  map[string]accountrank.Claim{},
		seen:     map[string]string{},
		invalid:  map[string]string{},
		state:    StateStarting,
		counters: map[string]uint64{},
		work:     make(chan struct{}, 1),
	}, nil
}

// Ready reports whether the initial load has completed. Once true it
// stays true (brief §5.3, owner decision D-2).
func (l *Loader) Ready() bool { return l.ready.Load() }

// Status returns a snapshot for /status.
func (l *Loader) Status() Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := Status{
		Ready:          l.ready.Load(),
		State:          l.state,
		Applied:        len(l.applied),
		Target:         l.target,
		Invalid:        []InvalidObject{},
		LastIndexToken: l.lastToken,
		LastSuccess:    l.lastSuccess,
		Counters:       maps.Clone(l.counters),
	}
	for _, k := range slices.Sorted(maps.Keys(l.invalid)) {
		st.Invalid = append(st.Invalid, InvalidObject{Key: k, Reason: l.invalid[k]})
	}
	for _, c := range []string{CounterStaleSkipped, CounterInvalid, CounterObjectMissing, CounterS3Errors, CounterPushes, CounterPushErrors} {
		if _, ok := st.Counters[c]; !ok {
			st.Counters[c] = 0
		}
	}
	return st
}

func (l *Loader) count(name string) {
	l.mu.Lock()
	l.counters[name]++
	l.mu.Unlock()
}

func (l *Loader) setState(s string) {
	l.mu.Lock()
	l.state = s
	l.mu.Unlock()
}

// Run loads every account, then follows events and the timers until ctx
// ends. It returns nil when ctx ends, and an error only when the loader
// must not run at all (its credential can write the bucket).
func (l *Loader) Run(ctx context.Context) error {
	if err := l.checkReadOnly(ctx); err != nil {
		return err
	}
	// Subscribe before the load so events during it are queued, not lost.
	if err := l.cfg.Node.Subscribe(l.cfg.EventSubject, l.HandleEvent); err != nil {
		return fmt.Errorf("accountloader: subscribing to %s: %w", l.cfg.EventSubject, err)
	}
	l.loadAll(ctx)
	if ctx.Err() != nil {
		return nil
	}
	go l.timers(ctx)
	l.worker(ctx)
	return nil
}

// checkReadOnly refuses to start with a credential that may write the
// bucket, retrying an inconclusive answer forever (brief §10).
func (l *Loader) checkReadOnly(ctx context.Context) error {
	c, ok := l.cfg.Source.(ReadOnlyChecker)
	if !ok {
		return nil
	}
	l.setState(StateReadOnlyCheck)
	for attempt := 1; ; attempt++ {
		rp := objectstore.RetryPolicy{
			MaxAttempts:    3,
			InitialBackoff: l.cfg.Backoff.Min,
			MaxBackoff:     l.cfg.Backoff.Max,
			AttemptTimeout: l.cfg.RequestTimeout,
		}
		err := c.CheckReadOnly(ctx, rp)
		if err == nil {
			return nil
		}
		if errors.Is(err, objectstore.ErrAccessAllowed) {
			return fmt.Errorf("accountloader: refusing to start, the object store credential is not read-only: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		l.count(CounterS3Errors)
		log.Warnf("accountloader: read-only credential check inconclusive, retrying: %v", err)
		if l.cfg.Sleep(ctx, l.cfg.Backoff.Jittered(attempt)) != nil {
			return nil
		}
	}
}

// loadAll is the start-up load (brief §5.3). It returns once the node
// holds every account in the bucket, or when ctx ends.
func (l *Loader) loadAll(ctx context.Context) {
	sysKey := AccountKey(l.cfg.SysAccount)
	for attempt := 1; ctx.Err() == nil; attempt++ {
		state, err := l.loadOnce(ctx, sysKey)
		if err == nil {
			// State before the ready flag: anyone who sees Ready() true
			// then reads Status() must find the state ready too.
			l.setState(StateReady)
			l.ready.Store(true)
			log.Infof("accountloader: initial load complete, %d accounts", l.Status().Applied)
			return
		}
		l.setState(state)
		log.Warnf("accountloader: not ready (%s): %v", state, err)
		if l.cfg.Sleep(ctx, l.initialWait(attempt)) != nil {
			return
		}
	}
}

// initialWait is the initial load's wait after a failed run or pass: the
// start-up backoff, capped at InitialPollInterval (±20%). Before P30 it
// grew to 30s, so a loader that had waited a while for an empty bucket
// (the DMZ installed before the core hub) could take up to that long to
// see farmer's first Accounts, and its bus node stayed unready meanwhile.
func (l *Loader) initialWait(attempt int) time.Duration {
	return min(l.cfg.Backoff.Jittered(attempt), jitter20(l.cfg.InitialPollInterval))
}

// loadOnce is one start-up run; on failure it returns the state to show.
func (l *Loader) loadOnce(ctx context.Context, sysKey string) (string, error) {
	if l.cfg.Node.ConnectedServerID() == "" {
		return StateWaitingNode, ErrNotConnected
	}
	token, err := l.index(ctx)
	if err != nil {
		return StateS3Unreachable, err
	}
	list, err := l.list(ctx)
	if err != nil {
		return StateS3Unreachable, err
	}
	if !slices.ContainsFunc(list, func(o ObjInfo) bool { return o.Key == sysKey }) {
		return StateNotInitialised, fmt.Errorf("no %s in the bucket", sysKey)
	}
	done := false
	for pass := 1; pass <= l.cfg.MaxPasses; pass++ {
		ok := l.pass(ctx, list)
		if list, err = l.list(ctx); err != nil {
			return StateS3Unreachable, err
		}
		if ok && !l.changed(list) {
			done = true
			break
		}
		if !ok && l.cfg.Sleep(ctx, l.initialWait(pass)) != nil {
			return StateIncomplete, ctx.Err()
		}
	}
	if !done {
		return StateIncomplete, fmt.Errorf("keys still unprocessed or changing after %d passes", l.cfg.MaxPasses)
	}
	l.mu.Lock()
	_, sysOK := l.applied[l.cfg.SysAccount]
	sysWhy, sysBad := l.invalid[sysKey]
	l.mu.Unlock()
	if sysBad || !sysOK {
		return StateSysInvalid, fmt.Errorf("SYS account object: %s", sysWhy)
	}
	target := l.targetPubs(list)
	if err := l.verifyNode(ctx, target); err != nil {
		return StateNodeMissing, err
	}
	l.mu.Lock()
	l.target = len(target)
	l.lastToken = token
	l.mu.Unlock()
	return StateReady, nil
}

// targetPubs is the target set T: every valid account object listed.
func (l *Loader) targetPubs(list []ObjInfo) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, o := range list {
		pub, _, ok := accountFromKey(o.Key)
		if !ok {
			continue
		}
		if _, bad := l.invalid[o.Key]; bad {
			continue
		}
		if _, ok := l.applied[pub]; ok {
			out = append(out, pub)
		}
	}
	return out
}

// verifyNode checks the own node lists every pub, re-pushing a missing
// one once (brief §5.3 step 5).
func (l *Loader) verifyNode(ctx context.Context, pubs []string) error {
	missing, err := l.missingOnNode(ctx, pubs)
	if err != nil {
		return err
	}
	if len(missing) == 0 {
		return nil
	}
	for _, pub := range missing {
		l.mu.Lock()
		c := l.applied[pub]
		l.mu.Unlock()
		if err := l.pushWithRetry(ctx, pub, c.Raw); err != nil {
			log.Warnf("accountloader: re-pushing %s: %v", pub, err)
		}
	}
	missing, err = l.missingOnNode(ctx, pubs)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("own node still lacks %d accounts, first %s", len(missing), missing[0])
	}
	return nil
}

func (l *Loader) missingOnNode(ctx context.Context, pubs []string) ([]string, error) {
	_, ids, err := l.cfg.Node.ListIDs(ctx)
	if err != nil {
		return nil, err
	}
	have := make(map[string]bool, len(ids))
	for _, id := range ids {
		have[id] = true
	}
	var missing []string
	for _, p := range pubs {
		if !have[p] {
			missing = append(missing, p)
		}
	}
	return missing, nil
}

// changed reports whether list holds an account object this loader has
// not processed at its listed ETag.
func (l *Loader) changed(list []ObjInfo) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, o := range list {
		if _, isJWT, _ := accountFromKey(o.Key); isJWT && l.seen[o.Key] != o.ETag {
			return true
		}
	}
	return false
}

// pass processes every listed account object not yet processed at its
// ETag, PushConcurrency at a time. It reports whether all succeeded.
func (l *Loader) pass(ctx context.Context, list []ObjInfo) bool {
	l.mu.Lock()
	var todo []ObjInfo
	for _, o := range list {
		if _, isJWT, _ := accountFromKey(o.Key); isJWT && l.seen[o.Key] != o.ETag {
			todo = append(todo, o)
		}
	}
	l.mu.Unlock()
	var failed atomic.Bool
	sem := make(chan struct{}, l.cfg.PushConcurrency)
	var wg sync.WaitGroup
	for _, o := range todo {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return false
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			if err := l.processKey(ctx, o.Key, o.ETag); err != nil {
				failed.Store(true)
				log.Debugf("accountloader: %s: %v", o.Key, err)
			}
		}()
	}
	wg.Wait()
	return !failed.Load() && ctx.Err() == nil
}

// processKey fetches, validates and applies one account object. A nil
// error means the object was dealt with (applied, skipped, rejected or
// gone) and is recorded as seen. listed is the ETag a listing showed for
// it, or empty; a listed object that has gone is recorded as seen at that
// ETag, so a lagging listing does not hold up the start-up load.
func (l *Loader) processKey(ctx context.Context, key, listed string) error {
	pub, _, ok := accountFromKey(key)
	data, info, err := l.get(ctx, key)
	if errors.Is(err, ErrNotExist) {
		l.count(CounterObjectMissing)
		log.Warnf("accountloader: %s disappeared from the bucket; keeping the held copy", key)
		if listed != "" {
			l.mu.Lock()
			l.seen[key] = listed
			l.mu.Unlock()
		}
		return nil
	}
	if errors.Is(err, ErrTooLarge) {
		l.reject(key, info.ETag, err.Error())
		return nil
	}
	if err != nil {
		return err
	}
	if !ok {
		l.reject(key, info.ETag, "key does not name an account")
		return nil
	}
	c, err := l.validate(pub, data)
	if err != nil {
		l.reject(key, info.ETag, err.Error())
		return nil
	}
	etag, err := l.apply(ctx, pub, c, info.ETag)
	if err != nil {
		return err
	}
	l.mu.Lock()
	delete(l.invalid, key)
	l.seen[key] = etag
	l.mu.Unlock()
	return nil
}

func (l *Loader) reject(key, etag, why string) {
	l.mu.Lock()
	l.invalid[key] = why
	l.seen[key] = etag
	l.counters[CounterInvalid]++
	l.mu.Unlock()
	log.Warnf("accountloader: rejecting %s: %s", key, why)
}

// validate checks an object body against brief §4.2.
func (l *Loader) validate(pub string, data []byte) (accountrank.Claim, error) {
	raw := strings.TrimSpace(string(data))
	iat, jti, locked, err := accountrank.Rank(raw, l.cfg.Trusted, pub)
	if err != nil {
		return accountrank.Claim{}, err
	}
	if iat <= 0 {
		return accountrank.Claim{}, errors.New("issued-at is not set")
	}
	return accountrank.Claim{IAT: iat, JTI: jti, LockedOut: locked, Raw: raw}, nil
}

// apply pushes c if it outranks what the node was given (brief §5.5),
// then re-reads the object and pushes anything newer (brief §5.6). It
// returns the ETag of the last object read.
func (l *Loader) apply(ctx context.Context, pub string, c accountrank.Claim, etag string) (string, error) {
	l.mu.Lock()
	cur, have := l.applied[pub]
	l.mu.Unlock()
	switch {
	case !have || c.IAT > cur.IAT:
	case c.Raw == cur.Raw:
		return etag, nil
	case c.IAT < cur.IAT:
		l.count(CounterStaleSkipped)
		log.Warnf("accountloader: stale JWT for %s in the bucket (issued at %d, already applied %d); not pushed", pub, c.IAT, cur.IAT)
		return etag, nil
	case !accountrank.Better(c, cur):
		return etag, nil
	}
	return l.pushAndReread(ctx, pub, c, etag)
}

// pushAndReread pushes c, then re-reads the object and pushes it again
// while it holds something better, up to RepushRounds times: a stale
// push fans out to every routed node, so a newer object written meanwhile
// must follow it.
func (l *Loader) pushAndReread(ctx context.Context, pub string, c accountrank.Claim, etag string) (string, error) {
	key := AccountKey(pub)
	for round := 0; ; round++ {
		if err := l.pushWithRetry(ctx, pub, c.Raw); err != nil {
			return etag, err
		}
		l.mu.Lock()
		if cur, ok := l.applied[pub]; !ok || accountrank.Better(c, cur) || c.Raw == cur.Raw {
			l.applied[pub] = c
		}
		l.mu.Unlock()
		if round >= l.cfg.RepushRounds {
			return etag, nil
		}
		data, info, err := l.get(ctx, key)
		if err != nil {
			// The push stands; the next pass or timer re-reads.
			return etag, nil
		}
		next, err := l.validate(pub, data)
		if err != nil || !accountrank.Better(next, c) {
			// Nothing better; an object that changed to something else
			// keeps its new ETag unseen, so the next pass judges it.
			return etag, nil
		}
		c, etag = next, info.ETag
	}
}

// pushWithRetry pushes one JWT, rate limited, with PushAttempts tries.
func (l *Loader) pushWithRetry(ctx context.Context, pub, raw string) error {
	var err error
	for attempt := 1; attempt <= l.cfg.PushAttempts; attempt++ {
		if err = l.limiter.wait(ctx, l.cfg.Sleep); err != nil {
			return err
		}
		if err = l.cfg.Node.Push(ctx, pub, []byte(raw)); err == nil {
			l.count(CounterPushes)
			return nil
		}
		l.count(CounterPushErrors)
		if attempt < l.cfg.PushAttempts {
			if serr := l.cfg.Sleep(ctx, l.cfg.PushBackoff.Jittered(attempt)); serr != nil {
				return serr
			}
		}
	}
	return fmt.Errorf("pushing %s: %w", pub, err)
}

// get, list and index are the source calls with the per-request timeout
// and error accounting.
func (l *Loader) get(ctx context.Context, key string) ([]byte, ObjInfo, error) {
	rctx, cancel := context.WithTimeout(ctx, l.cfg.RequestTimeout)
	defer cancel()
	b, info, err := l.cfg.Source.Get(rctx, key)
	if err != nil && !errors.Is(err, ErrNotExist) && !errors.Is(err, ErrTooLarge) {
		l.s3Failed(err)
	}
	return b, info, err
}

func (l *Loader) list(ctx context.Context) ([]ObjInfo, error) {
	rctx, cancel := context.WithTimeout(ctx, l.cfg.RequestTimeout)
	defer cancel()
	list, err := l.cfg.Source.List(rctx)
	if err != nil {
		l.s3Failed(err)
		return nil, err
	}
	l.mu.Lock()
	l.lastSuccess = l.cfg.Now()
	l.mu.Unlock()
	return list, nil
}

func (l *Loader) index(ctx context.Context) (string, error) {
	rctx, cancel := context.WithTimeout(ctx, l.cfg.RequestTimeout)
	defer cancel()
	tok, err := l.cfg.Source.Index(rctx)
	if err != nil {
		l.s3Failed(err)
	}
	return tok, err
}

// s3Failed counts an object store error and, once ready, warns at most
// once a minute (brief §5.7).
func (l *Loader) s3Failed(err error) {
	l.mu.Lock()
	l.counters[CounterS3Errors]++
	warn := l.ready.Load() && l.cfg.Now().Sub(l.lastWarn) >= time.Minute
	if warn {
		l.lastWarn = l.cfg.Now()
	}
	l.mu.Unlock()
	if warn {
		log.Warnf("accountloader: object store error, still serving the accounts held: %v", err)
	}
}

// event is the payload of the accounts-changed event (brief §4.3).
type event struct {
	V        int              `json:"v"`
	Token    string           `json:"token"`
	Accounts map[string]int64 `json:"accounts"`
}

// HandleEvent queues the work an accounts-changed event asks for. An
// event without accounts, or one that does not decode, asks for a full
// reconcile: the event is only a hint.
func (l *Loader) HandleEvent(data []byte) {
	var ev event
	if len(data) > maxEventSize || json.Unmarshal(data, &ev) != nil || ev.V != 1 {
		log.Warnf("accountloader: event not understood (%d bytes); reconciling", len(data))
		l.enqueue(func(p *pending) { p.full = true })
		return
	}
	if len(ev.Accounts) == 0 {
		l.enqueue(func(p *pending) { p.full = true })
		return
	}
	l.enqueue(func(p *pending) {
		if p.events == nil {
			p.events = map[string]int64{}
		}
		for pub, iat := range ev.Accounts {
			if nkeys.IsValidPublicAccountKey(pub) && iat > p.events[pub] {
				p.events[pub] = iat
			}
		}
	})
}

// NodeReconnected queues a check that the node still holds every
// applied account (brief §5.7). Before the initial load it does nothing:
// the load ends with the same check.
func (l *Loader) NodeReconnected() {
	if l.Ready() {
		l.enqueue(func(p *pending) { p.recheck = true })
	}
}

func (l *Loader) enqueue(fn func(*pending)) {
	l.mu.Lock()
	fn(&l.queued)
	l.mu.Unlock()
	select {
	case l.work <- struct{}{}:
	default:
	}
}

func (l *Loader) take() pending {
	l.mu.Lock()
	defer l.mu.Unlock()
	p := l.queued
	l.queued = pending{}
	return p
}

// timers queues an index check every ReconcileInterval (±20%) and a full
// resync every FullResyncInterval.
func (l *Loader) timers(ctx context.Context) {
	full := time.NewTicker(l.cfg.FullResyncInterval)
	defer full.Stop()
	next := time.NewTimer(jitter20(l.cfg.ReconcileInterval))
	defer next.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-full.C:
			l.enqueue(func(p *pending) { p.full = true })
		case <-next.C:
			l.enqueue(func(p *pending) { p.indexCheck = true })
			next.Reset(jitter20(l.cfg.ReconcileInterval))
		}
	}
}

// jitter20 spreads d over [0.8d, 1.2d].
func jitter20(d time.Duration) time.Duration {
	return Backoff{Min: d * 2 / 5, Max: d * 2 / 5}.Jittered(1) + d*4/5
}

// worker runs queued work one item at a time, so passes never overlap.
func (l *Loader) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-l.work:
		}
		l.runPending(ctx, l.take())
	}
}

func (l *Loader) runPending(ctx context.Context, p pending) {
	if p.recheck {
		l.recheck(ctx)
	}
	if len(p.events) > 0 {
		l.handleEvents(ctx, p.events)
	}
	switch {
	case p.full:
		l.reconcile(ctx, false)
	case p.indexCheck:
		l.reconcile(ctx, true)
	}
}

// reconcile lists the bucket and applies what changed (brief §5.4). With
// onlyIfIndexChanged it first reads the index and does nothing when its
// token is the one last applied.
func (l *Loader) reconcile(ctx context.Context, onlyIfIndexChanged bool) {
	token, err := l.index(ctx)
	if err != nil {
		return
	}
	l.mu.Lock()
	same := token == l.lastToken
	l.mu.Unlock()
	if onlyIfIndexChanged && same {
		return
	}
	list, err := l.list(ctx)
	if err != nil {
		return
	}
	ok := l.pass(ctx, list)
	target := l.targetPubs(list)
	l.mu.Lock()
	l.target = len(target)
	if ok {
		l.lastToken = token
	}
	l.mu.Unlock()
	l.sampleCheck(ctx)
}

// handleEvents fetches each account an event named whose issued-at is
// newer than what is applied, waiting up to EventWindow for the object
// to catch up with the event; what is still behind is left to the timer.
func (l *Loader) handleEvents(ctx context.Context, events map[string]int64) {
	sem := make(chan struct{}, l.cfg.PushConcurrency)
	var wg sync.WaitGroup
	for pub, iat := range events {
		l.mu.Lock()
		cur, have := l.applied[pub]
		l.mu.Unlock()
		if have && iat <= cur.IAT {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			l.fetchEvent(ctx, pub, iat)
		}()
	}
	wg.Wait()
}

func (l *Loader) fetchEvent(ctx context.Context, pub string, want int64) {
	key := AccountKey(pub)
	deadline := l.cfg.Now().Add(l.cfg.EventWindow)
	for attempt := 1; ; attempt++ {
		data, info, err := l.get(ctx, key)
		if errors.Is(err, ErrTooLarge) {
			l.reject(key, info.ETag, err.Error())
			return
		}
		if err == nil {
			c, verr := l.validate(pub, data)
			if verr != nil {
				l.reject(key, info.ETag, verr.Error())
				return
			}
			if c.IAT >= want {
				if etag, err := l.apply(ctx, pub, c, info.ETag); err == nil {
					l.mu.Lock()
					delete(l.invalid, key)
					l.seen[key] = etag
					l.mu.Unlock()
				}
				return
			}
		}
		if !l.cfg.Now().Before(deadline) {
			log.Warnf("accountloader: %s not at issued-at %d after %s; leaving it to the timer", key, want, l.cfg.EventWindow)
			return
		}
		if l.cfg.Sleep(ctx, l.cfg.Backoff.Jittered(attempt)) != nil {
			return
		}
	}
}

// recheck re-pushes every applied account the own node no longer lists.
// A failure is retried with the next timer tick.
func (l *Loader) recheck(ctx context.Context) {
	l.mu.Lock()
	pubs := slices.Collect(maps.Keys(l.applied))
	l.mu.Unlock()
	missing, err := l.missingOnNode(ctx, pubs)
	if err == nil {
		for _, pub := range missing {
			l.mu.Lock()
			c := l.applied[pub]
			l.mu.Unlock()
			if err = l.pushWithRetry(ctx, pub, c.Raw); err != nil {
				break
			}
		}
	}
	if err != nil {
		log.Warnf("accountloader: re-checking the node after a reconnect: %v; retrying", err)
		l.mu.Lock()
		l.queued.recheck = true
		l.mu.Unlock()
	}
}

// sampleCheck looks up SampleSize applied accounts on the node (and the
// nodes routed to it) and repairs any that hold something other than
// what was applied (brief §5.6): a better JWT there means the bucket has
// it too, so the object is re-read; a worse one, an invalid one (a
// future-dated JWT among them) or none is overwritten by pushing again.
func (l *Loader) sampleCheck(ctx context.Context) {
	l.mu.Lock()
	all := slices.Sorted(maps.Keys(l.applied))
	n := min(l.cfg.SampleSize, len(all))
	sample := make([]string, 0, n)
	for i := range n {
		sample = append(sample, all[(l.cursor+i)%len(all)])
	}
	if len(all) > 0 {
		l.cursor = (l.cursor + n) % len(all)
	}
	l.mu.Unlock()
	sem := make(chan struct{}, l.cfg.PushConcurrency)
	var wg sync.WaitGroup
	for _, pub := range sample {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			l.checkOne(ctx, pub)
		}()
	}
	wg.Wait()
}

func (l *Loader) checkOne(ctx context.Context, pub string) {
	lctx, cancel := context.WithTimeout(ctx, l.cfg.LookupWindow)
	answers, err := l.cfg.Node.Lookup(lctx, pub)
	cancel()
	if err != nil || len(answers) == 0 {
		return
	}
	l.mu.Lock()
	cur := l.applied[pub]
	l.mu.Unlock()
	behind := false
	for _, a := range answers {
		if len(a) == 0 {
			behind = true
			continue
		}
		c, err := l.validate(pub, a)
		if err != nil {
			// A node holds a JWT that fails validation, for example one
			// issued in the future that would outrank every later push
			// (security review 2026-10, L16): overwrite it. A claims
			// update replaces whatever the node holds.
			log.Warnf("accountloader: a node holds an invalid JWT for %s (%v); pushing the applied one again", pub, err)
			behind = true
			continue
		}
		if accountrank.Better(c, cur) {
			// A node holds something newer than this loader applied: it
			// came from the bucket, so read the bucket again.
			if err := l.processKey(ctx, AccountKey(pub), ""); err != nil {
				log.Debugf("accountloader: re-reading %s: %v", pub, err)
			}
			return
		}
		if c.Raw != cur.Raw {
			behind = true
		}
	}
	if behind {
		log.Warnf("accountloader: a node holds an older JWT for %s; pushing again", pub)
		if _, err := l.pushAndReread(ctx, pub, cur, ""); err != nil {
			log.Warnf("accountloader: re-pushing %s: %v", pub, err)
		}
	}
}

// limiter spaces pushes at most rate per second.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(rate float64) *limiter {
	return &limiter{interval: time.Duration(float64(time.Second) / rate)}
}

func (r *limiter) wait(ctx context.Context, sleep func(context.Context, time.Duration) error) error {
	r.mu.Lock()
	now := time.Now()
	if r.next.Before(now) {
		r.next = now
	}
	d := r.next.Sub(now)
	r.next = r.next.Add(r.interval)
	r.mu.Unlock()
	if d <= 0 {
		return ctx.Err()
	}
	return sleep(ctx, d)
}
