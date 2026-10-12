package pki

// The farmer side of the stateless bus (docs/briefs/P21-slice2-bus-
// loader.md §7): every Account JWT farmer pushes is first written to the
// accounts bucket, where each bus node's account loader finds it; then it
// is pushed to every bus node, and an accounts-changed event tells the
// loaders to look. FLAG FOR SECURITY REVIEW: the bucket decides which
// Account JWTs a restarted bus node trusts.

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/accountloader"
	"github.com/yogzblr/imas/internal/accountrank"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/lease"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/objectstore"
)

// AccountPublisher writes Account JWTs to the accounts bucket and tells
// the bus about them.
type AccountPublisher interface {
	// Publish runs §7.3 steps 3 to 6 for one Account JWT: the object
	// (never replacing a newer one), the index, the push to every bus
	// node, the event. Failures follow §7.5.
	Publish(ctx context.Context, accountPub, accountJWT string) error
	// ReconcileAll writes every Account JWT this farmer holds whose
	// object is missing or older, then bumps the index and announces
	// them once. It pushes nothing.
	ReconcileAll(ctx context.Context) error
}

// ErrAccountJWTSuperseded reports that the accounts bucket already holds
// a newer Account JWT for the account than the one being published. The
// older one is neither written nor pushed. pushAccountUpdate takes it as
// done (the replica that signed the newer one pushed it), except for a
// lock-out (errLockoutSuperseded).
var ErrAccountJWTSuperseded = errors.New("pki: the accounts bucket holds a newer Account JWT")

// errLockoutSuperseded marks a superseded lock-out, which is a failure.
var errLockoutSuperseded = errors.New("a lock-out must be the newest Account JWT")

const (
	// maxEventAccounts is the most accounts one event lists; a larger
	// change omits them, which the loaders take as "reconcile all".
	maxEventAccounts = 500
	// accountLockTTL bounds the per-account row lease: it covers the
	// bucket read, the PUTs, a push to every node with its retries
	// (pushToAllNodes, about 15s at worst) and the event.
	accountLockTTL = 60 * time.Second
	// accountLockWait is how long Publish waits for another replica's
	// lease on the same account.
	accountLockWait = 70 * time.Second
	// accountLockPoll is the re-try interval within that wait.
	accountLockPoll = 100 * time.Millisecond
	// accountsListPage is the page size of ReconcileAll's listing.
	accountsListPage = 1000
	// reconcileAccountsJob is PushAllAccounts' job lease for ReconcileAll
	// (farmer.job_leases), so N replicas reconnecting together reconcile
	// the bucket once.
	reconcileAccountsJob = "reconcile-accounts"
)

// accountObjects is the part of *objectstore.Store the publisher uses.
type accountObjects interface {
	GetLimitedWithInfo(ctx context.Context, key string, limit int64) ([]byte, objectstore.ObjectInfo, error)
	Put(ctx context.Context, key string, data []byte) error
	ListPage(ctx context.Context, prefix, startAfter string, max int) ([]objectstore.ObjectInfo, bool, error)
}

// accountBus is a SYS-account connection to the bus.
type accountBus interface {
	// pushAll pushes accountJWT to every bus node (pushToAllNodes).
	pushAll(accountJWT string) (pushResult, error)
	publish(subject string, payload []byte) error
	close()
}

// s3AccountPublisher is the AccountPublisher over the accounts bucket.
type s3AccountPublisher struct {
	objects accountObjects
	subject string
	// trusted are the keys an Account JWT in the bucket must be issued
	// by to count: anything else there is overwritten, not obeyed.
	trusted []string
	openBus func() (accountBus, error)
	// rowLock takes the cross-replica part of an account's critical
	// section; it returns the release.
	rowLock func(ctx context.Context, accountPub string) (func(), error)
	// local returns the Account JWTs this farmer holds (ReconcileAll).
	local func() ([]string, error)

	mu    sync.Mutex
	locks map[string]*sync.Mutex
	// seen caches what an object held at an ETag, so ReconcileAll reads
	// only objects that changed since it last looked.
	seen map[string]seenObject
}

type seenObject struct {
	etag  string
	claim accountrank.Claim
}

// NewAccountPublisher returns the publisher over store, the accounts
// bucket opened with farmer's write credential, announcing on subject.
// It trusts the operator and operator signing keys of the NATS trust
// directory.
func NewAccountPublisher(store *objectstore.Store, subject string) (AccountPublisher, error) {
	trust, err := LoadNATSTrustDir(NATSTrustDir())
	if err != nil {
		return nil, err
	}
	return newS3AccountPublisher(store, subject, []string{trust.OperatorPub, trust.OperatorSigningPub}), nil
}

func newS3AccountPublisher(objects accountObjects, subject string, trusted []string) *s3AccountPublisher {
	if subject == "" {
		subject = config.DefaultAccountsEventSubject
	}
	return &s3AccountPublisher{
		objects: objects,
		subject: subject,
		trusted: trusted,
		openBus: dialAccountBus,
		rowLock: accountRowLock,
		local:   localAccountJWTs,
		locks:   map[string]*sync.Mutex{},
		seen:    map[string]seenObject{},
	}
}

var (
	accountPublisherMu sync.Mutex
	accountPublisher   AccountPublisher
)

// SetAccountPublisher installs the publisher every Account JWT push goes
// through (pushAccountUpdate). Nil, the default, pushes straight to the
// bus nodes with no bucket.
func SetAccountPublisher(p AccountPublisher) {
	accountPublisherMu.Lock()
	defer accountPublisherMu.Unlock()
	accountPublisher = p
}

func currentAccountPublisher() AccountPublisher {
	accountPublisherMu.Lock()
	defer accountPublisherMu.Unlock()
	return accountPublisher
}

// ReconcileAccounts runs the installed publisher's ReconcileAll; without
// one it does nothing. cmd/farmer runs it at start-up.
func ReconcileAccounts(ctx context.Context) error {
	p := currentAccountPublisher()
	if p == nil {
		return nil
	}
	return p.ReconcileAll(ctx)
}

// reconcileAccountsLeased is PushAllAccounts' ReconcileAll, under the
// reconcile-accounts job lease (one replica at a time, at most once per
// pushAllMinInterval). Without a publisher it does nothing.
func reconcileAccountsLeased(ctx context.Context) error {
	p := currentAccountPublisher()
	if p == nil {
		return nil
	}
	l := JobLeases(pushAllNow)
	if l == nil {
		return p.ReconcileAll(ctx)
	}
	_, err := l.Run(ctx, reconcileAccountsJob, lease.JobTTL(), pushAllMinInterval, p.ReconcileAll)
	return err
}

// lock takes accountPub's critical section: an in-process mutex, then
// the cross-replica row lease.
func (p *s3AccountPublisher) lock(ctx context.Context, accountPub string) (func(), error) {
	p.mu.Lock()
	m := p.locks[accountPub]
	if m == nil {
		m = &sync.Mutex{}
		p.locks[accountPub] = m
	}
	p.mu.Unlock()
	m.Lock()
	release, err := p.rowLock(ctx, accountPub)
	if err != nil {
		m.Unlock()
		return nil, err
	}
	return func() { release(); m.Unlock() }, nil
}

// Publish implements AccountPublisher.
func (p *s3AccountPublisher) Publish(ctx context.Context, accountPub, accountJWT string) error {
	ac, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil {
		return fmt.Errorf("pki: publishing an Account JWT that does not decode: %w", err)
	}
	if ac.Subject != accountPub {
		return fmt.Errorf("pki: publishing an Account JWT for %s under %s", ac.Subject, accountPub)
	}
	unlock, err := p.lock(ctx, accountPub)
	var prev *jwt.AccountClaims
	stored := false
	if err == nil {
		defer unlock()
		prev, stored, err = p.storeObject(ctx, ac, accountJWT)
		if err == nil && stored {
			err = p.bumpIndex(ctx)
		}
	}
	if errors.Is(err, ErrAccountJWTSuperseded) {
		if ac.Limits.Conn == 0 {
			// A lock-out older than a live JWT: only replica clocks
			// apart can do that. Neither written nor pushed, and the
			// caller sees it.
			return fmt.Errorf("pki: lock-out of Account %s issued at %d: %w: %w", accountPub, ac.IssuedAt, errLockoutSuperseded, err)
		}
		log.Infof("not publishing Account %s issued at %d: %v", accountPub, ac.IssuedAt, err)
		return err
	}
	if err != nil {
		// §7.5: a lock-out or revocation still goes to the bus, security
		// first; an ordinary update waits for the bucket. Either way the
		// caller sees the failure, and ReconcileAll repairs the bucket.
		err = fmt.Errorf("pki: writing Account %s to the accounts bucket: %w", accountPub, err)
		if !tightens(ac, prev) {
			return err
		}
		log.Errorf("%v; pushing the lock-out or revocation to the bus anyway", err)
		p.pushAndAnnounce(accountPub, accountJWT, ac.IssuedAt, false)
		return err
	}
	p.pushAndAnnounce(accountPub, accountJWT, ac.IssuedAt, stored)
	return nil
}

// pushAndAnnounce is §7.3 steps 5 and 6. Failures are logged only
// (§7.5): the bucket has the JWT and the loaders repair the nodes.
func (p *s3AccountPublisher) pushAndAnnounce(accountPub, accountJWT string, iat int64, announce bool) {
	bus, err := p.openBus()
	if err != nil {
		log.Errorf("pushing Account %s: connecting to the bus: %v; the bus loaders will apply it from the accounts bucket", accountPub, err)
		return
	}
	defer bus.close()
	res, err := bus.pushAll(accountJWT)
	switch {
	case err != nil:
		log.Errorf("pushing Account %s to the bus: %v (farmer_account_push_missing_nodes=%d); the bus loaders will apply it from the accounts bucket", accountPub, err, res.missing)
	case res.missing > 0:
		log.Warnf("pushing Account %s: %d of %d bus nodes did not answer (farmer_account_push_missing_nodes=%d); their loaders will apply it from the accounts bucket", accountPub, res.missing, res.missing+res.acked, res.missing)
	}
	if announce {
		p.announce(bus, map[string]int64{accountPub: iat})
	}
}

// announce publishes the accounts-changed event (§4.3); a failure is
// logged only, since the event is a hint.
func (p *s3AccountPublisher) announce(bus accountBus, accounts map[string]int64) {
	ev := struct {
		V        int              `json:"v"`
		Accounts map[string]int64 `json:"accounts,omitempty"`
	}{V: 1}
	if len(accounts) <= maxEventAccounts {
		ev.Accounts = accounts
	}
	b, err := json.Marshal(ev)
	if err == nil {
		err = bus.publish(p.subject, b)
	}
	if err != nil {
		log.Warnf("publishing %s: %v; the bus loaders' timer picks the change up", p.subject, err)
	}
}

// storeObject is §7.3 step 3, inside the caller's critical section: read
// the account's object and write ac's JWT unless the object already
// holds it or a JWT that outranks it (accountrank.Better). An object that
// does not decode, is about another account or is not issued by a
// trusted key is overwritten. prev is the object's claims when it could
// be read; stored reports a PUT.
func (p *s3AccountPublisher) storeObject(ctx context.Context, ac *jwt.AccountClaims, accountJWT string) (prev *jwt.AccountClaims, stored bool, err error) {
	key := accountloader.AccountKey(ac.Subject)
	b, info, err := p.objects.GetLimitedWithInfo(ctx, key, accountloader.MaxJWTSize)
	switch {
	case objectstore.IsNotExist(err):
	case errors.Is(err, objectstore.ErrObjectTooLarge):
		log.Warnf("accounts bucket object %s is over %d bytes; replacing it", key, accountloader.MaxJWTSize)
	case err != nil:
		return nil, false, err
	default:
		held, herr := p.claim(string(b), ac.Subject)
		if herr != nil {
			log.Warnf("accounts bucket object %s is not a valid Account JWT (%v); replacing it", key, herr)
			break
		}
		p.remember(key, info.ETag, held)
		prev, _ = jwt.DecodeAccountClaims(held.Raw)
		if held.Raw == accountJWT {
			return prev, false, nil
		}
		if !accountrank.Better(claimOf(ac, accountJWT), held) {
			return prev, false, fmt.Errorf("%w: %s is issued at %d, this one at %d", ErrAccountJWTSuperseded, key, held.IAT, ac.IssuedAt)
		}
	}
	if err := p.objects.Put(ctx, key, []byte(accountJWT)); err != nil {
		return prev, false, err
	}
	p.forget(key)
	return prev, true, nil
}

// claim validates an object's JWT (trimmed, as the loader reads it) for
// account sub.
func (p *s3AccountPublisher) claim(raw, sub string) (accountrank.Claim, error) {
	raw = strings.TrimSpace(raw)
	iat, jti, locked, err := accountrank.Rank(raw, p.trusted, sub)
	if err != nil {
		return accountrank.Claim{}, err
	}
	return accountrank.Claim{IAT: iat, JTI: jti, LockedOut: locked, Raw: raw}, nil
}

func claimOf(ac *jwt.AccountClaims, raw string) accountrank.Claim {
	return accountrank.Claim{IAT: ac.IssuedAt, JTI: ac.ID, LockedOut: ac.Limits.Conn == 0, Raw: raw}
}

func (p *s3AccountPublisher) remember(key, etag string, c accountrank.Claim) {
	if etag == "" {
		return
	}
	p.mu.Lock()
	p.seen[key] = seenObject{etag: etag, claim: c}
	p.mu.Unlock()
}

func (p *s3AccountPublisher) forget(key string) {
	p.mu.Lock()
	delete(p.seen, key)
	p.mu.Unlock()
}

func (p *s3AccountPublisher) cached(key, etag string) (accountrank.Claim, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.seen[key]
	if !ok || etag == "" || s.etag != etag {
		return accountrank.Claim{}, false
	}
	return s.claim, true
}

// bumpIndex is §7.3 step 4: accounts/index with a fresh random token, so
// two concurrent bumps both read as a change.
func (p *s3AccountPublisher) bumpIndex(ctx context.Context) error {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		V       int    `json:"v"`
		Token   string `json:"token"`
		Written string `json:"written"`
	}{1, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]), time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	if err := p.objects.Put(ctx, accountloader.IndexKey, body); err != nil {
		return fmt.Errorf("writing %s: %w", accountloader.IndexKey, err)
	}
	return nil
}

// tightens reports whether ac is a lock-out, or revokes a key (or
// revokes it later) than prev did. With prev unknown, any revocation
// counts: §7.5 errs toward pushing a revocation.
func tightens(ac, prev *jwt.AccountClaims) bool {
	if ac.Limits.Conn == 0 {
		return true
	}
	for k, at := range ac.Revocations {
		if prev == nil {
			return true
		}
		if was, ok := prev.Revocations[k]; !ok || at > was {
			return true
		}
	}
	return false
}

// ReconcileAll implements AccountPublisher (§7.5): it lists the bucket
// and writes every Account JWT this farmer holds whose object is missing
// or older. Farmer state wins over an older object (a bucket rollback, a
// lost write); a newer object, signed by another replica, stays.
func (p *s3AccountPublisher) ReconcileAll(ctx context.Context) error {
	jwts, err := p.local()
	if err != nil {
		return fmt.Errorf("pki: reading this farmer's Account JWTs: %w", err)
	}
	best := map[string]accountrank.Claim{}
	for _, j := range jwts {
		ac, err := jwt.DecodeAccountClaims(j)
		if err != nil {
			continue
		}
		c := claimOf(ac, j)
		if old, ok := best[ac.Subject]; !ok || accountrank.Better(c, old) {
			best[ac.Subject] = c
		}
	}
	etags, err := p.listETags(ctx)
	if err != nil {
		return fmt.Errorf("pki: listing the accounts bucket: %w", err)
	}

	changed := map[string]int64{}
	var errs []error
	for _, pub := range slices.Sorted(maps.Keys(best)) {
		c := best[pub]
		key := accountloader.AccountKey(pub)
		if etag, ok := etags[key]; ok {
			if held, ok := p.cached(key, etag); ok && (held.Raw == c.Raw || !accountrank.Better(c, held)) {
				continue
			}
		}
		stored, err := p.reconcileOne(ctx, pub, c.Raw)
		switch {
		case errors.Is(err, ErrAccountJWTSuperseded):
		case err != nil:
			errs = append(errs, fmt.Errorf("account %s: %w", pub, err))
		case stored:
			changed[pub] = c.IAT
		}
	}
	if len(changed) > 0 {
		if err := p.bumpIndex(ctx); err != nil {
			errs = append(errs, err)
		} else {
			log.Infof("accounts bucket: wrote %d Account JWTs that were missing or older", len(changed))
		}
		if bus, err := p.openBus(); err != nil {
			log.Warnf("announcing %d reconciled Accounts: connecting to the bus: %v; the bus loaders' timer picks them up", len(changed), err)
		} else {
			p.announce(bus, changed)
			bus.close()
		}
	}
	return errors.Join(errs...)
}

func (p *s3AccountPublisher) reconcileOne(ctx context.Context, pub, accountJWT string) (bool, error) {
	ac, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil {
		return false, err
	}
	unlock, err := p.lock(ctx, pub)
	if err != nil {
		return false, err
	}
	defer unlock()
	_, stored, err := p.storeObject(ctx, ac, accountJWT)
	return stored, err
}

func (p *s3AccountPublisher) listETags(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}
	after := ""
	for {
		page, more, err := p.objects.ListPage(ctx, accountloader.AccountsPrefix, after, accountsListPage)
		if err != nil {
			return nil, err
		}
		for _, o := range page {
			out[o.Key] = o.ETag
		}
		if !more || len(page) == 0 {
			return out, nil
		}
		after = page[len(page)-1].Key
	}
}

// localAccountJWTs returns the Account JWTs this farmer holds: the SYS
// Account, the legacy tenant and every tenant with an Account JWT here
// (lock-outs included). A missing file is skipped.
func localAccountJWTs() ([]string, error) {
	paths := []string{sysAccountJWTPath(), tenantJWTPath()}
	ids, err := tenantIDsProvisionedOnDisk()
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		paths = append(paths, tenantAccountJWTPath(id))
	}
	var out []string
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, string(b))
	}
	return out, nil
}

// accountRowLock takes the farmer.job_leases row lease account:<pub>, so
// of the farmer replicas only one is in an account's critical section at
// a time; it waits up to accountLockWait. Without a database there is no
// other replica, and it takes nothing.
func accountRowLock(ctx context.Context, accountPub string) (func(), error) {
	if db == nil {
		return func() {}, nil
	}
	name := "account:" + accountPub
	if err := db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&lease.JobLease{Name: name}).Error; err != nil {
		return nil, fmt.Errorf("lease: creating %s: %w", name, err)
	}
	var tok [6]byte
	_, _ = rand.Read(tok[:])
	owner := replicaOwner() + "-" + hex.EncodeToString(tok[:])
	l := lease.New(db, nil)
	key := []any{name}
	deadline := time.Now().Add(accountLockWait)
	for {
		ok, err := l.Acquire(ctx, lease.JobLeases, key, owner, accountLockTTL)
		if err != nil {
			return nil, err
		}
		if ok {
			return func() { _, _ = l.Release(context.WithoutCancel(ctx), lease.JobLeases, key, owner) }, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("lease %s: another farmer replica held it for over %s", name, accountLockWait)
		}
		if err := sleepCtx(ctx, accountLockPoll); err != nil {
			return nil, err
		}
	}
}
