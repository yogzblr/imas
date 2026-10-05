package jobs

// Farmer-side job storage lives in object storage (S3/MinIO, through
// internal/objectstore), not under config.JobLogDir on local disk: with more
// than one farmer replica, a job-status query can land on any of them, so
// they all need to read the same job data (docs/design/imas-master-plan.md,
// "Job logs → object storage"). config.JobLogDir is now only the sprout's
// own local log directory (internal/cook/sproutcook.go's logStepResult,
// StartSproutReaper); the CLI's CLIStore stays on the user's own disk too.
//
// # Write strategy: one object per event
//
// Object storage can't append, and the old writer appended one line per job
// event as it arrived. The choice among the alternatives came down to what
// a job's event stream looks like and to who writes it.
//
// Volume. Cooking an N-step recipe makes one creation record when farmer
// dispatches it (N "not started" placeholders, written by
// recordJobCreation) and N+2 events on imas.cook.<sprout>.<jid>: a seeded
// "start-<jid>", one terminal completion per step (sproutcook.go publishes
// no separate in-progress event), and a final "completed-<jid>" or
// "timeout-<jid>". Each event is one cook.StepCompletion of a few hundred
// bytes (more only when a step reports long Changes notes). Recipes run
// tens of steps, so a job is tens of small events and a few KB in total.
//
// At that volume, rewriting the whole accumulated log on every event would
// be cheap. It is ruled out by the writers instead: RegisterNatsConn
// queue-subscribes, so a job's events are spread across farmer replicas and
// handled concurrently. A read-modify-write of one shared object would lose
// events whenever two replicas interleave, and objectstore.Store has no
// conditional (If-Match) Put to detect it. Buffering a job in memory and
// writing it once at the end fails for the same reason, since no replica
// sees all of a job's events, and it would also hide running jobs from
// status queries.
//
// Writing each event to its own object needs no coordination: every Put
// goes to a key no other writer uses, whichever replica received the event.
// Reads cost a List plus one Get per object, which at tens of objects per
// job is small, and loadJobs fetches jobs concurrently. Event keys start
// with the receiving replica's clock (zero-padded UnixNano), so sorting keys
// sorts by receive time. Events that two replicas receive within their
// clock skew of each other can come back slightly out of order. That only
// changes the order of JobSummary.Steps: everything buildSummary computes
// (counts, earliest start, latest end, status) ignores order.
//
// # Key layout
//
// Keys live in the dedicated job bucket (config.S3JobBucket). It must not be
// the recipe bucket, because GET /files/ serves any key in that bucket to
// any authenticated caller.
//
//	jobs/<tenant>/<sprout>/<jid>/created.jsonl               placeholders from recordJobCreation
//	jobs/<tenant>/<sprout>/<jid>/meta.json                   JobMeta (invoker, creation time)
//	jobs/<tenant>/<sprout>/<jid>/events/<unixnano>-<rand>.jsonl  one step event
//	jobs/<tenant>/<sprout>/<jid>/expired.json               ExpiredMarker, if the job expired
//
// A job exists once it has created.jsonl or at least one event.
// created.jsonl followed by events/ in key order holds the same lines the
// old local <jid>.jsonl file did.
//
// # Tenant safety
//
// A sprout_id is unique per tenant only (CLAUDE.md; API design §4 "Tenant
// safety"), so every key starts with the tenant, and every job is a
// jobRef{tenant, sprout, jid}. The tenant always comes from where the
// request or event arrived: the tenant connection a cook event or dispatch
// came in on (RegisterNatsConn), or the verified caller of a sealed API
// request (internal/natsapi's apiCaller.TenantID). Nothing in a message
// body names it.
//
// jobKey builds every key and prefix, and refuses a tenant, sprout or job
// ID that isn't safe as one key segment (validKeySegment: no "/", backslash,
// "..", control characters or invalid UTF-8). Every Store method takes the
// tenant and lists only that tenant's prefix, jobs/<tenant>/, and
// indexJobs drops any key outside it, so no method returns another
// tenant's job. The one platform-wide scan, the reaper (expiry.go), parses
// the tenant out of each key and deletes each job by its own full ref.
//
// The pre-tenant layout, jobs/<sprout>/<jid>/..., is never read: nothing
// was deployed with it, so there is no migration. Its keys don't parse
// under this layout (created.jsonl and meta.json sit one segment short;
// an event's last segment is not a job object name), so parseJobKey
// rejects them and indexJobs ignores them, in listings, lookups and the
// reaper alike. They are left where they are.
//
// Deferred: looking a job up by JID alone (FindJob) lists the tenant's
// whole jobs/<tenant>/ prefix. A jid-to-sprout index would make that one
// List call if job counts grow enough to matter. Nothing compacts a
// finished job's event objects into a single object.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore"
)

var (
	ErrJobNotFound  = errors.New("job not found")
	ErrSproutNoJobs = errors.New("no jobs found for sprout")
	// ErrJobStoreNotConfigured means SetStore was never called (or was
	// called with nil), so farmer has nowhere to keep job logs. It is never
	// a cue to fall back to local disk, which would bring back the
	// cross-replica inconsistency object storage exists to remove.
	ErrJobStoreNotConfigured = errors.New("job store not configured")
	// ErrInvalidJobKey means a tenant, sprout or job ID can't be used as
	// one segment of a job key (see validKeySegment). No key is built
	// from it, so nothing is read or written.
	ErrInvalidJobKey = errors.New("invalid job key")
)

// objStore is the object-storage backend farmer's job logs are kept in.
// Set once at startup via SetStore.
var objStore *objectstore.Store

// SetStore installs the object-storage backend job logs are written to
// (by RegisterNatsConn's listeners) and read from (by NewStore's Store).
// Call once at startup, as cmd/farmer/main.go does for cook.SetStore.
func SetStore(s *objectstore.Store) { objStore = s }

// opTimeout bounds each Store method, and each listener write, against
// the object store.
const opTimeout = 30 * time.Second

// loadConcurrency caps how many jobs a listing fetches at once.
const loadConcurrency = 16

const (
	jobKeyPrefix  = "jobs/"
	createdObject = "created.jsonl"
	metaObject    = "meta.json"
	expiredObject = "expired.json"
	eventsDir     = "events/"
	logExt        = ".jsonl"

	// maxKeySegmentLen bounds a tenant, sprout or job ID in a key. It is
	// the job-status index's widest ID column (sprout_id), and three of
	// them stay well inside an object key's 1024 bytes.
	maxKeySegmentLen = 253
)

// JobStatus represents the aggregate status of a job across all its steps.
type JobStatus int

const (
	JobPending   JobStatus = iota // Job created but no steps completed
	JobRunning                    // At least one step in progress
	JobSucceeded                  // All steps completed successfully
	JobFailed                     // At least one step failed
	JobPartial                    // Mix of completed and not-started steps
	// JobExpired: the job started later than farmer's reconcile window
	// allows, so its steps were not recorded (see reconcile.go).
	JobExpired
)

func (s JobStatus) String() string {
	switch s {
	case JobPending:
		return "pending"
	case JobRunning:
		return "running"
	case JobSucceeded:
		return "succeeded"
	case JobFailed:
		return "failed"
	case JobPartial:
		return "partial"
	case JobExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// MarshalJSON implements json.Marshaler for JobStatus.
func (s JobStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON implements json.Unmarshaler for JobStatus.
func (s *JobStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch str {
	case "pending":
		*s = JobPending
	case "running":
		*s = JobRunning
	case "succeeded":
		*s = JobSucceeded
	case "failed":
		*s = JobFailed
	case "partial":
		*s = JobPartial
	case "expired":
		*s = JobExpired
	default:
		return fmt.Errorf("unknown job status: %s", str)
	}
	return nil
}

// JobSummary provides an overview of a job's execution.
type JobSummary struct {
	JID string `json:"jid"`
	// TenantID is the tenant whose job store the job was read from (the
	// first segment of its keys). Empty for a job read from the CLI's
	// local store.
	TenantID  string                `json:"tenant_id,omitempty"`
	SproutID  string                `json:"sprout_id"`
	Status    JobStatus             `json:"status"`
	Steps     []cook.StepCompletion `json:"steps"`
	StartedAt time.Time             `json:"started_at"`
	Duration  time.Duration         `json:"duration"`
	Succeeded int                   `json:"succeeded"`
	Failed    int                   `json:"failed"`
	Skipped   int                   `json:"skipped"`
	Total     int                   `json:"total"`
	InvokedBy string                `json:"invoked_by,omitempty"`
}

// Store reads farmer-side job data from object storage. See the comment at
// the top of this file for the layout and why it's shaped this way.
type Store struct {
	// obj overrides the package-level objStore when set.
	obj *objectstore.Store
}

// NewStore returns a Store backed by the object store installed with
// SetStore. The backend is looked up on every call rather than captured
// here, because internal/natsapi builds its Store in an init(), before
// main has called SetStore.
func NewStore() *Store {
	return &Store{}
}

// NewStoreWithObjectStore returns a Store backed by obj rather than the
// package-level store. Tests use it, including to point two Stores (two
// "replicas") at one bucket.
func NewStoreWithObjectStore(obj *objectstore.Store) *Store {
	return &Store{obj: obj}
}

func (s *Store) backend() (*objectstore.Store, error) {
	if s.obj != nil {
		return s.obj, nil
	}
	if objStore != nil {
		return objStore, nil
	}
	return nil, ErrJobStoreNotConfigured
}

func opContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), opTimeout)
}

// GetJob retrieves tenantID's job jid on sproutID.
func (s *Store) GetJob(tenantID, sproutID, jid string) (*JobSummary, error) {
	obj, err := s.backend()
	if err != nil {
		return nil, err
	}
	ref, err := newJobRef(tenantID, sproutID, jid)
	if err != nil {
		return nil, err
	}
	prefix, err := ref.prefix()
	if err != nil {
		return nil, err
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, prefix, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing job: %w", err)
	}
	objs, ok := idx[ref]
	if !ok {
		return nil, ErrJobNotFound
	}
	summary, err := loadJob(ctx, obj, ref, objs)
	if err != nil {
		if objectstore.IsNotExist(err) {
			// Deleted between the List and the Get.
			return nil, ErrJobNotFound
		}
		return nil, fmt.Errorf("reading job: %w", err)
	}
	return summary, nil
}

// FindJob searches tenantID's sprouts, and only theirs, for a job with the
// given JID. If more than one of them ran it, it returns the first by
// sprout ID that loads.
func (s *Store) FindJob(tenantID, jid string) (*JobSummary, error) {
	obj, err := s.backend()
	if err != nil {
		return nil, err
	}
	if err := checkKeySegment("job", jid); err != nil {
		return nil, err
	}
	prefix, err := jobKey(tenantID, "", "", "")
	if err != nil {
		return nil, err
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, prefix, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing jobs: %w", err)
	}
	for _, ref := range refsForJID(idx, jid) {
		summary, loadErr := loadJob(ctx, obj, ref, idx[ref])
		if loadErr != nil {
			continue
		}
		return summary, nil
	}
	return nil, ErrJobNotFound
}

// ListJobsForSprout returns all job summaries for tenantID's sproutID,
// sorted by start time (most recent first).
func (s *Store) ListJobsForSprout(tenantID, sproutID string) ([]JobSummary, error) {
	obj, err := s.backend()
	if err != nil {
		return nil, err
	}
	prefix, err := jobKey(tenantID, sproutID, "", "")
	if err != nil {
		return nil, err
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, prefix, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing sprout jobs: %w", err)
	}
	if len(idx) == 0 {
		return nil, ErrSproutNoJobs
	}
	return loadJobs(ctx, obj, idx), nil
}

// ListAllJobs returns job summaries across all of tenantID's sprouts, and
// no other tenant's, sorted by start time (most recent first). Limit of 0
// means no limit.
func (s *Store) ListAllJobs(tenantID string, limit int) ([]JobSummary, error) {
	obj, err := s.backend()
	if err != nil {
		return nil, err
	}
	prefix, err := jobKey(tenantID, "", "", "")
	if err != nil {
		return nil, err
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, prefix, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing jobs: %w", err)
	}
	allSummaries := loadJobs(ctx, obj, idx)
	if limit > 0 && len(allSummaries) > limit {
		allSummaries = allSummaries[:limit]
	}
	return allSummaries, nil
}

// DeleteJob removes tenantID's job jid on sproutID: its log objects and
// metadata. It names the sprout, rather than deleting whichever sprout's
// run FindJob would pick, so a caller deletes exactly the job it looked up
// and checked access to.
func (s *Store) DeleteJob(tenantID, sproutID, jid string) error {
	obj, err := s.backend()
	if err != nil {
		return err
	}
	ref, err := newJobRef(tenantID, sproutID, jid)
	if err != nil {
		return err
	}
	prefix, err := ref.prefix()
	if err != nil {
		return err
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, prefix, tenantID)
	if err != nil {
		return fmt.Errorf("listing jobs: %w", err)
	}
	objs, ok := idx[ref]
	if !ok {
		return ErrJobNotFound
	}
	return deleteJobObjects(ctx, obj, ref, objs)
}

// ListSprouts returns the IDs of tenantID's sprouts that have job records.
func (s *Store) ListSprouts(tenantID string) ([]string, error) {
	obj, err := s.backend()
	if err != nil {
		return nil, err
	}
	prefix, err := jobKey(tenantID, "", "", "")
	if err != nil {
		return nil, err
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, prefix, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing jobs: %w", err)
	}
	seen := make(map[string]bool)
	var sprouts []string
	for ref := range idx {
		if !seen[ref.sproutID] {
			seen[ref.sproutID] = true
			sprouts = append(sprouts, ref.sproutID)
		}
	}
	slices.Sort(sprouts)
	return sprouts, nil
}

// CountJobsForSprout returns the number of jobs recorded for tenantID's
// sproutID.
func (s *Store) CountJobsForSprout(tenantID, sproutID string) (int, error) {
	obj, err := s.backend()
	if err != nil {
		return 0, err
	}
	prefix, err := jobKey(tenantID, sproutID, "", "")
	if err != nil {
		return 0, err
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, prefix, tenantID)
	if err != nil {
		return 0, fmt.Errorf("listing sprout jobs: %w", err)
	}
	return len(idx), nil
}

// validKeySegment reports whether id (a tenant ID, sprout ID or JID) can
// be used as one segment of an object key. Sprout IDs and JIDs arrive in
// NATS subject tokens, which may contain "/", and a "/" would let one
// job's keys land inside another's prefix, or another tenant's. "..", a
// backslash and control characters are refused too: some object stores
// and proxies normalise them, and none belongs in an ID.
func validKeySegment(id string) bool {
	if id == "" || id == "." || len(id) > maxKeySegmentLen || strings.Contains(id, "..") || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if r == '/' || r == '\\' || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// checkKeySegment is validKeySegment as an ErrInvalidJobKey error naming
// which part (tenant, sprout, job) was refused.
func checkKeySegment(part, id string) error {
	if !validKeySegment(id) {
		return fmt.Errorf("%w: %s ID %q is not usable as a key segment", ErrInvalidJobKey, part, id)
	}
	return nil
}

// validObjectName reports whether name is one of a job's own objects:
// created.jsonl, meta.json, expired.json or events/<one segment>.jsonl.
func validObjectName(name string) bool {
	switch name {
	case createdObject, metaObject, expiredObject:
		return true
	}
	event, ok := strings.CutPrefix(name, eventsDir)
	return ok && strings.HasSuffix(event, logExt) && validKeySegment(event)
}

// jobKey builds every key and key prefix the job store reads, writes,
// lists or deletes. Trailing parts may be left empty to build a prefix:
//
//	jobKey(t, "", "", "")     jobs/<t>/
//	jobKey(t, s, "", "")      jobs/<t>/<s>/
//	jobKey(t, s, j, "")       jobs/<t>/<s>/<j>/
//	jobKey(t, s, j, object)   jobs/<t>/<s>/<j>/<object>
//
// The tenant is always required, and an empty part may not be followed by
// a set one. Each ID must pass validKeySegment and object must be a job
// object name (validObjectName); otherwise no key is built and the error
// wraps ErrInvalidJobKey.
func jobKey(tenantID, sproutID, jid, object string) (string, error) {
	if err := checkKeySegment("tenant", tenantID); err != nil {
		return "", err
	}
	key := jobKeyPrefix + tenantID + "/"
	if sproutID == "" {
		if jid != "" || object != "" {
			return "", fmt.Errorf("%w: a job key needs a sprout ID", ErrInvalidJobKey)
		}
		return key, nil
	}
	if err := checkKeySegment("sprout", sproutID); err != nil {
		return "", err
	}
	key += sproutID + "/"
	if jid == "" {
		if object != "" {
			return "", fmt.Errorf("%w: a job object key needs a job ID", ErrInvalidJobKey)
		}
		return key, nil
	}
	if err := checkKeySegment("job", jid); err != nil {
		return "", err
	}
	key += jid + "/"
	if object == "" {
		return key, nil
	}
	if !validObjectName(object) {
		return "", fmt.Errorf("%w: %q is not a job object name", ErrInvalidJobKey, object)
	}
	return key + object, nil
}

// jobRef identifies one tenant's sprout's run of one job. Build one with
// newJobRef (or parseJobKey), which checks every part.
type jobRef struct {
	tenantID string
	sproutID string
	jid      string
}

// newJobRef returns the ref for tenantID's job jid on sproutID, or an
// ErrInvalidJobKey error if any part can't be a key segment.
func newJobRef(tenantID, sproutID, jid string) (jobRef, error) {
	ref := jobRef{tenantID: tenantID, sproutID: sproutID, jid: jid}
	if sproutID == "" || jid == "" {
		return jobRef{}, fmt.Errorf("%w: a job needs a tenant, sprout and job ID", ErrInvalidJobKey)
	}
	if _, err := ref.prefix(); err != nil {
		return jobRef{}, err
	}
	return ref, nil
}

// prefix is jobs/<tenant>/<sprout>/<jid>/.
func (r jobRef) prefix() (string, error) {
	return jobKey(r.tenantID, r.sproutID, r.jid, "")
}

// key is the key of the job's object named object (createdObject, ...).
func (r jobRef) key(object string) (string, error) {
	return jobKey(r.tenantID, r.sproutID, r.jid, object)
}

// eventKey names the object for one job event received at the given
// time. The zero-padded UnixNano sorts lexically in time order; the random
// suffix keeps two events received in the same nanosecond (on different
// replicas) from overwriting each other.
func (r jobRef) eventKey(at time.Time) (string, error) {
	var suffix [4]byte
	rand.Read(suffix[:])
	return r.key(fmt.Sprintf("%s%020d-%s%s", eventsDir, at.UnixNano(), hex.EncodeToString(suffix[:]), logExt))
}

// eventTime recovers the receive time eventKey encoded into key.
func eventTime(key string) (time.Time, bool) {
	name := key[strings.LastIndex(key, "/")+1:]
	digits, _, found := strings.Cut(name, "-")
	if !found {
		return time.Time{}, false
	}
	ns, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, ns), true
}

// jobObjects is what a List found under one job's prefix.
type jobObjects struct {
	created bool
	meta    bool
	expired bool
	events  []string // full keys, sorted
}

// hasLog reports whether the job has any step data, or was marked
// expired. A meta.json alone (say, recordJobCreation's second Put failed)
// doesn't make a job.
func (o *jobObjects) hasLog() bool {
	return o.created || len(o.events) > 0 || o.expired
}

// parseJobKey splits a key in the job layout into its job and object
// name. It reports false for a key that doesn't fit the layout, including
// every key in the pre-tenant layout (jobs/<sprout>/<jid>/...): those are
// never read.
func parseJobKey(key string) (jobRef, string, bool) {
	rest, ok := strings.CutPrefix(key, jobKeyPrefix)
	if !ok {
		return jobRef{}, "", false
	}
	parts := strings.SplitN(rest, "/", 4)
	if len(parts) != 4 {
		return jobRef{}, "", false
	}
	ref, err := newJobRef(parts[0], parts[1], parts[2])
	if err != nil || !validObjectName(parts[3]) {
		return jobRef{}, "", false
	}
	return ref, parts[3], true
}

// indexJobs groups object keys in the job layout by job. Keys that don't
// fit the layout are ignored. With onlyTenant set, so are keys of any
// other tenant: every Store method lists one tenant's prefix, and this
// keeps a listing that ever returned more than the prefix from handing
// back another tenant's job. Only the reaper passes "".
func indexJobs(keys []string, onlyTenant string) map[jobRef]*jobObjects {
	idx := make(map[jobRef]*jobObjects)
	for _, key := range keys {
		ref, name, ok := parseJobKey(key)
		if !ok || (onlyTenant != "" && ref.tenantID != onlyTenant) {
			continue
		}
		objs := idx[ref]
		if objs == nil {
			objs = &jobObjects{}
			idx[ref] = objs
		}
		switch name {
		case createdObject:
			objs.created = true
		case metaObject:
			objs.meta = true
		case expiredObject:
			objs.expired = true
		default:
			objs.events = append(objs.events, key)
		}
	}
	for _, objs := range idx {
		slices.Sort(objs.events)
	}
	return idx
}

// listJobs lists and indexes every job of tenantID under prefix (one of
// tenantID's own prefixes, from jobKey) that has step data.
func listJobs(ctx context.Context, obj *objectstore.Store, prefix, tenantID string) (map[jobRef]*jobObjects, error) {
	if err := checkKeySegment("tenant", tenantID); err != nil {
		return nil, err
	}
	keys, err := obj.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	idx := indexJobs(keys, tenantID)
	for ref, objs := range idx {
		if !objs.hasLog() {
			delete(idx, ref)
		}
	}
	return idx, nil
}

// refsForJID returns every sprout's run of jid in idx, ordered by sprout
// ID so lookups by JID alone are deterministic.
func refsForJID(idx map[jobRef]*jobObjects, jid string) []jobRef {
	var refs []jobRef
	for ref := range idx {
		if ref.jid == jid {
			refs = append(refs, ref)
		}
	}
	slices.SortFunc(refs, func(a, b jobRef) int { return strings.Compare(a.sproutID, b.sproutID) })
	return refs
}

// loadJob reads a job's log objects (created.jsonl, then events in key
// order) and its metadata into a JobSummary.
func loadJob(ctx context.Context, obj *objectstore.Store, ref jobRef, objs *jobObjects) (*JobSummary, error) {
	var logKeys []string
	if objs.created {
		key, err := ref.key(createdObject)
		if err != nil {
			return nil, err
		}
		logKeys = append(logKeys, key)
	}
	logKeys = append(logKeys, objs.events...)

	var steps []cook.StepCompletion
	for _, key := range logKeys {
		data, err := obj.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		chunk, err := parseJobLines(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		steps = append(steps, chunk...)
	}

	summary := buildSummary(ref.jid, ref.sproutID, steps)
	summary.TenantID = ref.tenantID
	if objs.expired {
		summary.Status = JobExpired
	}
	if objs.meta {
		if meta, err := readJobMeta(ctx, obj, ref); err == nil {
			summary.InvokedBy = meta.InvokedBy
		}
	}
	return summary, nil
}

// loadJobs loads every job in idx, loadConcurrency at a time, skipping any
// that fail to load, sorted by start time (most recent first).
func loadJobs(ctx context.Context, obj *objectstore.Store, idx map[jobRef]*jobObjects) []JobSummary {
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		summaries []JobSummary
	)
	sem := make(chan struct{}, loadConcurrency)
	for ref, objs := range idx {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			summary, err := loadJob(ctx, obj, ref, objs)
			if err != nil {
				return
			}
			mu.Lock()
			summaries = append(summaries, *summary)
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(summaries, func(i, j int) bool {
		if !summaries[i].StartedAt.Equal(summaries[j].StartedAt) {
			return summaries[i].StartedAt.After(summaries[j].StartedAt)
		}
		if summaries[i].SproutID != summaries[j].SproutID {
			return summaries[i].SproutID < summaries[j].SproutID
		}
		return summaries[i].JID < summaries[j].JID
	})
	return summaries
}

// deleteJobObjects removes one job's log objects, then its metadata. A
// failure to delete a log object is returned; the metadata delete is
// best-effort, like the old local-disk .meta.json removal.
func deleteJobObjects(ctx context.Context, obj *objectstore.Store, ref jobRef, objs *jobObjects) error {
	var logKeys []string
	if objs.created {
		key, err := ref.key(createdObject)
		if err != nil {
			return err
		}
		logKeys = append(logKeys, key)
	}
	logKeys = append(logKeys, objs.events...)
	for _, key := range logKeys {
		if err := obj.Delete(ctx, key); err != nil {
			return fmt.Errorf("deleting job: %w", err)
		}
	}
	for _, o := range []struct {
		name    string
		present bool
	}{{expiredObject, objs.expired}, {metaObject, objs.meta}} {
		if !o.present {
			continue
		}
		if key, err := ref.key(o.name); err == nil {
			obj.Delete(ctx, key)
		}
	}
	return nil
}

// readJobMeta reads a job's meta.json.
func readJobMeta(ctx context.Context, obj *objectstore.Store, ref jobRef) (*JobMeta, error) {
	key, err := ref.key(metaObject)
	if err != nil {
		return nil, err
	}
	data, err := obj.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	var meta JobMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// readJobFile reads and parses a local JSONL job file into step
// completions. Only CLIStore, which stays on the CLI user's disk, reads
// local files now.
func readJobFile(path string) ([]cook.StepCompletion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseJobLines(data)
}

// parseJobLines parses JSONL job data into step completions.
func parseJobLines(data []byte) ([]cook.StepCompletion, error) {
	var steps []cook.StepCompletion
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var step cook.StepCompletion
		if unmarshalErr := json.Unmarshal([]byte(line), &step); unmarshalErr != nil {
			return nil, fmt.Errorf("parsing step completion: %w", unmarshalErr)
		}
		steps = append(steps, step)
	}
	return steps, nil
}

// buildSummary aggregates step completions into a JobSummary.
func buildSummary(jid, sproutID string, steps []cook.StepCompletion) *JobSummary {
	summary := &JobSummary{
		JID:      jid,
		SproutID: sproutID,
		Steps:    steps,
		Total:    len(steps),
	}

	var earliest time.Time
	var latestEnd time.Time

	for _, step := range steps {
		switch step.CompletionStatus {
		case cook.StepCompleted:
			summary.Succeeded++
		case cook.StepFailed:
			summary.Failed++
		case cook.StepSkipped:
			summary.Skipped++
		}

		if !step.Started.IsZero() {
			if earliest.IsZero() || step.Started.Before(earliest) {
				earliest = step.Started
			}
			end := step.Started.Add(step.Duration)
			if end.After(latestEnd) {
				latestEnd = end
			}
		}
	}

	summary.StartedAt = earliest
	if !earliest.IsZero() && !latestEnd.IsZero() {
		summary.Duration = latestEnd.Sub(earliest)
	}

	// Determine overall status
	summary.Status = determineJobStatus(steps)

	return summary
}

// determineJobStatus computes the aggregate job status from step completions.
func determineJobStatus(steps []cook.StepCompletion) JobStatus {
	if len(steps) == 0 {
		return JobPending
	}

	hasInProgress := false
	hasFailed := false
	hasNotStarted := false
	hasCompleted := false

	for _, step := range steps {
		switch step.CompletionStatus {
		case cook.StepNotStarted:
			hasNotStarted = true
		case cook.StepInProgress:
			hasInProgress = true
		case cook.StepCompleted, cook.StepSkipped:
			hasCompleted = true
		case cook.StepFailed:
			hasFailed = true
		}
	}

	if hasInProgress {
		return JobRunning
	}
	if hasFailed {
		return JobFailed
	}
	if hasNotStarted && hasCompleted {
		return JobPartial
	}
	if hasNotStarted {
		return JobPending
	}
	return JobSucceeded
}
