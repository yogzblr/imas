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
// Volume. Cooking an N-step recipe makes one creation event on
// imas.sprouts.<sprout>.cook (N "not started" placeholders, written by
// logJobCreation) and N+2 events on imas.cook.<sprout>.<jid>: a seeded
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
//	jobs/<sprout>/<jid>/created.jsonl               placeholders from logJobCreation
//	jobs/<sprout>/<jid>/meta.json                   JobMeta (invoker, creation time)
//	jobs/<sprout>/<jid>/events/<unixnano>-<rand>.jsonl  one step event
//
// A job exists once it has created.jsonl or at least one event.
// created.jsonl followed by events/ in key order holds the same lines the
// old local <jid>.jsonl file did.
//
// Deferred: looking a job up by JID alone (FindJob, DeleteJob) lists the
// whole jobs/ prefix, as ListAllJobs always has to. A jid-to-sprout index
// would make that one List call if job counts grow enough to matter.
// Nothing compacts a finished job's event objects into a single object.

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
	eventsDir     = "events/"
	logExt        = ".jsonl"
)

// JobStatus represents the aggregate status of a job across all its steps.
type JobStatus int

const (
	JobPending   JobStatus = iota // Job created but no steps completed
	JobRunning                    // At least one step in progress
	JobSucceeded                  // All steps completed successfully
	JobFailed                     // At least one step failed
	JobPartial                    // Mix of completed and not-started steps
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
	default:
		return fmt.Errorf("unknown job status: %s", str)
	}
	return nil
}

// JobSummary provides an overview of a job's execution.
type JobSummary struct {
	JID       string                `json:"jid"`
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

// GetJob retrieves a job by its JID and sprout ID.
func (s *Store) GetJob(sproutID, jid string) (*JobSummary, error) {
	obj, err := s.backend()
	if err != nil {
		return nil, err
	}
	if !validKeySegment(sproutID) || !validKeySegment(jid) {
		return nil, ErrJobNotFound
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, jobPrefix(sproutID, jid))
	if err != nil {
		return nil, fmt.Errorf("listing job: %w", err)
	}
	ref := jobRef{sproutID: sproutID, jid: jid}
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

// FindJob searches all sprouts for a job with the given JID.
func (s *Store) FindJob(jid string) (*JobSummary, error) {
	obj, err := s.backend()
	if err != nil {
		return nil, err
	}
	if !validKeySegment(jid) {
		return nil, ErrJobNotFound
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, jobKeyPrefix)
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

// ListJobsForSprout returns all job summaries for a specific sprout,
// sorted by start time (most recent first).
func (s *Store) ListJobsForSprout(sproutID string) ([]JobSummary, error) {
	obj, err := s.backend()
	if err != nil {
		return nil, err
	}
	if !validKeySegment(sproutID) {
		return nil, ErrSproutNoJobs
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, sproutPrefix(sproutID))
	if err != nil {
		return nil, fmt.Errorf("listing sprout jobs: %w", err)
	}
	if len(idx) == 0 {
		return nil, ErrSproutNoJobs
	}
	return loadJobs(ctx, obj, idx), nil
}

// ListAllJobs returns job summaries across all sprouts,
// sorted by start time (most recent first). Limit of 0 means no limit.
func (s *Store) ListAllJobs(limit int) ([]JobSummary, error) {
	obj, err := s.backend()
	if err != nil {
		return nil, err
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, jobKeyPrefix)
	if err != nil {
		return nil, fmt.Errorf("listing jobs: %w", err)
	}
	allSummaries := loadJobs(ctx, obj, idx)
	if limit > 0 && len(allSummaries) > limit {
		allSummaries = allSummaries[:limit]
	}
	return allSummaries, nil
}

// DeleteJob removes a job's log and metadata objects. If more than one
// sprout ran the JID, it deletes the same one FindJob would return (the
// first by sprout ID).
func (s *Store) DeleteJob(jid string) error {
	obj, err := s.backend()
	if err != nil {
		return err
	}
	if !validKeySegment(jid) {
		return ErrJobNotFound
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, jobKeyPrefix)
	if err != nil {
		return fmt.Errorf("listing jobs: %w", err)
	}
	refs := refsForJID(idx, jid)
	if len(refs) == 0 {
		return ErrJobNotFound
	}
	return deleteJobObjects(ctx, obj, refs[0], idx[refs[0]])
}

// ListSprouts returns the IDs of all sprouts that have job records.
func (s *Store) ListSprouts() ([]string, error) {
	obj, err := s.backend()
	if err != nil {
		return nil, err
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, jobKeyPrefix)
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

// CountJobsForSprout returns the number of jobs recorded for a sprout.
func (s *Store) CountJobsForSprout(sproutID string) (int, error) {
	obj, err := s.backend()
	if err != nil {
		return 0, err
	}
	if !validKeySegment(sproutID) {
		return 0, nil
	}
	ctx, cancel := opContext()
	defer cancel()

	idx, err := listJobs(ctx, obj, sproutPrefix(sproutID))
	if err != nil {
		return 0, fmt.Errorf("listing sprout jobs: %w", err)
	}
	return len(idx), nil
}

// validKeySegment reports whether id (a sprout ID or JID) can be used as
// one segment of an object key. Both arrive in NATS subject tokens, which
// may contain "/", and a "/" would let one job's keys land inside
// another's prefix.
func validKeySegment(id string) bool {
	return id != "" && id != "." && id != ".." && !strings.Contains(id, "/")
}

func sproutPrefix(sproutID string) string {
	return jobKeyPrefix + sproutID + "/"
}

func jobPrefix(sproutID, jid string) string {
	return sproutPrefix(sproutID) + jid + "/"
}

func createdKey(sproutID, jid string) string {
	return jobPrefix(sproutID, jid) + createdObject
}

func metaKey(sproutID, jid string) string {
	return jobPrefix(sproutID, jid) + metaObject
}

// eventKey names the object for one job event received at the given
// time. The zero-padded UnixNano sorts lexically in time order; the random
// suffix keeps two events received in the same nanosecond (on different
// replicas) from overwriting each other.
func eventKey(sproutID, jid string, at time.Time) string {
	var suffix [4]byte
	rand.Read(suffix[:])
	return fmt.Sprintf("%s%s%020d-%s%s", jobPrefix(sproutID, jid), eventsDir, at.UnixNano(), hex.EncodeToString(suffix[:]), logExt)
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

// jobRef identifies one sprout's run of one job.
type jobRef struct {
	sproutID string
	jid      string
}

// jobObjects is what a List found under one job's prefix.
type jobObjects struct {
	created bool
	meta    bool
	events  []string // full keys, sorted
}

// hasLog reports whether the job has any step data. A meta.json alone
// (say, logJobCreation's second Put failed) doesn't make a job.
func (o *jobObjects) hasLog() bool {
	return o.created || len(o.events) > 0
}

// indexJobs groups object keys under jobKeyPrefix by job. Keys that don't
// fit the layout are ignored.
func indexJobs(keys []string) map[jobRef]*jobObjects {
	idx := make(map[jobRef]*jobObjects)
	for _, key := range keys {
		rest, ok := strings.CutPrefix(key, jobKeyPrefix)
		if !ok {
			continue
		}
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) != 3 || !validKeySegment(parts[0]) || !validKeySegment(parts[1]) {
			continue
		}
		ref := jobRef{sproutID: parts[0], jid: parts[1]}
		name := parts[2]
		objs := idx[ref]
		if objs == nil {
			objs = &jobObjects{}
		}
		switch {
		case name == createdObject:
			objs.created = true
		case name == metaObject:
			objs.meta = true
		case strings.HasPrefix(name, eventsDir) && strings.HasSuffix(name, logExt) && !strings.Contains(name[len(eventsDir):], "/"):
			objs.events = append(objs.events, key)
		default:
			continue
		}
		idx[ref] = objs
	}
	for _, objs := range idx {
		slices.Sort(objs.events)
	}
	return idx
}

// listJobs lists and indexes every job under prefix that has step data.
func listJobs(ctx context.Context, obj *objectstore.Store, prefix string) (map[jobRef]*jobObjects, error) {
	keys, err := obj.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	idx := indexJobs(keys)
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
		logKeys = append(logKeys, createdKey(ref.sproutID, ref.jid))
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
		logKeys = append(logKeys, createdKey(ref.sproutID, ref.jid))
	}
	logKeys = append(logKeys, objs.events...)
	for _, key := range logKeys {
		if err := obj.Delete(ctx, key); err != nil {
			return fmt.Errorf("deleting job: %w", err)
		}
	}
	if objs.meta {
		obj.Delete(ctx, metaKey(ref.sproutID, ref.jid))
	}
	return nil
}

// readJobMeta reads a job's meta.json.
func readJobMeta(ctx context.Context, obj *objectstore.Store, ref jobRef) (*JobMeta, error) {
	data, err := obj.Get(ctx, metaKey(ref.sproutID, ref.jid))
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
