package cook

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
)

// Sprout-side catch-up on dispatches missed while disconnected.
//
// NATS push stays the dispatch path. A push sent while the sprout was
// offline is lost, but farmer staged the same envelope first (stage.go),
// so the sprout pulls its staged recipe on startup, on every NATS
// reconnect, and when an operator asks farmer to nudge it
// (NudgeSubject), and cooks it if it missed it.
//
// A pulled recipe is cooked only if all of these hold:
//   - it opens as a payloadbox envelope farmer sealed for this sprout
//     under its pinned tenant key (FetchStagedRecipe; security review
//     2026-10-b, B1), so everything below is read from inside it, never
//     from the object key or the response;
//   - no push arrived while it was being fetched (a push is at least as
//     new as whatever was staged when the fetch began, so the pulled copy
//     can only be the same job or an older one);
//   - its JobID is not among the jobs this sprout already handled
//     (config.SproutHandledJobsFile, which pushes are recorded in too);
//   - farmer stamped its DispatchedAt, and it is no older than
//     config.StagedRecipeMaxAge;
//   - its DispatchedAt is not before that of the newest job this sprout
//     already handled, pushed or pulled (newestHandledFile). A sealed
//     staged copy can be captured by anyone holding the sprout's gateway
//     JWT (the DMZ sees it) and served again later; the job ID check
//     stops it being cooked twice, and this stops an older job the
//     sprout never ran being cooked after a newer one it did.
//
// A pulled job is recorded as handled before it is cooked, and whether or
// not it is cooked, so it is considered at most once.

// SyncTrigger names what prompted a SyncStagedRecipe, for its log lines.
type SyncTrigger string

const (
	SyncOnStartup   SyncTrigger = "startup"
	SyncOnReconnect SyncTrigger = "reconnect"
	SyncOnNudge     SyncTrigger = "farmer nudge"
)

// SyncOutcome is what SyncStagedRecipe did with the staged recipe.
type SyncOutcome string

const (
	SyncNothingStaged  SyncOutcome = "nothing staged"
	SyncAlreadyHandled SyncOutcome = "already handled"
	SyncPushRaced      SyncOutcome = "a push arrived while fetching"
	SyncUndated        SyncOutcome = "no dispatch time"
	SyncTooOld         SyncOutcome = "older than the max age"
	SyncSuperseded     SyncOutcome = "older than a job already handled"
	SyncCooked         SyncOutcome = "cooked"
)

// NudgeSubject is the subject farmer nudges sproutID on to make it pull
// its staged recipe (NudgeSprout). The sprout answers with an Ack before
// it pulls.
func NudgeSubject(sproutID string) string {
	return "imas.sprouts." + sproutID + ".recipe.nudge"
}

// maxHandledJobs bounds config.SproutHandledJobsFile. Only the latest
// staged job can ever be pulled, so this only needs to outlast the pushes
// (self updates included, which aren't staged) that can land between two
// pulls.
const maxHandledJobs = 256

var (
	// syncMu makes pulls run one at a time, so an older fetch can never be
	// decided on after a newer one.
	syncMu sync.Mutex
	// handledMu guards pushGen and config.SproutHandledJobsFile.
	handledMu sync.Mutex
	// pushGen counts pushes received, so a pull can tell one raced it.
	pushGen uint64

	// Swappable in tests.
	fetchStaged = FetchStagedRecipe
	cookPulled  = CookRecipeEnvelope
	syncClock   = time.Now
)

// NotePushedEnvelope records a job the sprout received by NATS push, so a
// later pull of its staged copy is skipped and a pull in flight is
// dropped. Call it before cooking the pushed envelope. RespondCook uses
// claimPushedEnvelope instead, which also refuses a job already handled.
func NotePushedEnvelope(jobID string) {
	if _, err := claimPushedEnvelope(jobID, time.Time{}); err != nil {
		log.Errorf("cook: recording pushed job %s as handled: %v", jobID, err)
	}
}

// claimPushedEnvelope records jobID, a job the sprout received by NATS
// push and farmer stamped dispatchedAt (zero if unknown), as handled, and
// reports whether it was new: false if the handled
// jobs file already lists it, in which case it must not be cooked again
// (security review 2026-10, M2: a dispatch replayed after a restart, or
// sent twice, names a job this sprout already ran). An error means the
// file couldn't be read or written, and the job must not be cooked
// either: nothing would then stop it being cooked a second time.
func claimPushedEnvelope(jobID string, dispatchedAt time.Time) (bool, error) {
	handledMu.Lock()
	defer handledMu.Unlock()
	handled, err := loadHandledJobs()
	if err != nil {
		return false, err
	}
	if slices.Contains(handled, jobID) {
		return false, nil
	}
	if err := recordHandledJob(jobID); err != nil {
		return false, err
	}
	if err := recordNewestHandled(dispatchedAt); err != nil {
		return false, err
	}
	pushGen++
	return true, nil
}

// SyncStagedRecipe pulls this sprout's staged recipe and cooks it if the
// sprout missed its push (see the rules above). It returns once the
// recipe has cooked, or straight away if it isn't cooked. ctx bounds the
// download, not the cook.
func SyncStagedRecipe(ctx context.Context, trigger SyncTrigger) (SyncOutcome, error) {
	env, outcome, err := pullStagedRecipe(ctx)
	if err != nil {
		return "", err
	}
	if outcome != SyncCooked {
		log.Debugf("cook: staged recipe pulled on %s not cooked: %s", trigger, outcome)
		return outcome, nil
	}
	log.Noticef("cook: cooking staged recipe %s pulled on %s; its push was missed", env.JobID, trigger)
	return SyncCooked, cookPulled(env)
}

// pullStagedRecipe fetches the staged recipe and decides whether to cook
// it, returning SyncCooked if so.
func pullStagedRecipe(ctx context.Context) (RecipeEnvelope, SyncOutcome, error) {
	syncMu.Lock()
	defer syncMu.Unlock()

	handledMu.Lock()
	gen := pushGen
	handledMu.Unlock()

	// Only a verified envelope comes back (FetchStagedRecipe): one that
	// doesn't open is an error here, and is neither cooked nor recorded.
	env, err := fetchStaged(ctx)
	if errors.Is(err, pki.ErrFarmerFileNotFound) {
		return RecipeEnvelope{}, SyncNothingStaged, nil
	}
	if err != nil {
		return RecipeEnvelope{}, "", fmt.Errorf("cook: pulling staged recipe: %w", err)
	}
	if env.JobID == "" {
		return RecipeEnvelope{}, "", errors.New("cook: staged recipe has no JobID")
	}

	handledMu.Lock()
	defer handledMu.Unlock()
	if pushGen != gen {
		return env, SyncPushRaced, nil
	}
	handled, err := loadHandledJobs()
	if err != nil {
		return env, "", err
	}
	if slices.Contains(handled, env.JobID) {
		return env, SyncAlreadyHandled, nil
	}
	newest, err := loadNewestHandled()
	if err != nil {
		return env, "", err
	}
	outcome := SyncCooked
	switch {
	case env.DispatchedAt.IsZero():
		outcome = SyncUndated
	case syncClock().Sub(env.DispatchedAt) > stagedRecipeMaxAge():
		outcome = SyncTooOld
	case env.DispatchedAt.Before(newest):
		outcome = SyncSuperseded
	}
	// Recorded even when skipped: it will only get older. If this fails
	// the job isn't cooked, since nothing would stop a later pull cooking
	// it again.
	if err := recordHandledJob(env.JobID); err != nil {
		return env, "", fmt.Errorf("cook: recording pulled job %s as handled: %w", env.JobID, err)
	}
	if outcome == SyncCooked {
		if err := recordNewestHandled(env.DispatchedAt); err != nil {
			return env, "", fmt.Errorf("cook: recording pulled job %s's dispatch time: %w", env.JobID, err)
		}
	}
	return env, outcome, nil
}

func stagedRecipeMaxAge() time.Duration {
	if d := config.StagedRecipeMaxAge; d > 0 {
		return d
	}
	return config.DefaultStagedRecipeMaxAge
}

// loadHandledJobs returns the handled job IDs, oldest first. A missing
// file is an empty list. Callers hold handledMu.
func loadHandledJobs() ([]string, error) {
	path := config.SproutHandledJobsFile
	if path == "" {
		return nil, errors.New("cook: sprouthandledjobsfile is not configured")
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cook: reading handled jobs: %w", err)
	}
	defer f.Close()
	var ids []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if id := strings.TrimSpace(sc.Text()); id != "" {
			ids = append(ids, id)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("cook: reading handled jobs: %w", err)
	}
	return ids, nil
}

// newestHandledFile holds the DispatchedAt (RFC 3339, farmer's clock) of
// the newest job this sprout has handled, next to the handled jobs file.
func newestHandledFile() string { return config.SproutHandledJobsFile + ".newest" }

// loadNewestHandled returns the DispatchedAt in newestHandledFile, or
// the zero time if there is none yet. Callers hold handledMu.
func loadNewestHandled() (time.Time, error) {
	if config.SproutHandledJobsFile == "" {
		return time.Time{}, errors.New("cook: sprouthandledjobsfile is not configured")
	}
	b, err := os.ReadFile(newestHandledFile())
	if os.IsNotExist(err) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("cook: reading newest handled job time: %w", err)
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	if err != nil {
		return time.Time{}, fmt.Errorf("cook: reading newest handled job time: %w", err)
	}
	return t, nil
}

// recordNewestHandled raises newestHandledFile to dispatchedAt if that is
// later than what it holds. A zero dispatchedAt changes nothing. Callers
// hold handledMu.
func recordNewestHandled(dispatchedAt time.Time) error {
	if dispatchedAt.IsZero() {
		return nil
	}
	newest, err := loadNewestHandled()
	if err != nil {
		return err
	}
	if !dispatchedAt.After(newest) {
		return nil
	}
	return writeFileAtomic(newestHandledFile(), []byte(dispatchedAt.UTC().Format(time.RFC3339Nano)+"\n"))
}

// recordHandledJob appends jobID to the handled jobs, keeping the newest
// maxHandledJobs, and writes the file atomically. Callers hold handledMu.
func recordHandledJob(jobID string) error {
	if jobID == "" || strings.ContainsAny(jobID, "\r\n") {
		return fmt.Errorf("cook: job ID %q can't be recorded", jobID)
	}
	ids, err := loadHandledJobs()
	if err != nil {
		return err
	}
	if slices.Contains(ids, jobID) {
		return nil
	}
	ids = append(ids, jobID)
	if len(ids) > maxHandledJobs {
		ids = ids[len(ids)-maxHandledJobs:]
	}
	return writeFileAtomic(config.SproutHandledJobsFile, []byte(strings.Join(ids, "\n")+"\n"))
}

// writeFileAtomic replaces path with data through a synced temp file and
// a rename, creating its directory 0700 if needed.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
