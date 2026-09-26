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
//   - no push arrived while it was being fetched (a push is at least as
//     new as whatever was staged when the fetch began, so the pulled copy
//     can only be the same job or an older one);
//   - its JobID is not among the jobs this sprout already handled
//     (config.SproutHandledJobsFile, which pushes are recorded in too);
//   - farmer stamped its DispatchedAt, and it is no older than
//     config.StagedRecipeMaxAge.
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
// dropped. Call it before cooking the pushed envelope.
func NotePushedEnvelope(jobID string) {
	handledMu.Lock()
	defer handledMu.Unlock()
	pushGen++
	if err := recordHandledJob(jobID); err != nil {
		log.Errorf("cook: recording pushed job %s as handled: %v", jobID, err)
	}
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
	outcome := SyncCooked
	switch {
	case env.DispatchedAt.IsZero():
		outcome = SyncUndated
	case syncClock().Sub(env.DispatchedAt) > stagedRecipeMaxAge():
		outcome = SyncTooOld
	}
	// Recorded even when skipped: it will only get older. If this fails
	// the job isn't cooked, since nothing would stop a later pull cooking
	// it again.
	if err := recordHandledJob(env.JobID); err != nil {
		return env, "", fmt.Errorf("cook: recording pulled job %s as handled: %w", env.JobID, err)
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
	path := config.SproutHandledJobsFile
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(strings.Join(ids, "\n") + "\n"); err != nil {
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
