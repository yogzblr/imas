package cook

// The refusal farmer gives instead of sending anything to a sprout with no
// payload-encryption (box) key on record (FIX.1, owner decision
// 2026-10-04: sealed only, no fallback, no compatibility window).
//
// FLAG FOR SECURITY REVIEW. Every farmer -> sprout request on the sealed
// command path (cmd.run in internal/ingredients/cmd, the cook dispatch and
// the recipe nudge here) is sealed to the sprout's active box key. A
// sprout with none can't open anything, so it gets nothing: not a sealed
// request, and not the plaintext one farmer used to send it. The operator
// re-enrolls it (imas keys delete, then enroll again under a new NKey with
// a fresh join token), and until then every request to it fails with
// ReenrollRequiredError, whose code is ReenrollRequiredCode.

import (
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/pki"
)

// ReenrollRequiredCode is the stable error code for a request farmer
// refused to send because the sprout has no box key on record. It appears
// in ReenrollRequiredError's message, and internal/natsapi replies to
// internal.sprout.action with it (ErrorSproutReenrollRequired).
const ReenrollRequiredCode = "sprout_reenroll_required"

// ErrSproutReenrollRequired matches (errors.Is) every
// ReenrollRequiredError, whichever request it refused.
var ErrSproutReenrollRequired = errors.New("sprout has no payload-encryption key on record and must be re-enrolled")

// ReenrollRequiredError is farmer's refusal to send Op to SproutID, which
// has no box key on record. Nothing was sent. It matches
// ErrSproutReenrollRequired and unwraps to pki.ErrNoActiveBoxKey.
type ReenrollRequiredError struct {
	// Op names the refused request: "cmd.run", "cook" or "recipe nudge".
	Op       string
	SproutID string
}

func (e *ReenrollRequiredError) Error() string {
	return fmt.Sprintf("%s: not sent to sprout %s: it has no payload-encryption key on record, and nothing is sent to a sprout in plaintext; re-enroll it (imas keys delete, then enroll it again with a fresh join token) [%s]",
		e.Op, e.SproutID, ReenrollRequiredCode)
}

// Is reports whether target is ErrSproutReenrollRequired.
func (e *ReenrollRequiredError) Is(target error) bool { return target == ErrSproutReenrollRequired }

// Unwrap returns pki.ErrNoActiveBoxKey, the reason.
func (e *ReenrollRequiredError) Unwrap() error { return pki.ErrNoActiveBoxKey }

// RequireSproutBoxKey checks, before anything is dispatched, that
// tenantID's sproutID has an active box key on record, so op can be
// sealed to it. It returns a ReenrollRequiredError if it has none, and
// any other error reading the key as is. The send itself checks again
// (SealToSprout): this only lets a caller that dispatches asynchronously
// (internal/natsapi's internal.sprout.action cook) report the refusal
// synchronously.
func RequireSproutBoxKey(tenantID, sproutID, op string) error {
	_, _, err := pki.ValidSproutBoxKeys(tenantID, sproutID)
	switch {
	case errors.Is(err, pki.ErrNoActiveBoxKey):
		return &ReenrollRequiredError{Op: op, SproutID: sproutID}
	case err != nil:
		return fmt.Errorf("%s: checking sprout %s's payload-encryption key: %w", op, sproutID, err)
	}
	return nil
}
