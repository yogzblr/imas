package heartbeat

// The "sprout needs an upgrade" marker (security review P6, U3): a sprout
// whose build can't seal its facts or cook step events
// (docs/design/imas-payload-encryption-design.md, Decision 6) keeps
// publishing them in plaintext, and farmer refuses every one. Without a
// marker that is a silent gap: the sprout's facts props expire and its
// jobs never finish. internal/facts and internal/jobs set the marker when
// they refuse a plaintext message from a sprout, and internal/facts clears
// it when a sealed facts report from that sprout opens; sprouts.list and
// sprouts.get show it as upgrade_required.
//
// Key imas:upgrade:{<tenant>:<sprout>}, value the kind of message last
// refused ("facts" or "cook step"), with UpgradeMarkerTTL. A sprout ID is
// unique per tenant only, so the key carries both, like the presence key.
//
// Not authority: the marker only labels a sprout in a listing. Anything on
// the bus can publish a plaintext message on a sprout's subject, so a
// compromised bus can set it (until the sprout's next sealed facts report,
// at most one facts interval later, clears it) or keep it from being
// set, as it can already drop the sprout's messages. It moves no sprout
// into or out of a cohort: it is not a prop.

import (
	"context"
	"time"

	"github.com/yogzblr/imas/internal/tenantpurge"
)

// UpgradeMarkerTTL is how long a marker outlives the last plaintext
// message that set it: three of a sprout's facts intervals
// (props.DefaultPropTTL/3 each), so an old sprout that keeps publishing
// keeps it set, and one that was upgraded or went away loses it.
const UpgradeMarkerTTL = 5 * time.Minute

// Kinds of plaintext message the marker names.
const (
	UpgradeKindFacts    = "facts"
	UpgradeKindCookStep = "cook step"
)

// upgradePrefix names the markers. internal/tenantpurge's inventory
// owns the name, so a purge deletes exactly these keys.
const upgradePrefix = tenantpurge.ValkeyUpgradePrefix

func upgradeKeyFor(tenant, sproutID string) string {
	return upgradePrefix + slotTag(tenant, sproutID)
}

// valkeyTimeout bounds each marker call.
const valkeyTimeout = 2 * time.Second

// MarkUpgradeRequired records that tenantID's sproutID sent a plaintext
// message of kind, which farmer refused. Best effort: no Valkey client or
// a Valkey error leaves the marker unset (the refusal is still logged).
func MarkUpgradeRequired(tenantID, sproutID, kind string) {
	client := loadClient()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), valkeyTimeout)
	defer cancel()
	_ = client.Do(ctx, client.B().Set().Key(upgradeKeyFor(tenantID, sproutID)).Value(kind).
		ExSeconds(int64(UpgradeMarkerTTL/time.Second)).Build()).Error()
}

// ClearUpgradeRequired removes the marker: tenantID's sproutID sealed a
// facts report that opened. Best effort, like MarkUpgradeRequired.
func ClearUpgradeRequired(tenantID, sproutID string) {
	client := loadClient()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), valkeyTimeout)
	defer cancel()
	_ = client.Do(ctx, client.B().Del().Key(upgradeKeyFor(tenantID, sproutID)).Build()).Error()
}

// UpgradeRequired returns the kind of plaintext message tenantID's
// sproutID last sent and farmer refused, or "" if there is no marker
// (or Valkey can't say).
func UpgradeRequired(ctx context.Context, tenantID, sproutID string) string {
	client := loadClient()
	if client == nil {
		return ""
	}
	v, err := client.Do(ctx, client.B().Get().Key(upgradeKeyFor(tenantID, sproutID)).Build()).ToString()
	if err != nil {
		return ""
	}
	return v
}
