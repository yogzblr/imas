package saasapi

// What each sprout last reported about itself, for fleet update rollouts
// (design doc §2.3): its OS and arch, which pick its catalog row, and its
// running version, which is how a wave sees it back on the new release.
// Read from farmer.props, where farmer's facts listener (internal/facts)
// stores every sprout's facts, through the saas service account's SELECT
// grant on farmer.* (§4.1), as job_status.go reads farmer.job_status.
// Nothing here goes over NATS.

import (
	"context"
	"time"

	"golang.org/x/mod/semver"

	"github.com/yogzblr/imas/internal/props"
)

// farmerPropsTable is internal/props' propRow table. Only its tenant_id,
// sprout_id, name, value, static and expiry columns are read
// (TestFarmerSproutFactsColumnContract pins them against props.Models()).
const farmerPropsTable = "farmer.props"

// Prop names internal/facts' listener stores a sprout's facts under
// (TestFarmerSproutVersionPropContract pins the version's against
// facts.PropSproutVersion).
const (
	farmerPropOS            = "os"
	farmerPropArch          = "arch"
	farmerPropSproutVersion = "sprout_version"
)

// SproutRef names one sprout. sprout_id is unique per tenant only, so it
// never means anything without its tenant.
type SproutRef struct {
	TenantID string
	SproutID string
}

// SproutFacts is what a sprout last reported. Version is canonical semver
// ("v2.4.1"), or "" if the sprout reported none or something that isn't
// semver. Any field the sprout hasn't reported is "".
type SproutFacts struct {
	OS      string
	Arch    string
	Version string
}

// SproutFactWriteTimes is when farmer stored each of a sprout's facts, in
// UTC. A zero time means unknown: the fact wasn't reported, or it is a
// static prop from farmer's config, which no sprout wrote.
type SproutFactWriteTimes struct {
	OS      time.Time
	Arch    time.Time
	Version time.Time
}

// TimedSproutFacts is SproutFacts plus when each fact was written.
type TimedSproutFacts struct {
	SproutFacts
	Written SproutFactWriteTimes
}

// SproutFactsReader reads what sprouts last reported. Implementations must
// scope every lookup by tenantID as well as sprout_id, key the result on
// both, and simply omit sprouts they know nothing about.
type SproutFactsReader interface {
	// SproutFacts is what each sprout last reported, however long ago:
	// what planning a rollout needs.
	SproutFacts(ctx context.Context, tenantID string, sproutIDs []string) (map[SproutRef]SproutFacts, error)
	// SproutFactsWithWriteTimes is SproutFacts plus when each fact was
	// written: what a rollout's wave gate needs, since only a report
	// written after an item's dispatch is proof the update landed.
	SproutFactsWithWriteTimes(ctx context.Context, tenantID string, sproutIDs []string) (map[SproutRef]TimedSproutFacts, error)
}

// sproutFactsReader defaults to the farmer.props reader.
// SetSproutFactsReader replaces it; while nil, no rollout sends anything.
var sproutFactsReader SproutFactsReader = farmerSproutFactsReader{}

// SetSproutFactsReader replaces the reader fleet update rollouts resolve
// sprouts and gate waves through (farmerSproutFactsReader by default).
// Call once at startup, before NewRouter's handlers serve requests.
func SetSproutFactsReader(r SproutFactsReader) { sproutFactsReader = r }

// farmerSproutFactsReader implements SproutFactsReader over farmer.props.
type farmerSproutFactsReader struct{}

// SproutFacts reads the os, arch and sprout_version props of sproutIDs in
// one query, keyed on (tenant_id, sprout_id, name) — farmer.props' primary
// key.
//
// Props' expiry is deliberately not applied. A sprout publishes its facts
// when it connects, and farmer stores them with a five-minute expiry
// (props.DefaultPropTTL), so a sprout connected for an hour has expired
// rows. For these three facts, the row is the sprout's last report: they
// change only when the sprout restarts, and a restart reconnects and
// overwrites them. That last report is what a rollout needs: a sprout that
// was already on the target version, and is sent an update it answers
// with "already running", reports nothing new.
func (r farmerSproutFactsReader) SproutFacts(ctx context.Context, tenantID string, sproutIDs []string) (map[SproutRef]SproutFacts, error) {
	timed, err := r.SproutFactsWithWriteTimes(ctx, tenantID, sproutIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[SproutRef]SproutFacts, len(timed))
	for ref, f := range timed {
		out[ref] = f.SproutFacts
	}
	return out, nil
}

// SproutFactsWithWriteTimes is SproutFacts, from the same single query,
// plus each fact's write time. Expiry is still not applied as a filter: it
// is read to recover the write time (propWriteTime).
func (farmerSproutFactsReader) SproutFactsWithWriteTimes(ctx context.Context, tenantID string, sproutIDs []string) (map[SproutRef]TimedSproutFacts, error) {
	d := db
	if d == nil {
		return nil, errNoDB
	}
	out := make(map[SproutRef]TimedSproutFacts, len(sproutIDs))
	if len(sproutIDs) == 0 {
		return out, nil
	}
	var rows []struct {
		SproutID string
		Name     string
		Value    string
		Static   bool
		Expiry   time.Time
	}
	err := d.WithContext(ctx).Table(farmerPropsTable).
		Select("sprout_id", "name", "value", "static", "expiry").
		Where("tenant_id = ? AND sprout_id IN ? AND name IN ?", tenantID, sproutIDs,
			[]string{farmerPropOS, farmerPropArch, farmerPropSproutVersion}).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		ref := SproutRef{TenantID: tenantID, SproutID: r.SproutID}
		f := out[ref]
		written := propWriteTime(r.Expiry, r.Static)
		switch r.Name {
		case farmerPropOS:
			f.OS, f.Written.OS = r.Value, written
		case farmerPropArch:
			f.Arch, f.Written.Arch = r.Value, written
		case farmerPropSproutVersion:
			f.Version, f.Written.Version = canonicalReportedVersion(r.Value), written
		}
		out[ref] = f
	}
	return out, nil
}

// propWriteTime recovers when farmer wrote a prop row from its expiry.
// Farmer's facts listener stores every fact with props.SetPropForTenant,
// which sets expiry to the write time plus props.DefaultPropTTL, on the
// clock of the farmer node that wrote it; there is no write-time column.
// TestPropWriteTimeMatchesProps pins this against internal/props itself,
// so a change there breaks a test rather than quietly moving the gate.
//
// A static row (farmer config's props.static, written with
// props.StaticPropTTL at load) was never written by a sprout, and its
// expiry would put the "write" a century ahead. It has no write time.
func propWriteTime(expiry time.Time, static bool) time.Time {
	if static || expiry.IsZero() {
		return time.Time{}
	}
	return expiry.Add(-props.DefaultPropTTL).UTC()
}

// canonicalReportedVersion is v as canonical semver, without build
// metadata, or "" if v isn't semver. A sprout reports the release tag it
// was linked with ("v2.4.1"), which is already canonical.
func canonicalReportedVersion(v string) string {
	if !semver.IsValid(v) {
		return ""
	}
	return semver.Canonical(v)
}
