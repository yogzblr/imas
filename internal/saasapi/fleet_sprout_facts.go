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

	"golang.org/x/mod/semver"
)

// farmerPropsTable is internal/props' propRow table. Only its tenant_id,
// sprout_id, name and value columns are read
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

// SproutFactsReader reads what sprouts last reported. Implementations must
// scope every lookup by tenantID as well as sprout_id, key the result on
// both, and simply omit sprouts they know nothing about.
type SproutFactsReader interface {
	SproutFacts(ctx context.Context, tenantID string, sproutIDs []string) (map[SproutRef]SproutFacts, error)
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
func (farmerSproutFactsReader) SproutFacts(ctx context.Context, tenantID string, sproutIDs []string) (map[SproutRef]SproutFacts, error) {
	d := db
	if d == nil {
		return nil, errNoDB
	}
	out := make(map[SproutRef]SproutFacts, len(sproutIDs))
	if len(sproutIDs) == 0 {
		return out, nil
	}
	var rows []struct {
		SproutID string
		Name     string
		Value    string
	}
	err := d.WithContext(ctx).Table(farmerPropsTable).
		Select("sprout_id", "name", "value").
		Where("tenant_id = ? AND sprout_id IN ? AND name IN ?", tenantID, sproutIDs,
			[]string{farmerPropOS, farmerPropArch, farmerPropSproutVersion}).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		ref := SproutRef{TenantID: tenantID, SproutID: r.SproutID}
		f := out[ref]
		switch r.Name {
		case farmerPropOS:
			f.OS = r.Value
		case farmerPropArch:
			f.Arch = r.Value
		case farmerPropSproutVersion:
			f.Version = canonicalReportedVersion(r.Value)
		}
		out[ref] = f
	}
	return out, nil
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
