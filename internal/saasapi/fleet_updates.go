package saasapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	log "github.com/yogzblr/imas/internal/log"
)

// Fleet updates, the non-dispatch half of design doc §1.8: the version
// catalog (GET /versions) and each tenant's update policy (GET/PATCH
// .../update-policy). Nothing here sends anything to a sprout. The
// dispatch half, POST .../sprouts/updates and its status endpoint, is in
// fleet_update_dispatch.go, behind a feature flag that's off by default
// until sprout has a real signed self-update path (§1.8's blocking
// dependency, §6).
//
// The catalog is CloudXP's own, not upstream imas's release feed. Upstream
// has each sprout poll <UpdateURL>/latest with no tenant concept, so every
// tenant would land on whatever upstream ships, whenever it ships it.
// Here, a version exists for a tenant only once CloudXP has published it
// to saas.fleet_versions, and a tenant's sprouts are eligible for it only
// once that tenant has approved it in saas.tenant_update_policy.

// maxFleetVersionLen matches FleetVersion's version column size (and
// TenantUpdatePolicy's approved_version). A longer string can't be in the
// catalog, so it's rejected before any query.
const maxFleetVersionLen = 64

// fleetVersionItem is one GET /versions entry. It leaves out
// artifact_url: the catalog tells a tenant what it can approve, and the
// artifact location is for the dispatch path, not the tenant. Adding the
// field later is compatible; removing it from a public response isn't.
type fleetVersionItem struct {
	Version        string    `json:"version"`
	ChecksumSHA256 string    `json:"checksum_sha256"`
	ReleasedAt     time.Time `json:"released_at"`
	Notes          string    `json:"notes,omitempty"`
}

// ListFleetVersions handles GET /versions (design doc §1.8): CloudXP's
// published sprout version catalog, newest first.
//
// The route has no {tenant_id}, so Auth skips its organization check (see
// middleware.go): the catalog is the same for every tenant. Not
// paginated: the catalog grows by one row per CloudXP release, not with
// any tenant's fleet.
func ListFleetVersions(w http.ResponseWriter, r *http.Request) {
	var versions []FleetVersion
	if err := db.Order("released_at DESC").Order("version DESC").Find(&versions).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list versions")
		return
	}
	items := make([]fleetVersionItem, 0, len(versions))
	for _, v := range versions {
		items = append(items, fleetVersionItem{
			Version:        v.Version,
			ChecksumSHA256: v.ChecksumSHA256,
			ReleasedAt:     v.ReleasedAt,
			Notes:          v.Notes,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": items})
}

// updatePolicyResponse is the GET and PATCH .../update-policy response.
// Unset fields are JSON null rather than omitted, so a caller always sees
// the whole policy. UpdatedAt is omitted only for a tenant that has never
// set one (the default policy has no row).
type updatePolicyResponse struct {
	TenantID           string     `json:"tenant_id"`
	ApprovedVersion    *string    `json:"approved_version"`
	AutoUpdate         bool       `json:"auto_update"`
	RolloutWindowStart *time.Time `json:"rollout_window_start"`
	RolloutWindowEnd   *time.Time `json:"rollout_window_end"`
	UpdatedAt          *time.Time `json:"updated_at,omitempty"`
}

// patchField is one PATCH body field, telling apart a field that's absent
// (leave it as is), explicitly null (clear it), and set to a value.
type patchField[T any] struct {
	Set   bool
	Value *T
}

func (f *patchField[T]) UnmarshalJSON(b []byte) error {
	f.Set = true
	if string(b) == "null" {
		f.Value = nil
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	f.Value = &v
	return nil
}

// patchUpdatePolicyRequest is the PATCH .../update-policy body. Every
// field is optional; null clears approved_version or the rollout window.
// Window bounds are RFC 3339 timestamps.
type patchUpdatePolicyRequest struct {
	ApprovedVersion    patchField[string]    `json:"approved_version"`
	AutoUpdate         patchField[bool]      `json:"auto_update"`
	RolloutWindowStart patchField[time.Time] `json:"rollout_window_start"`
	RolloutWindowEnd   patchField[time.Time] `json:"rollout_window_end"`
}

// errInvalidUpdatePolicy is a PATCH whose merged result breaks one of
// validateUpdatePolicy's rules. Its message is caller-safe.
type errInvalidUpdatePolicy struct{ msg string }

func (e errInvalidUpdatePolicy) Error() string { return e.msg }

// GetUpdatePolicy handles GET /tenants/{tenant_id}/update-policy (design
// doc §1.8). A tenant that has never set a policy gets the default one —
// nothing approved, auto_update off — not a 404.
func GetUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if !tenantExists(w, tenantID) {
		return
	}

	// Find, not First: no row is the ordinary default case, and First
	// would have GORM log it as a record-not-found error.
	var policies []TenantUpdatePolicy
	if err := db.Where("tenant_id = ?", tenantID).Limit(1).Find(&policies).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up update policy")
		return
	}
	if len(policies) == 0 {
		writeJSON(w, http.StatusOK, updatePolicyResponse{TenantID: tenantID})
		return
	}
	writeJSON(w, http.StatusOK, toUpdatePolicyResponse(policies[0]))
}

// PatchUpdatePolicy handles PATCH /tenants/{tenant_id}/update-policy
// (design doc §1.8): set or clear the tenant's approved version and
// rollout window, and turn auto_update on or off. Fields absent from the
// body are left as they are.
//
// Rules, checked against the policy as it will be after this PATCH:
//   - approved_version must be in CloudXP's catalog (saas.fleet_versions);
//     anything else is 400 unknown_version.
//   - auto_update needs an approved_version. Updates are opt-in: nothing
//     updates automatically unless the tenant has approved a version,
//     and clearing the approved version while auto_update is on is
//     rejected rather than silently turning it off.
//   - The rollout window is both bounds or neither, with end after start.
//
// The read-merge-write runs in one transaction, with the row locked, so
// two concurrent PATCHes can't each validate against the other's stale
// state. Storing the policy is all this does here. The dispatch path
// (fleet_update_dispatch.go) reads it before and during every rollout.
func PatchUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if !tenantExists(w, tenantID) {
		return
	}

	var req patchUpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}
	if !req.ApprovedVersion.Set && !req.AutoUpdate.Set && !req.RolloutWindowStart.Set && !req.RolloutWindowEnd.Set {
		writeError(w, http.StatusBadRequest, "invalid_request", "no updatable fields provided")
		return
	}
	if req.AutoUpdate.Set && req.AutoUpdate.Value == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "auto_update cannot be null")
		return
	}

	var approvedVersion *string
	if req.ApprovedVersion.Value != nil {
		v := strings.TrimSpace(*req.ApprovedVersion.Value)
		if v == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "approved_version cannot be empty; use null to clear it")
			return
		}
		if len(v) > maxFleetVersionLen {
			writeError(w, http.StatusBadRequest, "invalid_request", "approved_version is too long")
			return
		}
		known, err := fleetVersionExists(v)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up version")
			return
		}
		if !known {
			writeError(w, http.StatusBadRequest, "unknown_version", "approved_version is not in the version catalog")
			return
		}
		approvedVersion = &v
	}

	var policy TenantUpdatePolicy
	err := db.Transaction(func(tx *gorm.DB) error {
		// Make sure the row exists, so the locking read below always has
		// a row to lock, including on a tenant's first PATCH.
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).
			Create(&TenantUpdatePolicy{TenantID: tenantID}).Error; err != nil {
			return err
		}
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&policy, "tenant_id = ?", tenantID).Error; err != nil {
			return err
		}

		if req.ApprovedVersion.Set {
			policy.ApprovedVersion = approvedVersion
		}
		if req.AutoUpdate.Set {
			policy.AutoUpdate = *req.AutoUpdate.Value
		}
		if req.RolloutWindowStart.Set {
			policy.RolloutWindowStart = utcPtr(req.RolloutWindowStart.Value)
		}
		if req.RolloutWindowEnd.Set {
			policy.RolloutWindowEnd = utcPtr(req.RolloutWindowEnd.Value)
		}
		if err := validateUpdatePolicy(policy); err != nil {
			return err
		}
		return tx.Save(&policy).Error
	})
	var invalid errInvalidUpdatePolicy
	switch {
	case errors.As(err, &invalid):
		writeError(w, http.StatusBadRequest, "invalid_request", invalid.msg)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to save update policy")
		return
	}

	approved := "<none>"
	if policy.ApprovedVersion != nil {
		approved = *policy.ApprovedVersion
	}
	log.Infof("saasapi: tenant %s update policy set: approved_version=%s auto_update=%t",
		tenantID, approved, policy.AutoUpdate)

	writeJSON(w, http.StatusOK, toUpdatePolicyResponse(policy))
}

// validateUpdatePolicy checks the rules PatchUpdatePolicy documents that
// depend on the merged policy rather than on one request field.
func validateUpdatePolicy(p TenantUpdatePolicy) error {
	if p.AutoUpdate && p.ApprovedVersion == nil {
		return errInvalidUpdatePolicy{"auto_update requires an approved_version"}
	}
	start, end := p.RolloutWindowStart, p.RolloutWindowEnd
	if (start == nil) != (end == nil) {
		return errInvalidUpdatePolicy{"rollout_window_start and rollout_window_end must be set together"}
	}
	if start != nil && !end.After(*start) {
		return errInvalidUpdatePolicy{"rollout_window_end must be after rollout_window_start"}
	}
	return nil
}

func fleetVersionExists(version string) (bool, error) {
	var count int64
	err := db.Model(&FleetVersion{}).Where("version = ?", version).Count(&count).Error
	return count > 0, err
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func toUpdatePolicyResponse(p TenantUpdatePolicy) updatePolicyResponse {
	updatedAt := p.UpdatedAt
	return updatePolicyResponse{
		TenantID:           p.TenantID,
		ApprovedVersion:    p.ApprovedVersion,
		AutoUpdate:         p.AutoUpdate,
		RolloutWindowStart: p.RolloutWindowStart,
		RolloutWindowEnd:   p.RolloutWindowEnd,
		UpdatedAt:          &updatedAt,
	}
}
