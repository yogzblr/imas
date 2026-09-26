// Security-sensitive: asset linking and asset_id → sprout resolution.
// FLAG FOR SECURITY REVIEW per the task brief — §1.4's `unresolved` list
// is a tenant-isolation property, not just a response shape: it must
// never let a caller tell "this asset_id was never linked" apart from
// "this asset_id is linked, but to another tenant's sprout". Every
// caller-visible outcome in this file is built so those two cases (and
// "this sprout doesn't exist" vs. "this sprout is another tenant's")
// produce byte-identical responses.
package saasapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/pki"
)

const (
	assetLinkIDPrefix = "al_"

	// maxAssetIDsPerLookup is §1.4's (and §4 "Pagination"'s) cap on
	// caller-supplied asset_ids per GET .../sprouts call.
	maxAssetIDsPerLookup = 100

	// maxAssetIDLen matches AssetLink's asset_id column size. An ID
	// longer than its column can never have been linked, so it's
	// rejected up front rather than sent to the database.
	maxAssetIDLen = 191

	// farmerNKeysTable is internal/pki's nkeyRow table — farmer's
	// sprout identity/lifecycle record — read (never written) through
	// the saas service account's SELECT grant on farmer.* (§4.1). The
	// design doc's §1.4 SQL names a farmer.sprouts table that doesn't
	// exist; this is the real record. Only its tenant_id, sprout_id and
	// state columns are used (TestFarmerNKeysColumnContract pins them
	// against pki.Models()).
	farmerNKeysTable = "farmer.pki_nkeys"

	// heartbeatLookupTimeout bounds the Valkey reads for one §1.4
	// request's `connected` fields — the same 2s budget
	// internal/natsapi's probeSprout gives a single lookup.
	heartbeatLookupTimeout = 2 * time.Second

	// keyStateAccepted is pki's accepted nkey state. Only accepted
	// sprouts get a heartbeat lookup; any other state reports
	// connected=false — the same rule internal/natsapi's sprouts.list
	// and sprouts.get apply.
	keyStateAccepted = "accepted"
)

type linkAssetRequest struct {
	AssetID string `json:"asset_id"`
}

type assetLinkResponse struct {
	SproutID string    `json:"sprout_id"`
	AssetID  string    `json:"asset_id"`
	LinkedAt time.Time `json:"linked_at"`
}

// sproutByAssetItem is one §1.4 result row.
type sproutByAssetItem struct {
	SproutID  string `json:"sprout_id"`
	AssetID   string `json:"asset_id"`
	KeyState  string `json:"key_state"`
	Connected bool   `json:"connected"`
}

type sproutsByAssetResponse struct {
	Results    []sproutByAssetItem `json:"results"`
	Unresolved []string            `json:"unresolved"`
}

// LinkAsset handles POST /tenants/{tenant_id}/sprouts/{sprout_id}/asset-link
// (design doc §1.3).
//
// The sprout must belong to the caller's tenant in farmer.pki_nkeys (in
// any key state); a sprout that doesn't exist and one that belongs to
// another tenant are both 404 sprout_not_found (§4 "Tenant safety"), so
// no link row can ever point at a sprout outside its own tenant.
//
// Re-linking the exact same (sprout, asset) pair is idempotent: 200 with
// the existing link. Any other collision — this tenant's sprout already
// carrying an asset_id, or the asset_id already being linked anywhere —
// is 409 asset_link_conflict, with one fixed body whichever it was.
// sprout_id uniqueness is per tenant, so only the asset_id collision can
// involve another tenant's row; a 409 for an asset_id the caller can't
// see via §1.4 does imply another tenant holds it. That's accepted:
// asset_ids are CloudXP-generated and globally unique by design, so one
// VM's asset_id legitimately can't be claimed by two tenants.
//
// Not rate-limited: a tenant can create at most one link per sprout it
// owns, so the table can't grow faster than the tenant's own fleet.
func LinkAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	sproutID := r.PathValue("sprout_id")
	if !tenantExists(w, tenantID) {
		return
	}

	var req linkAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}
	assetID := strings.TrimSpace(req.AssetID)
	if assetID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "asset_id is required")
		return
	}
	if len(assetID) > maxAssetIDLen {
		writeError(w, http.StatusBadRequest, "invalid_request", "asset_id is too long")
		return
	}

	owned, err := sproutOwnedByTenant(tenantID, sproutID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up sprout")
		return
	}
	if !owned {
		writeError(w, http.StatusNotFound, "sprout_not_found", "no such sprout")
		return
	}

	linkID, err := newID(assetLinkIDPrefix)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to generate asset link id")
		return
	}
	link := AssetLink{
		ID:       linkID,
		TenantID: tenantID,
		SproutID: sproutID,
		AssetID:  assetID,
		LinkedAt: time.Now().UTC(),
	}

	// Insert first and let the UNIQUE indexes arbitrate, rather than a
	// check-then-insert that two concurrent requests could both pass.
	// Only if the insert fails do we work out why.
	if createErr := db.Create(&link).Error; createErr != nil {
		var existing AssetLink
		err := db.Where("tenant_id = ? AND sprout_id = ? AND asset_id = ?", tenantID, sproutID, assetID).
			First(&existing).Error
		if err == nil {
			writeJSON(w, http.StatusOK, toAssetLinkResponse(existing))
			return
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to link asset")
			return
		}
		conflict, err := assetLinkConflictExists(tenantID, sproutID, assetID)
		if err != nil || !conflict {
			// Not a uniqueness collision: a genuine write failure.
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to link asset")
			return
		}
		writeError(w, http.StatusConflict, "asset_link_conflict",
			"this sprout or asset_id is already linked; unlink it first")
		return
	}

	writeJSON(w, http.StatusCreated, toAssetLinkResponse(link))
}

// UnlinkAsset handles DELETE
// /tenants/{tenant_id}/sprouts/{sprout_id}/asset-link (design doc §1.3).
// The delete's WHERE clause carries tenant_id as well as sprout_id, so
// another tenant's link is indistinguishable from no link: both 404
// asset_link_not_found.
func UnlinkAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	sproutID := r.PathValue("sprout_id")
	if !tenantExists(w, tenantID) {
		return
	}

	res := db.Where("tenant_id = ? AND sprout_id = ?", tenantID, sproutID).Delete(&AssetLink{})
	if res.Error != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to unlink asset")
		return
	}
	if res.RowsAffected == 0 {
		writeError(w, http.StatusNotFound, "asset_link_not_found", "no asset link for this sprout")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sprout_id": sproutID, "unlinked": true})
}

// ListSproutsByAssetIDs handles GET
// /tenants/{tenant_id}/sprouts?asset_ids=a1,a2,... (design doc §1.4).
//
// Resolution is two steps, no NATS call: one local SQL join of
// asset_links against farmer.pki_nkeys for sprout_id/key_state, then a
// heartbeat.IsOnline (Valkey) read per resolved, accepted sprout for
// `connected` — the same composition internal/natsapi's sprouts.list
// uses. `connected` isn't stored in PXC, so it can't be part of the join.
//
// Only the join decides what resolves. An asset_id it doesn't return
// lands in `unresolved`, whatever the reason: never linked, linked by
// another tenant, or linked here but its sprout is missing from (or
// owned by another tenant in) pki_nkeys. The handler never looks at
// *why* an id didn't resolve, so it has no way to leak the difference.
// The heartbeat step only ever runs for rows the join already scoped to
// the caller's tenant, keyed by that same tenant_id.
func ListSproutsByAssetIDs(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if !tenantExists(w, tenantID) {
		return
	}

	assetIDs, ok := parseAssetIDs(w, r.URL.Query()["asset_ids"])
	if !ok {
		return
	}

	rows, err := resolveAssetIDs(tenantID, assetIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to resolve asset ids")
		return
	}
	fillConnected(r.Context(), tenantID, rows)

	byAsset := make(map[string]sproutByAssetItem, len(rows))
	for _, row := range rows {
		byAsset[row.AssetID] = row
	}
	resp := sproutsByAssetResponse{
		Results:    make([]sproutByAssetItem, 0, len(rows)),
		Unresolved: make([]string, 0),
	}
	for _, id := range assetIDs {
		if row, found := byAsset[id]; found {
			resp.Results = append(resp.Results, row)
		} else {
			resp.Unresolved = append(resp.Unresolved, id)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseAssetIDs flattens asset_ids (comma-separated, optionally repeated
// as asset_ids=a1&asset_ids=a2) into a deduplicated, order-preserving
// list. More than maxAssetIDsPerLookup ids is 400 too_many_asset_ids,
// counted before deduplication and checked as ids are scanned, so an
// oversized list is rejected without being fully split.
func parseAssetIDs(w http.ResponseWriter, values []string) ([]string, bool) {
	var ids []string
	seen := make(map[string]bool)
	count := 0
	for _, v := range values {
		for rest, more := v, true; more; {
			var id string
			id, rest, more = strings.Cut(rest, ",")
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			count++
			if count > maxAssetIDsPerLookup {
				writeErrorDetails(w, http.StatusBadRequest, "too_many_asset_ids",
					"at most 100 asset_ids per request", map[string]any{"max": maxAssetIDsPerLookup})
				return nil, false
			}
			if len(id) > maxAssetIDLen {
				writeError(w, http.StatusBadRequest, "invalid_request", "asset_id is too long")
				return nil, false
			}
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "asset_ids is required")
		return nil, false
	}
	return ids, true
}

// resolveAssetIDs is §1.4's local join of saas.asset_links against
// farmer.pki_nkeys. It joins on the (tenant_id, sprout_id) pair — pki_nkeys'
// primary key, since a sprout_id is only unique within a tenant there —
// so a link row can only ever resolve to a sprout in its own tenant, and
// the WHERE clause scopes the links themselves to the caller's tenant.
// key_state is pki_nkeys.state passed through as-is: pki's four states
// (unaccepted/accepted/denied/rejected) are already the strings
// internal/natsapi reports as key_state. Connected is left false;
// fillConnected sets it.
func resolveAssetIDs(tenantID string, assetIDs []string) ([]sproutByAssetItem, error) {
	var rows []sproutByAssetItem
	err := db.Raw(`SELECT a.asset_id AS asset_id, n.sprout_id AS sprout_id, n.state AS key_state
FROM `+AssetLink{}.TableName()+` a
JOIN `+farmerNKeysTable+` n ON n.tenant_id = a.tenant_id AND n.sprout_id = a.sprout_id
WHERE a.tenant_id = ? AND a.asset_id IN ?`, tenantID, assetIDs).Scan(&rows).Error
	return rows, err
}

// fillConnected sets Connected on each accepted row from its live
// heartbeat key, under one shared timeout. heartbeat.IsOnline reports
// false on any Valkey error or an unset client, so a heartbeat outage
// degrades to connected=false rather than failing the request — the
// same behavior as internal/natsapi's sprouts.list.
func fillConnected(ctx context.Context, tenantID string, rows []sproutByAssetItem) {
	ctx, cancel := context.WithTimeout(ctx, heartbeatLookupTimeout)
	defer cancel()
	for i := range rows {
		if rows[i].KeyState == keyStateAccepted {
			rows[i].Connected = heartbeat.IsOnline(ctx, tenantID, rows[i].SproutID)
		}
	}
}

// sproutOwnedByTenant reports whether farmer.pki_nkeys has sprout_id under
// tenant_id — false for both a missing sprout and another tenant's.
func sproutOwnedByTenant(tenantID, sproutID string) (bool, error) {
	if !pki.IsValidSproutID(sproutID) {
		return false, nil
	}
	var count int64
	err := db.Table(farmerNKeysTable).Where("tenant_id = ? AND sprout_id = ?", tenantID, sproutID).Count(&count).Error
	return count > 0, err
}

// assetLinkConflictExists reports whether an existing row collides with
// one of AssetLink's UNIQUE indexes: this tenant's (tenant_id, sprout_id)
// pair, or assetID in any tenant. The asset_id half is deliberately not
// tenant-scoped — it checks the global asset_id constraint rather than
// resolving an id for the caller, and its answer only ever surfaces as
// LinkAsset's fixed 409 body.
func assetLinkConflictExists(tenantID, sproutID, assetID string) (bool, error) {
	var count int64
	err := db.Model(&AssetLink{}).
		Where("(tenant_id = ? AND sprout_id = ?) OR asset_id = ?", tenantID, sproutID, assetID).
		Count(&count).Error
	return count > 0, err
}

func toAssetLinkResponse(l AssetLink) assetLinkResponse {
	return assetLinkResponse{SproutID: l.SproutID, AssetID: l.AssetID, LinkedAt: l.LinkedAt}
}
