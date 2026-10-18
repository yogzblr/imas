// Security-sensitive: enrollment-key issuance, listing, and revocation.
// FLAG FOR SECURITY REVIEW per the task brief — this is the SaaS API half
// of the design doc's §3 "one moment in the whole system where a caller
// has no credential yet." The redemption/validation half (farmer's
// internal/sprout.mint flow, §3.3) is explicitly out of scope here; this
// file only issues and stores keys.
package saasapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/jointoken"
	log "github.com/yogzblr/imas/internal/log"
)

const (
	defaultEnrollmentKeyPrefix = "ek_"

	minExpiresInHours = 1
	// maxExpiresInHours bounds how long a registration key stays valid —
	// the design doc doesn't set a number, but an unbounded/huge expiry
	// undermines the "one-time, tenant-scoped" intent of §1.2 by leaving a
	// long-lived bearer credential lying around. 30 days is a conservative
	// operational default; revisit alongside the security review.
	maxExpiresInHours = 24 * 30
	minMaxUses        = 1
	maxMaxUses        = 10000
)

type createEnrollmentKeyRequest struct {
	ExpiresInHours int `json:"expires_in_hours"`
	MaxUses        int `json:"max_uses"`
}

// createEnrollmentKeyResponse carries the raw secret exactly once, per
// design doc §1.2/§3.1. Nothing else in this package — no log line, no
// stored row, no other response — ever includes RegistrationKey again.
// TenantKeyFingerprint is the fingerprint RegistrationKey ends with
// (internal/jointoken), repeated so an operator can compare it with the
// tenant key a sprout pinned; it is not a secret.
type createEnrollmentKeyResponse struct {
	KeyID                string    `json:"key_id"`
	RegistrationKey      string    `json:"registration_key"`
	TenantKeyFingerprint string    `json:"tenant_key_fingerprint"`
	ExpiresAt            time.Time `json:"expires_at"`
	MaxUses              int       `json:"max_uses"`
}

// enrollmentKeyListItem is the GET listing shape (design doc §1.2: "List
// (with usage/expiry state)"). It deliberately excludes KeyHash — the
// EnrollmentKey struct already tags KeyHash json:"-", but this dedicated
// type keeps that guarantee explicit and independent of struct-tag
// upkeep on the storage model.
type enrollmentKeyListItem struct {
	KeyID     string    `json:"key_id"`
	State     string    `json:"state"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	UsedCount int       `json:"used_count"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateEnrollmentKey handles POST /tenants/{tenant_id}/enrollment-keys
// (design doc §1.2, §3.1). It generates a random key_id (public, indexed
// lookup) and a separate 32-byte random secret, persists only the
// secret's SHA-256 hash, and returns the full
// "{key_id}.{secret}.{tenant_key_fingerprint}" token exactly once. The
// fingerprint is of the tenant's current box key, which farmer gives
// over the sealed control plane (tenant_boxkey.go; security review
// 2026-10, L24); without it no key is created (503 farmer_unavailable).
func CreateEnrollmentKey(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if !tenantExists(w, tenantID) {
		return
	}

	var req createEnrollmentKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}
	if req.ExpiresInHours < minExpiresInHours || req.ExpiresInHours > maxExpiresInHours {
		writeError(w, http.StatusBadRequest, "invalid_request", "expires_in_hours out of range")
		return
	}
	if req.MaxUses < minMaxUses || req.MaxUses > maxMaxUses {
		writeError(w, http.StatusBadRequest, "invalid_request", "max_uses out of range")
		return
	}

	// Asked before anything is stored: a key without a fingerprint is
	// never handed out.
	fingerprint, err := tenantKeyFingerprintFor(r.Context(), tenantID)
	if errors.Is(err, errTenantKeyDeprovisioned) {
		writeError(w, http.StatusConflict, "tenant_deprovisioned", "the tenant is deprovisioned; its enrollment keys would enroll nothing")
		return
	}
	if err != nil {
		log.Errorf("saasapi: enrollment key for tenant %s: %v", tenantID, err)
		writeError(w, http.StatusServiceUnavailable, "farmer_unavailable", "the tenant's key could not be read from farmer; try again")
		return
	}

	keyID, err := newID(defaultEnrollmentKeyPrefix)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to generate key id")
		return
	}
	secret, err := newEnrollmentSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to generate enrollment secret")
		return
	}

	expiresAt := time.Now().UTC().Add(time.Duration(req.ExpiresInHours) * time.Hour)
	key := EnrollmentKey{
		KeyID:     keyID,
		TenantID:  tenantID,
		KeyHash:   hashSecret(secret),
		Expiry:    expiresAt,
		MaxUses:   req.MaxUses,
		UsedCount: 0,
		Revoked:   false,
	}
	if err := db.Create(&key).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to store enrollment key")
		return
	}

	token, err := jointoken.Format(key.KeyID, secret, fingerprint)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to build the enrollment token")
		return
	}
	writeJSON(w, http.StatusOK, createEnrollmentKeyResponse{
		KeyID:                key.KeyID,
		RegistrationKey:      token,
		TenantKeyFingerprint: fingerprint,
		ExpiresAt:            key.Expiry,
		MaxUses:              key.MaxUses,
	})
}

// ListEnrollmentKeys handles GET /tenants/{tenant_id}/enrollment-keys
// (design doc §1.2). It never returns KeyHash or any material a caller
// could use to redeem a key — only usage/expiry state.
func ListEnrollmentKeys(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if !tenantExists(w, tenantID) {
		return
	}

	var keys []EnrollmentKey
	if err := db.Where("tenant_id = ?", tenantID).Order("created_at DESC").Find(&keys).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list enrollment keys")
		return
	}

	items := make([]enrollmentKeyListItem, 0, len(keys))
	now := time.Now().UTC()
	for _, k := range keys {
		items = append(items, enrollmentKeyListItem{
			KeyID:     k.KeyID,
			State:     enrollmentKeyState(k, now),
			ExpiresAt: k.Expiry,
			MaxUses:   k.MaxUses,
			UsedCount: k.UsedCount,
			CreatedAt: k.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrollment_keys": items})
}

// DeleteEnrollmentKey handles DELETE
// /tenants/{tenant_id}/enrollment-keys/{key_id} (design doc §1.2) —
// revocation. The WHERE clause includes both tenant_id and key_id (design
// doc §4 "Tenant safety"): a key belonging to a different tenant resolves
// to 404, not a distinguishable authorization error.
func DeleteEnrollmentKey(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	keyID := r.PathValue("key_id")

	var key EnrollmentKey
	err := db.Where("tenant_id = ? AND key_id = ?", tenantID, keyID).First(&key).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		writeError(w, http.StatusNotFound, "enrollment_key_not_found", "no such enrollment key")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up enrollment key")
		return
	}

	if err := db.Model(&key).Update("revoked", true).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to revoke enrollment key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"key_id": key.KeyID, "revoked": true})
}

func enrollmentKeyState(k EnrollmentKey, now time.Time) string {
	switch {
	case k.Revoked:
		return "revoked"
	case now.After(k.Expiry):
		return "expired"
	case k.UsedCount >= k.MaxUses:
		return "exhausted"
	default:
		return "active"
	}
}

// tenantExists reports whether tenantID is a tenant this route may read or
// write data of, answering 404 tenant_not_found if not. A purged tenant
// counts as gone (S6): its data is erased, and no route may store more.
func tenantExists(w http.ResponseWriter, tenantID string) bool {
	var count int64
	if err := db.Model(&Tenant{}).Where("id = ? AND status <> ?", tenantID, TenantStatusPurged).Count(&count).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up tenant")
		return false
	}
	if count == 0 {
		writeError(w, http.StatusNotFound, "tenant_not_found", "no such tenant")
		return false
	}
	return true
}
