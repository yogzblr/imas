package saasapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/objectstore"
)

// Recipe audit (REC.1). FLAG FOR SECURITY REVIEW.
//
// Every PUT and DELETE that gets past authentication, the role check and
// name validation leaves audit records: the tenant, the caller (token
// subject), the recipe name, the SHA-256 and size before and after, and
// the outcome. Never the content: the struct has no field that could hold
// it, and TestRecipeAuditNeverHoldsContent pins that.
//
// A mutation is audited twice: an "attempted" record written before the
// object store changes, and an outcome record after. The first one fails
// closed: if it can't be written, nothing is stored and the request is
// 503 audit_unavailable, so no change happens without a trace. The
// outcome record is best effort; if it can't be written, the error log
// carries the same fields. A request refused before the store is touched
// (validation, quota, a failed precondition) gets one outcome record,
// best effort.
//
// Records are JSON objects in the recipe bucket, one per record, under
// tenants/<tenant_id>/recipe-audit/<YYYY-MM-DD>/, written create-only
// (If-None-Match: *) at a unique key. saasapi's object-store policy grants
// PutObject there and nothing else (no read or delete), so saasapi itself
// can't erase history. The prefix is deliberately not under recipes/:
// IAM's '*' matches '/', so tenants/*/recipes/* (where saasapi may also
// delete) would match tenants/<t>/audit/recipes/... too
// (TestRecipeObjectStorePolicy). Recipe resolution only ever reads
// tenants/<tenant_id>/recipes/, and no route serves the audit prefix. They
// are not in the saas schema because that needs a migration, outside
// REC.1's scope (see the PR's open questions).

// Recipe audit actions and outcomes.
const (
	recipeAuditPut    = "recipe.put"
	recipeAuditDelete = "recipe.delete"

	recipeOutcomeAttempted = "attempted"
	recipeOutcomeCreated   = "created"
	recipeOutcomeReplaced  = "replaced"
	recipeOutcomeDeleted   = "deleted"
	recipeOutcomeRejected  = "rejected"
	recipeOutcomeFailed    = "failed"
)

// RecipeAuditRecord is one audit record. It must never gain a field that
// holds recipe content.
type RecipeAuditRecord struct {
	Time     time.Time `json:"time"`
	TenantID string    `json:"tenant_id"`
	// Caller is the Keycloak token subject.
	Caller string `json:"caller"`
	Action string `json:"action"`
	Name   string `json:"name"`
	// Outcome is attempted, created, replaced, deleted, rejected or failed.
	Outcome string `json:"outcome"`
	// Code is the error code of a rejected or failed request.
	Code         string `json:"code,omitempty"`
	SHA256Before string `json:"sha256_before,omitempty"`
	SizeBefore   int64  `json:"size_before,omitempty"`
	SHA256After  string `json:"sha256_after,omitempty"`
	SizeAfter    int64  `json:"size_after,omitempty"`
}

// recipeAuditSink stores audit records.
type recipeAuditSink interface {
	record(ctx context.Context, rec RecipeAuditRecord) error
}

// objectStoreAuditSink writes each record as its own object (see above).
type objectStoreAuditSink struct {
	store *objectstore.Store
}

// recipeAuditKey returns a fresh, unique key for a record of tenantID at t.
func recipeAuditKey(tenantID string, t time.Time) (string, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("tenants/%s/recipe-audit/%s/%s-%s.json",
		tenantID, t.Format("2006-01-02"), t.Format("150405.000000000"), hex.EncodeToString(nonce[:])), nil
}

func (s objectStoreAuditSink) record(ctx context.Context, rec RecipeAuditRecord) error {
	if !isRecipeKeySegment(rec.TenantID) {
		return fmt.Errorf("saasapi: audit record for unusable tenant %q", rec.TenantID)
	}
	key, err := recipeAuditKey(rec.TenantID, rec.Time)
	if err != nil {
		return err
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = s.store.PutConditional(ctx, key, data, "application/json", objectstore.PutCondition{IfNoneMatch: true})
	return err
}

// auditRecipe stamps and stores rec, and always logs it (the log line is
// the fallback when the store fails). It returns the store's error.
func (svc *recipeService) auditRecipe(ctx context.Context, rec RecipeAuditRecord) error {
	if rec.Time.IsZero() {
		rec.Time = time.Now().UTC()
	}
	var err error
	if svc.audit == nil {
		err = fmt.Errorf("no audit sink")
	} else {
		err = svc.audit.record(ctx, rec)
	}
	if err != nil {
		log.Errorf("saasapi: recipe audit record NOT stored (%v): tenant=%s caller=%q action=%s name=%s outcome=%s code=%s sha256_before=%s size_before=%d sha256_after=%s size_after=%d",
			err, rec.TenantID, rec.Caller, rec.Action, rec.Name, rec.Outcome, rec.Code, rec.SHA256Before, rec.SizeBefore, rec.SHA256After, rec.SizeAfter)
		return err
	}
	log.Infof("saasapi: recipe audit: tenant=%s caller=%q action=%s name=%s outcome=%s code=%s sha256_before=%s size_before=%d sha256_after=%s size_after=%d",
		rec.TenantID, rec.Caller, rec.Action, rec.Name, rec.Outcome, rec.Code, rec.SHA256Before, rec.SizeBefore, rec.SHA256After, rec.SizeAfter)
	return nil
}
