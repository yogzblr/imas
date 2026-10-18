// Package retention deletes object-store data that is dated by its key
// and older than its retention (docs/retention.md, U4). Two things use it:
//
//   - farmer's recipe audit sweep (RecipeAuditDate, StartRecipeAuditSweeper):
//     the SaaS API writes recipe audit records create-only under
//     tenants/<tenant_id>/recipe-audit/<YYYY-MM-DD>/ in the recipe bucket;
//     farmer, whose credential has delete on that bucket, removes the days
//     older than IMAS_RECIPE_AUDIT_RETENTION_DAYS (default 365, 0 keeps
//     them for ever). The SaaS API's credential still cannot read or delete
//     them.
//   - the log retention CronJob (`farmer log-retention`, RunLogRetention):
//     Fluent Bit writes service and audit logs under
//     <prefix><YYYY>/<MM>/<DD>/ in the log bucket; the CronJob, with a
//     credential of its own that may list and delete there and nothing
//     else, removes the days older than its retention (default 30).
//
// An object is dated by the day in its key, never by its modification
// time, so a sweep needs no HEAD per object and a key that does not carry
// a day is never deleted. An object of day D is deleted once the whole of
// D is older than the retention: at the start of day D+N+1 (UTC) for a
// retention of N days.
//
// Why a sweep and not a bucket lifecycle rule: the production object
// store is Versity Gateway in front of Azure Blob (design D18), and
// Versity Gateway v1.8.0 answers PutBucketLifecycleConfiguration with
// NotImplemented; the code only speaks S3 (D15), so the one mechanism
// that works on every store is listing and deleting. Recipe audit keys
// also carry the tenant before the date, which no lifecycle prefix filter
// can match.
package retention

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Store is the part of an object store a sweep uses
// (*objectstore.Store satisfies it).
type Store interface {
	List(ctx context.Context, prefix string) ([]string, error)
	Delete(ctx context.Context, key string) error
}

// DateFunc returns the day (UTC midnight) an object's key is dated, or
// false for a key that carries none: such a key is never deleted.
type DateFunc func(key string) (time.Time, bool)

// Result counts what one sweep did.
type Result struct {
	// Deleted is the objects removed; Kept those still inside the
	// retention; Undated those whose key carries no day.
	Deleted, Kept, Undated int
}

// Cutoff is the first day a retention of days keeps at now: objects of
// an earlier day are deleted. days must be positive.
func Cutoff(now time.Time, days int) time.Time {
	y, m, d := now.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -days)
}

// SweepDated deletes every object under prefix whose day (dateOf) is
// before cutoff, and keeps the rest. A failed delete is counted neither
// deleted nor kept and the sweep goes on; the error returned joins the
// failures (the next sweep retries them). It stops early, with ctx's
// error, when ctx is done.
func SweepDated(ctx context.Context, s Store, prefix string, dateOf DateFunc, cutoff time.Time) (Result, error) {
	var r Result
	keys, err := s.List(ctx, prefix)
	if err != nil {
		return r, fmt.Errorf("retention: listing %s: %w", prefix, err)
	}
	var errs []error
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return r, errors.Join(append(errs, err)...)
		}
		day, ok := dateOf(k)
		if !ok {
			r.Undated++
			continue
		}
		if !day.Before(cutoff) {
			r.Kept++
			continue
		}
		if err := s.Delete(ctx, k); err != nil {
			errs = append(errs, err)
			continue
		}
		r.Deleted++
	}
	return r, errors.Join(errs...)
}

// RecipeAuditPrefix is the key root a recipe audit sweep lists: every
// tenant's tenants/<tenant_id>/ (internal/tenantpurge RootTenants).
const RecipeAuditPrefix = "tenants/"

// RecipeAuditDate dates a recipe audit record,
// tenants/<tenant_id>/recipe-audit/<YYYY-MM-DD>/<name>.json
// (internal/saasapi recipes_audit.go). Any other key under tenants/, a
// tenant's recipes among them, is undated and so never deleted.
func RecipeAuditDate(key string) (time.Time, bool) {
	parts := strings.Split(key, "/")
	if len(parts) < 5 || parts[0] != "tenants" || parts[1] == "" || parts[2] != "recipe-audit" || parts[4] == "" {
		return time.Time{}, false
	}
	return parseDay(parts[3], "2006-01-02")
}

// LogDate returns the DateFunc of log objects under prefix (which ends in
// "/" or is empty): <prefix><YYYY>/<MM>/<DD>/<name>, the key layout of the
// chart's Fluent Bit S3 output (logShipping, s3_key_format).
func LogDate(prefix string) DateFunc {
	return func(key string) (time.Time, bool) {
		rest, ok := strings.CutPrefix(key, prefix)
		if !ok {
			return time.Time{}, false
		}
		parts := strings.SplitN(rest, "/", 4)
		if len(parts) != 4 || parts[3] == "" {
			return time.Time{}, false
		}
		return parseDay(parts[0]+"-"+parts[1]+"-"+parts[2], "2006-01-02")
	}
}

// parseDay parses s in layout exactly (time.Parse accepts e.g. a one-digit
// month for "01" only in some layouts; the round trip refuses those).
func parseDay(s, layout string) (time.Time, bool) {
	t, err := time.Parse(layout, s)
	if err != nil || t.Format(layout) != s {
		return time.Time{}, false
	}
	return t.UTC(), true
}
