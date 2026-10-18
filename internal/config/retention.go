package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Farmer's retention settings (docs/retention.md, U4), set by the Helm
// chart's farmer.retention.* through these variables. Each also has a
// config file key (joblogttl, recipeauditretentiondays,
// boxkeygraceduration); the variable wins when both are set. Empty or 0
// is the documented default, never "delete at once" (recipe audit
// records: 0 keeps them for ever, as documented). A value that doesn't
// parse or is out of range stops farmer, naming the variable or key.
const (
	// EnvJobLogTTL: how long a job's records and step events (the job
	// bucket's jobs/<tenant>/<sprout>/<jid>/ objects and its job_status
	// row) are kept after the job's last activity. A Go duration,
	// default 720h (30 days), 1h to 87600h.
	EnvJobLogTTL = "IMAS_JOB_LOG_TTL"
	// EnvRecipeAuditRetentionDays: days the recipe audit records
	// (tenants/<id>/recipe-audit/<day>/ in the recipe bucket) are kept.
	// Default 365, 1 to 3650; 0 keeps them for ever.
	EnvRecipeAuditRetentionDays = "IMAS_RECIPE_AUDIT_RETENTION_DAYS"
	// EnvBoxKeyGraceDuration: how long a sprout's previous box public key
	// stays valid after a rotation (BoxKeyGraceDuration). A Go duration,
	// default 24h, 10m to 720h.
	EnvBoxKeyGraceDuration = "IMAS_BOX_KEY_GRACE_DURATION"
)

// Defaults and bounds of the retention settings.
const (
	DefaultJobLogTTL = 720 * time.Hour
	MinJobLogTTL     = time.Hour
	MaxJobLogTTL     = 87600 * time.Hour

	DefaultRecipeAuditRetentionDays = 365
	MaxRecipeAuditRetentionDays     = 3650

	DefaultBoxKeyGraceDuration = 24 * time.Hour
	// MinBoxKeyGraceDuration is twice the sealed messages' ±5 minute
	// window: a payload sealed to the old key just before a rotation
	// must still open when it arrives.
	MinBoxKeyGraceDuration = 10 * time.Minute
	MaxBoxKeyGraceDuration = 720 * time.Hour
)

// RecipeAuditRetentionDays is farmer's recipe audit retention in days
// (EnvRecipeAuditRetentionDays); 0 keeps the records for ever.
var RecipeAuditRetentionDays = DefaultRecipeAuditRetentionDays

// FarmerRetention is farmer's resolved retention settings.
type FarmerRetention struct {
	JobLogTTL                time.Duration
	RecipeAuditRetentionDays int
	BoxKeyGraceDuration      time.Duration
}

// farmerRetentionFrom resolves farmer's retention settings from the
// environment (getenv) and the config file's raw values (get, by key).
func farmerRetentionFrom(getenv func(string) string, get func(string) any) (FarmerRetention, error) {
	var r FarmerRetention
	var err error
	if r.JobLogTTL, err = retentionDuration(EnvJobLogTTL, "joblogttl", getenv, get, DefaultJobLogTTL, MinJobLogTTL, MaxJobLogTTL); err != nil {
		return r, err
	}
	if r.BoxKeyGraceDuration, err = retentionDuration(EnvBoxKeyGraceDuration, "boxkeygraceduration", getenv, get, DefaultBoxKeyGraceDuration, MinBoxKeyGraceDuration, MaxBoxKeyGraceDuration); err != nil {
		return r, err
	}
	if r.RecipeAuditRetentionDays, err = recipeAuditDays(getenv, get); err != nil {
		return r, err
	}
	return r, nil
}

// retentionDuration is one duration setting: env if set, else the config
// file key; empty or zero is def; anything else must be a Go duration from
// lo to hi.
func retentionDuration(env, key string, getenv func(string) string, get func(string) any, def, lo, hi time.Duration) (time.Duration, error) {
	name := key
	v := get(key)
	if s := strings.TrimSpace(getenv(env)); s != "" {
		name, v = env, s
	}
	var d time.Duration
	switch v := v.(type) {
	case nil:
		return def, nil
	case time.Duration:
		d = v
	case int:
		if v != 0 {
			return 0, fmt.Errorf("%s %d has no unit: want a duration such as %s, from %s to %s", name, v, def, lo, hi)
		}
	case string:
		s := strings.TrimSpace(v)
		if s == "" || s == "0" {
			return def, nil
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("%s=%q: want a duration such as %s, from %s to %s", name, v, def, lo, hi)
		}
		d = parsed
	default:
		return 0, fmt.Errorf("%s %v: want a duration such as %s, from %s to %s", name, v, def, lo, hi)
	}
	if d == 0 {
		return def, nil
	}
	if d < lo || d > hi {
		return 0, fmt.Errorf("%s %s: want a duration from %s to %s (empty or 0 for the default, %s)", name, d, lo, hi, def)
	}
	return d, nil
}

// recipeAuditDays is EnvRecipeAuditRetentionDays, else the config file's
// recipeauditretentiondays: empty is the default, 0 for ever, otherwise 1
// to MaxRecipeAuditRetentionDays whole days.
func recipeAuditDays(getenv func(string) string, get func(string) any) (int, error) {
	name := "recipeauditretentiondays"
	v := get(name)
	if s := strings.TrimSpace(getenv(EnvRecipeAuditRetentionDays)); s != "" {
		name, v = EnvRecipeAuditRetentionDays, s
	}
	var n int
	switch v := v.(type) {
	case nil:
		return DefaultRecipeAuditRetentionDays, nil
	case int:
		n = v
	case int64:
		n = int(v)
	case uint64:
		if v > MaxRecipeAuditRetentionDays {
			return 0, fmt.Errorf("%s %d: want 0 (keep for ever) or 1 to %d days", name, v, MaxRecipeAuditRetentionDays)
		}
		n = int(v)
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("%s %v: want a whole number of days", name, v)
		}
		n = int(v)
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return DefaultRecipeAuditRetentionDays, nil
		}
		parsed, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("%s=%q: want a whole number of days, 0 to keep for ever or 1 to %d", name, v, MaxRecipeAuditRetentionDays)
		}
		n = parsed
	default:
		return 0, fmt.Errorf("%s %v: want a whole number of days", name, v)
	}
	if n < 0 || n > MaxRecipeAuditRetentionDays {
		return 0, fmt.Errorf("%s %d: want 0 (keep for ever) or 1 to %d days", name, n, MaxRecipeAuditRetentionDays)
	}
	return n, nil
}

// farmerRetentionFromEnv is farmerRetentionFrom on the process's
// environment and the loaded config file.
func farmerRetentionFromEnv(get func(string) any) (FarmerRetention, error) {
	return farmerRetentionFrom(os.Getenv, get)
}
