package saasapi

import (
	"fmt"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	log "github.com/yogzblr/imas/internal/log"
)

// db is the package-level GORM handle used by the HTTP handlers, set once
// at startup via SetDB — the same injection pattern natsapi/cook/jobs use
// for their NATS connections (RegisterNatsConn).
var db *gorm.DB

// SetDB installs the GORM handle the handlers use. Call once at startup,
// after OpenDB.
func SetDB(d *gorm.DB) { db = d }

// OpenDB opens a GORM connection to the `saas` schema, after checkDSN. It
// creates and changes nothing: cmd/migrate owns the schema (internal/migrations,
// design doc §4.1a), and cmd/saasapi waits for the version it needs
// (migrations.WaitForSchema) before serving. This package never writes
// to the `farmer` schema; asset_links.go and sprout_actions.go only read
// farmer.pki_nkeys, through the saas service account's SELECT grant
// (§4.1).
func OpenDB(dsn string) (*gorm.DB, error) {
	if err := checkDSN(dsn); err != nil {
		return nil, err
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("saasapi: opening saas schema: %w", err)
	}
	return db, nil
}

// checkDSN refuses a DSN saasapi can't work with, before anything
// connects. parseTime=true is required: without it the driver returns
// DATETIME columns as bytes, and every time.Time field (updated_at,
// expiries, farmer.props' expiry the fleet update gate reads) fails to
// scan, which today would only surface as errors at read time. A loc other
// than UTC is allowed but logged: farmer and saasapi read and write the
// same DATETIME columns, and the Helm chart sets loc=UTC for both. The
// DSN itself is never echoed: it holds the password.
func checkDSN(dsn string) error {
	if dsn == "" {
		return fmt.Errorf("saasapi: empty DSN")
	}
	cfg, err := gomysql.ParseDSN(dsn)
	if err != nil {
		return fmt.Errorf("saasapi: SAASAPI_DSN is not a valid MySQL DSN: %w", err)
	}
	if !cfg.ParseTime {
		return fmt.Errorf("saasapi: SAASAPI_DSN must set parseTime=true (e.g. ...?parseTime=true&loc=UTC); without it DATETIME columns can't be read")
	}
	if cfg.Loc != nil && cfg.Loc != time.UTC {
		log.Warnf("saasapi: SAASAPI_DSN sets loc=%s; farmer and saasapi share DATETIME columns and the Helm chart uses loc=UTC", cfg.Loc)
	}
	return nil
}

// Models is every table this package owns (tenants, provisioning_jobs,
// enrollment_keys, asset_links, asset_action_batches, asset_action_items
// — design doc §4.2; fleet_versions, tenant_update_policy — §4.3). The
// schema itself comes from internal/migrations' saas set; this list is
// what that set's baseline is checked against (internal/migrations'
// tests).
func Models() []any {
	return []any{&Tenant{}, &ProvisioningJob{}, &EnrollmentKey{}, &AssetLink{},
		&AssetActionBatch{}, &AssetActionItem{},
		&FleetVersion{}, &TenantUpdatePolicy{}}
}

// migrateSchema creates Models' tables in a test's sqlite database. Tests
// only: production schema changes are internal/migrations'.
func migrateSchema(d *gorm.DB) error { return d.AutoMigrate(Models()...) }
