// Package pxc opens the shared GORM handle farmer's PKI, props/facts, and
// RBAC stores use against the `farmer` schema in the Percona XtraDB
// Cluster (see docs/design/cloudxp-machine-manager-api-design.md §5.1:
// farmer owns farmer.* with ALL grants). cmd/farmer/main.go calls OpenDB
// once at startup and hands the resulting *gorm.DB to each owning
// package's own SetDB (props.SetDB, pki.SetDB, rbac.SetDB) — mirroring
// the injection pattern internal/saasapi/db.go already uses for the
// `saas` schema — so each package reads through it on every call, with no
// in-memory cache layered on top by any caller.
//
// Nothing here creates or changes a table: cmd/migrate owns the schema
// (internal/migrations, design doc §4.1a), and cmd/farmer waits for the
// version it needs (migrations.WaitForSchema) before using the handle.
package pxc

import (
	"fmt"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
	"github.com/yogzblr/imas/internal/rbac"
)

// OpenDB opens a GORM connection to the farmer schema.
func OpenDB(dsn string) (*gorm.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("pxc: empty DSN")
	}
	d, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("pxc: opening farmer schema: %w", err)
	}
	return d, nil
}

// Models is every GORM model in the farmer schema, from each package that
// owns a part of it. The schema itself comes from internal/migrations'
// farmer set; this list is what that set's baseline is checked against
// (internal/migrations' tests) and what farmer's tests AutoMigrate into
// their sqlite databases.
func Models() []any {
	models := append(append(props.Models(), pki.Models()...), rbac.Models()...)
	return append(models, jobs.Models()...)
}
