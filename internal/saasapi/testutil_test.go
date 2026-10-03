package saasapi

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// newTestDB opens a fresh in-memory, pure-Go (no CGO) sqlite database,
// migrates this package's tables, and installs it as the package-level db
// used by the handlers. Tests in this package are not run in parallel
// with each other because of this shared global.
//
// GORM stamps created_at/updated_at in UTC here, as production's DSN
// (loc=UTC) has the MySQL driver store them: sqlite keeps a time as text
// with its zone offset, so a local-time stamp would compare wrongly with
// the UTC times the outbox sweeper's queries pass.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		NowFunc: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	if err := migrateSchema(gdb); err != nil {
		t.Fatalf("migrating test db: %v", err)
	}
	SetDB(gdb)
	t.Cleanup(func() { SetDB(nil) })
	return gdb
}
