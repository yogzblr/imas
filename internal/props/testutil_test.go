package props

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// memDBSeq numbers this package's in-memory sqlite test databases, so
// a DSN never repeats across `go test -count=N` runs of the same test.
var memDBSeq atomic.Int64

// newTestDB opens a fresh in-memory, pure-Go (no CGO) sqlite database,
// migrates this package's table, and installs it as the package-level db
// used by every store function — mirroring internal/saasapi's test
// pattern. Each test gets its own named in-memory database (rather than
// the bare "file::memory:?cache=shared" DSN) so tests never share rows
// even though the package-level db global means they can't run in
// parallel with each other.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", t.Name(), memDBSeq.Add(1))
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	if err := gdb.AutoMigrate(Models()...); err != nil {
		t.Fatalf("migrating test db: %v", err)
	}
	SetDB(gdb)
	t.Cleanup(func() { SetDB(nil) })
	return gdb
}
