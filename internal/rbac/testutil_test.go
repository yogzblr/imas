package rbac

import (
	"fmt"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/props"
)

// newTestDB opens a fresh in-memory, pure-Go (no CGO) sqlite database,
// migrates this package's tables, and installs it as the package-level db
// used by RoleStore/UserRoleMap/Registry. It also wires up a separate
// in-memory props database, since dynamic cohort resolution (cohort.go's
// resolveDynamic) reads through internal/props, which has its own
// package-level db global that must be set for tests to avoid a nil-db
// panic. Each test gets its own named in-memory database so tests never
// share rows; since none of these tests run in parallel with each other
// (they share the package-level db globals), this is safe to call
// unconditionally at the top of every test that touches PXC-backed
// storage.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	if err := gdb.AutoMigrate(Models()...); err != nil {
		t.Fatalf("migrating test db: %v", err)
	}
	SetDB(gdb)
	t.Cleanup(func() { SetDB(nil) })

	propsDSN := fmt.Sprintf("file:%s-props?mode=memory&cache=shared", t.Name())
	propsDB, err := gorm.Open(sqlite.Open(propsDSN), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening props test db: %v", err)
	}
	if err := propsDB.AutoMigrate(props.Models()...); err != nil {
		t.Fatalf("migrating props test db: %v", err)
	}
	props.SetDB(propsDB)
	t.Cleanup(func() { props.SetDB(nil) })

	return gdb
}

// putCohortRaw writes a cohort definition directly to the store, bypassing
// Registry.Register's validation (including its self-reference check) —
// used by tests that need to construct an invalid graph (circular or
// self-referencing cohorts) to exercise ValidateReferences/Resolve's own
// detection of it.
func putCohortRaw(c *Cohort) {
	upsertCohortRow(cohortRowFrom(c))
}
