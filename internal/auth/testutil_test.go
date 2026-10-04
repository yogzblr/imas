package auth

import (
	"fmt"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/props"
	"github.com/yogzblr/imas/internal/rbac"
)

// newTestDB wires up the in-memory PXC-backed stores internal/rbac (and,
// transitively, internal/props for dynamic cohort resolution) need — every
// RoleStore/UserRoleMap/Registry this package's tests construct now reads
// and writes straight through to rbac's package-level db rather than a
// local map, so it must be set before any of them are used. Each test gets
// its own named in-memory database so tests never share rows.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := fmt.Sprintf("file:%s-rbac?mode=memory&cache=shared", t.Name())
	rbacDB, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening rbac test db: %v", err)
	}
	if err := rbacDB.AutoMigrate(rbac.Models()...); err != nil {
		t.Fatalf("migrating rbac test db: %v", err)
	}
	rbac.SetDB(rbacDB)
	t.Cleanup(func() { rbac.SetDB(nil) })
	// The users and CLI box key stores (store.go) share the farmer
	// schema with rbac in production.
	if err := rbacDB.AutoMigrate(Models()...); err != nil {
		t.Fatalf("migrating auth test db: %v", err)
	}
	SetDB(rbacDB)
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

	return rbacDB
}
