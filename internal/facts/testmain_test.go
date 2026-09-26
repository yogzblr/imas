package facts

import (
	"fmt"
	"os"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/props"
)

func TestMain(m *testing.M) {
	// storeFacts (listener.go) writes through internal/props, which needs
	// its PXC-backed store wired up (see internal/props/store.go) — a
	// single shared in-memory db for the whole binary run is fine since
	// these tests use distinct sprout IDs.
	gdb, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		fmt.Println("opening props test db:", err)
		os.Exit(1)
	}
	if err := gdb.AutoMigrate(props.Models()...); err != nil {
		fmt.Println("migrating props test db:", err)
		os.Exit(1)
	}
	props.SetDB(gdb)

	os.Exit(m.Run())
}
