package pki

import (
	"fmt"
	"os"
	"testing"
)

// TEMPORARY CI diagnostic (UAT.12b), to be deleted: the CI log is not
// readable from the authoring environment, so surface a failing exit as an
// annotation.
func TestMain(m *testing.M) {
	code := m.Run()
	if code != 0 {
		fmt.Printf("\n::error::DIAG package %s exit code %d\n", "internal/pki", code)
	}
	os.Exit(code)
}
