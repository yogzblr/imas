package pxc

import (
	"strings"
	"testing"
)

func TestOpenDBEmptyDSN(t *testing.T) {
	if _, err := OpenDB(""); err == nil {
		t.Error("expected an error for an empty DSN")
	}
}

// Security review 2026-10, I1: farmer refuses to start on a DSN whose loc
// is not UTC, naming the setting, before it connects to anything.
func TestOpenDBRefusesNonUTCLoc(t *testing.T) {
	const secret = "s3cr3t-pw"
	for _, dsn := range []string{
		"farmer_svc:" + secret + "@tcp(pxc:3306)/farmer?parseTime=true&loc=Local",
		"farmer_svc:" + secret + "@tcp(pxc:3306)/farmer?parseTime=true&charset=utf8mb4&loc=Asia%2FKolkata",
	} {
		_, err := OpenDB(dsn)
		if err == nil || !strings.Contains(err.Error(), "IMAS_PXC_DSN") || !strings.Contains(err.Error(), "loc=UTC") {
			t.Errorf("OpenDB(%q) = %v, want an error naming IMAS_PXC_DSN and loc=UTC", dsn, err)
		}
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("error carries the password: %v", err)
		}
	}
}
